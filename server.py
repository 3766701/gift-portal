from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
import argparse
import getpass
import hashlib
import hmac
import io
import logging
import os
from pathlib import Path
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, unquote, urlparse
import json, re, secrets
import requests
from global_login.soop_drops_http import DropsClient

try:
    import qrcode
    import qrcode.image.svg
except ImportError:
    qrcode = None

try:
    import pymysql
except ImportError:
    pymysql = None

ROOT = Path(__file__).parent
LOG_PATH = ROOT / 'gift_portal.log'
LOGIN_RUNTIME_LOG_PATH = ROOT / 'login_runtime.log'
STEAM_KID_PROXY = 'http://127.0.0.1:7890'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.FileHandler(LOG_PATH, encoding='utf-8'), logging.StreamHandler()],
)
logger = logging.getLogger('gift_portal')


class LoginRuntimeTee:
    """Mirror console output into one redacted, timestamped login runtime log."""

    _SECRET_PATTERNS = (
        re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*[^\s,;\'"}]+'),
        re.compile(r'(?i)(authorization|bearer|token|cookie|_abck|ak_bmsc|bm_sz)\s*[=:]\s*[^\s,;\'"}]+'),
        re.compile(r'(?i)(https?://)([^\s/@:]+):([^\s/@]+)@'),
    )

    def __init__(self, original_stream, log_path):
        self._original_stream = original_stream
        self._log_path = log_path
        self._lock = threading.Lock()
        self._pending_by_thread = {}

    @property
    def encoding(self):
        return getattr(self._original_stream, 'encoding', 'utf-8')

    def isatty(self):
        return self._original_stream.isatty()

    def fileno(self):
        return self._original_stream.fileno()

    @classmethod
    def redact(cls, line):
        redacted = line
        for pattern in cls._SECRET_PATTERNS[:2]:
            redacted = pattern.sub(lambda match: f'{match.group(1)}=[REDACTED]', redacted)
        return cls._SECRET_PATTERNS[2].sub(r'\1[REDACTED]:[REDACTED]@', redacted)

    def _write_runtime_line(self, line):
        if not line:
            return
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with self._log_path.open('a', encoding='utf-8') as stream:
            stream.write(f'{timestamp} {self.redact(line)}\n')

    def write(self, text):
        if not text:
            return 0
        self._original_stream.write(text)
        thread_id = threading.get_ident()
        with self._lock:
            pending = self._pending_by_thread.get(thread_id, '') + text
            lines = pending.splitlines(keepends=True)
            self._pending_by_thread[thread_id] = ''
            for line in lines:
                if line.endswith(('\n', '\r')):
                    self._write_runtime_line(line.rstrip('\r\n'))
                else:
                    self._pending_by_thread[thread_id] = line
        return len(text)

    def flush(self):
        self._original_stream.flush()
        thread_id = threading.get_ident()
        with self._lock:
            pending = self._pending_by_thread.pop(thread_id, '')
            if pending:
                self._write_runtime_line(pending)


_ORIGINAL_STDOUT = sys.stdout
_ORIGINAL_STDERR = sys.stderr
sys.stdout = LoginRuntimeTee(_ORIGINAL_STDOUT, LOGIN_RUNTIME_LOG_PATH)
sys.stderr = LoginRuntimeTee(_ORIGINAL_STDERR, LOGIN_RUNTIME_LOG_PATH)


class RedactingRuntimeFormatter(logging.Formatter):
    def format(self, record):
        return LoginRuntimeTee.redact(super().format(record))


_login_runtime_handler = logging.FileHandler(LOGIN_RUNTIME_LOG_PATH, encoding='utf-8')
_login_runtime_handler.setFormatter(RedactingRuntimeFormatter('%(asctime)s %(levelname)s %(message)s'))
logging.getLogger().addHandler(_login_runtime_handler)
GLOBAL_LOGIN_GETTER_CLASS = None
GLOBAL_LOGIN_IMPORT_LOCK = threading.Lock()
EMAIL_PATTERN = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
ACTIVATION_CODE_PATTERN = re.compile(r'^[A-Z0-9]{12,64}$')
GLOBAL_CODE_DB_CONFIG = {
    'host': os.environ.get('GIFT_PORTAL_DB_HOST', '47.116.48.188'),
    'port': int(os.environ.get('GIFT_PORTAL_DB_PORT', '3306')),
    'user': os.environ.get('GIFT_PORTAL_DB_USER', 'root'),
    'password': os.environ.get('GIFT_PORTAL_DB_PASSWORD', 'n1ck'),
    'database': os.environ.get('GIFT_PORTAL_DB_NAME', 'gift_portal'),
    'charset': 'utf8mb4',
    'connect_timeout': 10,
    'read_timeout': 10,
    'write_timeout': 10,
}
ORDERS = {}
STEAM_QR_SESSIONS = {}
STEAM_QR_SESSIONS_LOCK = threading.Lock()
STEAM_QR_TTL_SECONDS = 120
LOCAL_SEED_HOSTNAME = os.environ.get('GIFT_PORTAL_LOCAL_SEED_HOSTNAME', 'DESKTOP-GKTNGET').casefold()
SOOP_CLAIM_RETRIES = 3
SOOP_CLAIM_RETRY_DELAY = 1.0
ADMIN_SESSION_COOKIE = 'dropzone_admin_session'
ADMIN_SESSION_TTL_SECONDS = 8 * 60 * 60
ADMIN_SESSIONS = {}
ADMIN_SESSIONS_LOCK = threading.Lock()
ADMIN_PASSWORD_HASH_ITERATIONS = 300_000
SYSTEM_LOG_MAX_MESSAGE_LENGTH = 2_000
SYSTEM_LOG_MAX_TRACE_LENGTH = 12_000
_SYSTEM_LOG_WRITE_GUARD = threading.local()
_SYSTEM_LOG_SECRET_PATTERN = re.compile(r'(?i)(cookie|password|authorization|bearer|authticket|userticket|bbsticket)\s*[=:]\s*[^\s,;\'"}]+')
_GLOBAL_LOGIN_HTTP_STATUS_PATTERN = re.compile(r'\bHTTP\s+(\d{3})\b', re.I)
_GLOBAL_LOGIN_ERROR_CODE_PATTERN = re.compile(r'(?i)(?:errorCode|error_code|code)[\'"\s]*[:=][\s\'"`]*([A-Za-z0-9_.-]+)')
RISKBYPASS_BALANCE_REFRESH_SECONDS = 60
_RISKBYPASS_BALANCE_LOCK = threading.Lock()
_RISKBYPASS_BALANCE = None
_RISKBYPASS_BALANCE_ERROR = None
_RISKBYPASS_BALANCE_UPDATED_AT = None
_RISKBYPASS_BALANCE_THREAD = None


def refresh_riskbypass_balance():
    """在后台查询余额，避免管理接口请求同步等待 RiskByPass API。"""
    global _RISKBYPASS_BALANCE, _RISKBYPASS_BALANCE_ERROR, _RISKBYPASS_BALANCE_UPDATED_AT
    try:
        from global_login import krafton_pure_http_login as krafton_login
        from riskbypass import RiskByPassClient

        balance = RiskByPassClient(
            token=krafton_login.load_riskbypass_token()
        ).check_balance()
    except Exception as exc:
        with _RISKBYPASS_BALANCE_LOCK:
            _RISKBYPASS_BALANCE_ERROR = type(exc).__name__
            _RISKBYPASS_BALANCE_UPDATED_AT = time.time()
        logger.warning('RiskByPass balance refresh failed: %s', type(exc).__name__)
        return
    with _RISKBYPASS_BALANCE_LOCK:
        _RISKBYPASS_BALANCE = balance
        _RISKBYPASS_BALANCE_ERROR = None
        _RISKBYPASS_BALANCE_UPDATED_AT = time.time()


def start_riskbypass_balance_refresh():
    """启动唯一的余额缓存刷新线程；首次启动时立即刷新一次。"""
    global _RISKBYPASS_BALANCE_THREAD
    with _RISKBYPASS_BALANCE_LOCK:
        if _RISKBYPASS_BALANCE_THREAD and _RISKBYPASS_BALANCE_THREAD.is_alive():
            return

        def worker():
            while True:
                refresh_riskbypass_balance()
                time.sleep(RISKBYPASS_BALANCE_REFRESH_SECONDS)

        _RISKBYPASS_BALANCE_THREAD = threading.Thread(
            target=worker,
            name='riskbypass-balance-refresh',
            daemon=True,
        )
        _RISKBYPASS_BALANCE_THREAD.start()


def get_cached_riskbypass_balance():
    with _RISKBYPASS_BALANCE_LOCK:
        return (
            _RISKBYPASS_BALANCE,
            _RISKBYPASS_BALANCE_ERROR,
            _RISKBYPASS_BALANCE_UPDATED_AT,
        )


def redact_log_text(value, limit):
    """Keep operational diagnostics while preventing credentials from entering the log database."""
    text = str(value or '')
    text = _SYSTEM_LOG_SECRET_PATTERN.sub(lambda match: f'{match.group(1)}=[REDACTED]', text)
    return text[:limit]


def log_business_error(message, *, exc_info=False):
    """Record a handled business failure in the system error log."""
    logger.error('Business error: %s', message, exc_info=exc_info)


class DatabaseErrorLogHandler(logging.Handler):
    """Persist business failures and unexpected errors without affecting requests."""
    def emit(self, record):
        if getattr(_SYSTEM_LOG_WRITE_GUARD, 'active', False) or pymysql is None:
            return
        try:
            _SYSTEM_LOG_WRITE_GUARD.active = True
            message = redact_log_text(record.getMessage(), SYSTEM_LOG_MAX_MESSAGE_LENGTH)
            trace = ''
            if record.exc_info:
                trace = redact_log_text(logging.Formatter().formatException(record.exc_info), SYSTEM_LOG_MAX_TRACE_LENGTH)
            connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG, autocommit=True)
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        'INSERT INTO system_logs (level, logger_name, message, trace) VALUES (%s, %s, %s, %s)',
                        (record.levelname, record.name[:128], message, trace or None),
                    )
            finally:
                connection.close()
        except Exception:
            pass
        finally:
            _SYSTEM_LOG_WRITE_GUARD.active = False


def ensure_system_log_table():
    """Create the error audit table on startup for existing installations."""
    if pymysql is None:
        return
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG, autocommit=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                'CREATE TABLE IF NOT EXISTS system_logs ('
                'id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, '
                'level VARCHAR(16) NOT NULL, '
                'logger_name VARCHAR(128) NOT NULL, '
                'message TEXT NOT NULL, '
                'trace MEDIUMTEXT NULL, '
                'created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, '
                'PRIMARY KEY (id), KEY ix_system_logs_created_at (created_at), '
                'KEY ix_system_logs_level_created_at (level, created_at)) '
                'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
            )
    finally:
        connection.close()


def get_system_logs(page, page_size, search):
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG)
    try:
        with connection.cursor() as cursor:
            where = 'WHERE level LIKE %s OR logger_name LIKE %s OR message LIKE %s OR trace LIKE %s' if search else ''
            params = [f'%{search}%'] * 4 if search else []
            cursor.execute('SELECT COUNT(*) FROM system_logs ' + where, params)
            total = cursor.fetchone()[0]
            cursor.execute(
                'SELECT id, level, logger_name, message, trace, created_at FROM system_logs ' + where
                + ' ORDER BY id DESC LIMIT %s OFFSET %s',
                params + [page_size, (page - 1) * page_size],
            )
            return total, cursor.fetchall()
    finally:
        connection.close()


def normalize_activation_code(raw_code):
    """Accept only the documented alphanumeric activation-code format."""
    code = str(raw_code).strip().upper().replace('-', '')
    return code if ACTIVATION_CODE_PATTERN.fullmatch(code) else None


def mask_value(value, prefix=3, suffix=2):
    """Keep request diagnostics useful without persisting full user identifiers."""
    value = str(value).strip()
    if not value:
        return ''
    if len(value) <= prefix + suffix:
        return '*' * len(value)
    return f'{value[:prefix]}***{value[-suffix:]}'


def mask_email(value):
    value = str(value).strip()
    if '@' not in value:
        return mask_value(value)
    local, domain = value.rsplit('@', 1)
    return f'{mask_value(local)}@{domain}'


def redemption_trace_context(code, account):
    """Attach safe identifiers to redemption errors for cross-system tracing."""
    return f'code={mask_value(code, prefix=4, suffix=4)} account={mask_email(account)}'


class GlobalLoginError(RuntimeError):
    """A safe summary of an authorization-stage failure."""


class SeedUnavailableError(GlobalLoginError):
    """The global KRAFTON login cannot start because no seed is available."""


class NoClaimableSoopRewardError(RuntimeError):
    """The assigned SOOP inventory has no eligible KRAFTON reward left."""


def summarize_global_login_error(error, stage_hint='', detail_stage=''):
    text = str(error or '')
    lowered = text.casefold()
    if lowered.startswith('foc signin failed') or 'foc 响应中没有 foctoken' in lowered:
        stage = 'foc_signin'
    elif lowered.startswith('oidc token failed'):
        stage = 'oidc_token'
    elif lowered.startswith('oidc authorize') or lowered.startswith('oidc authorization failed') or lowered.startswith('oidc unexpected'):
        stage = 'oidc_authorize'
    elif lowered.startswith('krafton 登录失败'):
        stage = 'krafton_login'
    else:
        stage = 'authorization'
    status = _GLOBAL_LOGIN_HTTP_STATUS_PATTERN.search(text)
    error_code = _GLOBAL_LOGIN_ERROR_CODE_PATTERN.search(text)
    details = [f'stage={stage_hint or stage}']
    if detail_stage:
        details.append(f'detail_stage={detail_stage}')
    if status:
        details.append(f'http_status={status.group(1)}')
    if error_code:
        details.append(f'error_code={error_code.group(1)}')
    if 'error.login-need-to-verify-mfa' in text:
        details.append('login_error=login-need-to-verify-mfa')
    return ' '.join(details)


def global_login_failure_message(error):
    """Return a user-safe, actionable message for the recorded login sub-stage."""
    text = str(error or '')
    if 'SOOP 库存账号登录状态已过期' in text:
        return 'SOOP 库存账号已过期。'
    if 'login_error=login-need-to-verify-mfa' in text or 'error.login-need-to-verify-mfa' in text:
        return '已设置双因素验证。请关闭双因素验证。'
    if re.search(r'(?i)(?:^|\s)http_status\s*=\s*404(?:\s|$)', text):
        return '无法找到使用该电子邮箱的账号。'
    if re.search(r'(?i)error[_]?code\s*[=:]\s*176(?:\s|$)', text) or re.search(
        r"['\"]errorCode['\"]\s*:\s*176(?:\s|$)", text,
    ):
        return '您输入的是近期更改过的旧密码。'
    # KRAFTON returns errorCode 2/26 for rejected email/password logins.
    if re.search(r'(?i)error[_]?code\s*[=:]\s*(?:2|26)(?!\d)', text) or re.search(
        r"['\"]errorCode['\"]\s*:\s*(?:2|26)(?!\d)", text,
    ):
        return '全球账号登录失败，请确认账号、密码及账号状态后重试。'
    if 'detail_stage=bootstrap' in text:
        return '全球账号登录初始化失败，请稍后重试。'
    if 'detail_stage=akamai_sec_cpt' in text:
        return '全球账号安全验证失败，请稍后重试。'
    # 登录首次尝试和完成 sec-cpt 后的密码重试都属于账号密码阶段。
    if 'detail_stage=password_login' in text or 'detail_stage=password_login_retry' in text:
        return '全球账号登录失败，请确认账号、密码及账号状态后重试。'
    if 'detail_stage=profile_before_soop' in text:
        return '全球账号登录会话验证失败，请稍后重试。'
    if 'detail_stage=soop_unbind' in text:
        return 'SOOP 解绑失败，请稍后重试。'
    if 'detail_stage=soop_bind_link' in text:
        return 'SOOP 授权绑定失败，请重新导入有效 Cookie 后重试。'
    if 'detail_stage=soop_bind_verify' in text:
        return 'SOOP 已授权，但绑定状态尚未生效，请稍后重试。'
    return '全球账号授权流程失败，请稍后重试。'


def steam_login_failure_response(error):
    """Translate Steam/KRAFTON login failures into safe customer actions."""
    text = str(error or '')
    lowered = text.casefold()
    if 'soop 库存账号登录状态已过期' in lowered:
        return 'SOOP 库存账号登录状态已过期，请在后台更新该库存账号的登录信息后重试。', 409, False
    if 'soop authorization did not return to krafton' in lowered:
        return 'SOOP 授权绑定失败，请在后台更新该库存账号的登录信息后重试。', 409, False
    if 'invalidpassword' in lowered or 'x-eresult\': \'5\'' in lowered:
        return 'Steam 账号或密码错误，请检查后重试。', 401, False
    if any(value in lowered for value in ('steamguardrequired', 'steam guard verification is required', 'steam token verification is required', 'accountlogindeniedneedtwofactor', 'eresult=85')):
        return '需要Steam令牌。', 428, True
    if any(value in lowered for value in ('steam guard rejected', 'steam令牌校验失败', 'twofactorcodemismatch', 'eresult=88', 'eresult=89')):
        return 'Steam令牌错误或已过期，请重新输入。', 401, True
    if any(value in lowered for value in ('accountlogindeniedthrottle', 'limitexceeded', 'ratelimitexceeded', 'eresult=16', 'eresult=84', 'eresult=87')):
        return 'Steam 登录尝试过于频繁，请稍后再试。', 429, False
    if any(value in lowered for value in ('accountlogondenied', 'qr login rejected', 'remote confirmation denied', 'eresult=63')):
        return 'Steam 阻止了本次登录，请在 Steam 手机客户端确认常用位置和登录行为后重试。', 403, False
    if 'eresult=9' in lowered or 'steam 手机端已拒绝登录' in lowered:
        return 'Steam 手机端已拒绝登录，请重新扫码。', 409, False
    if any(value in lowered for value in ('invalidloginauthcode', 'expiredloginauthcode', 'eresult=65', 'eresult=71')):
        return 'Steam 账号需要邮箱验证码，请先在 Steam 客户端完成验证后重试。', 409, False
    if any(value in lowered for value in ('accountlogondeniednomail', 'accountlogondeniedverifiedemailrequired', 'eresult=66', 'eresult=74')):
        return 'Steam 账号邮箱尚未验证或不可用，请先在 Steam 客户端完成邮箱验证。', 409, False
    if any(value in lowered for value in ('iploginrestrictionfailed', 'eresult=72')):
        return 'Steam 检测到新的网络环境，请先在 Steam 客户端完成本次登录验证后重试。', 409, False
    if any(value in lowered for value in ('accountlockeddown', 'accountdisabled', 'disabled', 'accessdenied', 'eresult=73', 'eresult=80')):
        return 'Steam 账号当前无法登录，请检查账号状态后重试。', 403, False
    if any(value in lowered for value in ('restricteddevice', 'eresult=82')):
        return '当前设备不允许进行 Steam 登录，请改用常用设备后重试。', 403, False
    if any(value in lowered for value in ('regionlocked', 'eresult=83')):
        return 'Steam 账号在当前地区不可用，请切换至账号常用地区后重试。', 403, False
    if 'pollauthsessionstatus timeout' in lowered:
        return 'Steam 登录验证超时，请稍后重试。', 504, False
    if 'healuprequired' in lowered or '需要补全/绑定资料' in lowered:
        return '该 Steam 账号尚未完成 KRAFTON/KID 账号绑定，请先完成绑定后再提货。', 409, False
    if any(value in lowered for value in ('oidcemailloginrequired', 'emailmfarequired', 'confirmemailrequired')):
        return '关联的 KRAFTON/KID 账号需要额外验证，请先在官网完成验证后再提货。', 409, False
    if 'serviceunavailable' in lowered or 'eresult=20' in lowered:
        return 'Steam 登录服务暂时不可用，请稍后重试。', 503, False
    return 'Steam 登录或 KRAFTON 授权失败，请确认账号已关联 KRAFTON/KID 后重试。', 503, False


def qr_login_failure_message(error):
    """Use the same customer-facing mapping as the regular redemption path."""
    text = str(error or '')
    if 'SOOP 库存账号登录状态已过期' in text:
        return 'SOOP 库存账号已过期。'
    if 'SOOP authorization did not return to KRAFTON' in text:
        return 'SOOP 绑定失败，请在后台更新该库存账号的登录信息后重试。'
    return steam_login_failure_response(error)[0]


def soop_account_name_from_cookie(cookie):
    """Derive the SOOP account name from the BbsTicket cookie field."""
    for raw_item in re.split(r'[;\r\n]+', str(cookie or '')):
        name, separator, value = raw_item.strip().partition('=')
        if separator and name.strip() == 'BbsTicket':
            account_name = unquote(value).strip()
            if account_name:
                return account_name
    raise ValueError('SOOP Cookie 中缺少 BbsTicket，无法识别 SOOP 账号。')


def hash_admin_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ADMIN_PASSWORD_HASH_ITERATIONS)
    return f'pbkdf2_sha256${ADMIN_PASSWORD_HASH_ITERATIONS}${salt.hex()}${digest.hex()}'


def verify_admin_password(password, encoded_hash):
    try:
        algorithm, iterations, salt_hex, digest_hex = str(encoded_hash).split('$', 3)
        if algorithm != 'pbkdf2_sha256':
            return False
        digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (TypeError, ValueError):
        return False


def create_admin_session(username):
    token = secrets.token_urlsafe(32)
    session = {'expires_at': time.time() + ADMIN_SESSION_TTL_SECONDS, 'username': username}
    with ADMIN_SESSIONS_LOCK:
        ADMIN_SESSIONS[token] = session
    return token


def get_admin_session_token(headers):
    cookie = SimpleCookie()
    cookie.load(headers.get('Cookie', ''))
    morsel = cookie.get(ADMIN_SESSION_COOKIE)
    if not morsel:
        return None
    token = morsel.value
    with ADMIN_SESSIONS_LOCK:
        session = ADMIN_SESSIONS.get(token)
        if not session or session['expires_at'] <= time.time():
            ADMIN_SESSIONS.pop(token, None)
            return None
    return token


def revoke_admin_session(token):
    if token:
        with ADMIN_SESSIONS_LOCK:
            ADMIN_SESSIONS.pop(token, None)


def get_admin_user(username):
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG)
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT username, password_hash FROM admin_users WHERE username = %s AND enabled = 1', (username,))
            return cursor.fetchone()
    finally:
        connection.close()


def create_admin_user(username, password):
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG, autocommit=False)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                'INSERT INTO admin_users (username, password_hash) VALUES (%s, %s)',
                (username, hash_admin_password(password)),
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_admin_inventory(page, page_size, search):
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG)
    try:
        with connection.cursor() as cursor:
            where = (
                'WHERE si.created_by LIKE %s OR si.soop_account_name LIKE %s OR si.product_name LIKE %s '
                'OR ac.code LIKE %s'
            ) if search else ''
            params = [f'%{search}%'] * 4 if search else []
            cursor.execute(
                'SELECT COUNT(*) FROM soop_inventory si '
                'LEFT JOIN activation_code_inventory aci ON aci.soop_inventory_id = si.id '
                'LEFT JOIN activation_codes ac ON ac.id = aci.activation_code_id ' + where,
                params,
            )
            total = cursor.fetchone()[0]
            cursor.execute(
                'SELECT si.id, si.created_by, si.soop_account_name, si.product_name, si.enabled, '
                'si.created_at, ac.code, ac.claim_status '
                'FROM soop_inventory si '
                'LEFT JOIN activation_code_inventory aci ON aci.soop_inventory_id = si.id '
                'LEFT JOIN activation_codes ac ON ac.id = aci.activation_code_id '
                + where + ' ORDER BY si.id DESC LIMIT %s OFFSET %s',
                params + [page_size, (page - 1) * page_size],
            )
            return total, cursor.fetchall()
    finally:
        connection.close()


def get_admin_claims(page, page_size, search):
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG)
    try:
        with connection.cursor() as cursor:
            where = (
                'WHERE ac.activation_code LIKE %s OR ac.claim_account LIKE %s OR si.product_name LIKE %s '
                'OR si.soop_account_name LIKE %s'
            ) if search else ''
            params = [f'%{search}%'] * 4 if search else []
            cursor.execute(
                'SELECT COUNT(*) FROM activation_claims ac '
                'LEFT JOIN activation_code_inventory aci ON aci.activation_code_id = ac.activation_code_id '
                'LEFT JOIN soop_inventory si ON si.id = aci.soop_inventory_id ' + where,
                params,
            )
            total = cursor.fetchone()[0]
            cursor.execute(
                'SELECT ac.id, ac.activation_code, ac.claim_account, si.product_name, '
                'ac.claimed_at, si.soop_account_name '
                'FROM activation_claims ac '
                'LEFT JOIN activation_code_inventory aci ON aci.activation_code_id = ac.activation_code_id '
                'LEFT JOIN soop_inventory si ON si.id = aci.soop_inventory_id '
                + where + ' ORDER BY ac.claimed_at DESC, ac.id DESC LIMIT %s OFFSET %s',
                params + [page_size, (page - 1) * page_size],
            )
            return total, cursor.fetchall()
    finally:
        connection.close()


def parse_pagination(request_path):
    params = parse_qs(urlparse(request_path).query)
    try:
        page = max(1, int(params.get('page', ['1'])[0]))
        page_size = min(100, max(10, int(params.get('page_size', ['20'])[0])))
    except ValueError:
        raise ValueError('分页参数无效。')
    return page, page_size


def normalize_soop_cookie(raw_cookie):
    """Accept a browser Cookie header or a JSON object exported by a cookie tool."""
    cookie = str(raw_cookie or '').strip()
    if not cookie:
        return ''
    if not cookie.startswith('{'):
        return cookie
    try:
        cookie_values = json.loads(cookie)
    except json.JSONDecodeError as exc:
        raise ValueError('SOOP Cookie JSON 格式错误。') from exc
    if not isinstance(cookie_values, dict):
        raise ValueError('SOOP Cookie JSON 必须是对象。')
    normalized = []
    for name, value in cookie_values.items():
        name = str(name).strip()
        value = '' if value is None else str(value).strip()
        if name:
            normalized.append(f'{name}={value}')
    if not normalized:
        raise ValueError('SOOP Cookie JSON 中没有可用字段。')
    return '; '.join(normalized)


def parse_inventory_import(text):
    entries = []
    for line_number, raw_line in enumerate(str(text).splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        separator = '\t' if '\t' in line else '|'
        fields = [field.strip() for field in line.split(separator)]
        if len(fields) != 3:
            raise ValueError(f'第 {line_number} 行格式错误，应为 3 列。')
        created_by, product_name, raw_cookie = fields
        cookie = normalize_soop_cookie(raw_cookie)
        account_name = soop_account_name_from_cookie(cookie)
        if not all((created_by, account_name, product_name, cookie)):
            raise ValueError(f'第 {line_number} 行有空字段。')
        if any(len(value) > limit for value, limit in ((created_by, 128), (account_name, 128), (product_name, 255))):
            raise ValueError(f'第 {line_number} 行字段长度超出限制。')
        entries.append((created_by, account_name, cookie, product_name))
    if not entries:
        raise ValueError('没有可导入的库存记录。')
    return entries


def import_soop_inventory(entries):
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG, autocommit=False)
    try:
        with connection.cursor() as cursor:
            generated_codes = []
            for entry in entries:
                cursor.execute(
                    'INSERT INTO soop_inventory '
                    '(created_by, soop_account_name, soop_cookie, product_name) '
                    'VALUES (%s, %s, %s, %s)',
                    entry,
                )
                inventory_id = cursor.lastrowid
                for _ in range(5):
                    code = secrets.token_hex(10).upper()
                    try:
                        cursor.execute('INSERT INTO activation_codes (code) VALUES (%s)', (code,))
                        activation_code_id = cursor.lastrowid
                        break
                    except pymysql.err.IntegrityError:
                        continue
                else:
                    raise RuntimeError('生成激活码失败，请重试。')
                cursor.execute(
                    'INSERT INTO activation_code_inventory (activation_code_id, soop_inventory_id) VALUES (%s, %s)',
                    (activation_code_id, inventory_id),
                )
                generated_codes.append({'product_name': entry[3], 'code': code})
        connection.commit()
        return generated_codes
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def create_soop_inventory(created_by, account_name, cookie, product_name):
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG, autocommit=False)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                'INSERT INTO soop_inventory '
                '(created_by, soop_account_name, soop_cookie, product_name) '
                'VALUES (%s, %s, %s, %s)',
                (created_by, account_name, cookie, product_name),
            )
            inventory_id = cursor.lastrowid
        connection.commit()
        return inventory_id
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def set_soop_inventory_enabled(inventory_id, enabled):
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG, autocommit=False)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                'UPDATE soop_inventory SET enabled = %s WHERE id = %s',
                (int(enabled), inventory_id),
            )
            if cursor.rowcount != 1:
                raise LookupError('库存商品不存在。')
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def delete_soop_inventory(inventory_id):
    """Delete inventory and its unused activation code as one transaction."""
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG, autocommit=False)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                'SELECT si.id, ac.id, ac.claim_status '
                'FROM soop_inventory si '
                'LEFT JOIN activation_code_inventory aci ON aci.soop_inventory_id = si.id '
                'LEFT JOIN activation_codes ac ON ac.id = aci.activation_code_id '
                'WHERE si.id = %s FOR UPDATE',
                (inventory_id,),
            )
            inventory = cursor.fetchone()
            if inventory is None:
                raise LookupError('库存商品不存在。')
            activation_code_id = inventory[1]
            if activation_code_id is not None and inventory[2] != 'available':
                raise ValueError('已领取或领取中的库存不能删除。')
            if activation_code_id is not None:
                cursor.execute('DELETE FROM activation_code_inventory WHERE soop_inventory_id = %s', (inventory_id,))
                cursor.execute('DELETE FROM activation_codes WHERE id = %s', (activation_code_id,))
            cursor.execute('DELETE FROM soop_inventory WHERE id = %s', (inventory_id,))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def create_activation_code_for_inventory(inventory_id):
    """Generate one code and bind it to one previously unassigned inventory row."""
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG, autocommit=False)
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT id FROM soop_inventory WHERE id = %s AND enabled = 1 FOR UPDATE', (inventory_id,))
            if cursor.fetchone() is None:
                raise LookupError('库存商品不存在或已禁用。')
            cursor.execute(
                'SELECT ac.code FROM activation_code_inventory aci '
                'JOIN activation_codes ac ON ac.id = aci.activation_code_id '
                'WHERE aci.soop_inventory_id = %s FOR UPDATE',
                (inventory_id,),
            )
            existing = cursor.fetchone()
            if existing:
                raise ValueError(f'该库存商品已关联激活码 {existing[0]}。')
            for _ in range(5):
                code = secrets.token_hex(10).upper()
                try:
                    cursor.execute('INSERT INTO activation_codes (code) VALUES (%s)', (code,))
                    activation_code_id = cursor.lastrowid
                    break
                except pymysql.err.IntegrityError:
                    continue
            else:
                raise RuntimeError('生成激活码失败，请重试。')
            cursor.execute(
                'INSERT INTO activation_code_inventory (activation_code_id, soop_inventory_id) VALUES (%s, %s)',
                (activation_code_id, inventory_id),
            )
        connection.commit()
        return code
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def request_log_parameters(path, data):
    """Return the permitted, masked request fields; passwords are never logged."""
    parameters = {'code': mask_value(data.get('code', ''), prefix=4, suffix=4)}
    if path == '/api/redeem/global':
        parameters['username'] = mask_email(data.get('username', ''))
    elif path == '/api/redeem':
        parameters['steam_user'] = mask_value(data.get('steam_user', ''))
    return parameters


def application_path(request_path):
    """Support both root hosting and the /gift deployment prefix."""
    path = urlparse(request_path).path
    if path == '/gift':
        return '/'
    if path.startswith('/gift/'):
        return path[len('/gift'):]
    return path


def has_gift_prefix(request_path):
    path = urlparse(request_path).path
    return path == '/gift' or path.startswith('/gift/')


def get_global_login_info(username, password, soop_cookie):
    """Authenticate once through the existing HTTP getter without persisting credentials."""
    global GLOBAL_LOGIN_GETTER_CLASS
    from global_login import krafton_pure_http_login as krafton_login

    with GLOBAL_LOGIN_IMPORT_LOCK:
        if GLOBAL_LOGIN_GETTER_CLASS is None:
            from global_login.pubg_cookie_getter_http import PUBGCookieGetter, logger as global_login_logger

            # The bundled module logs account-level diagnostics by default.
            # Portal requests must not persist account identifiers or tokens.
            # Keep only error diagnostics from the getter; these include
            # status/error codes but never credentials or tokens.
            global_login_logger.disabled = False
            global_login_logger.setLevel(logging.ERROR)
            GLOBAL_LOGIN_GETTER_CLASS = PUBGCookieGetter

        getter = GLOBAL_LOGIN_GETTER_CLASS()
    # KID/global-account redemption is intentionally direct.  The QG proxy is
    # reserved for the Steam OAuth flow in get_steam_login_info().
    getter.http_proxy = None
    try:
        with krafton_login.suppress_artifact_persistence():
            login_info = getter.get_authorization_info(
                username, password, soop_cookie=soop_cookie,
                require_game_authorization=False,
            )
        if login_info:
            return login_info
        failure = getter.get_last_login_info() or {}
        failure_error = str(failure.get('error') or '')
        if 'SOOP 库存账号登录状态已过期' in failure_error:
            raise GlobalLoginError(failure_error)
        if any(marker in failure_error for marker in (
            'RiskByPass seed 池暂无可用 seed',
            'RiskByPass seed 池等待超时',
            'RiskByPass seed 池补种失败',
            'RiskByPass 串行初始化未获得有效 seed',
            'RiskByPass 未返回有效 _abck',
        )):
            raise SeedUnavailableError('RiskByPass seed 池暂无可用 seed')
        logger.error(
            'Global login diagnostic stage=%s detail_stage=%s error=%s elapsed_s=%s',
            failure.get('stage', 'unknown'),
            failure.get('detail_stage', ''),
            failure.get('error', ''),
            failure.get('elapsed_s', ''),
        )
        raise GlobalLoginError(summarize_global_login_error(
            failure.get('error'), failure.get('stage'), failure.get('detail_stage'),
        ))
    finally:
        # The getter retains the last authorization response in memory; discard it
        # immediately after this request, regardless of whether login succeeded.
        getter.last_login_info = None


def get_steam_login_info(username, password, steam_token, soop_cookie):
    """Authenticate Steam into KRAFTON, then attach the selected SOOP account."""
    from global_login import krafton_pure_http_login as krafton_login
    from global_login import steam_kid_login
    from global_login.vpn_switcher import get_vpn_switcher
    from global_login.pubg_cookie_getter_http import (
        bind_soop_to_session,
        soop_cookie_from_session,
        unbind_soop_if_linked,
    )

    fallback_proxy = STEAM_KID_PROXY
    switcher = None
    try:
        switcher = get_vpn_switcher()
        if switcher.is_vpn_available():
            fallback_proxy = switcher.proxies.get('http') or fallback_proxy
            logger.info('Steam KID using Clash node=%s proxy=%s', switcher.get_current_node(), fallback_proxy)
        else:
            logger.warning('Clash controller has no usable node; using local proxy=%s', fallback_proxy)
    except Exception as exc:
        logger.warning('Clash controller unavailable; using local proxy=%s error=%s', fallback_proxy, type(exc).__name__)
    proxies = [fallback_proxy]
    last_proxy_error = None
    for proxy in proxies:
        try:
            proxy_host = proxy.rsplit('@', 1)[-1].rsplit('://', 1)[-1] if proxy else 'direct'
            logger.info('Steam proxy attempt host=%s', proxy_host)
            session, steam_info = steam_kid_login.login_steam_to_kid_session(username, password, steam_token, proxy)
            break
        except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError) as exc:
            last_proxy_error = exc
            logger.warning('Steam proxy failed host=%s error=%s', proxy_host, type(exc).__name__)
            if switcher is not None and len(proxies) < 3 and switcher.switch_to_next_node():
                next_proxy = switcher.proxies.get('http') or fallback_proxy
                # Clash node changes happen behind the same local listener.
                proxies.append(next_proxy)
            continue
        except RuntimeError as exc:
            last_proxy_error = exc
            text = str(exc).lower()
            if switcher is not None and any(code in text for code in ('eresult=16', 'eresult=84', 'eresult=87', 'http 403', 'http 429')):
                if len(proxies) < 3 and switcher.switch_to_next_node():
                    next_proxy = switcher.proxies.get('http') or fallback_proxy
                    proxies.append(next_proxy)
                    continue
            raise
    else:
        if last_proxy_error:
            raise last_proxy_error
    profile_response = krafton_login.profile(session)
    profile_body = krafton_login.try_json(profile_response)
    if profile_response.status_code != 200:
        raise GlobalLoginError(f'KRAFTON profile 验证失败 HTTP {profile_response.status_code}')
    unbind_soop_if_linked(session, profile_body)
    bind_soop_to_session(session, soop_cookie)
    return {
        'status': 'success',
        'steamid': steam_info.get('steamid'),
        'soop_claim_cookie': soop_cookie_from_session(session, soop_cookie),
    }


def build_steam_qr_svg(challenge_url):
    """生成本地 SVG，避免将一次性 Steam 挑战链接交给第三方二维码服务。"""
    if qrcode is None:
        raise RuntimeError('服务器缺少二维码生成组件。')
    image = qrcode.make(challenge_url, image_factory=qrcode.image.svg.SvgPathImage, border=2)
    output = io.BytesIO()
    image.save(output)
    return output.getvalue().decode('utf-8')


def cleanup_steam_qr_sessions():
    now = time.time()
    with STEAM_QR_SESSIONS_LOCK:
        expired = [key for key, value in STEAM_QR_SESSIONS.items() if value['expires_at'] <= now]
        for key in expired:
            STEAM_QR_SESSIONS.pop(key, None)


def finish_steam_qr_login(qr_session):
    """在扫码确认后将 Steam 会话连接到库存 SOOP 账号。"""
    from global_login import krafton_pure_http_login as krafton_login
    from global_login.pubg_cookie_getter_http import (
        bind_soop_to_session, soop_cookie_from_session, unbind_soop_if_linked,
    )

    session = qr_session['session']
    profile_response = krafton_login.profile(session)
    profile_body = krafton_login.try_json(profile_response)
    if profile_response.status_code != 200:
        raise GlobalLoginError(f'KRAFTON profile 验证失败 HTTP {profile_response.status_code}')
    unbind_soop_if_linked(session, profile_body)
    bind_soop_to_session(session, qr_session['inventory'][1])
    return soop_cookie_from_session(session, qr_session['inventory'][1])


def process_steam_qr_claim(qr_session, steam_info):
    """在扫码确认后异步完成 KID/SOOP 领取，避免阻塞二维码状态响应。"""
    try:
        from global_login import steam_kid_login
        steam_info = steam_kid_login.complete_steam_qr_login(
            qr_session['session'], qr_session['steam_state'], steam_info['poll_response'],
        )
        with qr_session['lock']:
            qr_session['claim_status'] = 'claiming'
        claim_cookie = finish_steam_qr_login(qr_session)
        claim_token = secrets.token_hex(16)
        if not reserve_global_code(qr_session['code'], claim_token):
            with qr_session['lock']:
                qr_session['terminal_status'] = 'conflict'
                qr_session['terminal_message'] = '该激活码正在领取中或已使用。'
            return
        try:
            _, reward, _ = claim_soop_stock(qr_session['inventory'], claim_cookie=claim_cookie)
        except NoClaimableSoopRewardError:
            release_global_code_reservation(qr_session['code'], claim_token)
            with qr_session['lock']:
                qr_session['terminal_status'] = 'failed'
                qr_session['terminal_message'] = 'SOOP 账号中没有可领取的奖励。'
            return
        except Exception:
            release_global_code_reservation(qr_session['code'], claim_token)
            logger.exception('SOOP reward claim failed after Steam QR login')
            with qr_session['lock']:
                qr_session['terminal_status'] = 'failed'
                qr_session['terminal_message'] = 'Steam 登录成功，但 SOOP 宝箱领取失败，请稍后重试。'
            return
        steamid = steam_info.get('steamid') or 'Steam 扫码用户'
        try:
            completed = complete_global_code_claim(qr_session['code'], claim_token, steamid, reward)
        except Exception:
            logger.exception('Activation-code completion persistence failed after Steam QR claim')
            completed = False
        with qr_session['lock']:
            qr_session['terminal_status'] = 'completed' if completed else 'submitted'
            qr_session['terminal_message'] = (
                '提交成功，请重启大厅。' if completed
                else 'SOOP 宝箱已提交领取，兑换状态正在确认，请稍后查询结果。'
            )
    except Exception as exc:
        logger.exception('Steam QR claim worker failed')
        message = qr_login_failure_message(exc)
        with qr_session['lock']:
            qr_session['terminal_status'] = 'failed'
            qr_session['terminal_message'] = message


def get_global_code_status(code):
    """Return the current database state of a global activation code."""
    if pymysql is None or not GLOBAL_CODE_DB_CONFIG['password']:
        raise RuntimeError("全球激活码数据库未配置。")
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG)
    try:
        with connection.cursor() as cursor:
            # Values are always bound parameters, never interpolated SQL text.
            cursor.execute(
                'SELECT si.product_name, ac.used_at, ac.claim_status '
                'FROM activation_codes ac '
                'LEFT JOIN activation_code_inventory aci ON aci.activation_code_id = ac.id '
                'LEFT JOIN soop_inventory si ON si.id = aci.soop_inventory_id '
                'WHERE ac.code = %s LIMIT 1',
                (code,),
            )
            row = cursor.fetchone()
    finally:
        connection.close()
    if row is None:
        return 'missing', None, None
    if row[1] or row[2] == 'claimed':
        return 'used', row[0], row[1]
    if row[2] == 'processing':
        return 'processing', row[0], None
    return 'available', row[0], None


def get_soop_inventory_for_code(code):
    """Resolve the SOOP account and its authenticated Drops session for an activation code."""
    if pymysql is None or not GLOBAL_CODE_DB_CONFIG['password']:
        raise RuntimeError("全球激活码数据库未配置。")
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                'SELECT si.soop_account_name, si.soop_cookie, si.product_name '
                'FROM activation_codes ac '
                'JOIN activation_code_inventory aci ON aci.activation_code_id = ac.id '
                'JOIN soop_inventory si ON si.id = aci.soop_inventory_id '
                'WHERE ac.code = %s AND si.enabled = 1 LIMIT 1',
                (code,),
            )
            return cursor.fetchone()
    finally:
        connection.close()


def ensure_inventory_schema():
    """Remove the legacy item-code claim record after the live-inventory migration."""
    if pymysql is None:
        return
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG, autocommit=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SHOW COLUMNS FROM soop_inventory LIKE 'item_code_idxs'")
            if cursor.fetchone():
                cursor.execute('ALTER TABLE soop_inventory DROP COLUMN item_code_idxs')
            cursor.execute("SHOW COLUMNS FROM activation_claims LIKE 'claimed_item_code_idxs'")
            if cursor.fetchone():
                cursor.execute('ALTER TABLE activation_claims DROP COLUMN claimed_item_code_idxs')
    finally:
        connection.close()


def ensure_feature_config_schema():
    """创建并迁移三种提货方式的开关配置表。"""
    if pymysql is None:
        return
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG, autocommit=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                'CREATE TABLE IF NOT EXISTS portal_feature_config ('
                'scope VARCHAR(128) NOT NULL PRIMARY KEY, '
                'global_enabled TINYINT(1) NOT NULL DEFAULT 1, '
                'steam_enabled TINYINT(1) NOT NULL DEFAULT 0, '
                'qr_enabled TINYINT(1) NOT NULL DEFAULT 0, '
                'updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP '
                'ON UPDATE CURRENT_TIMESTAMP'
                ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
            )
            cursor.execute("SHOW COLUMNS FROM portal_feature_config LIKE 'global_enabled'")
            if cursor.fetchone() is None:
                cursor.execute(
                    'ALTER TABLE portal_feature_config '
                    'ADD COLUMN global_enabled TINYINT(1) NOT NULL DEFAULT 1 '
                    'AFTER scope'
                )
    finally:
        connection.close()


_UNICODE_SURROGATE_PAIR = re.compile(
    r'\\u([dD][89aAbB][0-9a-fA-F]{2})\\u([dD][c-fC-F][0-9a-fA-F]{2})'
)
_UNICODE_ESCAPE = re.compile(r'\\u([0-9a-fA-F]{4})')


def decode_soop_item_name(value):
    """Decode literal Unicode escapes returned by a SOOP inventory item name."""
    text = str(value or '').strip()

    def decode_pair(match):
        high, low = (int(part, 16) for part in match.groups())
        return chr(0x10000 + ((high - 0xD800) << 10) + low - 0xDC00)

    text = _UNICODE_SURROGATE_PAIR.sub(decode_pair, text)
    return _UNICODE_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), text)


def claim_soop_stock(inventory, claim_cookie=None):
    """Claim current eligible KRAFTON Drops and return their live item names."""
    if not inventory:
        raise LookupError('激活码尚未关联 SOOP 库存商品。')
    account_name, stored_cookie, product_name = inventory
    inventory_client = DropsClient(claim_cookie or stored_cookie)
    available_items = inventory_client.get_inventory_items()
    selected_items = {}
    for item_code_idx, item in available_items.items():
        if (
            str(item.get('type', '')).lower() != 'krafton'
            or item.get('acctConn') is not True
            or str(item.get('useFlag')) == 'Y'
        ):
            continue
        if not decode_soop_item_name(item.get('itemName')).strip():
            logger.warning('Skipping SOOP KRAFTON inventory item without itemName item=%s', item_code_idx)
            continue
        inventory_client.log_inventory_preflight(item_code_idx, item)
        inventory_client.require_claimable(item)
        selected_items[item_code_idx] = item
    if not selected_items:
        raise NoClaimableSoopRewardError('SOOP 账号中没有可领取的奖励。')

    def claim_one(item_code_idx):
        """Each worker owns its HTTP session because requests sessions are not thread-safe."""
        client = DropsClient(claim_cookie or stored_cookie)
        last_error = None
        for attempt in range(1, SOOP_CLAIM_RETRIES + 1):
            try:
                return item_code_idx, client.claim(
                    item_code_idx, confirm=True, inventory_item=selected_items[item_code_idx],
                ), None
            except Exception as exc:
                last_error = exc
                logger.warning('SOOP claim failed item=%s attempt=%s/%s', item_code_idx, attempt, SOOP_CLAIM_RETRIES)
                if attempt < SOOP_CLAIM_RETRIES:
                    time.sleep(SOOP_CLAIM_RETRY_DELAY)
        return item_code_idx, None, type(last_error).__name__ if last_error else 'SOOP 请求失败'

    successful_by_index = {}
    failures = []
    indexes = list(selected_items)
    with ThreadPoolExecutor(max_workers=len(indexes), thread_name_prefix='soop-claim') as executor:
        futures = [executor.submit(claim_one, item_code_idx) for item_code_idx in indexes]
        for future in as_completed(futures):
            item_code_idx, result, error = future.result()
            if error is None:
                successful_by_index[item_code_idx] = result
            else:
                failures.append((item_code_idx, error))

    results = [(item_code_idx, successful_by_index[item_code_idx]) for item_code_idx in indexes if item_code_idx in successful_by_index]
    if not results:
        detail = '; '.join(f'{item}: {error}' for item, error in failures)
        raise RuntimeError(f'SOOP 宝箱领取失败（每项已重试 {SOOP_CLAIM_RETRIES} 次）：{detail}')
    if failures:
        logger.warning('SOOP partial claim failures failed_items=%s', [item for item, _ in failures])
    claimed_product_names = list(dict.fromkeys(
        decode_soop_item_name(selected_items[item_code_idx]['itemName'])
        for item_code_idx, _ in results
    ))
    return account_name, ','.join(claimed_product_names), results


def reserve_global_code(code, claim_token):
    """Atomically reserve an available code before making an external claim."""
    if pymysql is None or not GLOBAL_CODE_DB_CONFIG['password']:
        raise RuntimeError("全球激活码数据库未配置。")
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG, autocommit=False)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE activation_codes SET claim_status = 'processing', claim_token = %s, "
                'claim_started_at = UTC_TIMESTAMP() '
                "WHERE code = %s AND used_at IS NULL AND claim_status = 'available'",
                (claim_token, code),
            )
            reserved = cursor.rowcount == 1
        connection.commit()
        return reserved
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def release_global_code_reservation(code, claim_token):
    """Make a code available again only when this request owns its reservation."""
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG, autocommit=False)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE activation_codes SET claim_status = 'available', claim_token = NULL, claim_started_at = NULL "
                "WHERE code = %s AND claim_status = 'processing' AND claim_token = %s",
                (code, claim_token),
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def complete_global_code_claim(code, claim_token, claim_account, product_name):
    """Persist a completed claim; a failure leaves the durable reservation in processing."""
    if pymysql is None or not GLOBAL_CODE_DB_CONFIG['password']:
        raise RuntimeError("全球激活码数据库未配置。")
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG, autocommit=False)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE activation_codes SET used_at = UTC_TIMESTAMP(), claim_status = 'claimed', claim_token = NULL "
                "WHERE code = %s AND claim_status = 'processing' AND claim_token = %s",
                (code, claim_token),
            )
            completed = cursor.rowcount == 1
            if completed:
                cursor.execute(
                    'INSERT INTO activation_claims '
                    '(activation_code_id, activation_code, claim_account, claim_password, product_name, claimed_at) '
                    'SELECT id, code, %s, %s, %s, UTC_TIMESTAMP() '
                    'FROM activation_codes WHERE code = %s',
                    (claim_account, '', product_name or '', code),
                )
        connection.commit()
        return completed
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def is_loopback_request(headers):
    """Local browser testing always exposes all redemption methods."""
    host = str(headers.get('Host', '')).split(':', 1)[0].strip().casefold()
    return host in ('localhost', '127.0.0.1', '::1')


def is_local_seed_host():
    """只有指定开发电脑使用单 seed 池，部署服务器沿用常规容量。"""
    return socket.gethostname().casefold() == LOCAL_SEED_HOSTNAME


def get_feature_config(local_access=False):
    """Read feature switches from MySQL, preferring this machine's override."""
    if local_access:
        return {'global': True, 'steam': True, 'qr': True}
    if pymysql is None or not GLOBAL_CODE_DB_CONFIG['password']:
        raise RuntimeError('Feature configuration database is unavailable.')
    hostname = socket.gethostname()
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                'SELECT global_enabled, steam_enabled, qr_enabled FROM portal_feature_config '
                'WHERE scope IN (%s, %s) ORDER BY scope = %s DESC LIMIT 1',
                (hostname, 'default', hostname),
            )
            row = cursor.fetchone()
    finally:
        connection.close()
    if row is None:
        return {'global': True, 'steam': False, 'qr': False}
    return {'global': bool(row[0]), 'steam': bool(row[1]), 'qr': bool(row[2])}


def set_feature_config(global_enabled, steam_enabled, qr_enabled):
    """更新当前服务器的公开提货方式配置。"""
    if pymysql is None or not GLOBAL_CODE_DB_CONFIG['password']:
        raise RuntimeError('Feature configuration database is unavailable.')
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG, autocommit=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                'INSERT INTO portal_feature_config (scope, global_enabled, steam_enabled, qr_enabled) '
                'VALUES (%s, %s, %s, %s) '
                'ON DUPLICATE KEY UPDATE global_enabled = VALUES(global_enabled), '
                'steam_enabled = VALUES(steam_enabled), '
                'qr_enabled = VALUES(qr_enabled)',
                (socket.gethostname(), int(global_enabled), int(steam_enabled), int(qr_enabled)),
            )
    finally:
        connection.close()

class Handler(BaseHTTPRequestHandler):
    def send_json(self, data, status=200, headers=None):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status); self.send_header('Content-Type', 'application/json; charset=utf-8'); self.send_header('Cache-Control', 'no-store')
        for name, value in (headers or {}).items(): self.send_header(name, value)
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)

    def read_json(self):
        try:
            content_length = int(self.headers.get('Content-Length', '0'))
            if content_length <= 0 or content_length > 64 * 1024:
                raise ValueError
            data = json.loads(self.rfile.read(content_length))
        except (ValueError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def require_admin(self):
        if get_admin_session_token(self.headers):
            return True
        self.send_json({'message': '后台登录已失效，请重新登录。'}, 401)
        return False

    def do_GET(self):
        if not has_gift_prefix(self.path):
            return self.send_json({'message': '页面不存在。'}, 404)
        path = application_path(self.path)
        if path == '/api/admin/session':
            return self.send_json({'authenticated': bool(get_admin_session_token(self.headers))})
        if path == '/api/admin/runtime-status':
            if not self.require_admin(): return
            try:
                from global_login import krafton_pure_http_login as krafton_login
                from global_login.vpn_switcher import get_vpn_switcher
                seed_status = krafton_login._AbckPool.status()
                balance, balance_error, balance_updated_at = get_cached_riskbypass_balance()
                features = get_feature_config()
                switcher = get_vpn_switcher()
                return self.send_json({
                    'seed': {
                        'valid': seed_status.get('queue_size', 0),
                        'fresh': seed_status.get('fresh', 0),
                        'in_use': seed_status.get('in_use', 0),
                        'reusable': seed_status.get('reusable', 0),
                        'capacity': seed_status.get('target', 0),
                        'proxies': krafton_login._AbckPool.runtime_proxies(),
                        'balance': balance,
                        'balance_error': balance_error,
                        'balance_updated_at': balance_updated_at,
                    },
                    'features': features,
                    'clash': {
                        'available': bool(switcher.is_vpn_available()),
                        'group': switcher.get_proxy_group(),
                        'node': switcher.get_current_node(),
                        'available_nodes': switcher.get_available_nodes_count(),
                        'node_name_keywords': switcher.get_node_name_keywords(),
                        'node_name_filter_enabled': switcher.is_node_name_filter_enabled(),
                        'test_url': switcher.test_url,
                    },
                })
            except Exception:
                logger.exception('Admin runtime status query failed')
                return self.send_json({'message': '运行状态查询失败。'}, 503)
        if path == '/api/admin/inventory':
            if not self.require_admin(): return
            try:
                page, page_size = parse_pagination(self.path)
                search = parse_qs(urlparse(self.path).query).get('q', [''])[0].strip()[:128]
                total, rows = get_admin_inventory(page, page_size, search)
                inventory = [{
                    'id': row[0], 'created_by': row[1], 'soop_account_name': row[2],
                    'product_name': row[3], 'enabled': bool(row[4]),
                    'created_at': row[5].strftime('%Y-%m-%d %H:%M:%S') if row[5] else None,
                    'activation_code': row[6], 'claim_status': row[7],
                } for row in rows]
                return self.send_json({'inventory': inventory, 'page': page, 'page_size': page_size, 'total': total, 'search': search})
            except ValueError as exc:
                return self.send_json({'message': str(exc)}, 400)
            except Exception:
                logger.exception('Admin inventory query failed')
                return self.send_json({'message': '库存查询失败。'}, 503)
        if path == '/api/admin/claims':
            if not self.require_admin(): return
            try:
                page, page_size = parse_pagination(self.path)
                search = parse_qs(urlparse(self.path).query).get('q', [''])[0].strip()[:128]
                total, rows = get_admin_claims(page, page_size, search)
                claims = [{
                    'id': row[0], 'activation_code': row[1], 'claim_account': row[2],
                    'product_name': row[3],
                    'claimed_at': row[4].strftime('%Y-%m-%d %H:%M:%S') if row[4] else None,
                    'soop_account_name': row[5],
                } for row in rows]
                return self.send_json({'claims': claims, 'page': page, 'page_size': page_size, 'total': total, 'search': search})
            except ValueError as exc:
                return self.send_json({'message': str(exc)}, 400)
            except Exception:
                logger.exception('Admin claim query failed')
                return self.send_json({'message': '领取记录查询失败。'}, 503)
        if path == '/api/admin/system-logs':
            if not self.require_admin(): return
            try:
                page, page_size = parse_pagination(self.path)
                search = parse_qs(urlparse(self.path).query).get('q', [''])[0].strip()[:128]
                total, rows = get_system_logs(page, page_size, search)
                logs = [{
                    'id': row[0], 'level': row[1], 'logger_name': row[2], 'message': row[3], 'trace': row[4],
                    'created_at': row[5].strftime('%Y-%m-%d %H:%M:%S') if row[5] else None,
                } for row in rows]
                return self.send_json({'logs': logs, 'page': page, 'page_size': page_size, 'total': total, 'search': search})
            except ValueError as exc:
                return self.send_json({'message': str(exc)}, 400)
            except Exception:
                logger.exception('System log query failed')
                return self.send_json({'message': '系统日志查询失败。'}, 503)
        if path == '/api/health': return self.send_json({'ok': True, 'service': 'drop-zone'})
        if path == '/api/config':
            try:
                return self.send_json({'features': get_feature_config(is_loopback_request(self.headers))})
            except Exception:
                logger.exception('Feature configuration query failed')
                return self.send_json({'message': '提货方式配置暂不可用，请稍后重试。'}, 503)
        qr_status_match = re.fullmatch(r'/api/qr/([A-Za-z0-9_-]{16,64})/status', path)
        if qr_status_match:
            cleanup_steam_qr_sessions()
            with STEAM_QR_SESSIONS_LOCK:
                qr_session = STEAM_QR_SESSIONS.get(qr_status_match.group(1))
            if qr_session is None:
                return self.send_json({'message': '二维码已过期，请重新生成。'}, 410)
            with qr_session['lock']:
                if qr_session.get('terminal_status'):
                    return self.send_json({
                        'status': qr_session['terminal_status'],
                        'message': qr_session.get('terminal_message', '提交成功，请重启大厅。'),
                    })
                if qr_session.get('claim_status') == 'processing':
                    return self.send_json({'status': 'processing', 'message': '正在登录 KID，请稍候…'}, 202)
                if qr_session.get('claim_status') == 'claiming':
                    return self.send_json({'status': 'claiming', 'message': '正在提货，请稍候…'}, 202)
                try:
                    from global_login import steam_kid_login
                    steam_info = steam_kid_login.poll_steam_qr_login(
                        qr_session['session'], qr_session['steam_state'], complete_login=False,
                    )
                    if steam_info is None:
                        return self.send_json({'status': 'pending', 'message': '等待 Steam 手机端扫码确认…'})
                    qr_session['claim_status'] = 'processing'
                    threading.Thread(
                        target=process_steam_qr_claim,
                        args=(qr_session, steam_info),
                        name='steam-qr-claim', daemon=True,
                    ).start()
                    return self.send_json({'status': 'confirmed', 'message': 'Steam 扫码成功，正在登录…'}, 202)
                except Exception as exc:
                    logger.exception('Steam QR login failed')
                    message = qr_login_failure_message(exc)
                    # The surrounding session lock is already held here. Re-acquiring
                    # this non-reentrant lock would deadlock the status request exactly
                    # when Steam returns a rejection/error result.
                    qr_session['terminal_status'] = 'failed'
                    qr_session['terminal_message'] = message
                    return self.send_json({'message': message}, 409 if 'SOOP' in message else 503)
        match = re.fullmatch(r'/api/orders/([^/]+)', path)
        if match:
            code = normalize_activation_code(unquote(match.group(1)))
            if code is None:
                return self.send_json({'message': '激活码格式错误。'}, 400)
            try:
                code_status, reward, used_at = get_global_code_status(code)
            except Exception:
                logger.exception('Activation-code database query failed')
                return self.send_json({'message': '激活码服务暂不可用，请稍后重试。'}, 503)
            if code_status == 'missing':
                return self.send_json({'message': '未找到该激活码。'}, 404)
            status = {'used': '已领取', 'processing': '领取中'}.get(code_status, '未领取')
            message = {
                'used': '提货成功，请重启大厅。',
                'processing': 'SOOP 宝箱已提交领取，兑换状态正在确认，请稍后查询结果。',
            }.get(code_status, '该激活码未领取。')
            return self.send_json({
                'code': code,
                'status': status,
                'reward': reward,
                'used_at': used_at.strftime('%Y-%m-%d %H:%M:%S') if used_at else None,
                'message': message,
            })
        relative = 'admin.html' if path == '/admin' else ('index.html' if path in ('', '/') else path.lstrip('/'))
        file_path = (ROOT / relative).resolve()
        if ROOT.resolve() not in file_path.parents or not file_path.is_file(): return self.send_json({'message': '页面不存在。'}, 404)
        content_type = {'.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'application/javascript; charset=utf-8'}.get(file_path.suffix, 'application/octet-stream')
        body = file_path.read_bytes(); self.send_response(200); self.send_header('Content-Type', content_type); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        if not has_gift_prefix(self.path):
            return self.send_json({'message': '接口不存在。'}, 404)
        path = application_path(self.path)
        if path == '/api/admin/runtime-settings':
            if not self.require_admin(): return
            data = self.read_json()
            if not isinstance(data, dict): return self.send_json({'message': '请求参数无效。'}, 400)
            try:
                from global_login import krafton_pure_http_login as krafton_login
                from global_login.vpn_switcher import get_vpn_switcher
                if data.get('seed_capacity') is not None:
                    requested_capacity = int(data.get('seed_capacity'))
                    krafton_login._AbckPool.set_capacity(requested_capacity)
                proxies = data.get('seed_proxies')
                if proxies is not None:
                    if not isinstance(proxies, list) or len(proxies) > 2 or any(not str(p).strip() for p in proxies):
                        return self.send_json({'message': 'seed 代理最多填写两条有效地址。'}, 400)
                    krafton_login._AbckPool.set_runtime_proxies([str(p).strip() for p in proxies])
                switcher = get_vpn_switcher()
                if data.get('proxy_group') is not None:
                    group = str(data.get('proxy_group')).strip()
                    if not group or not switcher.set_proxy_group(group):
                        return self.send_json({'message': '代理组不存在或初始化失败。'}, 400)
                keywords_changed = False
                if data.get('node_name_keywords') is not None:
                    keywords_changed = switcher.set_node_name_keywords(data.get('node_name_keywords'))
                filter_changed = False
                if 'node_name_filter_enabled' in data:
                    if not isinstance(data['node_name_filter_enabled'], bool):
                        return self.send_json({'message': '节点名称关键词过滤开关参数无效。'}, 400)
                    filter_changed = switcher.set_node_name_filter_enabled(data['node_name_filter_enabled'])
                if data.get('test_url') is not None:
                    url = str(data.get('test_url')).strip()
                    if not url.startswith(('http://', 'https://')):
                        return self.send_json({'message': '测试 URL 必须以 http:// 或 https:// 开头。'}, 400)
                    switcher.test_url = url
                feature_keys = ('global_enabled', 'steam_enabled', 'qr_enabled')
                if any(key in data for key in feature_keys):
                    if not all(isinstance(data.get(key), bool) for key in feature_keys):
                        return self.send_json({'message': '提货方式开关参数无效。'}, 400)
                    set_feature_config(
                        data['global_enabled'], data['steam_enabled'], data['qr_enabled'],
                    )
                nodes_refreshed = False
                if data.get('refresh_nodes') or data.get('best_node') or keywords_changed or filter_changed:
                    switcher.refresh_nodes()
                    nodes_refreshed = True
                elif data.get('switch_node') and not switcher.switch_to_next_node():
                    return self.send_json({'message': '没有可切换的 Clash 节点。'}, 503)
                return self.send_json({'message': '运行配置已更新。', 'nodes_refreshed': nodes_refreshed})
            except (TypeError, ValueError):
                return self.send_json({'message': 'Seed 池容量必须是 1 到 50 的整数。'}, 400)
            except Exception:
                logger.exception('Admin runtime settings update failed')
                return self.send_json({'message': '运行配置更新失败。'}, 503)
        if path == '/api/admin/login':
            data = self.read_json()
            username = str((data or {}).get('username', '')).strip()
            password = str((data or {}).get('password', ''))
            if not username or not password:
                return self.send_json({'message': '请输入后台账号和密码。'}, 400)
            try:
                user = get_admin_user(username)
            except Exception:
                logger.exception('Admin login query failed')
                return self.send_json({'message': '后台账号服务暂不可用。'}, 503)
            if not user or not verify_admin_password(password, user[1]):
                return self.send_json({'message': '后台密码错误。'}, 401)
            token = create_admin_session(user[0])
            cookie = f'{ADMIN_SESSION_COOKIE}={token}; Path=/gift; Max-Age={ADMIN_SESSION_TTL_SECONDS}; HttpOnly; SameSite=Strict'
            return self.send_json({'message': '登录成功。'}, headers={'Set-Cookie': cookie})
        if path == '/api/admin/logout':
            revoke_admin_session(get_admin_session_token(self.headers))
            cookie = f'{ADMIN_SESSION_COOKIE}=; Path=/gift; Max-Age=0; HttpOnly; SameSite=Strict'
            return self.send_json({'message': '已退出登录。'}, headers={'Set-Cookie': cookie})
        if path == '/api/admin/inventory':
            if not self.require_admin(): return
            data = self.read_json()
            if not data:
                return self.send_json({'message': '请求数据格式错误。'}, 400)
            created_by = str(data.get('created_by', '')).strip()
            try:
                cookie = normalize_soop_cookie(data.get('soop_cookie', ''))
                account_name = soop_account_name_from_cookie(cookie)
            except ValueError as exc:
                return self.send_json({'message': str(exc)}, 400)
            product_name = str(data.get('product_name', '')).strip()
            if not all((created_by, account_name, cookie, product_name)):
                return self.send_json({'message': '请完整填写录入人、Cookie 和商品名称。'}, 400)
            if any(len(value) > limit for value, limit in ((created_by, 128), (account_name, 128), (product_name, 255))):
                return self.send_json({'message': '录入字段长度超出限制。'}, 400)
            try:
                inventory_id = create_soop_inventory(created_by, account_name, cookie, product_name)
                return self.send_json({'message': '库存录入成功。', 'inventory_id': inventory_id}, 201)
            except pymysql.err.IntegrityError:
                return self.send_json({'message': '该 SOOP 账号下已存在同名商品库存。'}, 409)
            except Exception:
                logger.exception('Admin inventory creation failed')
                return self.send_json({'message': '库存录入失败。'}, 503)
        if path == '/api/admin/inventory/status':
            if not self.require_admin(): return
            data = self.read_json()
            try:
                inventory_id = int((data or {}).get('inventory_id'))
                enabled = (data or {}).get('enabled')
                if inventory_id <= 0 or not isinstance(enabled, bool): raise ValueError
            except (TypeError, ValueError):
                return self.send_json({'message': '库存 ID 或状态无效。'}, 400)
            try:
                set_soop_inventory_enabled(inventory_id, enabled)
                return self.send_json({'message': '库存状态已更新。', 'enabled': enabled})
            except LookupError as exc:
                return self.send_json({'message': str(exc)}, 404)
            except Exception:
                logger.exception('Admin inventory status update failed')
                return self.send_json({'message': '库存状态更新失败。'}, 503)
        if path == '/api/admin/inventory/delete':
            if not self.require_admin(): return
            data = self.read_json()
            try:
                inventory_id = int((data or {}).get('inventory_id'))
                if inventory_id <= 0: raise ValueError
            except (TypeError, ValueError):
                return self.send_json({'message': '库存 ID 无效。'}, 400)
            try:
                delete_soop_inventory(inventory_id)
                return self.send_json({'message': '库存已删除。'})
            except LookupError as exc:
                return self.send_json({'message': str(exc)}, 404)
            except ValueError as exc:
                return self.send_json({'message': str(exc)}, 409)
            except Exception:
                logger.exception('Admin inventory deletion failed')
                return self.send_json({'message': '库存删除失败。'}, 503)
        if path == '/api/admin/inventory/import':
            if not self.require_admin(): return
            data = self.read_json()
            if not data:
                return self.send_json({'message': '请求数据格式错误。'}, 400)
            try:
                codes = import_soop_inventory(parse_inventory_import(data.get('text', '')))
                return self.send_json({'message': f'成功导入 {len(codes)} 条库存并生成激活码。', 'count': len(codes), 'codes': codes}, 201)
            except ValueError as exc:
                return self.send_json({'message': str(exc)}, 400)
            except pymysql.err.IntegrityError:
                return self.send_json({'message': '存在重复的 SOOP 账号和商品名称，未导入任何记录。'}, 409)
            except Exception:
                logger.exception('Admin inventory import failed')
                return self.send_json({'message': '库存导入失败。'}, 503)
        if path == '/api/admin/activation-codes':
            if not self.require_admin(): return
            data = self.read_json()
            try:
                inventory_id = int((data or {}).get('inventory_id'))
                if inventory_id <= 0: raise ValueError
            except (TypeError, ValueError):
                return self.send_json({'message': '库存 ID 无效。'}, 400)
            try:
                code = create_activation_code_for_inventory(inventory_id)
                return self.send_json({'message': '激活码生成成功。', 'code': code}, 201)
            except LookupError as exc:
                return self.send_json({'message': str(exc)}, 404)
            except ValueError as exc:
                return self.send_json({'message': str(exc)}, 409)
            except Exception:
                logger.exception('Admin activation-code generation failed')
                return self.send_json({'message': '激活码生成失败。'}, 503)
        if path == '/api/qr/create':
            try:
                if not get_feature_config(is_loopback_request(self.headers))['qr']:
                    return self.send_json({'message': '当前未启用 Steam 扫码提货。'}, 403)
            except Exception:
                logger.exception('Feature configuration query failed')
                return self.send_json({'message': '提货方式配置暂不可用，请稍后重试。'}, 503)
            data = self.read_json()
            code = normalize_activation_code((data or {}).get('code', ''))
            if code is None:
                return self.send_json({'message': '激活码格式错误。'}, 400)
            try:
                code_status, _, _ = get_global_code_status(code)
                if code_status == 'missing':
                    return self.send_json({'message': '激活码不存在或已失效。'}, 404)
                if code_status in ('used', 'processing'):
                    return self.send_json({'message': '该激活码已经使用或正在领取中。'}, 409)
                inventory = get_soop_inventory_for_code(code)
                if not inventory:
                    return self.send_json({'message': '该激活码尚未关联可领取的 SOOP 宝箱。'}, 409)
                from global_login import steam_kid_login
                session, steam_state = steam_kid_login.begin_steam_qr_login(STEAM_KID_PROXY)
                challenge_url = str(steam_state['auth']['challenge_url'])
                qr_id = secrets.token_urlsafe(18)
                qr_session = {
                    'code': code, 'inventory': inventory, 'session': session,
                    'steam_state': steam_state, 'expires_at': time.time() + STEAM_QR_TTL_SECONDS,
                    'lock': threading.Lock(), 'login_status': 'pending',
                }
                cleanup_steam_qr_sessions()
                with STEAM_QR_SESSIONS_LOCK:
                    STEAM_QR_SESSIONS[qr_id] = qr_session
                return self.send_json({
                    'qr_id': qr_id,
                    'qr_svg': build_steam_qr_svg(challenge_url),
                    'expires_at': int(qr_session['expires_at']),
                }, 201)
            except ValueError as exc:
                return self.send_json({'message': str(exc)}, 400)
            except Exception:
                logger.exception('Steam QR creation failed')
                return self.send_json({'message': 'Steam 扫码二维码创建失败，请稍后重试。'}, 503)
        if path not in ('/api/redeem', '/api/redeem/global'): return self.send_json({'message': '接口不存在。'}, 404)
        if path == '/api/redeem':
            try:
                if not get_feature_config(is_loopback_request(self.headers))['steam']:
                    return self.send_json({'message': '当前未启用 Steam 提货。'}, 403)
            except Exception:
                logger.exception('Feature configuration query failed')
                return self.send_json({'message': '提货方式配置暂不可用，请稍后重试。'}, 503)
        try: data = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        except (ValueError, json.JSONDecodeError): return self.send_json({'message': '请求数据格式错误。'}, 400)
        if not isinstance(data, dict):
            return self.send_json({'message': '请求数据格式错误。'}, 400)
        logger.info('Request parameters route=%s parameters=%s', path, json.dumps(request_log_parameters(path, data), ensure_ascii=False))
        code = normalize_activation_code(data.get('code', ''))
        if code is None:
            return self.send_json({'message': '激活码格式错误。'}, 400)
        if path == '/api/redeem/global':
            try:
                if not get_feature_config(is_loopback_request(self.headers))['global']:
                    return self.send_json({'message': '当前未启用全球提货。'}, 403)
            except Exception:
                logger.exception('Feature configuration query failed')
                return self.send_json({'message': '提货方式配置暂不可用，请稍后重试。'}, 503)
            username = str(data.get('username', '')).strip()
            password = str(data.get('password', ''))
            if not username or not password:
                return self.send_json({'message': '请填写完整的激活码、全球账号和密码。'}, 400)
            if not EMAIL_PATTERN.fullmatch(username):
                return self.send_json({'message': '请输入正确的邮箱格式。'}, 400)
            trace_context = redemption_trace_context(code, username)
            try:
                code_status, reward, _ = get_global_code_status(code)
            except Exception:
                logger.exception('Activation-code database query failed %s', trace_context)
                return self.send_json({'message': '激活码服务暂不可用，请稍后重试。'}, 503)
            if code_status == 'missing':
                return self.send_json({'message': '激活码不存在或已失效。'}, 404)
            if code_status == 'used':
                return self.send_json({'message': '该激活码已经使用过了。'}, 409)
            if code_status == 'processing':
                return self.send_json({'message': '该激活码正在领取中，请稍后查询结果。'}, 409)
        else:
            username = str(data.get('steam_user', '')).strip()
            password = str(data.get('steam_password', ''))
            steam_token = str(data.get('steam_token', '')).strip()
            if not username or not password:
                return self.send_json({'message': '请填写完整的激活码、Steam 账号和密码。'}, 400)
            trace_context = redemption_trace_context(code, username)
            try:
                code_status, reward, _ = get_global_code_status(code)
            except Exception:
                logger.exception('Activation-code database query failed %s', trace_context)
                return self.send_json({'message': '激活码服务暂不可用，请稍后重试。'}, 503)
            if code_status == 'missing':
                return self.send_json({'message': '激活码不存在或已失效。'}, 404)
            if code_status == 'used':
                return self.send_json({'message': '该激活码已经使用过了。'}, 409)
            if code_status == 'processing':
                return self.send_json({'message': '该激活码正在领取中，请稍后查询结果。'}, 409)

        if path in ('/api/redeem/global', '/api/redeem'):
            try:
                inventory = get_soop_inventory_for_code(code)
            except LookupError as exc:
                log_business_error(f'SOOP inventory mapping missing: {exc} {trace_context}')
                return self.send_json({'message': '该激活码尚未关联可领取的 SOOP 宝箱。'}, 409)
            except Exception:
                logger.exception('SOOP inventory lookup failed before global login %s', trace_context)
                return self.send_json({'message': 'SOOP 库存服务暂不可用，请稍后重试。'}, 503)
            if not inventory:
                log_business_error(f'SOOP inventory mapping missing after activation-code lookup {trace_context}')
                return self.send_json({'message': '该激活码尚未关联可领取的 SOOP 宝箱。'}, 409)
            logger.info(
                'Global redemption inventory soop_account=%s product=%s %s',
                inventory[0], inventory[2], trace_context,
            )
            try:
                if path == '/api/redeem/global':
                    from global_login import krafton_pure_http_login as krafton_login
                    seed_status = krafton_login._AbckPool.status()
                    available_seeds = (
                        int(seed_status.get('fresh', 0))
                        + int(seed_status.get('reusable', 0))
                    )
                    if available_seeds <= 0:
                        try:
                            steam_enabled = bool(get_feature_config()['steam'])
                        except Exception:
                            steam_enabled = False
                        logger.warning(
                            'Global redemption skipped: no available seed %s pool=%s',
                            trace_context, seed_status,
                        )
                        return self.send_json({
                            'message': '全球提货暂时不可用，请改用 Steam 提货。',
                            'seed_unavailable': True,
                            'fallback_to_steam': steam_enabled,
                        }, 503)
                    login_info = get_global_login_info(username, password, inventory[1])
                else:
                    login_info = get_steam_login_info(username, password, steam_token, inventory[1])
            except ValueError as exc:
                if path == '/api/redeem':
                    return self.send_json({'message': str(exc)}, 400)
                raise
            except RuntimeError as exc:
                if path == '/api/redeem/global' and isinstance(exc, SeedUnavailableError):
                    try:
                        steam_enabled = bool(get_feature_config()['steam'])
                    except Exception:
                        steam_enabled = False
                    log_business_error(f'Global seed unavailable {trace_context}', exc_info=True)
                    response = {
                        'message': '全球提货暂时不可用，请改用 Steam 提货。',
                        'seed_unavailable': True,
                        'fallback_to_steam': steam_enabled,
                    }
                    return self.send_json(response, 503)
                if str(exc) == 'SOOP 解绑失败，请稍后重试。':
                    log_business_error(f'SOOP unlink failed before global redemption {trace_context}', exc_info=True)
                    return self.send_json({'message': 'SOOP 解绑失败，请稍后重试。'}, 502)
                if str(exc) in (
                    'SOOP 绑定失败，请稍后重试。',
                    'SOOP 绑定尚未生效，请稍后重试。',
                    'SOOP 库存账号登录状态已过期，请在后台更新该库存账号的登录信息后重试。',
                ):
                    log_business_error(f'SOOP binding failed before global redemption {trace_context}', exc_info=True)
                    if 'SOOP 库存账号登录状态已过期' in str(exc):
                        return self.send_json({'message': 'SOOP 库存账号已过期。'}, 502)
                    return self.send_json({'message': str(exc)}, 502)
                if path == '/api/redeem':
                    message, status, steam_guard_required = steam_login_failure_response(exc)
                    log_business_error(f'Steam login failed {trace_context}', exc_info=True)
                    response = {'message': message}
                    if steam_guard_required:
                        response['steam_guard_required'] = True
                    return self.send_json(response, status)
                log_business_error(f'Global login service failed {trace_context}', exc_info=True)
                return self.send_json({'message': global_login_failure_message(exc)}, 503)
            except requests.exceptions.ProxyError:
                log_business_error(f'Proxy connection failed during redemption {trace_context}', exc_info=True)
                return self.send_json({'message': '代理连接失败，请检查代理配置后重试。'}, 503)
            except Exception:
                log_business_error(f'Global login service failed {trace_context}', exc_info=True)
                message = (
                    'Steam 提货流程失败，请稍后重试。'
                    if path == '/api/redeem'
                    else '全球账号授权流程失败，请稍后重试。'
                )
                return self.send_json({'message': message}, 503)
            if not login_info or login_info.get('status') != 'success':
                log_business_error(f'Global login did not complete KRAFTON/SOOP connection {trace_context}')
                return self.send_json({'message': '全球账号登录失败，请确认账号、密码正确，并关闭二级验证后重试。'}, 401)
            if path == '/api/redeem/global':
                player_name = str(login_info.get('globalNickname') or login_info.get('nickname') or login_info.get('gameName') or '全球账号')
                order_details = {'delivery_mode': 'global', 'player_name': player_name}
            else:
                order_details = {'delivery_mode': 'steam', 'player_id': login_info.get('steamid') or username, 'player_name': username}
        else:
            order_details = {}
        order_id = 'DZ-' + datetime.now(timezone.utc).strftime('%y%m%d') + '-' + secrets.token_hex(3).upper()
        if path in ('/api/redeem/global', '/api/redeem'):
            claim_token = secrets.token_hex(16)
            try:
                reserved = reserve_global_code(code, claim_token)
            except Exception:
                logger.exception('Activation-code reservation failed %s', trace_context)
                return self.send_json({'message': '激活码服务暂不可用，请稍后重试。'}, 503)
            if not reserved:
                try:
                    current_status, _, _ = get_global_code_status(code)
                except Exception:
                    current_status = 'processing'
                if current_status == 'used':
                    return self.send_json({'message': '该激活码已经使用过了。'}, 409)
                return self.send_json({'message': '该激活码正在领取中，请稍后查询结果。'}, 409)
            try:
                _, reward, claimed_items = claim_soop_stock(
                    inventory, claim_cookie=login_info.get('soop_claim_cookie'),
                )
            except NoClaimableSoopRewardError:
                try:
                    release_global_code_reservation(code, claim_token)
                except Exception:
                    logger.exception('Activation-code reservation release failed %s', trace_context)
                    return self.send_json({'message': 'SOOP 宝箱领取状态正在确认，请稍后查询结果。'}, 202)
                return self.send_json({'message': 'SOOP 账号中没有可领取的奖励。'}, 409)
            except Exception:
                try:
                    release_global_code_reservation(code, claim_token)
                except Exception:
                    logger.exception('Activation-code reservation release failed %s', trace_context)
                    return self.send_json({'message': 'SOOP 领取失败，兑换状态正在确认，请稍后查询结果。'}, 202)
                logger.exception('SOOP reward claim failed after global login %s', trace_context)
                return self.send_json({'message': '全球账号登录成功，但 SOOP 宝箱领取失败，请稍后重试。'}, 502)
            try:
                claimed = complete_global_code_claim(
                    code, claim_token, username, reward,
                )
            except Exception:
                logger.exception('Activation-code completion failed after SOOP claim %s', trace_context)
                return self.send_json({'message': 'SOOP 宝箱已提交领取，兑换状态正在确认，请稍后查询结果。'}, 202)
            if not claimed:
                return self.send_json({'message': '该激活码正在领取中，请稍后查询结果。'}, 409)
        ORDERS[order_id] = {'order_id': order_id, 'status': '处理中', 'reward': reward, 'message': '提交成功，请重启大厅。', **order_details}
        return self.send_json({'message': '提交成功', 'status': '处理中'}, 201)
    def log_message(self, fmt, *args):
        path = application_path(self.path)
        route = '/api/orders/:code' if path.startswith('/api/orders/') else path
        status = args[1] if len(args) > 1 else 'unknown'
        logger.info('HTTP %s %s status=%s', self.command, route, status)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DROP//ZONE service')
    parser.add_argument('--create-admin', metavar='USERNAME', help='create the first or an additional admin user')
    parser.add_argument('--admin-password', help='password for --create-admin; omit to enter it securely')
    args = parser.parse_args()
    if args.create_admin:
        username = args.create_admin.strip()
        password = args.admin_password or getpass.getpass('Admin password: ')
        if not re.fullmatch(r'[A-Za-z0-9_.-]{3,64}', username) or len(password) < 12:
            parser.error('admin username must be 3-64 characters and password must be at least 12 characters')
        try:
            create_admin_user(username, password)
        except pymysql.err.IntegrityError:
            parser.error('admin username already exists')
        print(f'Admin user created: {username}')
        raise SystemExit(0)
    try:
        ensure_inventory_schema()
        ensure_feature_config_schema()
        ensure_system_log_table()
        database_log_handler = DatabaseErrorLogHandler(level=logging.ERROR)
        logger.addHandler(database_log_handler)
    except Exception:
        logger.exception('System log table initialization failed')
    # Initialize the shared Mihomo/Clash controller and select a node before
    # accepting requests, so the first Steam login does not pay the startup
    # discovery and latency-test cost.
    try:
        from global_login.vpn_switcher import get_vpn_switcher
        logger.info('[clash] 服务启动，开始初始化 Mihomo 节点')
        clash_switcher = get_vpn_switcher()
        if clash_switcher.is_vpn_available():
            logger.info(
                '[clash] 初始化完成 group=%s node=%s available=%s proxy=%s',
                clash_switcher.get_proxy_group(),
                clash_switcher.get_current_node(),
                clash_switcher.get_available_nodes_count(),
                clash_switcher.proxies.get('http'),
            )
        else:
            logger.warning('[clash] 初始化完成但没有可用节点；Steam 登录请求将继续使用本机代理入口')
    except Exception:
        logger.exception('[clash] 服务启动初始化失败')
    # RiskByPass 余额仅由后台线程每分钟刷新一次；管理接口直接读取缓存。
    start_riskbypass_balance_refresh()
    # Warm the shared RiskByPass seed pool when the service starts.  The
    # global getter is otherwise lazy-loaded on the first redemption request.
    try:
        from global_login import krafton_pure_http_login as krafton_login
        seed_proxy = (
            os.environ.get('KRAFTON_RISKBYPASS_PROXY')
            or os.environ.get('PUBG_RISKBYPASS_PROXY')
        )
        local_seed_host = is_local_seed_host()
        initial_seed_count = 1 if local_seed_host else 5
        if local_seed_host:
            krafton_login._AbckPool.set_capacity(1)
            logger.info('[riskbypass-pool] 本机 %s 启动，seed 容量固定为 1', socket.gethostname())
        else:
            logger.info('[riskbypass-pool] 非本机 %s 启动，使用默认 seed 容量 %s', socket.gethostname(), initial_seed_count)
        krafton_login.initialize_abck_pool(proxy=seed_proxy, count=initial_seed_count)
    except Exception:
        logger.exception('[riskbypass-pool] 服务启动初始化调度失败')
    port = int(os.environ.get('GIFT_PORTAL_PORT', '8000'))
    logger.info('DROP//ZONE running at http://127.0.0.1:%s', port)
    ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()
