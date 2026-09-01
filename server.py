from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
import argparse
import getpass
import hashlib
import hmac
import logging
import os
from pathlib import Path
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, unquote, urlparse
import json, re, secrets
from global_login.soop_drops_http import DropsClient

try:
    import pymysql
except ImportError:
    pymysql = None

ROOT = Path(__file__).parent
LOG_PATH = ROOT / 'gift_portal.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.FileHandler(LOG_PATH, encoding='utf-8'), logging.StreamHandler()],
)
logger = logging.getLogger('gift_portal')
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
GIFTS = {'TAECG5XVAQ8XQNQY414': {'reward': '战术补给箱 × 1', 'used': False}, 'DEMO2026DROP001': {'reward': '补给券 × 3', 'used': False}}
ORDERS = {}
SOOP_CLAIM_RETRIES = 3
SOOP_CLAIM_RETRY_DELAY = 1.0
ADMIN_SESSION_COOKIE = 'dropzone_admin_session'
ADMIN_SESSION_TTL_SECONDS = 8 * 60 * 60
ADMIN_SESSIONS = {}
ADMIN_SESSIONS_LOCK = threading.Lock()
ITEM_CODE_INDEXES_PATTERN = re.compile(r'^\d+(?:\s*,\s*\d+)*$')
ADMIN_PASSWORD_HASH_ITERATIONS = 300_000
SYSTEM_LOG_MAX_MESSAGE_LENGTH = 2_000
SYSTEM_LOG_MAX_TRACE_LENGTH = 12_000
_SYSTEM_LOG_WRITE_GUARD = threading.local()
_SYSTEM_LOG_SECRET_PATTERN = re.compile(r'(?i)(cookie|password|authorization|bearer|authticket|userticket|bbsticket)\s*[=:]\s*[^\s,;\'"}]+')
SOOP_COOKIE_NAME_MAP = {
    'userticket': 'UserTicket', 'user_ticket': 'UserTicket',
    'authticket': 'AuthTicket', 'auth_ticket': 'AuthTicket',
    'bbsticket': 'BbsTicket', 'bbs_ticket': 'BbsTicket',
    'bbssaveticket': 'BbsSaveTicket', 'bbs_save_ticket': 'BbsSaveTicket',
}


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


def normalize_item_code_indexes(raw_value):
    value = str(raw_value).strip()
    if not value or not ITEM_CODE_INDEXES_PATTERN.fullmatch(value):
        return None
    indexes = []
    for item in value.split(','):
        normalized = item.strip()
        if normalized not in indexes:
            indexes.append(normalized)
    return ','.join(indexes)


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
                'OR si.item_code_idxs LIKE %s OR ac.code LIKE %s'
            ) if search else ''
            params = [f'%{search}%'] * 5 if search else []
            cursor.execute(
                'SELECT COUNT(*) FROM soop_inventory si '
                'LEFT JOIN activation_code_inventory aci ON aci.soop_inventory_id = si.id '
                'LEFT JOIN activation_codes ac ON ac.id = aci.activation_code_id ' + where,
                params,
            )
            total = cursor.fetchone()[0]
            cursor.execute(
                'SELECT si.id, si.created_by, si.soop_account_name, si.product_name, si.item_code_idxs, '
                'si.enabled, si.created_at, ac.code, ac.claim_status '
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
                'WHERE ac.activation_code LIKE %s OR ac.claim_account LIKE %s OR ac.product_name LIKE %s '
                'OR ac.claimed_item_code_idxs LIKE %s OR si.soop_account_name LIKE %s'
            ) if search else ''
            params = [f'%{search}%'] * 5 if search else []
            cursor.execute(
                'SELECT COUNT(*) FROM activation_claims ac '
                'LEFT JOIN activation_code_inventory aci ON aci.activation_code_id = ac.activation_code_id '
                'LEFT JOIN soop_inventory si ON si.id = aci.soop_inventory_id ' + where,
                params,
            )
            total = cursor.fetchone()[0]
            cursor.execute(
                'SELECT ac.id, ac.activation_code, ac.claim_account, ac.product_name, '
                'ac.claimed_item_code_idxs, ac.claimed_at, si.soop_account_name '
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
        # Some export tools escape underscores, although ``\_`` is not valid JSON.
        cookie_values = json.loads(cookie.replace(r'\_', '_'))
    except json.JSONDecodeError as exc:
        raise ValueError('SOOP Cookie JSON 格式错误。') from exc
    if not isinstance(cookie_values, dict):
        raise ValueError('SOOP Cookie JSON 必须是对象。')
    normalized = []
    for name, value in cookie_values.items():
        name = SOOP_COOKIE_NAME_MAP.get(str(name).strip().casefold(), str(name).strip())
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
        if len(fields) != 5:
            raise ValueError(f'第 {line_number} 行格式错误，应为 5 列。')
        created_by, account_name, product_name, raw_indexes, raw_cookie = fields
        item_code_idxs = normalize_item_code_indexes(raw_indexes)
        cookie = normalize_soop_cookie(raw_cookie)
        if not all((created_by, account_name, product_name, item_code_idxs, cookie)):
            raise ValueError(f'第 {line_number} 行有空字段或 itemCodeIdx 格式错误。')
        if any(len(value) > limit for value, limit in ((created_by, 128), (account_name, 128), (product_name, 255), (item_code_idxs, 2048))):
            raise ValueError(f'第 {line_number} 行字段长度超出限制。')
        entries.append((created_by, account_name, cookie, product_name, item_code_idxs))
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
                    '(created_by, soop_account_name, soop_cookie, product_name, item_code_idxs) '
                    'VALUES (%s, %s, %s, %s, %s)',
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


def create_soop_inventory(created_by, account_name, cookie, product_name, item_code_idxs):
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG, autocommit=False)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                'INSERT INTO soop_inventory '
                '(created_by, soop_account_name, soop_cookie, product_name, item_code_idxs) '
                'VALUES (%s, %s, %s, %s, %s)',
                (created_by, account_name, cookie, product_name, item_code_idxs),
            )
            inventory_id = cursor.lastrowid
        connection.commit()
        return inventory_id
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
        parameters['player_id'] = mask_value(data.get('player_id', ''))
        parameters['player_name'] = mask_value(data.get('player_name', ''))
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
            global_login_logger.disabled = True
            GLOBAL_LOGIN_GETTER_CLASS = PUBGCookieGetter

    getter = GLOBAL_LOGIN_GETTER_CLASS()
    try:
        with krafton_login.suppress_artifact_persistence():
            return getter.get_authorization_info(username, password, soop_cookie=soop_cookie)
    finally:
        # The getter retains the last authorization response in memory; discard it
        # immediately after this request, regardless of whether login succeeded.
        getter.last_login_info = None


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
    """Resolve the SOOP account and stock indexes linked to an activation code."""
    if pymysql is None or not GLOBAL_CODE_DB_CONFIG['password']:
        raise RuntimeError("全球激活码数据库未配置。")
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                'SELECT si.soop_account_name, si.soop_cookie, si.product_name, si.item_code_idxs '
                'FROM activation_codes ac '
                'JOIN activation_code_inventory aci ON aci.activation_code_id = ac.id '
                'JOIN soop_inventory si ON si.id = aci.soop_inventory_id '
                'WHERE ac.code = %s AND si.enabled = 1 LIMIT 1',
                (code,),
            )
            return cursor.fetchone()
    finally:
        connection.close()


def claim_soop_stock(inventory):
    """Claim every stock index concurrently; one success makes redemption successful."""
    if not inventory:
        raise LookupError('激活码尚未关联 SOOP 库存商品。')
    account_name, cookie, product_name, raw_indexes = inventory
    indexes = [item.strip() for item in str(raw_indexes).split(',') if item.strip()]
    if not indexes:
        raise LookupError('SOOP 库存商品没有可用 itemCodeIdx。')
    def claim_one(item_code_idx):
        """Each worker owns its HTTP session because requests sessions are not thread-safe."""
        client = DropsClient(cookie)
        last_error = None
        for attempt in range(1, SOOP_CLAIM_RETRIES + 1):
            try:
                return item_code_idx, client.claim(item_code_idx, confirm=True), None
            except Exception as exc:
                last_error = exc
                logger.warning('SOOP claim failed item=%s attempt=%s/%s', item_code_idx, attempt, SOOP_CLAIM_RETRIES)
                if attempt < SOOP_CLAIM_RETRIES:
                    time.sleep(SOOP_CLAIM_RETRY_DELAY)
        return item_code_idx, None, type(last_error).__name__ if last_error else 'SOOP 请求失败'

    successful_by_index = {}
    failures = []
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
    return account_name, product_name, results


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


def complete_global_code_claim(code, claim_token, claim_account, claim_password, product_name, claimed_item_code_idxs):
    """Persist a completed claim; a failure leaves the durable reservation in processing."""
    if pymysql is None or not GLOBAL_CODE_DB_CONFIG['password']:
        raise RuntimeError("全球激活码数据库未配置。")
    successful_indexes = ','.join(str(item).strip() for item in claimed_item_code_idxs if str(item).strip())
    if not successful_indexes:
        raise ValueError('成功领取记录缺少 itemCodeIdx。')
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
                    '(activation_code_id, activation_code, claim_account, claim_password, product_name, '
                    'claimed_item_code_idxs, claimed_at) '
                    'SELECT id, code, %s, %s, %s, %s, UTC_TIMESTAMP() '
                    'FROM activation_codes WHERE code = %s',
                    (claim_account, claim_password, product_name or '', successful_indexes, code),
                )
        connection.commit()
        return completed
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_feature_config():
    """Read feature switches from MySQL, preferring this machine's override."""
    if pymysql is None or not GLOBAL_CODE_DB_CONFIG['password']:
        raise RuntimeError('Feature configuration database is unavailable.')
    hostname = socket.gethostname()
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                'SELECT steam_enabled, qr_enabled FROM portal_feature_config '
                'WHERE scope IN (%s, %s) ORDER BY scope = %s DESC LIMIT 1',
                (hostname, 'default', hostname),
            )
            row = cursor.fetchone()
    finally:
        connection.close()
    if row is None:
        return {'steam': False, 'qr': False}
    return {'steam': bool(row[0]), 'qr': bool(row[1])}

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
        if path == '/api/admin/inventory':
            if not self.require_admin(): return
            try:
                page, page_size = parse_pagination(self.path)
                search = parse_qs(urlparse(self.path).query).get('q', [''])[0].strip()[:128]
                total, rows = get_admin_inventory(page, page_size, search)
                inventory = [{
                    'id': row[0], 'created_by': row[1], 'soop_account_name': row[2],
                    'product_name': row[3], 'item_code_idxs': row[4], 'enabled': bool(row[5]),
                    'created_at': row[6].strftime('%Y-%m-%d %H:%M:%S') if row[6] else None,
                    'activation_code': row[7], 'claim_status': row[8],
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
                    'product_name': row[3], 'claimed_item_code_idxs': row[4],
                    'claimed_at': row[5].strftime('%Y-%m-%d %H:%M:%S') if row[5] else None,
                    'soop_account_name': row[6],
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
                return self.send_json({'features': get_feature_config()})
            except Exception:
                logger.exception('Feature configuration query failed')
                return self.send_json({'message': '提货方式配置暂不可用，请稍后重试。'}, 503)
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
            account_name = str(data.get('soop_account_name', '')).strip()
            try:
                cookie = normalize_soop_cookie(data.get('soop_cookie', ''))
            except ValueError as exc:
                return self.send_json({'message': str(exc)}, 400)
            product_name = str(data.get('product_name', '')).strip()
            item_code_idxs = normalize_item_code_indexes(data.get('item_code_idxs', ''))
            if not all((created_by, account_name, cookie, product_name, item_code_idxs)):
                return self.send_json({'message': '请完整填写录入人、SOOP 账号、Cookie、商品名称和 itemCodeIdx。'}, 400)
            if any(len(value) > limit for value, limit in ((created_by, 128), (account_name, 128), (product_name, 255), (item_code_idxs, 2048))):
                return self.send_json({'message': '录入字段长度超出限制。'}, 400)
            try:
                inventory_id = create_soop_inventory(created_by, account_name, cookie, product_name, item_code_idxs)
                return self.send_json({'message': '库存录入成功。', 'inventory_id': inventory_id}, 201)
            except pymysql.err.IntegrityError:
                return self.send_json({'message': '该 SOOP 账号下已存在同名商品库存。'}, 409)
            except Exception:
                logger.exception('Admin inventory creation failed')
                return self.send_json({'message': '库存录入失败。'}, 503)
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
        if path not in ('/api/redeem', '/api/redeem/global'): return self.send_json({'message': '接口不存在。'}, 404)
        if path == '/api/redeem':
            try:
                if not get_feature_config()['steam']:
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
            username = str(data.get('username', '')).strip()
            password = str(data.get('password', ''))
            if not username or not password:
                return self.send_json({'message': '请填写完整的激活码、全球账号和密码。'}, 400)
            if not EMAIL_PATTERN.fullmatch(username):
                return self.send_json({'message': '请输入正确的邮箱格式。'}, 400)
            try:
                code_status, reward, _ = get_global_code_status(code)
            except Exception:
                logger.exception('Activation-code database query failed')
                return self.send_json({'message': '激活码服务暂不可用，请稍后重试。'}, 503)
            if code_status == 'missing':
                return self.send_json({'message': '激活码不存在或已失效。'}, 404)
            if code_status == 'used':
                return self.send_json({'message': '该激活码已经使用过了。'}, 409)
            if code_status == 'processing':
                return self.send_json({'message': '该激活码正在领取中，请稍后查询结果。'}, 409)
        else:
            player_id = str(data.get('player_id', '')).strip(); player_name = str(data.get('player_name', '')).strip()
            if len(player_id) < 3: return self.send_json({'message': '请填写完整的激活码和 Steam 账号。'}, 400)
            gift = GIFTS.get(code)
            if not gift: return self.send_json({'message': '激活码不存在或已失效。'}, 404)
            if gift['used']: return self.send_json({'message': '该激活码已经使用过了。'}, 409)

        if path == '/api/redeem/global':
            try:
                inventory = get_soop_inventory_for_code(code)
            except LookupError as exc:
                log_business_error(f'SOOP inventory mapping missing: {exc}')
                return self.send_json({'message': '该激活码尚未关联可领取的 SOOP 宝箱。'}, 409)
            except Exception:
                logger.exception('SOOP inventory lookup failed before global login')
                return self.send_json({'message': 'SOOP 库存服务暂不可用，请稍后重试。'}, 503)
            if not inventory:
                log_business_error('SOOP inventory mapping missing after activation-code lookup')
                return self.send_json({'message': '该激活码尚未关联可领取的 SOOP 宝箱。'}, 409)
            try:
                login_info = get_global_login_info(username, password, inventory[1])
            except RuntimeError as exc:
                if str(exc) == 'SOOP 解绑失败，请稍后重试。':
                    log_business_error('SOOP unlink failed before global redemption', exc_info=True)
                    return self.send_json({'message': 'SOOP 解绑失败，请稍后重试。'}, 502)
                if str(exc) == 'SOOP 绑定失败，请稍后重试。':
                    log_business_error('SOOP binding failed before global redemption', exc_info=True)
                    return self.send_json({'message': 'SOOP 绑定失败，请稍后重试。'}, 502)
                log_business_error('Global login service failed', exc_info=True)
                return self.send_json({'message': '全球账号登录服务暂不可用，请稍后重试。'}, 503)
            except Exception:
                log_business_error('Global login service failed', exc_info=True)
                return self.send_json({'message': '全球账号登录服务暂不可用，请稍后重试。'}, 503)
            if not login_info or not login_info.get('authorization'):
                log_business_error('Global login did not return authorization')
                return self.send_json({'message': '全球账号登录失败，请确认账号、密码正确，并关闭二级验证后重试。'}, 401)
            player_name = str(login_info.get('globalNickname') or login_info.get('nickname') or login_info.get('gameName') or '全球账号')
            order_details = {'delivery_mode': 'global', 'player_name': player_name}
        else:
            order_details = {'delivery_mode': 'steam', 'player_id': player_id, 'player_name': player_name}
        order_id = 'DZ-' + datetime.now(timezone.utc).strftime('%y%m%d') + '-' + secrets.token_hex(3).upper()
        if path == '/api/redeem/global':
            claim_token = secrets.token_hex(16)
            try:
                reserved = reserve_global_code(code, claim_token)
            except Exception:
                logger.exception('Activation-code reservation failed')
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
                _, reward, claimed_items = claim_soop_stock(inventory)
            except Exception:
                try:
                    release_global_code_reservation(code, claim_token)
                except Exception:
                    logger.exception('Activation-code reservation release failed')
                    return self.send_json({'message': 'SOOP 领取失败，兑换状态正在确认，请稍后查询结果。'}, 202)
                logger.exception('SOOP reward claim failed after global login')
                return self.send_json({'message': '全球账号登录成功，但 SOOP 宝箱领取失败，请稍后重试。'}, 502)
            try:
                claimed = complete_global_code_claim(
                    code, claim_token, username, password, reward,
                    [item_code_idx for item_code_idx, _ in claimed_items],
                )
            except Exception:
                logger.exception('Activation-code completion failed after SOOP claim')
                return self.send_json({'message': 'SOOP 宝箱已提交领取，兑换状态正在确认，请稍后查询结果。'}, 202)
            if not claimed:
                return self.send_json({'message': '该激活码正在领取中，请稍后查询结果。'}, 409)
        else:
            gift['used'] = True
            reward = gift['reward']
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
        ensure_system_log_table()
        database_log_handler = DatabaseErrorLogHandler(level=logging.ERROR)
        logger.addHandler(database_log_handler)
    except Exception:
        logger.exception('System log table initialization failed')
    port = int(os.environ.get('GIFT_PORTAL_PORT', '8000'))
    logger.info('DROP//ZONE running at http://127.0.0.1:%s', port)
    ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()
