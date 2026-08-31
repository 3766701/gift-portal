from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import logging
import os
from pathlib import Path
import socket
import threading
from urllib.parse import unquote, urlparse
import json, re, secrets

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


def normalize_activation_code(raw_code):
    """Accept only the documented alphanumeric activation-code format."""
    code = str(raw_code).strip().upper().replace('-', '')
    return code if ACTIVATION_CODE_PATTERN.fullmatch(code) else None


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


def get_global_login_info(username, password):
    """Authenticate once through the existing HTTP getter without persisting credentials."""
    global GLOBAL_LOGIN_GETTER_CLASS
    with GLOBAL_LOGIN_IMPORT_LOCK:
        if GLOBAL_LOGIN_GETTER_CLASS is None:
            from global_login.pubg_cookie_getter_http import PUBGCookieGetter, logger as global_login_logger

            # The bundled module logs account-level diagnostics by default.
            # Portal requests must not persist account identifiers or tokens.
            global_login_logger.disabled = True
            GLOBAL_LOGIN_GETTER_CLASS = PUBGCookieGetter

    getter = GLOBAL_LOGIN_GETTER_CLASS()
    try:
        return getter.get_authorization_info(username, password)
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
                'SELECT reward, used_at IS NOT NULL FROM activation_codes WHERE code = %s',
                (code,),
            )
            row = cursor.fetchone()
    finally:
        connection.close()
    if row is None:
        return 'missing', None
    return ('used' if row[1] else 'available'), row[0]


def consume_global_code(code, order_id):
    """Atomically mark a code used only if no prior request has used it."""
    if pymysql is None or not GLOBAL_CODE_DB_CONFIG['password']:
        raise RuntimeError("全球激活码数据库未配置。")
    connection = pymysql.connect(**GLOBAL_CODE_DB_CONFIG, autocommit=False)
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                'UPDATE activation_codes SET used_at = UTC_TIMESTAMP(), order_id = %s '
                'WHERE code = %s AND used_at IS NULL',
                (order_id, code),
            )
            claimed = cursor.rowcount == 1
        connection.commit()
        return claimed
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
    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status); self.send_header('Content-Type', 'application/json; charset=utf-8'); self.send_header('Cache-Control', 'no-store'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if not has_gift_prefix(self.path):
            return self.send_json({'message': '页面不存在。'}, 404)
        path = application_path(self.path)
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
                code_status, reward = get_global_code_status(code)
            except Exception:
                logger.exception('Activation-code database query failed')
                return self.send_json({'message': '激活码服务暂不可用，请稍后重试。'}, 503)
            if code_status == 'missing':
                return self.send_json({'message': '未找到该激活码。'}, 404)
            status = '已领取' if code_status == 'used' else '未领取'
            message = '提货成功，请重启大厅。' if code_status == 'used' else '该激活码未领取。'
            return self.send_json({'code': code, 'status': status, 'reward': reward, 'message': message})
        relative = 'index.html' if path in ('', '/') else path.lstrip('/')
        file_path = (ROOT / relative).resolve()
        if ROOT.resolve() not in file_path.parents or not file_path.is_file(): return self.send_json({'message': '页面不存在。'}, 404)
        content_type = {'.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'application/javascript; charset=utf-8'}.get(file_path.suffix, 'application/octet-stream')
        body = file_path.read_bytes(); self.send_response(200); self.send_header('Content-Type', content_type); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        if not has_gift_prefix(self.path):
            return self.send_json({'message': '接口不存在。'}, 404)
        path = application_path(self.path)
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
                code_status, reward = get_global_code_status(code)
            except Exception:
                logger.exception('Activation-code database query failed')
                return self.send_json({'message': '激活码服务暂不可用，请稍后重试。'}, 503)
            if code_status == 'missing':
                return self.send_json({'message': '激活码不存在或已失效。'}, 404)
            if code_status == 'used':
                return self.send_json({'message': '该激活码已经使用过了。'}, 409)
        else:
            player_id = str(data.get('player_id', '')).strip(); player_name = str(data.get('player_name', '')).strip()
            if len(player_id) < 3: return self.send_json({'message': '请填写完整的激活码和 Steam 账号。'}, 400)
            gift = GIFTS.get(code)
            if not gift: return self.send_json({'message': '激活码不存在或已失效。'}, 404)
            if gift['used']: return self.send_json({'message': '该激活码已经使用过了。'}, 409)

        if path == '/api/redeem/global':
            try:
                login_info = get_global_login_info(username, password)
            except Exception:
                logger.warning('Global login service failed')
                return self.send_json({'message': '全球账号登录服务暂不可用，请稍后重试。'}, 503)
            if not login_info or not login_info.get('authorization'):
                return self.send_json({'message': '全球账号登录失败，请确认账号、密码正确，并关闭二级验证后重试。'}, 401)
            player_name = str(login_info.get('globalNickname') or login_info.get('nickname') or login_info.get('gameName') or '全球账号')
            order_details = {'delivery_mode': 'global', 'player_name': player_name}
        else:
            order_details = {'delivery_mode': 'steam', 'player_id': player_id, 'player_name': player_name}
        order_id = 'DZ-' + datetime.now(timezone.utc).strftime('%y%m%d') + '-' + secrets.token_hex(3).upper()
        if path == '/api/redeem/global':
            try:
                claimed = consume_global_code(code, order_id)
            except Exception:
                logger.exception('Activation-code database claim failed')
                return self.send_json({'message': '激活码服务暂不可用，请稍后重试。'}, 503)
            if not claimed:
                return self.send_json({'message': '该激活码已经使用过了。'}, 409)
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
    port = int(os.environ.get('GIFT_PORTAL_PORT', '8000'))
    logger.info('DROP//ZONE running at http://127.0.0.1:%s', port)
    ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()
