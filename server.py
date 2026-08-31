from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse
import json, re, secrets

ROOT = Path(__file__).parent
GIFTS = {'TAECG5XVAQ8XQNQY414': {'reward': '战术补给箱 × 1', 'used': False}, 'DEMO2026DROP001': {'reward': '补给券 × 3', 'used': False}}
ORDERS = {}

class Handler(BaseHTTPRequestHandler):
    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status); self.send_header('Content-Type', 'application/json; charset=utf-8'); self.send_header('Cache-Control', 'no-store'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/api/health': return self.send_json({'ok': True, 'service': 'drop-zone'})
        match = re.fullmatch(r'/api/orders/([^/]+)', path)
        if match:
            order = ORDERS.get(unquote(match.group(1))); return self.send_json(order or {'message': '未找到该订单。'}, 200 if order else 404)
        relative = 'index.html' if path in ('', '/') else path.lstrip('/')
        file_path = (ROOT / relative).resolve()
        if ROOT.resolve() not in file_path.parents or not file_path.is_file(): return self.send_json({'message': '页面不存在。'}, 404)
        content_type = {'.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'application/javascript; charset=utf-8'}.get(file_path.suffix, 'application/octet-stream')
        body = file_path.read_bytes(); self.send_response(200); self.send_header('Content-Type', content_type); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        if urlparse(self.path).path != '/api/redeem': return self.send_json({'message': '接口不存在。'}, 404)
        try: data = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        except (ValueError, json.JSONDecodeError): return self.send_json({'message': '请求数据格式错误。'}, 400)
        code = re.sub(r'[^A-Za-z0-9]', '', str(data.get('code', ''))).upper(); player_id = str(data.get('player_id', '')).strip(); player_name = str(data.get('player_name', '')).strip()
        if len(code) < 12 or len(player_id) < 3: return self.send_json({'message': '请填写完整的激活码和游戏 UID。'}, 400)
        gift = GIFTS.get(code)
        if not gift: return self.send_json({'message': '激活码不存在或已失效。'}, 404)
        if gift['used']: return self.send_json({'message': '该激活码已经领取过了。'}, 409)
        gift['used'] = True; order_id = 'DZ-' + datetime.now(timezone.utc).strftime('%y%m%d') + '-' + secrets.token_hex(3).upper()
        ORDERS[order_id] = {'order_id': order_id, 'status': '处理中', 'reward': gift['reward'], 'player_id': player_id, 'player_name': player_name, 'message': '提交成功，预计 5–15 分钟到账。'}
        return self.send_json({'message': f'提交成功，订单号：{order_id}', 'order_id': order_id, 'status': '处理中'}, 201)
    def log_message(self, fmt, *args): print(f'[{datetime.now():%H:%M:%S}] {fmt % args}')

if __name__ == '__main__': print('DROP//ZONE running at http://127.0.0.1:8000'); ThreadingHTTPServer(('127.0.0.1', 8000), Handler).serve_forever()
