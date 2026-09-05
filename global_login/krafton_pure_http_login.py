#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KRAFTON ID 纯 HTTP 登录器（requests 版）。

不启动浏览器，不依赖 Playwright。
流程：
  1) GET / 初始化 cookies
  2) POST /auth/local 提交邮箱密码
  3) 如果返回 428，保存 Akamai challenge 原始响应并停止
  4) 如果登录接口放行，GET /settings/profile 验证登录态

用法：
  $env:KRAFTON_EMAIL='xxx@qq.com'
  $env:KRAFTON_PASSWORD='password'
  python .\krafton_pure_http_login.py

可选：
  python .\krafton_pure_http_login.py --email xxx --password xxx --trusted
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import logging
import os
import random
import re
import shutil
import sys
import subprocess
import time
import uuid
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque
from pathlib import Path
from typing import Any, Dict
from urllib.parse import parse_qsl, quote, urlparse

# 带指纹 HTTP 客户端:curl_cffi 模拟真实 Chrome 的 TLS/HTTP2 指纹。
# 与打开的浏览器同版本(chrome150),使 cookie 的"出生环境"与请求端一致。
try:
    from curl_cffi import requests
except Exception as e:  # pragma: no cover
    raise SystemExit(f"[!] 需要 curl_cffi(带指纹 HTTP): pip install -U curl_cffi ({e})")

BASE = "https://accounts.krafton.com"
# RiskByPass 服务端要求 payload.proxy 为有效字符串；本机请求链仍可直连。
DEFAULT_RISKBYPASS_PROXY = "http://42.96.18.62:1311"
DEFAULT_RISKBYPASS_PROXIES = (
    "http://42.96.18.62:1311",
    "http://mkhl05k1:ZWB2aijU@222.73.154.219:2024",
)
ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts"
COOKIE_FILE = ART / "pure_http_cookies.json"
LOGIN_RESPONSE_FILE = ART / "pure_http_login_response.json"
PROFILE_RESPONSE_FILE = ART / "pure_http_profile_response.json"
CHALLENGE_FILE = ART / "pure_http_akamai_428.json"

# 指纹目标:curl_cffi impersonate 版本 = 浏览器 chrome150 版本(二者 TLS/HTTP2 指纹一致)
FINGERPRINT = os.environ.get("KRAFTON_CURL_FINGERPRINT", "chrome150").strip().lower()
# playwright 使用的真实 Chrome for Testing 150 可执行文件(与 curl_cffi chrome150 同源)
CHROME150_EXE = os.environ.get(
    "KRAFTON_CHROME150_EXE",
    r"E:\QQfile\steam_login\chrome150\chrome-win64\chrome.exe",
)
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"

# 浏览器(chrome150)实际发出的 UA-CH 头(实测基准,见 tmp_ua_benchmark.py):
# sec-ch-ua 值必须与浏览器页面 navigator.userAgentData.brands 完全一致,
# 否则 sensor_data 内嵌画像与 HTTP 请求头不一致,Akamai 直接拒。
UA_CH = os.environ.get(
    "KRAFTON_UA_CH",
    '"Not;A=Brand";v="8", "Chromium";v="150"',
)
UA_CH_MOBILE = os.environ.get("KRAFTON_UA_CH_MOBILE", "?0")
UA_CH_PLATFORM = os.environ.get("KRAFTON_UA_CH_PLATFORM", '"Windows"')
BROWSER_LOCALE = os.environ.get("KRAFTON_BROWSER_LOCALE", "zh-CN")
BROWSER_TZ = os.environ.get("KRAFTON_BROWSER_TZ", "Asia/Shanghai")
# 独立持久 profile 目录(为空则不启用;启用后 chrome150 以 launch_persistent_context 打开)
BROWSER_PROFILE_DIR = os.environ.get("KRAFTON_PROFILE_DIR") or None

# sensor ??????"playwright" = ???? Chromium?"bitbrowser" = ??????? CDP?
SENSOR_BROWSER_BACKEND = os.environ.get("KRAFTON_SENSOR_BROWSER", "playwright").strip().lower()
NODE_EXE = os.environ.get(
    "KRAFTON_NODE_EXE",
    r"C:\Users\Administrator\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe",
)
BITBROWSER_API_URL = os.environ.get("BITBROWSER_API_URL", "http://127.0.0.1:54345")
BITBROWSER_PROFILE_ID = os.environ.get("BITBROWSER_PROFILE_ID") or None
BITBROWSER_PROFILE_NAME = os.environ.get("BITBROWSER_PROFILE_NAME", "PUBG_Worker_50")
BITBROWSER_KEEP_OPEN = os.environ.get("BITBROWSER_KEEP_OPEN", "1") == "1"
_PERSIST_ARTIFACTS = ContextVar("krafton_persist_artifacts", default=True)
_RISKBYPASS_SUBMIT_LOCK = threading.Lock()

_POOL_LOGGER = logging.getLogger("krafton.abck_pool")
_POOL_LOGGER.setLevel(logging.INFO)
_POOL_LOGGER.propagate = True

# server.py may configure the parent logger after this module is imported and
# may raise the global_login logger level. Keep an explicit runtime sink for
# pool events so startup/refill diagnostics are always visible.
_POOL_LOG_PATH = Path(__file__).resolve().parents[1] / "login_runtime.log"
try:
    _POOL_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not any(getattr(h, "_krafton_pool_file", False) for h in _POOL_LOGGER.handlers):
        _pool_file_handler = logging.FileHandler(_POOL_LOG_PATH, encoding="utf-8")
        _pool_file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        _pool_file_handler._krafton_pool_file = True
        _POOL_LOGGER.addHandler(_pool_file_handler)
    if not any(getattr(h, "_krafton_pool_console", False) for h in _POOL_LOGGER.handlers):
        _pool_console_handler = logging.StreamHandler()
        _pool_console_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        _pool_console_handler._krafton_pool_console = True
        _POOL_LOGGER.addHandler(_pool_console_handler)
except Exception:
    pass


def _pool_log(message: str, level: int = logging.INFO) -> None:
    """Write seed-pool events to both the existing console and app log."""
    safe_message = re.sub(r"(https?://)([^:@/\s]+):([^@/\s]+)@", r"\1\2:***@", message)
    _POOL_LOGGER.log(level, safe_message)

LOGIN_MESSAGE_MAP: Dict[str, Dict[str, str]] = {
    "error.invalid-csrf-token": {
        "zh": "请刷新并重试。",
        "meaning": "业务 CSRF/session 绑定不完整或已失效。",
        "action": "重新预热登录页和初始化 API：/config/v1/init、/profile/trusted-devices/last-login-info、/auth/sms/country-codes。",
    },
    "error.invalid-password": {
        "zh": "密码错误。",
        "meaning": "账号存在但密码不正确。",
        "action": "停止重试该密码，换正确密码；连续错误可能触发账号锁定或限流。",
    },
    "error.login-denied": {
        "zh": "无法找到使用该电子邮箱和密码的账号。",
        "meaning": "邮箱/密码组合不匹配，或账号不存在。",
        "action": "检查邮箱和密码；不要对同一账号连续失败重试。",
    },
    "error.login-ip-rate-limit": {
        "zh": "很抱歉，您尝试登录的次数已达上限。请稍后再试。",
        "meaning": "当前 IP 登录尝试过多。",
        "action": "更换代理/IP，或等待风控窗口恢复。",
    },
    "error.login-rate-limit": {
        "zh": "登录似乎遇到问题。请等待20分钟后再试一次。",
        "meaning": "账号或登录行为触发限流。",
        "action": "等待约 20 分钟后再试，避免持续请求。",
    },
    "error.login-locked": {
        "zh": "由于尝试登录失败次数过多，此账号已被锁定。",
        "meaning": "账号因多次失败登录被锁定。",
        "action": "停止登录尝试，走忘记密码/账号恢复流程。",
    },
    "error.login-need-to-verify-mfa": {
        "zh": "已设置双因素验证。请完成双因素验证以登录。",
        "meaning": "账号启用了 MFA/二次验证。",
        "action": "需要补 MFA 验证流程；单纯账号密码不能直接完成登录。",
    },
    "error.login-required": {
        "zh": "您必须先登录才能执行该操作。",
        "meaning": "当前 cookie 未登录、登录态过期或关键登录 cookie 缺失。",
        "action": "重新跑完整登录链路；不要只复用过期 cookies。",
    },
    "error.session-expired": {
        "zh": "会话已过期。",
        "meaning": "session 已过期。",
        "action": "重新初始化 session 并完整登录。",
    },
    "error.local-auth-validate-failed": {
        "zh": "无法验证证书",
        "meaning": "本地账号认证校验失败。",
        "action": "检查账号类型、密码状态和请求参数。",
    },
    "error.invalid-request": {
        "zh": "申请无效。",
        "meaning": "请求参数或当前状态无效。",
        "action": "检查 payload、Referer、初始化 API 和 cookie 状态。",
    },
    "error.invalid-token": {
        "zh": "无效令牌",
        "meaning": "token 无效。",
        "action": "重新初始化页面/session，避免复用旧 token。",
    },
    "error.token-expired": {
        "zh": "令牌已过期。",
        "meaning": "token 过期。",
        "action": "重新获取 token 或重新开始登录流程。",
    },
    "error.email-invalid": {
        "zh": "请输入有效的电子邮箱",
        "meaning": "邮箱格式无效。",
        "action": "检查 email 参数。",
    },
    "error.email-required": {
        "zh": "电子邮箱必填",
        "meaning": "缺少邮箱。",
        "action": "传入 --email 或设置 KRAFTON_EMAIL。",
    },
    "error.password-required": {
        "zh": "密码必填。",
        "meaning": "缺少密码。",
        "action": "传入 --password 或设置 KRAFTON_PASSWORD。",
    },
    "error.provider-locked": {
        "zh": "该KRAFTON ID已与其他第三方账号绑定。",
        "meaning": "第三方平台绑定冲突。",
        "action": "检查账号绑定关系；本地登录脚本不能直接解决绑定冲突。",
    },
    "error.set-password-first": {
        "zh": "如果您尚未设置密码，请先进行设置。",
        "meaning": "第三方创建的 KRAFTON ID 尚未设置本地密码。",
        "action": "先通过网页登录/找回流程设置本地密码。",
    },
    "error.email-not-found-for-account": {
        "zh": "未找到此账户的邮箱地址。",
        "meaning": "账号缺少邮箱信息。",
        "action": "检查账号状态或改用绑定平台流程。",
    },
    "error.server": {
        "zh": "发生错误。（代码：{0}）",
        "meaning": "服务端通用错误。",
        "action": "记录 errorCode、响应体和请求阶段，稍后重试或换代理。",
    },
    "login.success": {
        "zh": "登录成功。",
        "meaning": "账号密码认证成功，服务端已下发登录态。",
        "action": "继续 GET /settings/profile 验证登录态。",
    },
}


HTTP_STATUS_HINTS: Dict[int, Dict[str, str]] = {
    400: {
        "meaning": "业务请求错误，常见于 CSRF/session 不完整或参数无效。",
        "action": "优先看 JSON message；若是 invalid-csrf-token，重新跑初始化 API。",
    },
    401: {
        "meaning": "未登录或登录态过期。",
        "action": "重新完整登录。",
    },
    403: {
        "meaning": "访问被拒，可能是 IP/风控/权限问题。",
        "action": "换代理或重新初始化风控链路。",
    },
    428: {
        "meaning": "Akamai adaptive sec-cp-challenge。",
        "action": "继续加载 challenge 页面、提交 sensor_data、计算 sec-cpt PoW、GET verify_url。",
    },
}


@contextmanager
def suppress_artifact_persistence():
    """Disable credential-bearing diagnostics for one request context."""
    token = _PERSIST_ARTIFACTS.set(False)
    try:
        yield
    finally:
        _PERSIST_ARTIFACTS.reset(token)


def save_json(path: Path, data: Any) -> None:
    if not _PERSIST_ARTIFACTS.get():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def try_json(r: requests.Response) -> Any:
    try:
        return r.json()
    except Exception:
        return r.text[:8000]


def snapshot(r: requests.Response) -> Dict[str, Any]:
    return {
        "ts": int(time.time()),
        "status_code": r.status_code,
        "reason": r.reason,
        "url": r.url,
        "headers": dict(r.headers),
        "body": try_json(r),
    }


def _iter_cookies(s: requests.Session):
    """统一返回 session 的真 Cookie 对象列表。

    requests 的 CookieJar 直接迭代即 Cookie；curl_cffi 的 s.cookies 迭代是
    name=value 字符串,真对象在 .jar(http.cookiejar.CookieJar)里。
    """
    jar = getattr(s.cookies, "jar", None)
    if jar is not None:
        return list(jar)
    return list(s.cookies)


AKAMAI_COOKIE_NAMES = {"_abck", "bm_sz", "ak_bmsc", "bm_sv", "bm_mi"}


def is_valid_abck(value: str | None) -> bool:
    """RiskByPass _abck 的状态段必须为 0 才允许进入 seed 池。"""
    if not value:
        return False
    parts = str(value).split("~")
    return len(parts) >= 2 and parts[1] == "0"


def load_riskbypass_token() -> str | None:
    """riskbypass token:优先 env,其次读 pubg_cookie/abck.py 的 TOKEN。"""
    tok = os.environ.get("PUBG_RISKBYPASS_TOKEN")
    if tok:
        print(f"[riskbypass-token] 来源=env PUBG_RISKBYPASS_TOKEN token={tok[:24]}...")
        return tok.strip()
    candidates = [
        ROOT / "pubg_cookie" / "abck.py",
        Path(r"E:\QQfile\pubg_cookie\abck.py"),
        Path(r"E:\QQfile\abck.py"),
    ]
    for path in candidates:
        if path.exists():
            m = re.search(r'TOKEN\s*=\s*"([^"]+)"', path.read_text(encoding="utf-8", errors="ignore"))
            if m:
                print(f"[riskbypass-token] 来源={path} token={m.group(1)[:24]}...")
                return m.group(1)
    return None


def fetch_target_init_cookies(target_url: str, proxy: str | None) -> dict[str, str]:
    """GET target_url 一次,收集 Set-Cookie 作为 init_cookies。

    用带浏览器 TLS 指纹的客户端(curl_cffi chrome150)获取——与后续登录请求
    指纹同源,init_cookies 与 Akamai 判定环境更一致(裸 urllib 指纹差异大)。
    """
    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "sec-ch-ua": UA_CH,
        "sec-ch-ua-mobile": UA_CH_MOBILE,
        "sec-ch-ua-platform": UA_CH_PLATFORM,
    }
    init_cookies: dict[str, str] = {}
    try:
        s = make_session(load_saved=False, proxy=proxy)
        resp = s.get(target_url, headers=headers, timeout=30)
        # curl_cffi 的 headers 是 HeaderMap,遍历 Set-Cookie 需要走原始响应头
        raw = getattr(resp, "_raw_headers", None)
        if raw is None:
            try:
                raw = resp.headers.get_list("set-cookie") or []
            except Exception:
                raw = []
        for h in raw:
            if isinstance(h, (list, tuple)) and len(h) == 2 and h[0].lower() == "set-cookie":
                h = h[1]
            pair = str(h).split(";", 1)[0]
            if "=" in pair:
                k, v = pair.split("=", 1)
                init_cookies[k.strip()] = v.strip()
        # 若上面没取到,兜底用 curl_cffi cookie jar 里 target 域的值
        if not init_cookies:
            for c in _iter_cookies(s):
                if c.value:
                    init_cookies[c.name] = c.value
    except Exception as e:
        print(f"[riskbypass] 获取 init_cookies 失败: {type(e).__name__}: {e}")
    return init_cookies


def riskbypass_seed_cookies(
    proxy: str | None = None,
    akamai_js_url: str | None = None,
    return_metadata: bool = False,
) -> dict[str, str] | tuple[dict[str, str], str]:
    """调 riskbypass 生成全套 Akamai cookies(init_cookies + 动态 akamai_js_url)。

    返回 dict(cookies),失败返回空 dict。需要 riskbypass 库 + abck.py 提供 TOKEN。
    """
    target_url = f"{BASE}/v2/zh_CN/web/login-main"
    task_proxy = proxy or os.environ.get("KRAFTON_RISKBYPASS_PROXY") or os.environ.get("PUBG_RISKBYPASS_PROXY") or DEFAULT_RISKBYPASS_PROXY
    # 目标站点链路与 payload 使用同一代理；RiskByPass API 本身仍在下方强制直连。
    request_proxy = task_proxy
    token = load_riskbypass_token()
    if not token:
        print("[riskbypass] 未找到 TOKEN(设置 PUBG_RISKBYPASS_TOKEN 或 pubg_cookie/abck.py)")
        return ({}, "") if return_metadata else {}
    try:
        from riskbypass import RiskByPassClient
    except Exception as e:
        print(f"[riskbypass] riskbypass 库不可用: {e}")
        return ({}, "") if return_metadata else {}

    # 1) GET target_url 拿 init_cookies
    init_cookies = fetch_target_init_cookies(target_url, request_proxy)
    print(f"[riskbypass] init_cookies proxy={request_proxy} keys={sorted(init_cookies.keys())}")

    # 2) 若未给 akamai_js_url,顺带从同一 HTML 发现——fetch 只返回 cookies,
    #    简单起见此处用传入或环境值;否则再 GET 一次抓 JS。
    if not akamai_js_url:
        import urllib.request
        try:
            opener = (
                urllib.request.build_opener(urllib.request.ProxyHandler({"http": request_proxy, "https": request_proxy}))
                if request_proxy
                else urllib.request.build_opener(urllib.request.ProxyHandler({}))
            )
            req = urllib.request.Request(target_url, headers={"User-Agent": UA, "Accept": "text/html,*/*;q=0.8"})
            with opener.open(req, timeout=30) as resp:
                html = resp.read().decode("utf-8", "replace")
            scripts = re.findall(r'<script[^>]+src="([^"]+)"', html)
            akamai_js_url = next((BASE + x for x in scripts if x.startswith("/") and not x.startswith("/v2/") and "akam/13" not in x), None)
        except Exception as e:
            print(f"[riskbypass] 发现 akamai_js_url 失败: {e}")

    # diffcult:普通模式不过时设 true(riskbypass 面板参数,注意官方拼写就是 diffcult)
    difficult = os.environ.get("PUBG_RISKBYPASS_DIFFICULT", "0") == "1"
    payload: dict[str, Any] = {
        "task_type": "akamai",
        "proxy": task_proxy,
        "target_url": target_url,
        "init_cookies": init_cookies,
        "diffcult": difficult,
        "engine": "chrome",
        "os": "windows",
    }
    if akamai_js_url:
        payload["akamai_js_url"] = akamai_js_url
    print(f"[riskbypass] diffcult={difficult} proxy={task_proxy} akamai_js_url={akamai_js_url}")

    try:
        # RiskByPass 的 /task/submit 对同一 token 的并发提交容易出现 TLS EOF；
        # seed 前置 Cookie/JS 获取仍可并行，仅串行化第三方任务提交。
        with _RISKBYPASS_SUBMIT_LOCK:
            # RiskByPass API 本身直连；代理只放在 payload.proxy 供服务端访问目标。
            proxy_env_names = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy")
            old_proxy_env = {name: os.environ.get(name) for name in proxy_env_names}
            for name in proxy_env_names:
                if name in ("NO_PROXY", "no_proxy"):
                    os.environ[name] = "*"
                else:
                    os.environ.pop(name, None)
            try:
                client = RiskByPassClient(token=token, base_url="https://riskbypass.com")
                result = client.run_task(payload, timeout=120)
                print(f"[riskbypass] 完整返回结果: {result!r}")
            finally:
                for name, value in old_proxy_env.items():
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value
        if isinstance(result, dict) and isinstance(result.get("cookies"), dict):
            cookies = {k: str(v) for k, v in result["cookies"].items() if str(v)}
            if not is_valid_abck(cookies.get("_abck")):
                abck = cookies.get("_abck", "")
                print(f"[riskbypass] 丢弃无效 _abck 状态段={abck.split('~')[1] if '~' in abck else 'missing'}")
                return ({}, "") if return_metadata else {}
            print(f"[riskbypass] 返回 cookies: proxy={task_proxy} {sorted(cookies.keys())} _abck_len={len(cookies.get('_abck', ''))} abck={cookies.get('_abck', '')[:12]}...")
            result_ua = str(result.get("ua") or "").strip() if isinstance(result, dict) else ""
            return (cookies, result_ua) if return_metadata else cookies
        print(f"[riskbypass] 结果无 cookies: {str(result)[:200]}")
    except Exception as e:
        print(f"[riskbypass] 生成 seed 失败: {type(e).__name__}: {e}")
    return ({}, "") if return_metadata else {}


KDL_PROXY_API_URL = os.environ.get(
    "KRAFTON_PROXY_API_URL",
    "https://dps.kdlapi.com/api/getdps/?secret_id=oyipc4pdovvevsnz0fsb&signature=ayj42ou17uvlrmxmvw2zvpc2hplxbh1x&num={num}&format=json&sep=1&f_auth=1&generateType=1&dedup=1",
)


def fetch_kdl_proxies(count: int) -> list[str]:
    """从动态代理池获取 host:port:user:password，并转换为 HTTP 代理 URL。"""
    url = KDL_PROXY_API_URL.format(num=max(1, int(count)))
    with urllib.request.urlopen(url, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8", "replace"))
    items = payload.get("data", {}).get("proxy_list", [])
    if payload.get("code") != 0 or not items:
        raise RuntimeError(f"KDL proxy API returned error: {payload}")
    proxies: list[str] = []
    for item in items:
        parts = str(item).strip().split(":")
        if len(parts) != 4:
            continue
        host, port, user, password = parts
        proxies.append(f"http://{user}:{password}@{host}:{port}")
    if not proxies:
        raise RuntimeError("KDL proxy API returned no valid proxies")
    return proxies


class _AbckPool:
    """进程级 RiskByPass seed 池：复用有效 seed，并在低水位后台补种。"""

    _lock = threading.RLock()
    _queue: deque[dict[str, Any]] = deque()
    _fill_cond = threading.Condition(_lock)
    _fill_in_progress = False
    _startup_started = False
    _refill_thread: threading.Thread | None = None
    _ttl_s = max(60, int(os.environ.get("KRAFTON_ABCK_TTL", os.environ.get("PUBG_HTTP_ABCK_TTL", "3600"))))
    _target = max(1, int(os.environ.get("KRAFTON_ABCK_QUEUE_TARGET", os.environ.get("PUBG_RISKBYPASS_QUEUE_TARGET", "5"))))
    _fresh_target = max(1, int(os.environ.get("KRAFTON_ABCK_FRESH_TARGET", os.environ.get("PUBG_RISKBYPASS_FRESH_TARGET", "5"))))
    _min_available = max(0, int(os.environ.get("KRAFTON_ABCK_QUEUE_MIN", os.environ.get("PUBG_RISKBYPASS_QUEUE_MIN", "1"))))
    _max_uses = max(1, int(os.environ.get("KRAFTON_ABCK_MAX_USES", os.environ.get("PUBG_RISKBYPASS_SEED_MAX_USES", "100"))))

    @classmethod
    def _prune_locked(cls) -> None:
        now = time.time()
        cls._queue = deque(
            e for e in cls._queue
            if now - float(e.get("created", now)) < cls._ttl_s
            and int(e.get("uses", 0)) < cls._max_uses
        )

    @classmethod
    def _fill_one(cls, proxy: str | None) -> dict[str, Any]:
        effective_proxy = proxy or os.environ.get("KRAFTON_RISKBYPASS_PROXY") or os.environ.get("PUBG_RISKBYPASS_PROXY") or DEFAULT_RISKBYPASS_PROXY
        cookies, result_ua = riskbypass_seed_cookies(proxy=effective_proxy, return_metadata=True)
        if not cookies.get("_abck"):
            raise RuntimeError("RiskByPass 未返回有效 _abck")
        return {"cookies": cookies, "ua": result_ua, "abck": cookies["_abck"], "proxy": effective_proxy, "created": time.time(), "uses": 0, "in_use": False}

    @classmethod
    def _fill_batch(cls, proxy: str | None, count: int = 4, on_entry: Any = None) -> list[dict[str, Any]]:
        """使用两条固定代理并发初始化；每条完成后立即入队。"""
        count = max(1, int(count))
        results: list[dict[str, Any]] = []
        errors: list[str] = []
        _pool_log(f"[riskbypass-pool] 动态代理 5 线程并发初始化 {count} 个 seed ...")
        configured = os.environ.get("KRAFTON_RISKBYPASS_PROXIES") or os.environ.get("PUBG_RISKBYPASS_PROXIES")
        proxy_list = [p.strip() for p in configured.split(",") if p.strip()] if configured else list(DEFAULT_RISKBYPASS_PROXIES)
        if proxy:
            proxy_list = [proxy, *[p for p in proxy_list if p != proxy]]
        proxies = [proxy_list[i % len(proxy_list)] for i in range(count)]
        if os.environ.get("KRAFTON_USE_PROXY_POOL", os.environ.get("PUBG_USE_PROXY_POOL", "0")) == "1":
            try:
                proxies = fetch_kdl_proxies(count)
                _pool_log(f"[riskbypass-pool] 动态代理池获取 {len(proxies)} 条代理")
            except Exception as exc:
                _pool_log(f"[riskbypass-pool] 动态代理池获取失败，回退单代理: {type(exc).__name__}: {exc}", logging.WARNING)
        def run_one(item: tuple[int, str]) -> tuple[int, dict[str, Any] | None, str | None]:
            index, current_proxy = item
            _pool_log(f"[riskbypass-pool] 并发任务 {index}/{count} proxy={current_proxy}")
            try:
                return index, cls._fill_one(current_proxy), None
            except Exception as exc:
                return index, None, f"{type(exc).__name__}: {exc}"

        with ThreadPoolExecutor(max_workers=min(5, count), thread_name_prefix="krafton-seed") as executor:
            futures = [executor.submit(run_one, item) for item in enumerate(proxies[:count], 1)]
            for future in as_completed(futures):
                _index, entry, error = future.result()
                if entry is not None:
                    results.append(entry)
                    if on_entry is not None:
                        on_entry(entry)
                elif error:
                    errors.append(error)
        _pool_log(f"[riskbypass-pool] 动态代理并发初始化完成 success={len(results)} failed={len(errors)}")
        for error in errors:
            _pool_log(f"[riskbypass-pool] seed 初始化失败: {error}", logging.WARNING)
        return results

    @classmethod
    def _start_refill_locked(cls, proxy: str | None) -> None:
        if cls._refill_thread and cls._refill_thread.is_alive():
            return
        def worker() -> None:
            try:
                while True:
                    with cls._lock:
                        cls._prune_locked()
                        fresh = sum(1 for e in cls._queue if int(e.get("uses", 0)) == 0)
                        if fresh >= cls._fresh_target:
                            cls._refill_thread = None
                            return
                        need = cls._fresh_target - fresh
                    cls._fill_batch(
                        proxy, count=need,
                        on_entry=lambda entry: cls._enqueue_filled_entry(entry),
                    )
            except Exception as exc:
                _pool_log(f"[riskbypass-pool] 后台补种失败: {type(exc).__name__}: {exc}", logging.ERROR)
                with cls._lock:
                    cls._refill_thread = None
        cls._refill_thread = threading.Thread(target=worker, name="krafton-abck-refill", daemon=True)
        cls._refill_thread.start()

    @classmethod
    def _enqueue_filled_entry(cls, entry: dict[str, Any]) -> None:
        with cls._fill_cond:
            cls._queue.append(entry)
            _pool_log(
                f"[riskbypass-pool] seed 入队 abck={str(entry.get('abck', ''))[:12]}... "
                f"uses={entry.get('uses', 0)} queue={len(cls._queue)} fresh="
                f"{sum(1 for e in cls._queue if int(e.get('uses', 0)) == 0)}"
            )
            cls._fill_cond.notify_all()

    @classmethod
    def _wait_and_take_entry_locked(cls, proxy: str | None) -> dict[str, Any]:
        """在持有条件锁时等待可用 seed，避免并发账号递归重入 get_entry。"""
        wait_limit = max(30, int(os.environ.get("KRAFTON_ABCK_WAIT_TIMEOUT", "300")))
        deadline = time.monotonic() + wait_limit
        while True:
            cls._prune_locked()
            available = [e for e in cls._queue if not e.get("in_use")]
            if available:
                entry = max(available, key=lambda e: int(e.get("uses", 0)))
                entry["in_use"] = True
                entry["uses"] = int(entry.get("uses", 0)) + 1
                out = dict(entry)
                out["reused"] = int(entry.get("uses", 0)) > 1
                _pool_log(f"[riskbypass-pool] {'复用成功' if out['reused'] else '新生成'} seed abck={str(entry.get('abck', ''))[:12]}... proxy={entry.get('proxy')} abck_len={len(str(entry.get('abck', '')))} uses={entry['uses']} queue={len(cls._queue)}")
                return out
            if not cls._fill_in_progress and not (cls._refill_thread and cls._refill_thread.is_alive()):
                cls._start_refill_locked(proxy)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(f"RiskByPass seed 池等待超时({wait_limit}s)，后台补种仍未产生可用 seed")
            if int(remaining) % 30 == 0:
                _pool_log(f"[riskbypass-pool] 等待可用 seed remaining={int(remaining)}s queue={len(cls._queue)} in_use={sum(1 for e in cls._queue if e.get('in_use'))}")
            cls._fill_cond.wait(timeout=min(1.0, remaining))

    @classmethod
    def get_entry(cls, proxy: str | None = None, force_refresh: bool = False) -> dict[str, Any]:
        should_fill = False
        with cls._fill_cond:
            if force_refresh:
                cls._queue.clear()
            cls._prune_locked()
            if cls._queue:
                available = [e for e in cls._queue if not e.get("in_use")]
                if not available:
                    available = []
                if available:
                    # 优先复用已成功使用过的旧 seed；旧 seed 全部占用时才取全新 seed。
                    # 同一条 seed 仍受 in_use 保护，不会被两个账号同时租用。
                    entry = max(available, key=lambda e: int(e.get("uses", 0)))
                else:
                    entry = None
                if entry is not None:
                    entry["in_use"] = True
                    entry["uses"] = int(entry.get("uses", 0)) + 1
                    if int(entry.get("uses", 0)) == 1:
                        cls._start_refill_locked(proxy)
                    out = dict(entry)
                    out["reused"] = int(entry.get("uses", 0)) > 1
                    _pool_log(f"[riskbypass-pool] {'复用成功' if out['reused'] else '新生成'} seed abck={str(entry.get('abck', ''))[:12]}... uses={entry['uses']} queue={len(cls._queue)}")
                    return out
            # 登录线程只领取现有 seed；seed 生成始终由启动/后台补种线程负责。
            if not force_refresh and not cls._queue:
                # 启动初始化正在后台串行生成时，等待其结果；等待期间不执行 API。
                while cls._fill_in_progress and not cls._queue:
                    cls._fill_cond.wait(timeout=1.0)
                while cls._refill_thread and cls._refill_thread.is_alive() and not cls._queue:
                    cls._fill_cond.wait(timeout=1.0)
                if cls._queue:
                    return cls._wait_and_take_entry_locked(proxy)
                cls._start_refill_locked(proxy)
                wait_limit = max(30, int(os.environ.get("KRAFTON_ABCK_WAIT_TIMEOUT", "300")))
                deadline = time.monotonic() + wait_limit
                while not cls._queue and (cls._fill_in_progress or (cls._refill_thread and cls._refill_thread.is_alive())):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RuntimeError(f"RiskByPass seed 池等待超时({wait_limit}s)，后台补种仍未产生 seed")
                    cls._fill_cond.wait(timeout=min(1.0, remaining))
                if cls._queue:
                    return cls._wait_and_take_entry_locked(proxy)
                raise RuntimeError("RiskByPass seed 池补种失败，暂无可用 seed")
            if cls._fill_in_progress:
                while cls._fill_in_progress and not cls._queue:
                    cls._fill_cond.wait(timeout=1.0)
                if cls._queue:
                    entry = next((e for e in cls._queue if not e.get("in_use")), None)
                    if entry is None:
                        return cls._wait_and_take_entry_locked(proxy)
                    entry["in_use"] = True
                    entry["uses"] = int(entry.get("uses", 0)) + 1
                    out = dict(entry)
                    out["reused"] = True
                    _pool_log(f"[riskbypass-pool] 复用成功 seed abck={str(entry.get('abck', ''))[:12]}... proxy={entry.get('proxy')} abck_len={len(str(entry.get('abck', '')))} uses={entry['uses']} queue={len(cls._queue)}")
                    return out
            if not force_refresh:
                if not cls._fill_in_progress:
                    cls._start_refill_locked(proxy)
                wait_limit = max(30, int(os.environ.get("KRAFTON_ABCK_WAIT_TIMEOUT", "300")))
                deadline = time.monotonic() + wait_limit
                while not cls._queue and (cls._fill_in_progress or (cls._refill_thread and cls._refill_thread.is_alive())):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RuntimeError(f"RiskByPass seed 池等待超时({wait_limit}s)，后台补种仍未产生 seed")
                    cls._fill_cond.wait(timeout=min(1.0, remaining))
                if cls._queue:
                    return cls._wait_and_take_entry_locked(proxy)
                raise RuntimeError("RiskByPass seed 池补种失败，暂无可用 seed")
            cls._fill_in_progress = True
            should_fill = True

        if should_fill:
            entries = cls._fill_batch(proxy, count=cls._fresh_target)
            with cls._fill_cond:
                cls._queue.extend(entries)
                cls._fill_in_progress = False
                cls._fill_cond.notify_all()
                if not cls._queue:
                    raise RuntimeError("RiskByPass 串行初始化未获得有效 seed")
                entry = next((e for e in cls._queue if not e.get("in_use")), cls._queue[0])
                entry["in_use"] = True
                entry["uses"] = int(entry.get("uses", 0)) + 1
                out = dict(entry)
                out["reused"] = False
                _pool_log(f"[riskbypass-pool] 新生成 seed abck={str(entry.get('abck', ''))[:12]}... proxy={entry.get('proxy')} abck_len={len(str(entry.get('abck', '')))} uses={entry['uses']} queue={len(cls._queue)}")
                return out

    @classmethod
    def discard(cls, abck: str) -> None:
        if not abck:
            return
        with cls._lock:
            cls._queue = deque(e for e in cls._queue if e.get("abck") != abck)
            cls._fill_cond.notify_all()

    @classmethod
    def release(cls, abck: str, success: bool = True, proxy: str | None = None) -> None:
        """归还账号独占的 seed；失败 seed 直接剔除，成功 seed 可串行复用。"""
        if not abck:
            return
        with cls._fill_cond:
            for entry in list(cls._queue):
                if entry.get("abck") != abck:
                    continue
                if success:
                    entry["in_use"] = False
                    _pool_log(f"[riskbypass-pool] 登录成功归还 seed abck={abck[:12]}... proxy={entry.get('proxy') or proxy} abck_len={len(str(entry.get('abck', '')))} uses={entry.get('uses', 0)} 可串行复用")
                else:
                    cls._queue.remove(entry)
                    _pool_log(f"[riskbypass-pool] 登录失败剔除 seed abck={abck[:12]}... proxy={entry.get('proxy') or proxy} abck_len={len(str(entry.get('abck', '')))} uses={entry.get('uses', 0)}", logging.WARNING)
                cls._fill_cond.notify_all()
                if success:
                    cls._start_refill_locked(proxy)
                return

    @classmethod
    def status(cls) -> dict[str, Any]:
        with cls._lock:
            cls._prune_locked()
            return {
                "queue_size": len(cls._queue),
                "fresh": sum(1 for e in cls._queue if int(e.get("uses", 0)) == 0),
                "in_use": sum(1 for e in cls._queue if e.get("in_use")),
                "target": cls._target,
                "fresh_target": cls._fresh_target,
                "ttl_s": cls._ttl_s,
                "max_uses": cls._max_uses,
            }

    @classmethod
    def initialize_background(cls, proxy: str | None = None, count: int = 3) -> None:
        """项目启动时后台初始化固定代理下的全新 seed。"""
        with cls._fill_cond:
            if cls._startup_started or cls._queue or cls._fill_in_progress:
                _pool_log(
                    f"[riskbypass-pool] 启动初始化跳过 queue={len(cls._queue)} "
                    f"in_progress={cls._fill_in_progress} startup_started={cls._startup_started}"
                )
                return
            cls._startup_started = True
            cls._fill_in_progress = True
            _pool_log(f"[riskbypass-pool] 启动初始化已调度 target={count} fresh_target={cls._fresh_target}")

        def worker() -> None:
            try:
                cls._fill_batch(
                    proxy, count=count,
                    on_entry=lambda entry: cls._enqueue_filled_entry(entry),
                )
                with cls._fill_cond:
                    _pool_log(f"[riskbypass-pool] 启动初始化完成 fresh={sum(1 for e in cls._queue if not e.get('uses'))}/{count} queue={len(cls._queue)}")
            except Exception as exc:
                _pool_log(f"[riskbypass-pool] 启动初始化失败: {type(exc).__name__}: {exc}", logging.ERROR)
            finally:
                with cls._fill_cond:
                    cls._fill_in_progress = False
                    cls._fill_cond.notify_all()

        threading.Thread(target=worker, name="krafton-abck-startup", daemon=True).start()


def initialize_abck_pool(proxy: str | None = None, count: int = 5) -> None:
    """供上层项目启动入口调用的 seed 池初始化函数。"""
    _AbckPool.initialize_background(proxy=proxy, count=count)


def riskbypass_login(
    email: str,
    password: str,
    proxy: str | None = None,
    trusted: bool = False,
    attempts: int = 5,
) -> int:
    """riskbypass 生成 Akamai seed -> curl_cffi 会话预热 -> /auth/local,失败换 seed 重试。"""
    session_proxy = None
    seed_proxy = proxy or DEFAULT_RISKBYPASS_PROXY
    last = None
    for attempt in range(1, attempts + 1):
        print(f"\n[riskbypass-login] 尝试 {attempt}/{attempts}:生成 Akamai seed ...")
        cookies, result_ua = riskbypass_seed_cookies(proxy=seed_proxy, return_metadata=True)
        if not cookies.get("_abck"):
            print("[riskbypass-login] seed 生成失败,重试...")
            continue

        s = make_session(load_saved=False, proxy=session_proxy)
        if result_ua:
            s.headers.update({"User-Agent": result_ua})
            print(f"[riskbypass-login] 使用返回 UA: {result_ua}")
        for name, val in cookies.items():
            s.cookies.set(name, val, domain=".accounts.krafton.com", path="/", secure=True)
        print(f"[riskbypass-login] 注入 cookies: {sorted(cookies.keys())}")

        r0 = bootstrap(s)
        print(f"[bootstrap] HTTP {r0.status_code}")
        try:
            akamai_js_url = discover_akamai_js(r0.text)
        except Exception:
            akamai_js_url = None
        prewarm_login_route(s, email=email, last_login=False)

        r1 = login(s, email, password, trusted=trusted)
        body = try_json(r1)
        print_short(f"login-attempt-{attempt}", r1)
        if r1.status_code == 200:
            print(f"[riskbypass-login] ✅ 登录成功(尝试 {attempt})")
            r2 = profile(s)
            print_short("profile", r2)
            return 0
        # 换新 seed 再试
        last = body
        print(f"[riskbypass-login] 未成功(HTTP {r1.status_code}),换新 seed 重试...")
    print(f"[riskbypass-login] 所有 {attempts} 次尝试失败: {last}")
    return 1


def _akamai_digest(s: requests.Session) -> str:
    """当前 session 里所有 Akamai cookie(_abck/bm_sz/ak_bmsc/bm_sv/bm_mi)的简短摘要。"""
    found: dict[str, str] = {}
    for c in _iter_cookies(s):
        if getattr(c, "name", None) in AKAMAI_COOKIE_NAMES and c.value:
            found[c.name] = f"{len(c.value)}:{c.value[:12]}"
    return " ".join(f"{k}={found[k]}" for k in sorted(found)) or "NONE"


def save_cookies(s: requests.Session) -> None:
    if not _PERSIST_ARTIFACTS.get():
        return
    rows = []
    for c in _iter_cookies(s):
        rows.append({
            "name": c.name,
            "value": c.value,
            "domain": c.domain,
            "path": c.path,
            "expires": c.expires,
            "secure": c.secure,
            "rest": dict(getattr(c, "_rest", {}) or {}),
        })
    save_json(COOKIE_FILE, rows)


def load_cookies(s: requests.Session) -> bool:
    if not COOKIE_FILE.exists():
        return False
    rows = json.loads(COOKIE_FILE.read_text(encoding="utf-8"))
    for c in rows:
        s.cookies.set(c["name"], c["value"], domain=c.get("domain") or "", path=c.get("path", "/"))
    return True


def ensure_krafton_did(s: requests.Session) -> None:
    """复现 Nuxt 插件生成的 KRAFTON_DID / KRAFTON_DID_UAT。"""
    did = s.cookies.get("KRAFTON_DID")
    uat = s.cookies.get("KRAFTON_DID_UAT")
    if did and uat and "::" in uat:
        return
    did = str(uuid.uuid4())
    # 前端使用 (new Date).toISOString().substring(0,10)，即 UTC 日期。
    day = time.strftime("%Y-%m-%d", time.gmtime())
    sig = hashlib.sha1(f"{did}::{day}".encode("utf-8")).hexdigest()
    uat = f"{day}::{sig}"
    # 浏览器插件设置 domain 为 "." + window.location.hostname，即 .accounts.krafton.com。
    s.cookies.set("KRAFTON_DID", did, domain=".accounts.krafton.com", path="/", secure=True)
    s.cookies.set("KRAFTON_DID_UAT", uat, domain=".accounts.krafton.com", path="/", secure=True)
    save_cookies(s)
    print(f"[did] generated KRAFTON_DID={did} KRAFTON_DID_UAT={uat}")


def make_session(load_saved: bool = True, proxy: str | None = None) -> requests.Session:
    # curl_cffi 带指纹 Session:模拟 Chrome/150 的 TLS + HTTP2 指纹
    s = requests.Session(impersonate=FINGERPRINT)
    # 不让系统 HTTP_PROXY/HTTPS_PROXY/ALL_PROXY 在未显式指定时接管请求。
    s.trust_env = False
    s.headers.update({
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Connection": "keep-alive",
        # UA-CH 三件套与浏览器完全对齐(sensor 内嵌画像 == 请求头画像)
        "sec-ch-ua": UA_CH,
        "sec-ch-ua-mobile": UA_CH_MOBILE,
        "sec-ch-ua-platform": UA_CH_PLATFORM,
    })
    if load_saved:
        load_cookies(s)
    if proxy:
        try:
            s.proxies.update({"http": proxy, "https": proxy})
        except Exception:
            s.proxies = {"http": proxy, "https": proxy}
    return s


def bootstrap(s: requests.Session) -> requests.Response:
    # 首页会下发 Nuxt 配置、sessionId / X2RF_T0KEN 以及 Akamai 初始 cookies。
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Upgrade-Insecure-Requests": "1",
    }
    r = s.get(f"{BASE}/", headers=headers, timeout=30, allow_redirects=True)
    save_cookies(s)
    return r


def login_page_url(email: str | None = None, last_login: bool = False) -> str:
    """KRAFTON 登录页 URL。last_login=True 时模拟网页的上次登录账号入口。"""
    base = f"{BASE}/v2/zh_CN/web/login-main"
    if last_login and email:
        return f"{base}?type=last-login&email={quote(email, safe='')}"
    return base


def prewarm_login_route(s: requests.Session, email: str | None = None, last_login: bool = False) -> str:
    """按浏览器入口顺序预热 Nuxt 登录路由。"""
    ensure_krafton_did(s)
    s.cookies.set("current_language", "zh_CN", domain=".krafton.com", path="/")
    final_login_url = login_page_url(email, last_login=last_login)
    routes = [
        f"{BASE}/v2/",
        f"{BASE}/v2/zh_CN",
        final_login_url,
    ]
    for idx, url in enumerate(routes, 1):
        try:
            r = s.get(url, headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Referer": BASE + "/" if idx == 1 else routes[idx - 2],
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": s.headers.get("User-Agent", UA),
            }, timeout=30, allow_redirects=True)
            save_json(ART / f"pure_http_prewarm_route_{idx}.json", snapshot(r))
            print(f"[prewarm] GET {url} -> HTTP {r.status_code}")
        except Exception as e:
            print(f"[prewarm] GET {url} error: {type(e).__name__}: {e}")
    api_routes = [
        f"{BASE}/config/v1/init",
        f"{BASE}/profile/trusted-devices/last-login-info",
        f"{BASE}/auth/sms/country-codes",
    ]
    for idx, url in enumerate(api_routes, 1):
        try:
            r = s.get(url, headers={
                "Accept": "application/json, text/plain, */*",
                "Referer": final_login_url,
                "User-Agent": s.headers.get("User-Agent", UA),
            }, timeout=30, allow_redirects=False)
            save_json(ART / f"pure_http_prewarm_api_{idx}.json", snapshot(r))
            print(f"[prewarm-api] GET {url} -> HTTP {r.status_code}")
        except Exception as e:
            print(f"[prewarm-api] GET {url} error: {type(e).__name__}: {e}")
    save_cookies(s)
    setattr(s, "_krafton_login_referer", final_login_url)
    return final_login_url


def discover_akamai_js(html: str) -> str:
    """从首页 HTML 中找当前 Akamai bm/挑战脚本。"""
    scripts = re.findall(r'<script[^>]+src="([^"]+)"', html)
    candidates = []
    for src in scripts:
        if src.startswith("/") and not src.startswith("/v2/"):
            # 当前页面中 /Uomd... 这类随机路径就是 Akamai 注入脚本。
            candidates.append(BASE + src)
    if not candidates:
        raise RuntimeError("未在首页 HTML 中发现 Akamai 脚本 URL")
    # 优先使用第一个非 async 的 bm 脚本；当前页面第一个 /Uomd... 是主脚本。
    return candidates[0]


def discover_akamai_js_verified(proxy: str | None = None) -> str | None:
    """发现真正可用的 akamai_js_url:候选脚本逐个 GET,校验响应 content-type 为
    application/javascript,并选 body 最大的那个 sensor 脚本(实测 572KB 那个
    正是页面 POST sensor_data 的目标,详见 tmp_find_sensor_post.py)。

    缺失此验证时主文件 riskbypass 分支会 AttributeError 并回退旧版 discover_akamai_js,
    akamai_js_url 可能不是真正接收 sensor 的脚本,导致 sec-cpt 失败。
    """
    from curl_cffi import requests as cr
    try:
        s = cr.Session(impersonate="chrome150")
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}
        html = s.get(f"{BASE}/", headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": UA,
        }, timeout=30).text
    except Exception as e:
        print(f"[akamai-js] 抓首页失败: {type(e).__name__}: {e}")
        return None

    scripts = re.findall(r'<script[^>]+src="([^"]+)"', html)
    candidates = [
        BASE + x for x in scripts
        if x.startswith("/") and not x.startswith("/v2/") and "akam/13" not in x and not x.startswith("/assets/")
    ]
    print(f"[akamai-js] HTML candidates={len(candidates)}")
    best_url, best_len = None, 0
    for url in candidates:
        try:
            r = s.get(url, timeout=30)
            ct = (r.headers.get("content-type") or r.headers.get("Content-Type") or "").lower()
            if "javascript" not in ct:
                print(f"[akamai-js] skip non-js: ...{url[-40:]} ct={ct}")
                continue
            body_len = len(r.content)
            print(f"[akamai-js] JS OK: ...{url[-40:]} body_len={body_len}")
            if body_len > best_len:
                best_url, best_len = url, body_len
        except Exception as e:
            print(f"[akamai-js] GET ...{url[-30:]} fail: {type(e).__name__}")
    if best_url:
        print(f"[akamai-js] pick main script body_len={best_len}")
        return best_url
    return None


def _load_bitbrowser_api():
    """Load the optional BitBrowser API integration for the HTTP login flow."""
    pubg_cookie_dir = ROOT.parent / "pubg_cookie"
    if str(pubg_cookie_dir) not in sys.path:
        sys.path.insert(0, str(pubg_cookie_dir))
    from bitbrowser_api import BitBrowserAPI  # type: ignore
    return BitBrowserAPI


def _select_bitbrowser_profile(api: Any, profile_id: str | None = None, profile_name: str | None = None) -> str:
    """??????????????? profile_id???? profile_name ??/?????? mapping ????"""
    if profile_id:
        return profile_id
    mapping = getattr(api, "mapping", {}) or {}
    names = []
    if profile_name:
        names.append(profile_name)
    names.extend(["PUBG_Worker_50", "PUBG_Worker_1"])
    for name in names:
        bid = mapping.get(name)
        if bid:
            return bid
        creator = getattr(api, "get_or_create_browser_id", None) or getattr(api, "create_browser", None)
        if callable(creator):
            bid = creator(name)
            if bid:
                return bid
    if mapping:
        return next(iter(mapping.values()))
    fallback_name = profile_name or "PUBG_Worker_50"
    creator = getattr(api, "get_or_create_browser_id", None) or getattr(api, "create_browser", None)
    if callable(creator):
        bid = creator(fallback_name)
        if bid:
            return bid
    raise RuntimeError(f"BitBrowser ??????????? profile?{fallback_name}??????????????? API ???")


def _open_bitbrowser(profile_id: str | None = None, profile_name: str | None = None) -> tuple[Any, str, str]:
    BitBrowserAPI = _load_bitbrowser_api()
    mapping_file = str(ROOT.parent / "pubg_cookie" / "bitbrowser_mapping.json")
    api = BitBrowserAPI(api_url=BITBROWSER_API_URL, mapping_file=mapping_file)
    if not api.check_health():
        raise RuntimeError(f"BitBrowser API ???: {BITBROWSER_API_URL}??????????????")
    bid = _select_bitbrowser_profile(api, profile_id=profile_id, profile_name=profile_name)
    opened = api.open_browser(bid)
    if not opened and not profile_id:
        # mapping ?? profile id ?????????????????????
        new_name = f"{profile_name or BITBROWSER_PROFILE_NAME or 'PUBG_Worker'}_{int(time.time())}"
        creator = getattr(api, "create_browser", None) or getattr(api, "get_or_create_browser_id", None)
        if callable(creator):
            new_bid = creator(new_name)
            if new_bid:
                bid = new_bid
                opened = api.open_browser(bid)
    if not opened:
        raise RuntimeError(f"BitBrowser open_browser ??: {bid}")
    endpoint = opened.get("ws") or (f"ws://{opened.get('http')}/devtools/browser" if opened.get("http") else None)
    if not endpoint:
        raise RuntimeError(f"BitBrowser open_browser ??? ws/http: {opened}")
    return api, bid, endpoint


def _playwright_proxy(proxy: str | None) -> Dict[str, str] | None:
    if not proxy:
        return None
    u = urlparse(proxy)
    if not u.scheme or not u.hostname:
        return {"server": proxy}
    out = {"server": f"{u.scheme}://{u.hostname}:{u.port}" if u.port else f"{u.scheme}://{u.hostname}"}
    if u.username:
        out["username"] = u.username
    if u.password:
        out["password"] = u.password
    return out


def session_cookies_for_playwright(s: requests.Session) -> list[dict]:
    rows = []
    for c in _iter_cookies(s):
        domain = (c.domain or "accounts.krafton.com").lstrip(".")
        item = {
            "name": c.name,
            "value": c.value,
            "domain": c.domain or domain,
            "path": c.path or "/",
            "secure": bool(c.secure),
            "httpOnly": "HttpOnly" in (getattr(c, "_rest", {}) or {}),
        }
        if c.expires:
            item["expires"] = int(c.expires)
        rows.append(item)
    return rows


def _human_enhanced_moves(page: Any) -> None:
    """增强版拟人鼠标轨迹:多段随机曲线移动 + 随机停留 + 微抖动 + 随机滚轮/Tab。

    每段用独立随机步数/曲率,期间穿插随机延时,让 Akamai 采集到的
    sensor 事件流更像真实用户操作,而不是固定套路。
    """
    def rnd(a: int, b: int) -> int:
        return random.randint(a, b)

    def pause(lo: int = 60, hi: int = 420) -> None:
        page.wait_for_timeout(rnd(lo, hi))

    # 页面顶部随机起点(避开固定 (180,220) 套路)
    page.mouse.move(rnd(60, 420), rnd(60, 260))
    pause(180, 700)

    # 多段目标点:在页面中部/右侧画"漫游"轨迹,不做点击
    points = [
        (rnd(320, 760), rnd(180, 420)),
        (rnd(180, 520), rnd(300, 560)),
        (rnd(500, 880), rnd(240, 480)),
        (rnd(240, 640), rnd(380, 620)),
        (rnd(420, 800), rnd(200, 400)),
    ]
    for (tx, ty) in points:
        steps = rnd(9, 24)
        page.mouse.move(tx, ty, steps=steps)
        pause(120, 520)
        # 微抖动:围绕目标点小幅来回
        if random.random() < 0.8:
            jx, jy = tx, ty
            for _ in range(rnd(1, 4)):
                jx += rnd(-6, 6)
                jy += rnd(-6, 6)
                page.mouse.move(jx, jy, steps=rnd(2, 5))
                pause(50, 220)

    # 随机滚轮(轻微上下翻动,模拟浏览页面)
    for _ in range(rnd(1, 3)):
        page.mouse.wheel(0, rnd(-160, 300))
        pause(180, 600)

    # 随机 Tab(模拟键盘浏览)
    for _ in range(rnd(0, 3)):
        page.keyboard.press("Tab")
        pause(140, 480)

    # 收尾:慢速回到表单附近(留下"准备输入"的停顿)
    page.mouse.move(rnd(360, 520), rnd(300, 380), steps=rnd(14, 30))
    pause(300, 900)


def browser_collect_sensor(
    target_url: str = f"{BASE}/",
    wait_ms: int = 5000,
    cookies: list[dict] | None = None,
    proxy: str | None = None,
    interact: bool = False,
    backend: str | None = None,
    bitbrowser_profile_id: str | None = None,
    bitbrowser_profile_name: str | None = None,
    bitbrowser_keep_open: bool | None = None,
    profile_dir: str | None = None,
) -> Dict[str, Any]:
    """
    ???? Akamai main JS????????

    backend:
      - playwright: ???? Chromium????
      - bitbrowser: ????????? profile ? CDP??????/????
    ????? cookie + bmak.get_telemetry()?

    profile_dir: 非空时用 launch_persistent_context 以独立持久 profile 打开
      (同目录跨会话保留 cookie/Akamai 信任状态,与真实浏览器一致)。
    """
    from playwright.sync_api import sync_playwright

    backend = (backend or SENSOR_BROWSER_BACKEND or "playwright").strip().lower()
    bitbrowser_keep_open = BITBROWSER_KEEP_OPEN if bitbrowser_keep_open is None else bitbrowser_keep_open
    profile_dir = (profile_dir or BROWSER_PROFILE_DIR) or None

    def _drive_page(ctx: Any) -> Dict[str, Any]:
        if cookies:
            try:
                # 只灌 Akamai 五件套(与浏览器同 chrome150 指纹时被接受,不触发 cookie-error)。
                # 不灌 sessionId/X2RF_T0KEN/KRAFTON_DID 等业务 cookie:
                # 实验证明带业务 cookie 灌入后,页面点登录会 target-close。
                akamai5 = {"_abck", "bm_sz", "ak_bmsc", "bm_sv", "bm_mi"}
                seed = [c for c in cookies if c.get("name") in akamai5 and c.get("value")]
                if seed:
                    ctx.add_cookies(seed)
            except Exception:
                pass
        page = ctx.new_page()
        page.goto(target_url, wait_until="domcontentloaded", timeout=45000)
        if interact:
            try:
                _human_enhanced_moves(page)
            except Exception:
                pass
        page.wait_for_timeout(wait_ms)
        data = page.evaluate(
            """() => {
                const out = { url: location.href, telemetry: null, has_bmak: !!window.bmak };
                if (window.bmak && typeof window.bmak.get_telemetry === 'function') {
                    out.telemetry = window.bmak.get_telemetry();
                }
                return out;
            }"""
        )
        try:
            data["cookies"] = ctx.cookies(BASE)
        except Exception:
            data["cookies"] = []
        try:
            page.close()
        except Exception:
            pass
        return data

    with sync_playwright() as p:
        if backend in ("bit", "bitbrowser", "bit-browser"):
            api, bid, endpoint = _open_bitbrowser(
                profile_id=bitbrowser_profile_id or BITBROWSER_PROFILE_ID,
                profile_name=bitbrowser_profile_name or BITBROWSER_PROFILE_NAME,
            )
            browser = p.chromium.connect_over_cdp(endpoint)
            try:
                ctx = browser.contexts[0] if browser.contexts else browser.new_context(locale=BROWSER_LOCALE, timezone_id=BROWSER_TZ, user_agent=UA)
                data = _drive_page(ctx)
                data["backend"] = "bitbrowser"
                data["bitbrowser_id"] = bid
                data["bitbrowser_ws"] = endpoint
                return data
            finally:
                try:
                    browser.close()
                except Exception:
                    pass
                if not bitbrowser_keep_open:
                    try:
                        api.close_browser(bid)
                    except Exception:
                        pass

        launch_kw = {}
        pw_proxy = _playwright_proxy(proxy)
        if pw_proxy:
            launch_kw["proxy"] = pw_proxy
        # 用 Chrome for Testing 150(与 curl_cffi chrome150 指纹同源)
        if os.path.exists(CHROME150_EXE):
            launch_kw["executable_path"] = CHROME150_EXE
            print(f"[browser] executable_path={CHROME150_EXE}")
        else:
            print(f"[browser] chrome150 不存在({CHROME150_EXE}),回退 playwright 自带 chromium")

        if profile_dir:
            # 独立持久 profile:同目录跨会话保留 cookie/Akamai 状态
            os.makedirs(profile_dir, exist_ok=True)
            launch_kw.update({
                "headless": True,
                "locale": BROWSER_LOCALE,
                "timezone_id": BROWSER_TZ,
                "user_agent": UA,
            })
            ctx = p.chromium.launch_persistent_context(profile_dir, **launch_kw)
            print(f"[browser] persistent profile: {profile_dir}")
            try:
                data = _drive_page(ctx)
                data["backend"] = "playwright-persistent"
                data["profile_dir"] = profile_dir
                return data
            finally:
                try:
                    ctx.close()  # 持久 context:关闭即保存 profile
                except Exception:
                    pass
        else:
            browser = p.chromium.launch(headless=True, **launch_kw)
            try:
                ctx = browser.new_context(locale=BROWSER_LOCALE, timezone_id=BROWSER_TZ, user_agent=UA)
                data = _drive_page(ctx)
                data["backend"] = "playwright"
                return data
            finally:
                browser.close()


_NODE_BUNDLE_CACHE: dict[str, Path] = {}


def node_collect_sensor(
    s: requests.Session,
    akamai_js_url: str,
    target_url: str,
    label: str,
    wait_ms: int = 250,
) -> Dict[str, Any]:
    """在 Node VM 中运行当前 Akamai bundle，不启动浏览器。

    这里保留网页脚本本身的 bmak/VM 运算，但把 HTTP 传输留给当前
    requests.Session；这样不会把浏览器 cookie 或浏览器登录态混回会话。
    """
    node = NODE_EXE if Path(NODE_EXE).exists() else shutil.which("node")
    if not node:
        raise RuntimeError("找不到 Node.js；请设置 KRAFTON_NODE_EXE")
    cache_key = akamai_js_url
    bundle_path = _NODE_BUNDLE_CACHE.get(cache_key)
    if not bundle_path or not bundle_path.exists():
        r = s.get(
            akamai_js_url,
            headers={"User-Agent": UA, "Referer": target_url, "Accept": "*/*"},
            timeout=45,
            allow_redirects=False,
        )
        if r.status_code != 200 or not r.content:
            raise RuntimeError(f"Akamai JS 下载失败 HTTP {r.status_code}")
        bundle_path = ART / "akamai_reverse" / f"pure_node_bundle_{int(time.time())}.js"
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        bundle_path.write_bytes(r.content)
        _NODE_BUNDLE_CACHE[cache_key] = bundle_path

    safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "_", label)
    telemetry_path = ART / "akamai_reverse" / f"pure_node_telemetry_{safe_label}_{int(time.time_ns())}.txt"
    cmd = [
        str(node), str(ROOT / "akamai_node_sensor.js"),
        "--bundle", str(bundle_path),
        "--target-url", target_url,
        "--script-url", akamai_js_url,
        "--out", str(telemetry_path),
        "--wait-ms", str(max(0, int(wait_ms))),
        "--user-agent", UA,
    ]
    child_env = os.environ.copy()
    # requests 的 CookieJar 在不同响应路径上可能保留空 domain；Node 侧需要看到
    # bm_sz/sec_cpt 等 host-only cookie，不能只按 Cookie.domain 过滤。
    cookie_pairs: list[str] = []
    seen_cookie_names: set[str] = set()
    for c in _iter_cookies(s):
        if not c.name or c.name in seen_cookie_names:
            continue
        seen_cookie_names.add(c.name)
        cookie_pairs.append(f"{c.name}={c.value}")
    child_env["KRAFTON_NODE_COOKIE"] = "; ".join(cookie_pairs)
    # The current Akamai bundle family uses an obfuscated global lookup table.
    # In Chromium the decoded aliases resolve to native Object/TextEncoder;
    # enable the equivalent deterministic Node repairs without enabling broad
    # callable stubs for unrelated globals.
    child_env.setdefault("NODE_REPAIR_MISSING_OBJECT", "1")
    child_env.setdefault("NODE_STUB_MISSING_GLOBALS", "0")
    child_env.setdefault("NODE_REPAIR_BROWSER_KEYS", "1")
    proc = subprocess.run(
        cmd, cwd=str(ROOT), env=child_env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=60
    )
    stdout = proc.stdout.strip()
    try:
        meta = json.loads(stdout) if stdout else {}
    except json.JSONDecodeError:
        meta = {"raw_stdout": stdout[-2000:]}
    if proc.returncode != 0 or not meta.get("ok"):
        stderr = (proc.stderr or "").strip()
        raise RuntimeError(f"Node bmak 失败: {meta or stdout[-500:]} {stderr[-500:]}")
    telemetry = telemetry_path.read_text(encoding="utf-8")
    return {
        "backend": "node",
        "url": target_url,
        "telemetry": telemetry,
        "has_bmak": True,
        "cookies": [],
        "node": {k: v for k, v in meta.items() if k != "output"},
        "bundle": str(bundle_path),
        "telemetry_path": str(telemetry_path),
    }


def apply_browser_cookies(s: requests.Session, cookies: list[dict]) -> None:
    for c in cookies:
        s.cookies.set(c["name"], c["value"], domain=c.get("domain"), path=c.get("path", "/"))
    save_cookies(s)



def apply_akamai_browser_cookies(s: requests.Session, cookies: list[dict]) -> list[str]:
    """??? Akamai ?? cookie???? sec_cpt??? sec-cpt token/prefix ???"""
    allowed = {"_abck", "bm_sz", "ak_bmsc", "bm_sv", "bm_mi"}
    changed: list[str] = []
    for c in cookies or []:
        name = c.get("name")
        value = c.get("value")
        if name in allowed and value:
            s.cookies.set(name, value, domain=c.get("domain") or ".accounts.krafton.com", path=c.get("path", "/"), secure=bool(c.get("secure", True)))
            changed.append(name)
    if changed:
        save_cookies(s)
    return changed

def telemetry_to_sensor_data(telemetry: str) -> str:
    """
    bmak.get_telemetry() 返回 a=...&&&e=...&&&sensor_data=<base64>&&&j=...
    Akamai POST 需要 JSON text: {"sensor_data": "<decoded raw sensor>"}
    """
    if not telemetry:
        raise RuntimeError("empty telemetry")
    params = dict(parse_qsl(telemetry.replace("&&&", "&"), keep_blank_values=True))
    encoded = params.get("sensor_data")
    if not encoded:
        # 有些版本可能已经直接返回 sensor_data=
        m = re.search(r"sensor_data=([^&]+)", telemetry)
        encoded = m.group(1) if m else None
    if not encoded:
        raise RuntimeError("telemetry missing sensor_data")
    encoded = encoded.replace(" ", "+")
    encoded += "=" * (-len(encoded) % 4)
    raw = base64.b64decode(encoded).decode("utf-8", "replace")
    return raw


def post_sensor_data(s: requests.Session, akamai_js_url: str, sensor_data: str, referer: str = f"{BASE}/") -> requests.Response:
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Accept": "*/*",
        "Origin": BASE,
        "Referer": referer,
        "User-Agent": UA,
    }
    body = json.dumps({"sensor_data": sensor_data}, separators=(",", ":"))
    r = s.post(akamai_js_url, headers=headers, data=body, timeout=30, allow_redirects=False)
    save_cookies(s)
    return r


def collect_and_post_sensor(
    s: requests.Session,
    akamai_js_url: str,
    target_url: str,
    referer: str,
    label: str,
    session_proxy: str | None = None,
    wait_ms: int = 2500,
    interact: bool = True,
    sensor_backend: str | None = None,
    bitbrowser_profile_id: str | None = None,
    bitbrowser_profile_name: str | None = None,
    sync_akamai_cookies: bool = True,
    profile_dir: str | None = None,
) -> str | None:
    """用浏览器生成当前 cookie 上下文的 sensor，再由 requests 发送到 Akamai endpoint。"""
    try:
        backend = (sensor_backend or SENSOR_BROWSER_BACKEND or "playwright").strip().lower()
        if backend in {"node", "pure", "pure-node", "browserless"}:
            result = node_collect_sensor(s, akamai_js_url, target_url, label, wait_ms=min(wait_ms, 500))
        else:
            result = browser_collect_sensor(
                target_url=target_url,
                wait_ms=wait_ms,
                cookies=session_cookies_for_playwright(s),
                proxy=session_proxy,
                interact=interact,
                backend=backend,
                bitbrowser_profile_id=bitbrowser_profile_id,
                bitbrowser_profile_name=bitbrowser_profile_name,
                profile_dir=profile_dir,
            )
        save_json(ART / f"pure_http_sensor_browser_{label}.json", {k: v for k, v in result.items() if k != "telemetry"})
        if sync_akamai_cookies:
            changed = apply_akamai_browser_cookies(s, result.get("cookies") or [])
            if changed:
                print(f"[sensor:{label}] synced browser Akamai cookies: {','.join(sorted(set(changed)))} _abck_len={len(s.cookies.get('_abck') or '')}")
        # 注意：challenge 页在浏览器里加载时可能重新下发 sec_cpt。
        # 这里浏览器只作为 telemetry 生成器，不能把它的 cookies 回灌到当前
        # requests.Session，否则 428 token 与 sec_cpt prefix 会失配，/_sec/verify
        # 第一轮直接 success:false。
        telemetry = result.get("telemetry")
        print(f"[sensor:{label}] url={result.get('url')} has_bmak={result.get('has_bmak')} telemetry_len={len(telemetry or '')}")
        if not telemetry:
            return None
        sensor_data = telemetry_to_sensor_data(telemetry)
        sensor_fields = sensor_data.split(";", 7)
        sd_type = sensor_fields[6] if len(sensor_fields) >= 7 else ""
        print(f"[sensor:{label}] decoded_len={len(sensor_data)} sd_type={sd_type}")
        r = post_sensor_data(s, akamai_js_url, sensor_data, referer=referer)
        save_json(ART / f"pure_http_sensor_post_{label}.json", snapshot(r))
        print(f"[sensor:{label}] POST -> HTTP {r.status_code}, stage={sec_cpt_cookie_stage(s)}, _abck_len={len(s.cookies.get('_abck') or '')}")
        return sensor_data
    except Exception as e:
        print(f"[sensor:{label}] error: {type(e).__name__}: {e}")
        return None


def get_sec_cpt_prefix(s: requests.Session) -> str:
    value = s.cookies.get("sec_cpt")
    if not value or "~" not in value:
        raise RuntimeError("缺少 sec_cpt cookie，无法生成 sec-cpt answers")
    return value.split("~", 1)[0]


def sec_cpt_cookie_stage(s: requests.Session) -> str | None:
    value = s.cookies.get("sec_cpt")
    if not value:
        return None
    parts = value.split("~")
    return parts[1] if len(parts) > 1 else None


def generate_sec_cpt_answers(sec_prefix: str, token: str, timestamp: int, nonce: str,
                             difficulty: int, count: int) -> list[str]:
    """
    Akamai sec-cpt PoW:
      sha256(sec + timestamp + nonce + difficulty + answer) % difficulty == 0
      每命中一个 answer 后 difficulty += 1。
    """
    answers: list[str] = []
    diff = int(difficulty)
    count = int(count or 1)
    while len(answers) < count:
        answer = f"0.{os.urandom(8).hex()}"
        material = f"{sec_prefix}{int(timestamp)}{nonce}{diff}{answer}".encode("ascii")
        n = int.from_bytes(hashlib.sha256(material).digest(), "big") % diff
        if n == 0:
            answers.append(answer)
            diff += 1
    return answers


def solve_sec_cpt_challenge(s: requests.Session, challenge: Dict[str, Any],
                            max_rounds: int = 50, sleep_first: bool = True,
                            akamai_js_url: str | None = None,
                            session_proxy: str | None = None,
                            sensor_interleave: bool = True,
                            sensor_backend: str | None = None,
                            bitbrowser_profile_id: str | None = None,
                            bitbrowser_profile_name: str | None = None) -> bool:
    """
    处理 428 返回的 adaptive sec-cp-challenge。
    成功标准：服务端 Set-Cookie 后 sec_cpt 第二段变成 2，或响应不再返回下一轮 token。
    """
    ch = dict(challenge)
    # 浏览器触发 428 后会先加载 branding challenge 页和其注入脚本；这些 GET 会更新
    # _abck/bm_sz/sec_cpt 等状态。纯 HTTP 这里也按同样顺序预热一次。
    branding_url = ch.get("branding_cust_url")
    if branding_url:
        try:
            print(f"[sec-cpt] GET branding {branding_url}")
            rb = s.get(branding_url, headers={"User-Agent": UA, "Referer": f"{BASE}/v2/zh_CN/web/login-main"},
                       timeout=30, allow_redirects=False)
            save_json(ART / "pure_http_sec_cpt_branding.json", snapshot(rb))
            html = rb.text
            assets = re.findall(r'<(?:script|link)[^>]+(?:src|href)="([^"]+)"', html)
            for src in assets:
                if src.startswith("/"):
                    u = BASE + src
                elif src.startswith("http"):
                    u = src
                else:
                    u = BASE + "/v2/" + src.lstrip("/")
                if "/v2/challenge/" in u or "/Uomd" in u:
                    try:
                        ra = s.get(u, headers={"User-Agent": UA, "Referer": branding_url}, timeout=30, allow_redirects=False)
                        print(f"[sec-cpt] asset {ra.status_code} {u}")
                    except Exception as e:
                        print(f"[sec-cpt] asset error {u}: {e}")
            save_cookies(s)
        except Exception as e:
            print(f"[sec-cpt] branding preflight error: {e}")

    if sleep_first:
        duration = int(ch.get("chlg_duration") or 0)
        if duration > 0:
            print(f"[sec-cpt] wait chlg_duration={duration}s")
            time.sleep(duration)

    url = f"{BASE}/_sec/verify?provider={ch.get('provider', 'adaptive')}"
    challenge_url = ch.get("branding_cust_url") or f"{BASE}/v2/challenge/bot_challenge.html"
    if challenge_url.startswith("/"):
        challenge_url = BASE + challenge_url
    challenge_referer = f"{BASE}/v2/challenge/bot_challenge.html"

    if sensor_interleave and akamai_js_url:
        collect_and_post_sensor(
            s, akamai_js_url,
            target_url=challenge_url,
            referer=challenge_referer,
            label="sec_cpt_before_1",
            session_proxy=session_proxy,
            sensor_backend=sensor_backend,
            bitbrowser_profile_id=bitbrowser_profile_id,
            bitbrowser_profile_name=bitbrowser_profile_name,
            wait_ms=1800,
            interact=False,
        )

    headers = {
        "Accept": "*/*",
        "Content-Type": "text/plain;charset=UTF-8",
        "Origin": BASE,
        "Referer": f"{BASE}/v2/challenge/bot_challenge.html",
        "User-Agent": UA,
    }

    for round_idx in range(1, max_rounds + 1):
        token = ch.get("token")
        timestamp = ch.get("timestamp")
        nonce = ch.get("nonce")
        difficulty = int(ch.get("difficulty") or 0)
        count = int(ch.get("count") or 1)
        if not token or not timestamp or not nonce or not difficulty:
            print(f"[sec-cpt] no next token at round={round_idx}, stage={sec_cpt_cookie_stage(s)}")
            return sec_cpt_cookie_stage(s) == "2"

        sec = get_sec_cpt_prefix(s)
        print(f"[sec-cpt] round={round_idx} difficulty={difficulty} count={count} stage={sec_cpt_cookie_stage(s)}")
        answers = generate_sec_cpt_answers(sec, token, int(timestamp), str(nonce), difficulty, count)
        payload = {"token": token, "answers": answers}
        r = s.post(url, headers=headers, data=json.dumps(payload), timeout=60, allow_redirects=False)
        save_json(ART / f"pure_http_sec_cpt_round_{round_idx}.json", snapshot(r))
        save_cookies(s)
        print(f"[sec-cpt] verify -> HTTP {r.status_code}, stage={sec_cpt_cookie_stage(s)}")

        if sensor_interleave and akamai_js_url and round_idx in (3, 12, 24):
            collect_and_post_sensor(
                s, akamai_js_url,
                target_url=challenge_url,
                referer=challenge_referer,
                label=f"sec_cpt_after_{round_idx}",
                session_proxy=session_proxy,
                sensor_backend=sensor_backend,
                bitbrowser_profile_id=bitbrowser_profile_id,
                bitbrowser_profile_name=bitbrowser_profile_name,
                wait_ms=1600,
                interact=True,
            )

        body = try_json(r)
        if isinstance(body, dict):
            if sec_cpt_cookie_stage(s) == "2" and not body.get("token"):
                print("[sec-cpt] solved: sec_cpt stage=2")
                verify_url = ch.get("verify_url")
                if verify_url:
                    try:
                        rv = s.get(verify_url, headers={"User-Agent": UA, "Referer": f"{BASE}/v2/challenge/bot_challenge.html"},
                                   timeout=30, allow_redirects=False)
                        save_json(ART / "pure_http_sec_cpt_stage2_verify_url.json", snapshot(rv))
                        save_cookies(s)
                        print(f"[sec-cpt] stage2 GET verify_url -> HTTP {rv.status_code}, stage={sec_cpt_cookie_stage(s)}")
                    except Exception as e:
                        print(f"[sec-cpt] stage2 verify_url error: {e}")
                if sensor_interleave and akamai_js_url:
                    collect_and_post_sensor(
                        s, akamai_js_url,
                        target_url=challenge_url,
                        referer=challenge_referer,
                        label="sec_cpt_stage2_final",
                        session_proxy=session_proxy,
                        sensor_backend=sensor_backend,
                        bitbrowser_profile_id=bitbrowser_profile_id,
                        bitbrowser_profile_name=bitbrowser_profile_name,
                        wait_ms=2500,
                        interact=True,
                    )
                return True
            if body.get("success") is not True:
                print(f"[sec-cpt] server returned non-success: {body}")
                return False
            if not body.get("token"):
                print(f"[sec-cpt] final body without next token: {body}")
                verify_url = ch.get("verify_url")
                if verify_url:
                    try:
                        rv = s.get(verify_url, headers={"User-Agent": UA, "Referer": f"{BASE}/v2/challenge/bot_challenge.html"},
                                   timeout=30, allow_redirects=False)
                        save_json(ART / "pure_http_sec_cpt_final_verify_url.json", snapshot(rv))
                        save_cookies(s)
                        print(f"[sec-cpt] final GET verify_url -> HTTP {rv.status_code}, stage={sec_cpt_cookie_stage(s)}")
                    except Exception as e:
                        print(f"[sec-cpt] final verify_url error: {e}")
                if sensor_interleave and akamai_js_url:
                    collect_and_post_sensor(
                        s, akamai_js_url,
                        target_url=challenge_url,
                        referer=challenge_referer,
                        label="sec_cpt_final",
                        session_proxy=session_proxy,
                        sensor_backend=sensor_backend,
                        bitbrowser_profile_id=bitbrowser_profile_id,
                        bitbrowser_profile_name=bitbrowser_profile_name,
                        wait_ms=2500,
                        interact=True,
                    )
                # 部分边缘节点第一轮只返回 {"success": true}，不立即把 sec_cpt
                # 提升到 2；仍然让上层重试 /auth/local，以服务端最终分支为准。
                return True
            ch = {
                "provider": ch.get("provider", "adaptive"),
                "token": body.get("token"),
                "timestamp": body.get("timestamp"),
                "nonce": body.get("nonce"),
                "difficulty": body.get("difficulty"),
                "count": body.get("count") or count,
                "verify_url": body.get("verify_url") or ch.get("verify_url"),
            }
            continue

        print(f"[sec-cpt] unexpected response: {str(body)[:500]}")
        return False

    print(f"[sec-cpt] max rounds reached, stage={sec_cpt_cookie_stage(s)}")
    return sec_cpt_cookie_stage(s) == "2"


def login(s: requests.Session, email: str, password: str, trusted: bool = False) -> requests.Response:
    ensure_krafton_did(s)
    referer = getattr(s, "_krafton_login_referer", None) or login_page_url(email, last_login=False)
    headers = {
        "Origin": BASE,
        "Referer": referer,
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
    }
    payload = {
        "email": email,
        "password": password,
        "trusted_device": bool(trusted),
        "client_id": "local",
        "activationVersion": "v2",
    }
    r = s.post(f"{BASE}/auth/local", headers=headers, json=payload, timeout=30, allow_redirects=False)
    save_json(LOGIN_RESPONSE_FILE, snapshot(r))
    save_cookies(s)
    if r.status_code == 428:
        save_json(CHALLENGE_FILE, try_json(r))
    return r


def profile(s: requests.Session) -> requests.Response:
    headers = {
        "Referer": f"{BASE}/v2/zh_CN/settings/personal-info",
        "Accept": "application/json, text/plain, */*",
    }
    r = s.get(f"{BASE}/settings/profile", headers=headers, timeout=30, allow_redirects=False)
    save_json(PROFILE_RESPONSE_FILE, snapshot(r))
    save_cookies(s)
    return r


def login_credentials(email: str, password: str) -> Dict[str, Any]:
    """完成 KRAFTON 登录并返回后续流程所需上下文。

    调用方只需要提供邮箱和密码；Session、Akamai 初始化、sensor、challenge
    和登录页 Referer 均在本模块内生成。返回的 ``session`` 可直接继续 OIDC。
    """
    proxy = os.environ.get("KRAFTON_HTTP_PROXY") or os.environ.get("PUBG_HTTP_PROXY") or os.environ.get("HTTP_PROXY_URL")
    sensor_backend = os.environ.get("KRAFTON_SENSOR_BROWSER") or os.environ.get("PUBG_HTTP_SENSOR_BROWSER") or SENSOR_BROWSER_BACKEND
    profile_dir = os.environ.get("KRAFTON_PROFILE_DIR") or os.environ.get("PUBG_HTTP_PROFILE_DIR") or None
    last_login = os.environ.get("KRAFTON_LAST_LOGIN_PREWARM", os.environ.get("PUBG_HTTP_LAST_LOGIN_PREWARM", "0")) == "1"
    prelogin_sensor = os.environ.get("KRAFTON_PRELOGIN_SENSOR", os.environ.get("PUBG_HTTP_PRELOGIN_SENSOR", "1")) == "1"
    sensor_rounds = max(1, int(os.environ.get("KRAFTON_PRELOGIN_SENSOR_ROUNDS", os.environ.get("PUBG_HTTP_PRELOGIN_SENSOR_ROUNDS", "1"))))
    max_rounds = max(1, int(os.environ.get("KRAFTON_SEC_CPT_ROUNDS", os.environ.get("PUBG_HTTP_SEC_CPT_ROUNDS", "80"))))
    no_wait = os.environ.get("KRAFTON_NO_SEC_CPT_WAIT", os.environ.get("PUBG_HTTP_NO_SEC_CPT_WAIT", "1")) == "1"
    no_interleave = os.environ.get("KRAFTON_NO_SENSOR_INTERLEAVE", os.environ.get("PUBG_HTTP_NO_SENSOR_INTERLEAVE", "0")) == "1"

    # 与命令行 --riskbypass 保持一致：seed、代理和重试都在 kid 内部处理。
    riskbypass_enabled = os.environ.get("KRAFTON_ENABLE_RISKBYPASS", os.environ.get("PUBG_ENABLE_RISKBYPASS", "1")) == "1"
    if riskbypass_enabled:
        rb_proxy = (os.environ.get("KRAFTON_RISKBYPASS_PROXY")
                    or os.environ.get("PUBG_RISKBYPASS_PROXY")
                    or proxy
                    or DEFAULT_RISKBYPASS_PROXY)
        attempts = max(1, int(os.environ.get("KRAFTON_RISKBYPASS_ATTEMPTS", os.environ.get("PUBG_RISKBYPASS_ATTEMPTS", "3"))))
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            print(f"[riskbypass-login] 尝试 {attempt}/{attempts}: 获取 Akamai seed ...")
            seed_entry: dict[str, Any] = {}
            try:
                seed_entry = _AbckPool.get_entry(proxy=rb_proxy)
                seed = seed_entry.get("cookies") or {}
                login_proxy = None
                seed_ua = str(seed_entry.get("ua") or "").strip()
                seed_action = "复用" if seed_entry.get("reused") else "新生成"
                pool_status = _AbckPool.status()
                print(f"[riskbypass-login] seed_action={seed_action} uses={seed_entry.get('uses')} fresh={pool_status.get('fresh')}/{pool_status.get('fresh_target')} in_use={pool_status.get('in_use')} pool={pool_status.get('queue_size')}")
                s = make_session(load_saved=False, proxy=login_proxy)
                if seed_ua:
                    s.headers.update({"User-Agent": seed_ua})
                    print(f"[riskbypass-login] 使用返回 UA: {seed_ua}")
                for name, value in seed.items():
                    s.cookies.set(name, value, domain=".accounts.krafton.com", path="/", secure=True)
                bootstrap_response = bootstrap(s)
                akamai_js_url = discover_akamai_js(bootstrap_response.text)
                referer = prewarm_login_route(s, email=email, last_login=last_login)
                response = login(s, email, password, trusted=False)
                if response.status_code != 200:
                    body = try_json(response)
                    if response.status_code == 428:
                        challenge = body if isinstance(body, dict) else {}
                        if solve_sec_cpt_challenge(
                            s, challenge, max_rounds=max_rounds, sleep_first=not no_wait,
                            akamai_js_url=akamai_js_url, session_proxy=login_proxy,
                            sensor_interleave=not no_interleave, sensor_backend=sensor_backend,
                            bitbrowser_profile_id=BITBROWSER_PROFILE_ID,
                            bitbrowser_profile_name=BITBROWSER_PROFILE_NAME,
                        ):
                            referer = prewarm_login_route(s, email=email, last_login=last_login)
                            response = login(s, email, password, trusted=False)
                    if response.status_code != 200:
                        raise RuntimeError(f"KRAFTON 登录失败 HTTP {response.status_code}: {str(try_json(response))[:300]}")
                profile_response = profile(s)
                if profile_response.status_code != 200:
                    raise RuntimeError(f"KRAFTON profile 验证失败 HTTP {profile_response.status_code}")
                _AbckPool.release(str(seed_entry.get("abck") or ""), success=True, proxy=rb_proxy)
                return {
                    "session": s,
                    "akamai_js_url": akamai_js_url,
                    "referer": referer,
                    "login_response": response,
                    "profile_response": profile_response,
                    "challenge_count": 0,
                    "login_mode": "riskbypass",
                    "riskbypass_attempt": attempt,
                }
            except Exception as exc:
                last_error = exc
                try:
                    _AbckPool.release(str(seed_entry.get("abck") or ""), success=False, proxy=rb_proxy)
                except Exception:
                    pass
                print(f"[riskbypass-login] 尝试 {attempt} 失败: {type(exc).__name__}: {exc}")
        raise RuntimeError(f"RiskByPass 登录失败（{attempts} 次）: {last_error}")

    s = make_session(load_saved=False, proxy=proxy)
    r0 = bootstrap(s)
    akamai_js_url = discover_akamai_js(r0.text)
    referer = prewarm_login_route(s, email=email, last_login=last_login)
    if prelogin_sensor:
        for idx in range(1, sensor_rounds + 1):
            collect_and_post_sensor(
                s, akamai_js_url, target_url=referer, referer=referer,
                label=f"credentials_prelogin_{idx}", session_proxy=proxy,
                wait_ms=2200, interact=True, sensor_backend=sensor_backend,
                bitbrowser_profile_id=BITBROWSER_PROFILE_ID,
                bitbrowser_profile_name=BITBROWSER_PROFILE_NAME,
                sync_akamai_cookies=True, profile_dir=profile_dir,
            )
            if idx < sensor_rounds:
                time.sleep(random.uniform(1.2, 2.8))

    response = login(s, email, password, trusted=False)
    challenge_count = 0
    while response.status_code == 428 and challenge_count < 8:
        challenge_count += 1
        challenge = try_json(response)
        if not isinstance(challenge, dict):
            raise RuntimeError("KRAFTON challenge 响应不是 JSON")
        if not solve_sec_cpt_challenge(
            s, challenge, max_rounds=max_rounds, sleep_first=not no_wait,
            akamai_js_url=akamai_js_url, session_proxy=proxy,
            sensor_interleave=not no_interleave, sensor_backend=sensor_backend,
            bitbrowser_profile_id=BITBROWSER_PROFILE_ID,
            bitbrowser_profile_name=BITBROWSER_PROFILE_NAME,
        ):
            raise RuntimeError(f"KRAFTON sec-cpt challenge#{challenge_count} 未完成")
        referer = prewarm_login_route(s, email=email, last_login=last_login)
        response = login(s, email, password, trusted=False)
    if response.status_code != 200:
        body = try_json(response)
        info = classify_response(response, body)
        detail = info.get("zh") if info else str(body)[:300]
        raise RuntimeError(f"KRAFTON 登录失败 HTTP {response.status_code}: {detail}")
    profile_response = profile(s)
    if profile_response.status_code != 200:
        raise RuntimeError(f"KRAFTON profile 验证失败 HTTP {profile_response.status_code}")
    return {
        "session": s,
        "akamai_js_url": akamai_js_url,
        "referer": referer,
        "login_response": response,
        "profile_response": profile_response,
        "challenge_count": challenge_count,
    }


BROWSER_LOGIN_COOKIE_FILE = ART / "browser_login_cookies.json"


def browser_fetch_login(
    email: str,
    password: str,
    trusted: bool = False,
    profile_dir: str | None = None,
    proxy: str | None = None,
    headless: bool = True,
) -> int:
    """浏览器进程内 fetch /auth/local 登录(真 Chrome 发请求,已验证可行)。

    用 chrome150 + 可选持久 profile 打开登录页,在页面上下文里 fetch('/auth/local'),
    由真 Chrome 网络栈发出(带页面自己的全套 cookie)。成功即登录,返回 0。

    与 curl_cffi 发 /auth/local 的区别:真 Chrome 进程 = 通过 Akamai 风控;
    curl 模拟栈 = 400/2·26。这是唯一已验证能到 login.success 的脚本化路径。
    """
    from playwright.sync_api import sync_playwright

    profile_dir = (profile_dir or BROWSER_PROFILE_DIR) or str(ROOT / "profiles_chrome150" / "auto")
    os.makedirs(profile_dir, exist_ok=True)

    launch_kw: dict[str, Any] = {
        "executable_path": CHROME150_EXE if os.path.exists(CHROME150_EXE) else None,
        "headless": bool(headless),
        "locale": BROWSER_LOCALE,
        "timezone_id": BROWSER_TZ,
        "user_agent": UA,
        "viewport": {"width": 1365, "height": 860},
    }
    if launch_kw["executable_path"] is None:
        launch_kw.pop("executable_path")
    pw_proxy = _playwright_proxy(proxy)
    if pw_proxy:
        launch_kw["proxy"] = pw_proxy

    print(f"[browser-login] profile_dir={profile_dir} headless={headless} chrome150={CHROME150_EXE if os.path.exists(CHROME150_EXE) else 'fallback'}")
    with sync_playwright() as p:
        ctx = p.chromium.launch_persistent_context(profile_dir, **launch_kw)
        try:
            page = ctx.pages[0] if ctx.pages else ctx.new_page()
            page.goto(login_page_url(email, last_login=False), wait_until="domcontentloaded", timeout=45000)
            page.wait_for_timeout(2500)
            print(f"[browser-login] page.url={page.url}")

            payload = {
                "email": email,
                "password": password,
                "trusted_device": bool(trusted),
                "client_id": "local",
                "activationVersion": "v2",
            }
            result = page.evaluate(
                """async (payload) => {
                    const r = await fetch('/auth/local', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'include',
                        body: JSON.stringify(payload),
                    });
                    let body = null;
                    try { body = await r.json(); } catch (e) { body = await r.text(); }
                    return { status: r.status, body: body, url: location.href };
                }""",
                payload,
            )
            status = result.get("status")
            body = result.get("body")
            print(f"[browser-login] /auth/local HTTP {status}")
            if isinstance(body, dict):
                print(f"[browser-login] body={json.dumps(body, ensure_ascii=False)[:500]}")

            # 保存登录后的 cookie
            cookies = ctx.cookies()
            save_json(BROWSER_LOGIN_COOKIE_FILE, cookies)
            print(f"[browser-login] cookies saved: {BROWSER_LOGIN_COOKIE_FILE} ({len(cookies)} 个)")
            print(f"[browser-login] cookie names: {sorted({c['name'] for c in cookies})}")

            # 若登录成功,再验证 /settings/profile
            if status == 200:
                prof = page.evaluate(
                    """async () => {
                        const r = await fetch('/settings/profile', { credentials: 'include' });
                        let b = null;
                        try { b = await r.json(); } catch (e) { b = await r.text(); }
                        return { status: r.status, body: b };
                    }"""
                )
                print(f"[browser-login] /settings/profile HTTP {prof.get('status')}")
                pbody = prof.get("body")
                if isinstance(pbody, dict):
                    summ = {k: v for k, v in pbody.items() if k != "profile"}
                    print(f"[browser-login] profile summary={json.dumps(summ, ensure_ascii=False)[:400]}")
                return 0 if prof.get("status") == 200 else 1
            return 1
        finally:
            try:
                ctx.close()  # 持久 profile:登录态自动落盘
            except Exception:
                pass


def classify_response(r: requests.Response, body: Any | None = None) -> Dict[str, str] | None:
    if body is None:
        body = try_json(r)

    if isinstance(body, dict):
        msg = body.get("message")
        if isinstance(msg, str):
            info = LOGIN_MESSAGE_MAP.get(msg)
            if info:
                out = {"message": msg, **info}
                error_code = body.get("errorCode")
                if error_code is not None:
                    out["errorCode"] = str(error_code)
                return out
            if msg.startswith("error."):
                return {
                    "message": msg,
                    "zh": "源码中未收录的错误 key。",
                    "meaning": "服务端返回了新的业务错误。",
                    "action": "记录响应体，并从 Nuxt i18n 字典继续补映射。",
                }

        if body.get("sec-cp-challenge") == "true":
            info = HTTP_STATUS_HINTS[428]
            return {
                "message": "sec-cp-challenge",
                "zh": "需要完成 Akamai 风控挑战。",
                **info,
            }

    info = HTTP_STATUS_HINTS.get(r.status_code)
    if info:
        return {
            "message": f"HTTP {r.status_code}",
            "zh": "",
            **info,
        }
    return None


def print_short(label: str, r: requests.Response) -> None:
    print(f"[{label}] HTTP {r.status_code} {r.reason}")
    print(f"[{label}] url={r.url}")
    print(f"[{label}] content-type={r.headers.get('content-type')}")
    body = try_json(r)
    if isinstance(body, dict):
        print(json.dumps(body, ensure_ascii=False, indent=2)[:3000])
    else:
        print(str(body)[:1500])
    classification = classify_response(r, body)
    if classification:
        print(f"[{label}] classify.message={classification.get('message')}")
        if classification.get("errorCode"):
            print(f"[{label}] classify.errorCode={classification.get('errorCode')}")
        if classification.get("zh"):
            print(f"[{label}] classify.zh={classification.get('zh')}")
        print(f"[{label}] classify.meaning={classification.get('meaning')}")
        print(f"[{label}] classify.action={classification.get('action')}")


def main() -> int:
    # Windows 控制台常为 GBK,emoji/中文打印会 UnicodeEncodeError;统一 utf-8+replace 避免崩。
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--list-login-errors", action="store_true", help="打印已内置的登录错误映射并退出")
    ap.add_argument("--email", default=os.getenv("KRAFTON_EMAIL"))
    ap.add_argument("--password", default=os.getenv("KRAFTON_PASSWORD"))
    ap.add_argument("--trusted", action="store_true")
    ap.add_argument("--no-saved-cookies", action="store_true", help="不加载历史 pure_http_cookies.json")
    ap.add_argument("--profile-only", action="store_true", help="只用已有 cookie 请求 /settings/profile")
    ap.add_argument("--akamai-js-url", default=os.getenv("AKAMAI_JS_URL"), help="手工指定 Akamai JS URL；默认从首页 HTML 发现")
    ap.add_argument("--http-proxy", default=os.getenv("KRAFTON_HTTP_PROXY"), help="本机 requests 也走指定代理")
    ap.add_argument("--solve-sec-cpt", action="store_true", help="遇到 428 后纯 HTTP 计算并提交二段 sec-cp-challenge")
    ap.add_argument("--no-sec-cpt-wait", action="store_true", help="sec-cpt 不等待 chlg_duration")
    ap.add_argument("--sec-cpt-rounds", type=int, default=50)
    ap.add_argument("--no-sec-cpt-sensor-interleave", action="store_true", help="sec-cpt 解题过程中不插入 challenge 页面 sensor POST")
    ap.add_argument("--sensor-browser", choices=["node", "playwright", "bitbrowser"], default=SENSOR_BROWSER_BACKEND, help="sensor backend: node=browserless VM, playwright=headless Chromium, bitbrowser=CDP")
    ap.add_argument("--bitbrowser-profile-id", default=BITBROWSER_PROFILE_ID, help="????? profile id????? profile name/mapping ???")
    ap.add_argument("--bitbrowser-profile-name", default=BITBROWSER_PROFILE_NAME, help="????? profile ????? PUBG_Worker_50")
    ap.add_argument("--bitbrowser-close", action="store_true", help="sensor ????????????????????????????")
    ap.add_argument("--prelogin-sensor", action="store_true", help="(已默认必选,此参数仅为兼容保留)/auth/local 前总会先做 prelogin sensor")
    ap.add_argument("--no-prelogin-sensor", action="store_true", help="跳过 prelogin sensor(默认必选,除非显式关闭)")
    ap.add_argument("--sensor-rounds", type=int, default=1,
                    help="prelogin sensor 采集+发送轮数(默认 1;设 N>1 为 _abck 自举迭代)")
    ap.add_argument("--profile-dir", default=BROWSER_PROFILE_DIR, metavar="DIR",
                    help="chrome150 独立持久 profile 目录(跨会话保留 cookie/Akamai 状态;默认不启用)")
    ap.add_argument("--browser-login", action="store_true",
                    help="浏览器进程内 fetch /auth/local 登录(真 Chrome 发请求,唯一已验证通过 Akamai 的脚本化路径)")
    ap.add_argument("--browser-login-headed", action="store_true",
                    help="browser-login 用可见窗口(headed),默认 headless")
    ap.add_argument("--riskbypass", action="store_true",
                    help="用 riskbypass(第三方 abck 生成 API)+ init_cookies 生成 Akamai seed 后纯 HTTP 登录(已验证可行)")
    ap.add_argument("--riskbypass-attempts", type=int, default=5,
                    help="riskbypass seed 登录最大尝试次数(seed 有概率无效,默认重试 5 次换新 seed)")
    ap.add_argument("--riskbypass-proxy", default=os.getenv("PUBG_RISKBYPASS_PROXY"),
                    help="RiskByPass API、任务 payload 和 KRAFTON 请求使用的代理；默认使用固定代理")
    ap.add_argument("--riskbypass-token", default=os.getenv("PUBG_RISKBYPASS_TOKEN"),
                    help="riskbypass 访问令牌(默认读 pubg_cookie/abck.py 的 TOKEN)")
    ap.add_argument("--last-login-prewarm", action="store_true", help="预热 /web/login-main?type=last-login&email=当前邮箱，更贴近网页上次登录入口")
    args = ap.parse_args()
    global BITBROWSER_KEEP_OPEN
    if getattr(args, "bitbrowser_close", False):
        BITBROWSER_KEEP_OPEN = False

    if args.list_login_errors:
        print(json.dumps(LOGIN_MESSAGE_MAP, ensure_ascii=False, indent=2))
        return 0

    if not args.profile_only and (not args.email or not args.password):
        print("[-] 缺少账号密码：设置 KRAFTON_EMAIL/KRAFTON_PASSWORD 或传 --email/--password", file=sys.stderr)
        return 2

    session_proxy = args.http_proxy
    if args.browser_login:
        return browser_fetch_login(
            args.email,
            args.password,
            trusted=args.trusted,
            profile_dir=args.profile_dir,
            proxy=session_proxy,
            headless=not args.browser_login_headed,
        )
    if args.riskbypass:
        rb_proxy = args.riskbypass_proxy or session_proxy
        return riskbypass_login(
            args.email,
            args.password,
            proxy=rb_proxy,
            trusted=args.trusted,
            attempts=max(1, args.riskbypass_attempts),
        )

    s = make_session(load_saved=not args.no_saved_cookies, proxy=session_proxy)
    if session_proxy:
        print(f"[http-proxy] requests session proxy={session_proxy}")
    print(f"[sensor-browser] backend={args.sensor_browser}" + (f" profile_id={args.bitbrowser_profile_id or ''} profile_name={args.bitbrowser_profile_name or ''}" if args.sensor_browser == "bitbrowser" else ""))

    if args.profile_only:
        r = profile(s)
        print_short("profile", r)
        print(f"[+] profile response: {PROFILE_RESPONSE_FILE}")
        print(f"[+] cookies: {COOKIE_FILE}")
        return 0 if r.status_code == 200 else 1

    r0 = bootstrap(s)
    print_short("bootstrap", r0)
    discovered_akamai_js_url = args.akamai_js_url or discover_akamai_js(r0.text)
    login_referer = prewarm_login_route(s, email=args.email, last_login=args.last_login_prewarm)
    # prelogin sensor 默认必选:POST /auth/local 前先做一轮(或多轮)浏览器 sensor,
    # 用真实 chrome150 刷新 Akamai cookie + 提交 telemetry,再走 HTTP 登录。
    # --sensor-rounds N:全部 Akamai cookie(_abck/bm_sz/ak_bmsc/bm_sv/bm_mi)自举迭代
    # —— 每轮把当前 session 的 Akamai cookie 全部注入浏览器,浏览器加载后返回
    # (重签后的)新版并回灌 session;再 POST sensor,响应再更新;下一轮注入新值。
    sensor_rounds = max(1, int(getattr(args, "sensor_rounds", 1) or 1))
    if not args.no_prelogin_sensor:
        print(f"[sensor:prelogin] Akamai cookie 迭代起点: {_akamai_digest(s)}")
        for round_idx in range(1, sensor_rounds + 1):
            print(f"[sensor:prelogin] 轮次 {round_idx}/{sensor_rounds}: 注入当前 Akamai cookie -> 浏览器返回 -> POST sensor")
            collect_and_post_sensor(
                s,
                discovered_akamai_js_url,
                target_url=login_referer,
                referer=login_referer,
                label=f"prelogin-r{round_idx}",
                session_proxy=session_proxy,
                wait_ms=2200,
                interact=True,
                sensor_backend=args.sensor_browser,
                bitbrowser_profile_id=args.bitbrowser_profile_id,
                bitbrowser_profile_name=args.bitbrowser_profile_name,
                sync_akamai_cookies=True,
                profile_dir=args.profile_dir,
            )
            print(f"[sensor:prelogin] 轮次 {round_idx} 后 Akamai cookie: {_akamai_digest(s)}")
            if round_idx < sensor_rounds:
                time.sleep(random.uniform(1.2, 2.8))
    else:
        print("[sensor:prelogin] skipped (--no-prelogin-sensor)")
    print(f"[sensor:prelogin] 迭代结束 Akamai cookie: {_akamai_digest(s)}")

    r1 = login(s, args.email, args.password, args.trusted)
    print_short("login", r1)
    print(f"[+] login response: {LOGIN_RESPONSE_FILE}")
    print(f"[+] cookies: {COOKIE_FILE}")

    if r1.status_code == 428:
        print(f"[!] 纯 HTTP 已到达 Akamai challenge 边界，challenge 已保存: {CHALLENGE_FILE}")
        if not args.solve_sec_cpt:
            print("[!] 这不是账号密码错误；服务端要求完成前置风控验证后才会进入业务登录分支。")
            print("[!] 可加 --solve-sec-cpt 尝试纯 HTTP 计算二段 challenge。")
            return 3

        # 一个 /_sec/verify 链结束后，边缘节点可能仍以新的 428
        # challenge 继续验证。旧的成功链会在同一 requests session
        # 中重复“解题 -> 预热 -> /auth/local”，不能在第一次 428 后提前退出。
        current = r1
        for challenge_idx in range(1, 9):
            if current.status_code != 428:
                break
            ch = try_json(current)
            if not isinstance(ch, dict):
                print(f"[!] challenge#{challenge_idx} body 不是 JSON，无法处理 sec-cpt")
                return 3
            print(f"[sec-cpt] login challenge #{challenge_idx}")
            ok = solve_sec_cpt_challenge(
                s, ch,
                max_rounds=args.sec_cpt_rounds,
                sleep_first=not args.no_sec_cpt_wait,
                akamai_js_url=discovered_akamai_js_url,
                session_proxy=session_proxy,
                sensor_interleave=not args.no_sec_cpt_sensor_interleave,
                sensor_backend=args.sensor_browser,
                bitbrowser_profile_id=args.bitbrowser_profile_id,
                bitbrowser_profile_name=args.bitbrowser_profile_name,
            )
            if not ok:
                print(f"[!] sec-cpt challenge#{challenge_idx} 未解完")
                return 3
            print(f"[+] refresh login route after sec-cpt challenge#{challenge_idx} ...")
            login_referer = prewarm_login_route(s, email=args.email, last_login=args.last_login_prewarm)
            current = login(s, args.email, args.password, args.trusted)
            print_short(f"login-retry-{challenge_idx}", current)

        if current.status_code == 428:
            print("[!] 连续 challenge 达到上限，/auth/local 仍然返回 428")
            return 3
        r2 = profile(s)
        print_short("profile", r2)
        print(f"[+] profile response: {PROFILE_RESPONSE_FILE}")
        return 0 if r2.status_code == 200 else 1

    r2 = profile(s)
    print_short("profile", r2)
    print(f"[+] profile response: {PROFILE_RESPONSE_FILE}")
    return 0 if r2.status_code == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
