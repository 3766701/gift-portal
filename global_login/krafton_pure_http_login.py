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
import os
import re
import shutil
import sys
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Dict
from urllib.parse import parse_qsl, quote, urlparse

import requests

BASE = "https://accounts.krafton.com"
ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts"
COOKIE_FILE = ART / "pure_http_cookies.json"
LOGIN_RESPONSE_FILE = ART / "pure_http_login_response.json"
PROFILE_RESPONSE_FILE = ART / "pure_http_profile_response.json"
CHALLENGE_FILE = ART / "pure_http_akamai_428.json"

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

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


def save_cookies(s: requests.Session) -> None:
    if not _PERSIST_ARTIFACTS.get():
        return
    rows = []
    for c in s.cookies:
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
        s.cookies.set(c["name"], c["value"], domain=c.get("domain"), path=c.get("path", "/"))
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
    s = requests.Session()
    s.headers.update({
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Connection": "keep-alive",
    })
    if load_saved:
        load_cookies(s)
    if proxy:
        s.proxies.update({"http": proxy, "https": proxy})
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
                "User-Agent": UA,
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
                "User-Agent": UA,
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
    for c in s.cookies:
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
) -> Dict[str, Any]:
    """
    ?????? Akamai main JS?????????

    backend:
      - playwright: ???? Chromium????
      - bitbrowser: ????????? profile ? CDP??????/????
    ????? cookie + bmak.get_telemetry()?
    """
    from playwright.sync_api import sync_playwright

    backend = (backend or SENSOR_BROWSER_BACKEND or "playwright").strip().lower()
    bitbrowser_keep_open = BITBROWSER_KEEP_OPEN if bitbrowser_keep_open is None else bitbrowser_keep_open

    def _drive_page(ctx: Any) -> Dict[str, Any]:
        if cookies:
            try:
                ctx.add_cookies(cookies)
            except Exception:
                pass
        page = ctx.new_page()
        page.goto(target_url, wait_until="domcontentloaded", timeout=45000)
        if interact:
            try:
                page.mouse.move(180, 220)
                page.mouse.move(420, 360, steps=8)
                page.mouse.wheel(0, 280)
                page.keyboard.press("Tab")
                page.wait_for_timeout(350)
                page.mouse.move(640, 420, steps=6)
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
                ctx = browser.contexts[0] if browser.contexts else browser.new_context(locale="zh-CN")
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
        browser = p.chromium.launch(headless=True, **launch_kw)
        try:
            ctx = browser.new_context(locale="zh-CN")
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
    for c in s.cookies:
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
    allowed = {"_abck", "bm_sz", "ak_bmsc"}
    changed: list[str] = []
    for c in cookies or []:
        name = c.get("name")
        value = c.get("value")
        if name in allowed and value:
            s.cookies.set(name, value, domain=c.get("domain") or ".krafton.com", path=c.get("path", "/"), secure=bool(c.get("secure", True)))
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
    ap.add_argument("--prelogin-sensor", action="store_true", help="?? /auth/local ??????????? sensor???? _abck/bm_sz/ak_bmsc")
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
    if args.prelogin_sensor or args.sensor_browser in {"bitbrowser", "node"}:
        print("[sensor:prelogin] collect login page sensor before /auth/local ...")
        collect_and_post_sensor(
            s,
            discovered_akamai_js_url,
            target_url=login_referer,
            referer=login_referer,
            label="prelogin",
            session_proxy=session_proxy,
            wait_ms=2500,
            interact=True,
            sensor_backend=args.sensor_browser,
            bitbrowser_profile_id=args.bitbrowser_profile_id,
            bitbrowser_profile_name=args.bitbrowser_profile_name,
            sync_akamai_cookies=True,
        )

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
