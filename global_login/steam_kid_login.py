#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PUBG Selfservice Steam 纯 HTTP 登录获取 focToken。

直接改下面 DEFAULT_STEAM_USER / DEFAULT_STEAM_PASSWORD / DEFAULT_STEAM_TOKEN 后运行：
  python E:\QQfile\steam_login\pubgselfservice_steam_http_token.py

也可以命令行覆盖：
  python E:\QQfile\steam_login\pubgselfservice_steam_http_token.py --steam-user xxx --steam-password xxx --steam-token ABCDE

DEFAULT_STEAM_TOKEN / --steam-token 自动按位数判断：5位=手机令牌，7位=备用令牌/恢复码。
"""
from __future__ import annotations

import argparse
import contextlib
import contextvars
import io
import base64
import calendar
import hashlib
import html
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs, parse_qsl, urljoin

import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from . import krafton_pure_http_login as kid
from . import pubgselfservice_http_token as pubg

# ===================== 直接改这里就能跑 =====================
DEFAULT_STEAM_USER = ""
DEFAULT_STEAM_PASSWORD = ""
DEFAULT_STEAM_TOKEN = ""  # 5位=手机令牌，7位=备用令牌/恢复码
DEFAULT_PROXY = ""
DEFAULT_PRINT_FULL_TOKEN = False
DEFAULT_HEAL_EMAIL = ""
DEFAULT_HEAL_EMAIL_PASSWORD = ""
DEFAULT_HEAL_USERNAME = ""
DEFAULT_HEAL_KRAFTON_PASSWORD = ""
DEFAULT_HEAL_INBOX_URL = ""
DEFAULT_HEAL_COUNTRY = "HK"
DEFAULT_HEAL_DOB = "2000-01-01"
# Steam Web 登录 platform_type：3=WebBrowser，和 Steam 前端网页一致
DEFAULT_STEAM_PLATFORM_TYPE = 3
# ============================================================

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts" / "pubgselfservice_steam_http"
OUT = ART / "pubgselfservice_steam_http_token.json"
STEAM_REFRESH_FILE = ART / "steam_refresh_token.txt"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
STEAM_API = "https://api.steampowered.com/IAuthenticationService"
STEAM_COMMUNITY = "https://steamcommunity.com"
STEAM_LOGIN = "https://login.steampowered.com"
KRAFTON_BASE = "https://accounts.krafton.com"
MAILBOX_API = "https://mail.xiongmaodianjing.top/api/fetch"
PORTAL_NO_PERSIST = contextvars.ContextVar('portal_no_persist', default=False)


STEAM_ERESULT_MAP = {
    "1": "OK：成功",
    "2": "Fail：通用失败",
    "5": "InvalidPassword：账号或密码错误/凭据不被接受",
    "6": "LoggedInElsewhere：账号已在别处登录",
    "7": "InvalidProtocolVer：协议版本不匹配",
    "9": "Steam 手机端已拒绝登录",
    "8": "InvalidParam：参数错误，常见于 settoken 缺 steamID 或 nonce/auth 不匹配",
    "15": "AccessDenied：访问被拒绝",
    "16": "LimitExceeded：请求过多/限流",
    "17": "Revoked：令牌或会话被撤销",
    "18": "Expired：令牌/会话过期",
    "20": "ServiceUnavailable：Steam 服务不可用",
    "26": "AlreadyLoggedIn：已经登录",
    "27": "AccountDisabled：账号不可用",
    "29": "DuplicateRequest：重复登录请求",
    "63": "AccountLogonDenied：账号登录被拒绝",
    "65": "InvalidLoginAuthCode：需要或验证 Steam 邮箱验证码",
    "66": "AccountLogonDeniedNoMail：账号没有可用的验证邮箱",
    "71": "ExpiredLoginAuthCode：Steam 邮箱验证码已过期",
    "72": "IPLoginRestrictionFailed：当前网络/IP 需要额外验证",
    "73": "AccountLockedDown：账号已锁定",
    "74": "AccountLogonDeniedVerifiedEmailRequired：Steam 邮箱尚未验证",
    "80": "Disabled：账号已禁用",
    "82": "RestrictedDevice：当前设备受限制",
    "83": "RegionLocked：当前地区受限制",
    "84": "RateLimitExceeded：接口频率限制",
    "85": "AccountLoginDeniedNeedTwoFactor：需要Steam令牌",
    "87": "AccountLoginDeniedThrottle：登录被风控限流",
    "88": "TwoFactorCodeMismatch：Steam令牌不匹配/过期",
    "89": "TwoFactorActivationCodeMismatch：Steam令牌不匹配/过期",
}

STEAM_SETTOKEN_MAP = {
    1: "OK：登录态转移成功，应该种下 steamLoginSecure",
    8: "InvalidParam：登录态转移失败，通常是缺 steamID 或 transfer nonce/auth 不匹配",
}


class HealUpRequired(RuntimeError):
    def __init__(self, url: str):
        super().__init__(f"KRAFTON 账号需要补全/绑定资料: {url}")
        self.url = url


class OidcEmailLoginRequired(RuntimeError):
    def __init__(self, url: str):
        super().__init__(f"KRAFTON OIDC 需要邮箱密码登录: {url}")
        self.url = url


class EmailMfaRequired(RuntimeError):
    def __init__(self, url: str):
        super().__init__(f"KRAFTON OIDC 需要邮箱验证码: {url}")
        self.url = url


class ConfirmEmailRequired(RuntimeError):
    def __init__(self, url: str):
        super().__init__(f"KRAFTON 账号需要邮箱激活验证码: {url}")
        self.url = url


class SmsSetupRequired(RuntimeError):
    def __init__(self, url: str):
        super().__init__(f"KRAFTON OIDC 需要手机号设置/可跳过: {url}")
        self.url = url


class PersonalInfoRequired(RuntimeError):
    def __init__(self, url: str):
        super().__init__(f"KRAFTON OIDC 需要补国家/生日信息: {url}")
        self.url = url


class SteamGuardRequired(RuntimeError):
    """The account requires a Steam token before OAuth can continue."""

def steam_result_message(eresult: Any, body: Any = None) -> str:
    code = "" if eresult is None else str(eresult)
    msg = STEAM_ERESULT_MAP.get(code, f"未知 Steam EResult={code or 'None'}")
    ext = ""
    try:
        resp = unwrap_response(body) if body is not None else {}
        ext = str(resp.get("extended_error_message") or resp.get("error_message") or resp.get("message") or "")
    except Exception:
        ext = ""
    return msg + (f"；服务端信息={ext}" if ext else "")


def settoken_result_message(body: Any) -> str:
    result = None
    if isinstance(body, dict):
        result = body.get("result")
    try:
        key = int(result)
    except Exception:
        key = result
    return STEAM_SETTOKEN_MAP.get(key, f"未知 settoken result={result}")


def save_json(path: Path, data: Any) -> None:
    if PORTAL_NO_PERSIST.get():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def try_json(r: requests.Response) -> Any:
    try:
        return r.json()
    except Exception:
        return r.text[:4000]


def snap(r: requests.Response, include_body: bool = True) -> dict[str, Any]:
    d = {"ts": int(time.time()), "status_code": r.status_code, "url": r.url, "headers": dict(r.headers)}
    if include_body:
        d["body"] = try_json(r)
    return d


def redact(v: Any, keep: int = 10) -> Any:
    if isinstance(v, str) and len(v) > 40:
        return v[:keep] + "..." + v[-6:]
    return v


def summarize(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: (redact(v) if "token" in k.lower() or k.lower() in {"authorization", "nonce"} else summarize(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [summarize(x) for x in obj]
    return obj


def read_saved_steam_refresh_token() -> str:
    try:
        return STEAM_REFRESH_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def save_steam_refresh_token(token: str) -> None:
    if token and not PORTAL_NO_PERSIST.get():
        STEAM_REFRESH_FILE.parent.mkdir(parents=True, exist_ok=True)
        STEAM_REFRESH_FILE.write_text(token.strip(), encoding="utf-8")


def krafton_headers(referer: str | None = None, json_body: bool = True) -> dict[str, str]:
    h = {
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Origin": KRAFTON_BASE,
    }
    if json_body:
        h["Content-Type"] = "application/json"
    if referer:
        h["Referer"] = referer
    return h


def derive_krafton_password(seed: str) -> str:
    """前端密码规则：>=8，含字母/数字/特殊字符。邮箱密码不合规时派生一个 KRAFTON 密码。"""
    pwd = (seed or "").strip()
    if len(pwd) >= 8 and re.search(r"[A-Za-z]", pwd) and re.search(r"\d", pwd) and re.search(r"[^A-Za-z0-9]", pwd):
        return pwd
    base = pwd or secrets.token_urlsafe(8)
    return base + "!A1"


def valid_krafton_password(pwd: str) -> bool:
    return bool(
        pwd
        and len(pwd) >= 8
        and re.search(r"[A-Za-z]", pwd)
        and re.search(r"\d", pwd)
        and re.search(r"[^A-Za-z0-9]", pwd)
    )


def normalize_username(value: str, fallback_email: str) -> str:
    raw = (value or fallback_email.split("@", 1)[0] or "pubguser").strip()
    raw = re.sub(r"[^A-Za-z0-9]", "", raw)
    if len(raw) < 3:
        raw = "pubg" + raw
    if len(raw) > 24:
        raw = raw[:24]
    return raw


def fetch_mailbox(email_addr: str) -> dict[str, Any]:
    encoded = requests.utils.quote(email_addr, safe="")
    url = f"{MAILBOX_API}/{encoded}/1"
    r = requests.get(url, headers={"User-Agent": UA, "Accept": "application/json"}, timeout=15)
    body = try_json(r)
    save_json(ART / "heal_mailbox_fetch.json", {"request_url": url, **snap(r, include_body=False), "body": body})
    if r.status_code != 200 or not isinstance(body, dict):
        raise RuntimeError(f"mailbox fetch failed HTTP {r.status_code}: {str(body)[:300]}")
    return body


def extract_krafton_email_code(payload: dict[str, Any], after_ts: float = 0) -> str:
    candidates: list[tuple[str, str]] = []
    for item in payload.get("emails", []) if isinstance(payload, dict) else []:
        subject = str(item.get("subject") or "")
        sender = str(item.get("from") or item.get("sender") or "")
        date_s = str(item.get("date") or "")
        blob = "\n".join(
            str(item.get(k) or "")
            for k in ("subject", "text_body", "body", "html_body")
        )
        text = html.unescape(re.sub(r"<[^>]+>", " ", blob))
        # 优先 KRAFTON/KRAFTON ID 邮件；如果邮箱里只有新邮件，也允许兜底提取 6 位码。
        is_krafton = bool(re.search(r"krafton|accts\.krafton|account|verification|验证|驗證|认证|認證|激活", subject + sender + text, re.I))
        weight = 10 if is_krafton else 0
        # KRAFTON 邮件验证码可能是 6 位大写字母数字，也可能是 6 位纯字母，例如 VQHLNW。
        # 先从 HTML 的大标题/颜色区块附近提取，避免把 PLEASE/RIGHTS 等普通英文误判为验证码。
        html_blob = html.unescape(str(item.get("html_body") or item.get("body") or ""))
        for m in re.finditer(r">\s*([A-Z0-9]{6})\s*<", html_blob.upper()):
            code = m.group(1)
            start = max(0, m.start() - 200)
            end = min(len(html_blob), m.end() + 200)
            near = html_blob[start:end]
            if is_krafton and re.search(r"color\s*:\s*#?CC5329|font-size\s*:\s*30px|验证码|驗證碼|verification", near, re.I):
                candidates.append((f"99:{date_s}", code))
        # 兜底：非 KRAFTON 或普通文本中只接受“含数字”的 6 位码，防止英文单词误判。
        for m in re.finditer(r"(?<![A-Z0-9])([A-Z0-9]{6})(?![A-Z0-9])", text.upper()):
            code = m.group(1)
            if not is_krafton and not re.search(r"\d", code):
                continue
            if is_krafton and code in {"KRAFTON", "PLEASE", "RIGHTS"}:
                continue
            if not is_krafton and not re.search(r"\d", code):
                continue
            candidates.append((f"{weight}:{date_s}", code))
    candidates.sort(reverse=True)
    return candidates[0][1] if candidates else ""


def poll_krafton_email_code(email_addr: str, retries: int = 24, interval: float = 5.0) -> str:
    for i in range(1, retries + 1):
        payload = fetch_mailbox(email_addr)
        code = extract_krafton_email_code(payload)
        if code:
            print(f"[heal] mailbox code found try={i} code_len={len(code)}")
            return code
        print(f"[heal] mailbox no code try={i}/{retries}")
        time.sleep(interval)
    raise RuntimeError("KRAFTON email code not found in mailbox")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def rand_urlsafe(nbytes: int = 32) -> str:
    return b64url(secrets.token_bytes(nbytes))


def pkce_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def classify_steam_token(token: str) -> str:
    token = (token or "").strip().replace(" ", "")
    if len(token) == 5:
        return "mobile"
    if len(token) == 7:
        return "backup"
    return "unknown"


class SteamScopedSession(requests.Session):
    """Route Steam hosts through the supplied proxy; keep Krafton/KID direct."""

    STEAM_HOSTS = {
        "api.steampowered.com",
        "login.steampowered.com",
        "steamcommunity.com",
        "store.steampowered.com",
    }

    def __init__(self, proxy: str | None = None):
        super().__init__()
        self.steam_proxy = proxy
        self.trust_env = False

    def request(self, method, url, **kwargs):
        host = (urlparse(url).hostname or "").lower()
        if self.steam_proxy and (
            host in self.STEAM_HOSTS
            or host.endswith(".steampowered.com")
            or host.endswith(".steamcommunity.com")
        ):
            kwargs["proxies"] = {"http": self.steam_proxy, "https": self.steam_proxy}
        else:
            kwargs["proxies"] = {}
        return super().request(method, url, **kwargs)


def make_session(proxy: str | None = None) -> requests.Session:
    s = SteamScopedSession(proxy)
    s.headers.update({"User-Agent": UA, "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"})
    return s


def prewarm_akamai_like_pubg_cookie(s: requests.Session, proxy: str | None = None) -> str | None:
    """复用 pubg_cookie_getter_http.py 的 Akamai seed 逻辑：bootstrap -> login-main sensor -> 同步 _abck/bm_sz/ak_bmsc。"""
    if os.environ.get("PUBG_STEAM_PREWARM_AKAMAI", "1") != "1":
        return None
    try:
        sensor_browser = os.environ.get("PUBG_HTTP_SENSOR_BROWSER") or os.environ.get("KRAFTON_SENSOR_BROWSER") or "playwright"
        kid.SENSOR_BROWSER_BACKEND = sensor_browser
        r = kid.bootstrap(s)
        save_json(ART / "steam_akamai_bootstrap.json", {**snap(r, include_body=False), "body_text_len": len(r.text or "")})
        akamai_js_url = kid.discover_akamai_js(r.text)
        lang = os.environ.get("PUBG_HTTP_LOGIN_LANG", "zh_CN")
        login_url = f"{KRAFTON_BASE}/v2/{lang}/web/login-main"
        kid.prewarm_login_route(s)
        sensor = kid.collect_and_post_sensor(
            s,
            akamai_js_url,
            target_url=login_url,
            referer=login_url,
            label="steam_oidc_seed_prelogin",
            # Akamai/KRAFTON telemetry stays direct; only Steam hosts use the
            # proxy through SteamScopedSession.
            session_proxy=None,
            wait_ms=max(500, int(os.environ.get("PUBG_BROWSER_SEED_WAIT_MS", "2500"))),
            interact=True,
            sensor_backend=sensor_browser,
            sync_akamai_cookies=True,
        )
        info = {
            "akamai_js_url": akamai_js_url,
            "sensor_browser": sensor_browser,
            "sensor_len": len(sensor or ""),
            "cookies": {name: bool(s.cookies.get(name)) for name in ("_abck", "bm_sz", "ak_bmsc")},
            "_abck_len": len(s.cookies.get("_abck") or ""),
        }
        setattr(s, "_akamai_js_url", akamai_js_url)
        save_json(ART / "steam_akamai_seed.json", info)
        print(f"[akamai-seed] backend={sensor_browser} _abck_len={info['_abck_len']} bm_sz={info['cookies']['bm_sz']} ak_bmsc={info['cookies']['ak_bmsc']}")
        return akamai_js_url
    except Exception as e:
        print(f"[akamai-seed] failed: {type(e).__name__}: {e}")
        return None


def unwrap_response(body: Any) -> dict[str, Any]:
    if isinstance(body, dict) and isinstance(body.get("response"), dict):
        return body["response"]
    if isinstance(body, dict):
        return body
    raise RuntimeError(f"Unexpected response: {str(body)[:300]}")


def post_steam_api(s: requests.Session, method: str, payload: dict[str, Any], referer: str | None = None) -> dict[str, Any]:
    url = f"{STEAM_API}/{method}/v1/"
    headers = {
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Origin": "https://steamcommunity.com",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    }
    if referer:
        headers["Referer"] = referer
    r = s.post(url, headers=headers, data={"input_json": json.dumps(payload, separators=(",", ":"))}, timeout=30)
    body = try_json(r)
    if isinstance(body, dict):
        body.setdefault("_headers", {})
        body["_headers"].update({"X-eresult": r.headers.get("X-eresult"), "X-error_message": r.headers.get("X-error_message")})
    save_json(ART / f"steam_{method}.json", {**snap(r, include_body=False), "body": body})
    er = r.headers.get("X-eresult")
    if er and er != "1":
        print(f"[steam.error] {method} X-eresult={er} {steam_result_message(er, body)}")
    if r.status_code != 200:
        raise RuntimeError(f"Steam {method} HTTP {r.status_code}: {steam_result_message(er, body)} raw={str(body)[:800]}")
    return body if isinstance(body, dict) else {"raw": body}


def get_rsa_and_encrypt(s: requests.Session, account_name: str, password: str) -> tuple[str, str]:
    r = s.get(f"{STEAM_API}/GetPasswordRSAPublicKey/v1/", params={"account_name": account_name}, headers={"User-Agent": UA, "Accept": "application/json"}, timeout=30)
    body = unwrap_response(try_json(r))
    save_json(ART / "steam_GetPasswordRSAPublicKey.json", snap(r))
    mod = body.get("publickey_mod") or body.get("public_key_mod")
    exp = body.get("publickey_exp") or body.get("public_key_exp")
    ts = str(body.get("timestamp") or body.get("encryption_timestamp") or "")
    if not mod or not exp or not ts:
        raise RuntimeError(f"Steam RSA key missing fields: {body}")
    key = RSA.construct((int(str(mod), 16), int(str(exp), 16)))
    enc = PKCS1_v1_5.new(key).encrypt(password.encode("utf-8"))
    return base64.b64encode(enc).decode("ascii"), ts


def begin_auth(s: requests.Session, account_name: str, password: str, referer: str, platform_type: int = DEFAULT_STEAM_PLATFORM_TYPE) -> dict[str, Any]:
    encrypted, ts = get_rsa_and_encrypt(s, account_name, password)
    payload = {
        "device_friendly_name": UA,
        "account_name": account_name,
        "encrypted_password": encrypted,
        "encryption_timestamp": ts,
        "remember_login": True,
        "platform_type": int(platform_type),
        "persistence": 1,
        "website_id": "Community",
        "device_details": {"device_friendly_name": UA, "platform_type": int(platform_type)},
        "guard_data": "",
        "language": 6,
        "qos_level": 2,
    }
    body = post_steam_api(s, "BeginAuthSessionViaCredentials", payload, referer=referer)
    resp = unwrap_response(body)
    if not resp.get("client_id") or not resp.get("request_id"):
        er = (body.get("_headers") or {}).get("X-eresult")
        raise RuntimeError(f"BeginAuthSessionViaCredentials failed: {steam_result_message(er, body)} response={resp} headers={body.get('_headers')}")
    return resp


def update_guard(s: requests.Session, auth: dict[str, Any], code: str, guard_type: str = "") -> None:
    steamid = str(auth.get("steamid") or auth.get("steam_id") or "")
    client_id = str(auth.get("client_id") or "")
    if not steamid or not client_id:
        raise RuntimeError(f"auth missing steamid/client_id: {auth}")
    # Steam 邮箱验证码为 code_type=2；手机令牌为 3。备用码保留原有兼容重试。
    types = [2] if guard_type == "email" else ([3] if len(code) == 5 else [2, 3])
    last = None
    for code_type in types:
        body = post_steam_api(s, "UpdateAuthSessionWithSteamGuardCode", {"client_id": client_id, "steamid": steamid, "code": code, "code_type": code_type}, referer=STEAM_COMMUNITY)
        resp = unwrap_response(body)
        last = {"resp": resp, "headers": body.get("_headers"), "code_type": code_type}
        if not resp.get("extended_error_message") and not resp.get("error") and (body.get("_headers", {}).get("X-eresult") in (None, "1")):
            return
    er = ((last or {}).get("headers") or {}).get("X-eresult")
    raise RuntimeError(f"Steam令牌校验失败: {steam_result_message(er, (last or {}).get('resp'))} detail={last}")


def poll_auth(s: requests.Session, auth: dict[str, Any], max_wait: int = 60) -> dict[str, Any]:
    client_id = str(auth.get("client_id") or "")
    request_id = str(auth.get("request_id") or "")
    interval = float(auth.get("interval") or 2)
    deadline = time.time() + max_wait
    last = None
    while time.time() < deadline:
        body = post_steam_api(s, "PollAuthSessionStatus", {"client_id": client_id, "request_id": request_id}, referer=STEAM_COMMUNITY)
        resp = unwrap_response(body)
        last = resp
        if resp.get("refresh_token") or resp.get("access_token"):
            return resp
        time.sleep(max(1.0, interval))
    raise RuntimeError(f"PollAuthSessionStatus timeout last={last}")


def steam_finalize_login(s: requests.Session, poll: dict[str, Any], oauth_url: str) -> dict[str, Any]:
    nonce = poll.get("refresh_token") or poll.get("access_token")
    if not nonce:
        raise RuntimeError(f"poll missing token: {poll}")
    s.get(STEAM_COMMUNITY + "/login/home/", headers={"User-Agent": UA}, timeout=30)
    sessionid = s.cookies.get("sessionid") or secrets.token_hex(12)
    r = s.post(f"{STEAM_LOGIN}/jwt/finalizelogin", headers={"User-Agent": UA, "Origin": STEAM_COMMUNITY, "Referer": oauth_url}, data={"nonce": nonce, "sessionid": sessionid, "redir": oauth_url}, timeout=30)
    body = unwrap_response(try_json(r))
    save_json(ART / "steam_jwt_finalizelogin.json", snap(r))
    steam_id = str(body.get("steamID") or body.get("steamid") or "")
    for idx, t in enumerate(body.get("transfer_info") or []):
        url, params = t.get("url"), dict(t.get("params") or {})
        if url:
            # Steam transfer endpoint /login/settoken 需要把 finalizelogin 返回的 steamID
            # 一起提交；只提交 nonce/auth 会返回 {"result":8}，不会种下
            # steamLoginSecure，后续 /oauth/login 会继续跳回 loginform。
            if steam_id:
                params.setdefault("steamID", steam_id)
            rr = s.post(
                url,
                headers={
                    "User-Agent": UA,
                    "Origin": STEAM_LOGIN,
                    "Referer": f"{STEAM_LOGIN}/",
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                },
                data=params,
                timeout=30,
                allow_redirects=False,
            )
            save_json(ART / f"steam_transfer_{idx}.json", snap(rr))
            tb = try_json(rr)
            print(f"[steam] transfer {idx} -> HTTP {rr.status_code} {settoken_result_message(tb)} body={str(tb)[:120]}")
    return body


def build_pubg_oidc_start(s: requests.Session, redirect_uri: str, prompt: str | None = "consent") -> dict[str, Any]:
    disc = pubg.get_discovery(s)
    auth_ep = disc.get("authorization_endpoint") or "https://accounts.krafton.com/oidc/auth"
    token_ep = disc.get("token_endpoint") or "https://accounts.krafton.com/oidc/token"
    code_verifier = rand_urlsafe(48)
    state = rand_urlsafe(18)
    nonce = rand_urlsafe(18)
    q = {
        "client_id": pubg.PUBG_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": pubg.PUBG_SCOPE,
        "state": state,
        "nonce": nonce,
        "code_challenge": pkce_challenge(code_verifier),
        "code_challenge_method": "S256",
    }
    if prompt:
        q["prompt"] = prompt
    return {"token_ep": token_ep, "start_url": auth_ep + "?" + urlencode(q), "state": state, "code_verifier": code_verifier, "redirect_uri": redirect_uri}


def get_steam_oauth_url_from_krafton(s: requests.Session, oidc: dict[str, Any]) -> str:
    url = oidc["start_url"]
    trace = []
    for step in range(1, 15):
        r = s.get(url, headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}, timeout=30, allow_redirects=False)
        trace.append(snap(r, include_body=False))
        print(f"[krafton] step={step} HTTP {r.status_code} {url}")
        loc = r.headers.get("Location")
        if r.status_code in (301, 302, 303, 307, 308) and loc:
            url = urljoin(url, loc)
            continue
        break
    r = s.get(f"{KRAFTON_BASE}/oidc/social/steam", headers={"User-Agent": UA, "Referer": f"{KRAFTON_BASE}/v2/zh_CN/login-main"}, timeout=30, allow_redirects=False)
    trace.append(snap(r, include_body=False))
    save_json(ART / "krafton_to_steam_trace.json", trace)
    if r.status_code not in (301, 302) or not r.headers.get("Location"):
        raise RuntimeError(f"/oidc/social/steam did not redirect: HTTP {r.status_code} {try_json(r)}")
    steam_url = urljoin(r.url, r.headers["Location"])
    print(f"[krafton] steam oauth url={steam_url}")
    return steam_url


def follow_oauth_for_code(s: requests.Session, steam_oauth_url: str, expected_state: str) -> str:
    url = steam_oauth_url
    trace = []
    for step in range(1, 30):
        parsed_current = urlparse(url)
        if parsed_current.netloc.endswith("accounts.krafton.com") and parsed_current.path == "/auth/steam/callback" and parsed_current.fragment:
            fq = parse_qs(parsed_current.fragment)
            if fq.get("access_token") and fq.get("state") and fq.get("steamid"):
                url = (
                    f"{KRAFTON_BASE}/auth/steam/token?"
                    + urlencode(
                        {
                            "access_token": fq["access_token"][0],
                            "state": fq["state"][0],
                            "steamid": fq["steamid"][0],
                        }
                    )
                )
                print("[krafton] emulate callback JS -> /auth/steam/token")
        r = s.get(url, headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}, timeout=30, allow_redirects=False)
        trace.append(snap(r, include_body=False))
        print(f"[oauth] step={step} HTTP {r.status_code} {url}")
        loc = r.headers.get("Location")
        if r.status_code in (301, 302, 303, 307, 308) and loc:
            url = urljoin(url, loc)
            q = parse_qs(urlparse(url).query)
            if q.get("code"):
                if (q.get("state") or [""])[0] != expected_state:
                    raise RuntimeError("KRAFTON state mismatch")
                save_json(ART / "steam_oauth_krafton_follow_trace.json", trace)
                return q["code"][0]
            frag = parse_qs(urlparse(url).fragment)
            if frag.get("access_token") and frag.get("state") and frag.get("steamid"):
                # 浏览器会先打开 /auth/steam/callback#...，然后 callback HTML 的 JS
                # 再跳 /auth/steam/token?...；HTTP 里需要手动模拟。
                continue
            continue
        text = r.text
        save_json(ART / f"steam_oauth_200_step_{step}.json", {**snap(r, include_body=False), "body": text})
        if "heal-up-game-platform" in r.url or "HealUpGamePlatform" in text or "account.submit-required-info" in text:
            save_json(ART / "heal_up_required.json", {"url": r.url, "step": step})
            save_json(ART / "steam_oauth_krafton_follow_trace.json", trace)
            raise HealUpRequired(r.url)
        path_l = urlparse(r.url).path.lower()
        text_l = text[:200000].lower()
        if "/login-email" in path_l and getattr(s, "_krafton_after_healup_needs_confirm_email", False):
            save_json(ART / "confirm_email_required_after_healup.json", {"url": r.url, "step": step})
            save_json(ART / "steam_oauth_krafton_follow_trace.json", trace)
            raise ConfirmEmailRequired(r.url)
        if (
            "/login-email" in path_l
            and ("电子邮箱验证" in text or "验证码" in text or "verify" in text_l)
        ):
            save_json(ART / "confirm_email_required.json", {"url": r.url, "step": step})
            save_json(ART / "steam_oauth_krafton_follow_trace.json", trace)
            raise ConfirmEmailRequired(r.url)
        if "/login-email" in path_l:
            save_json(ART / "oidc_email_login_required.json", {"url": r.url, "step": step})
            save_json(ART / "steam_oauth_krafton_follow_trace.json", trace)
            raise OidcEmailLoginRequired(r.url)
        if "/personal-info-input" in path_l:
            save_json(ART / "personal_info_required.json", {"url": r.url, "step": step})
            save_json(ART / "steam_oauth_krafton_follow_trace.json", trace)
            raise PersonalInfoRequired(r.url)
        if (
            "/authentication" in path_l
            or "/login-email-code" in path_l
            or "/login-mfa" in path_l
            or "request-email-code" in text_l
            or "verify-email-code" in text_l
        ):
            save_json(ART / "email_mfa_required.json", {"url": r.url, "step": step})
            save_json(ART / "steam_oauth_krafton_follow_trace.json", trace)
            raise EmailMfaRequired(r.url)
        if (
            "/sms" in path_l
            or "skip-setup" in text_l
            or "phone-number" in text_l
            or "bind phone" in text_l
            or "mobile" in path_l
        ):
            save_json(ART / "sms_setup_required.json", {"url": r.url, "step": step})
            save_json(ART / "steam_oauth_krafton_follow_trace.json", trace)
            raise SmsSetupRequired(r.url)
        m = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', text, re.I)
        if m:
            form_url = urljoin(r.url, m.group(1))
            fields = extract_form_fields(text)
            if form_url.endswith("/oauth/auth_response"):
                fields["response"] = "allow"
            print(f"[oauth] submit form {form_url} fields={sorted(fields.keys())}")
            rr = s.post(form_url, headers={"User-Agent": UA, "Referer": r.url}, data=fields, timeout=30, allow_redirects=False)
            save_json(ART / f"steam_oauth_form_post_step_{step}.json", {**snap(rr, include_body=False), "body": rr.text})
            trace.append(snap(rr, include_body=False))
            print(f"[oauth] form result HTTP {rr.status_code} loc={rr.headers.get('Location')}")
            if rr.headers.get("Location"):
                url = urljoin(form_url, rr.headers["Location"])
                q = parse_qs(urlparse(url).query)
                if q.get("code"):
                    save_json(ART / "steam_oauth_krafton_follow_trace.json", trace)
                    return q["code"][0]
                continue
            # Steam 第一次 POST /oauth/auth 后常返回第二个“允许”表单。
            # 这里直接把返回 HTML 作为下一轮输入继续处理。
            if rr.status_code == 200 and re.search(r'<form[^>]+action=["\']([^"\']+)["\']', rr.text, re.I):
                text2 = rr.text
                m2 = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', text2, re.I)
                form_url2 = urljoin(rr.url, m2.group(1))
                fields2 = extract_form_fields(text2)
                if form_url2.endswith("/oauth/auth_response"):
                    fields2["response"] = "allow"
                print(f"[oauth] submit form2 {form_url2} fields={sorted(fields2.keys())}")
                rr2 = s.post(form_url2, headers={"User-Agent": UA, "Referer": rr.url}, data=fields2, timeout=30, allow_redirects=False)
                save_json(ART / f"steam_oauth_form2_post_step_{step}.json", {**snap(rr2, include_body=False), "body": rr2.text})
                trace.append(snap(rr2, include_body=False))
                print(f"[oauth] form2 result HTTP {rr2.status_code} loc={rr2.headers.get('Location')}")
                if rr2.headers.get("Location"):
                    url = urljoin(form_url2, rr2.headers["Location"])
                    q = parse_qs(urlparse(url).query)
                    if q.get("code"):
                        save_json(ART / "steam_oauth_krafton_follow_trace.json", trace)
                        return q["code"][0]
                    frag = parse_qs(urlparse(url).fragment)
                    if frag.get("access_token") and frag.get("state") and frag.get("steamid"):
                        continue
                    continue
        break
    save_json(ART / "steam_oauth_krafton_follow_trace.json", trace)
    raise RuntimeError(f"OIDC code not found, last_url={url}")


def request_and_confirm_heal_email(s: requests.Session, email_addr: str, referer: str) -> None:
    """无邮箱 profile 需要先过前端 ModalEmailValidation：发送邮箱码 -> 邮箱 API 取码 -> 确认。"""
    print(f"[heal] request email verification -> {email_addr}")
    payloads = [
        ("profile_resend", f"{KRAFTON_BASE}/profile/resend", {"email": email_addr, "activationVersion": "v2"}),
        ("profile_v1_resend", f"{KRAFTON_BASE}/profile/v1/resend", {"email": email_addr, "activationVersion": "v2"}),
    ]
    last_body: Any = None
    sent = False
    for name, url, payload in payloads:
        r = s.post(url, headers=krafton_headers(referer), json=payload, timeout=30, allow_redirects=False)
        last_body = try_json(r)
        save_json(ART / f"heal_email_{name}.json", {**snap(r, include_body=False), "body": last_body})
        print(f"[heal] {name} HTTP {r.status_code}")
        if r.status_code in (200, 201, 204):
            sent = True
            break
    if not sent:
        raise RuntimeError(f"email verification request failed: {str(last_body)[:800]}")
    code = poll_krafton_email_code(email_addr)
    for name, url in [
        ("profile_v1_confirm_email", f"{KRAFTON_BASE}/profile/v1/confirm/email"),
        ("profile_confirm_email", f"{KRAFTON_BASE}/profile/confirm/email"),
    ]:
        r = s.post(url, headers=krafton_headers(referer), json={"code": code, "activationVersion": "v2"}, timeout=30, allow_redirects=False)
        body = try_json(r)
        save_json(ART / f"heal_email_{name}.json", {**snap(r, include_body=False), "body": body})
        print(f"[heal] {name} HTTP {r.status_code}")
        if r.status_code in (200, 201, 204):
            return
    raise RuntimeError("email verification confirm failed; see heal_email_* artifacts")


def perform_heal_up(
    s: requests.Session,
    heal_url: str,
    email_addr: str,
    email_password: str,
    username: str,
    krafton_password: str,
    inbox_url: str,
) -> str:
    """补全/绑定 KRAFTON 资料，返回后续 OIDC redirect URL。"""
    print(f"[heal] start url={heal_url}")
    r_page = s.get(heal_url, headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml"}, timeout=30)
    save_json(ART / "heal_page_get.json", snap(r_page, include_body=False))
    referer = r_page.url or heal_url

    for name, url in [
        ("oidc_init", f"{KRAFTON_BASE}/oidc/init"),
        ("settings_profile", f"{KRAFTON_BASE}/settings/profile"),
    ]:
        r = s.get(url, headers=krafton_headers(referer, json_body=False), timeout=30, allow_redirects=False)
        save_json(ART / f"heal_{name}.json", {**snap(r, include_body=False), "body": try_json(r)})
        print(f"[heal] GET {url} -> HTTP {r.status_code}")

    profile_path = ART / "heal_settings_profile.json"
    profile_body: Any = {}
    try:
        profile_body = json.loads(profile_path.read_text(encoding="utf-8")).get("body") or {}
    except Exception:
        pass
    prof = profile_body.get("value", {}).get("profile") if isinstance(profile_body, dict) else None
    prof = prof or (profile_body.get("profile") if isinstance(profile_body, dict) else {}) or {}
    has_email = bool(prof.get("email") or (prof.get("masked_email") and prof.get("masked_email") != "ERR"))
    if not has_email:
        # 前端 ModalEmailValidation 只是“确认这个邮箱是否正确”的弹窗：
        # chunk_190_4e20318.js 里 onClickModal() 只 closeModal() 后调用 onSuccess()
        # 不会先发验证码。真正的绑定/补全由 /profile/healup-v2 完成。
        print("[heal] profile has no email; browser modal only confirms email text, skip pre-email-code flow")
    else:
        print("[heal] profile already has email; skip email validation")

    kpwd = krafton_password or email_password
    if not valid_krafton_password(kpwd):
        kpwd = derive_krafton_password(kpwd)
        print("[heal] supplied KRAFTON password does not satisfy policy; derived password with suffix")
    uname = normalize_username(username, email_addr)
    payload = {
        "email_opt_in": False,
        "email": email_addr,
        "username": uname,
        "password": kpwd,
        "password_confirmation": kpwd,
        "tosAccepted": True,
        "dob": None,
        "country": "",
        "activationVersion": "v2",
        "type": "healup",
        "personal_ad_opt_in": False,
    }
    r = s.post(f"{KRAFTON_BASE}/profile/healup-v2", headers=krafton_headers(referer), json=payload, timeout=30, allow_redirects=False)
    body = try_json(r)
    save_json(ART / "heal_profile_healup_v2.json", {**snap(r, include_body=False), "body": body, "request_payload": {**payload, "password": "***", "password_confirmation": "***"}})
    print(f"[heal] POST /profile/healup-v2 -> HTTP {r.status_code}")
    if r.status_code not in (200, 201, 204):
        raise RuntimeError(f"healup-v2 failed HTTP {r.status_code}: {str(body)[:1000]}")
    # heal-up 提交成功后，前端下一步的 /login-email?email=... 是“邮箱激活验证码页”，
    # 不是普通邮箱密码登录页。给后续 follow_oauth_for_code 留一个明确状态，避免误 POST /oidc/local。
    setattr(s, "_krafton_after_healup_needs_confirm_email", True)

    redirect = ""
    if isinstance(body, dict):
        value = body.get("value") if isinstance(body.get("value"), dict) else {}
        redirect = str(body.get("redirect") or value.get("redirect") or body.get("url") or "")
    if not redirect:
        # 前端 SDK redirectOrSuccessResult 正常会给 redirect；如果没有，从刚才的 OIDC trace
        # 找 /oidc/auth/{interaction} 继续，避免回到 heal 页面死循环。
        try:
            trace = json.loads((ART / "steam_oauth_krafton_follow_trace.json").read_text(encoding="utf-8"))
            for item in reversed(trace):
                u = str(item.get("url") or "")
                if "/oidc/auth/" in u:
                    redirect = u
                    break
        except Exception:
            redirect = ""
    if not redirect:
        redirect = heal_url
    redirect = urljoin(KRAFTON_BASE, redirect)
    print(f"[heal.success] KRAFTON 资料补全提交成功 username={uname} inbox={inbox_url or '(api)'} next={redirect}")
    return redirect


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


def generate_sec_cpt_answers(sec_prefix: str, token: str, timestamp: int, nonce: str, difficulty: int, count: int) -> list[str]:
    """Akamai adaptive sec-cpt PoW：sha256(sec+timestamp+nonce+difficulty+answer) % difficulty == 0。"""
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


def discover_akamai_js(s: requests.Session, referer: str) -> str | None:
    try:
        r = s.get(KRAFTON_BASE + "/", headers={"User-Agent": UA, "Referer": referer}, timeout=30, allow_redirects=False)
        save_json(ART / "oidc_local_akamai_discover.json", {**snap(r, include_body=False), "body_text_len": len(r.text or "")})
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text or "", flags=re.I)
        for src in scripts:
            if src.startswith("/") and not src.startswith("/v2/"):
                return urljoin(KRAFTON_BASE, src)
            if src.startswith(KRAFTON_BASE) and "/v2/" not in src:
                return src
    except Exception as e:
        print(f"[sensor] discover Akamai JS error: {e}")
    return None


def session_cookies_for_playwright(s: requests.Session) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for c in s.cookies:
        rows.append({
            "name": c.name,
            "value": c.value,
            "domain": c.domain or "accounts.krafton.com",
            "path": c.path or "/",
            "secure": bool(c.secure),
            "httpOnly": "HttpOnly" in (getattr(c, "_rest", {}) or {}),
            **({"expires": int(c.expires)} if c.expires else {}),
        })
    return rows


def telemetry_to_sensor_data(telemetry: str) -> str:
    params = dict(parse_qsl(telemetry.replace("&&&", "&"), keep_blank_values=True))
    encoded = params.get("sensor_data")
    if not encoded:
        m = re.search(r"sensor_data=([^&]+)", telemetry)
        encoded = m.group(1) if m else None
    if not encoded:
        raise RuntimeError("telemetry missing sensor_data")
    encoded = encoded.replace(" ", "+")
    encoded += "=" * (-len(encoded) % 4)
    return base64.b64decode(encoded).decode("utf-8", "replace")


def browser_collect_challenge_sensor(
    target_url: str,
    cookies: list[dict[str, Any]],
    wait_ms: int = 2500,
    interact: bool = True,
) -> dict[str, Any]:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            ctx = browser.new_context(locale="zh-CN")
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
            data["cookies"] = ctx.cookies(KRAFTON_BASE)
            return data
        finally:
            browser.close()


def apply_akamai_browser_cookies(s: requests.Session, cookies: list[dict[str, Any]]) -> list[str]:
    # 只同步 bmak 主链路 cookie；不要同步 sec_cpt，否则当前 428 token 与 sec_cpt prefix 会失配。
    allowed = {"_abck", "bm_sz", "ak_bmsc"}
    changed: list[str] = []
    for c in cookies or []:
        name = c.get("name")
        value = c.get("value")
        if name in allowed and value:
            s.cookies.set(
                name,
                value,
                domain=c.get("domain") or ".krafton.com",
                path=c.get("path", "/"),
                secure=bool(c.get("secure", True)),
            )
            changed.append(name)
    return changed


def collect_and_post_challenge_sensor(
    s: requests.Session,
    akamai_js_url: str | None,
    target_url: str,
    referer: str,
    label: str,
) -> str | None:
    if not akamai_js_url:
        return None
    try:
        result = browser_collect_challenge_sensor(target_url, session_cookies_for_playwright(s), interact=True)
        save_json(ART / f"oidc_local_sensor_browser_{label}.json", {k: v for k, v in result.items() if k != "telemetry"})
        changed = apply_akamai_browser_cookies(s, result.get("cookies") or [])
        if changed:
            print(f"[sensor:{label}] synced browser cookies: {','.join(sorted(set(changed)))}")
        telemetry = result.get("telemetry")
        print(f"[sensor:{label}] url={result.get('url')} has_bmak={result.get('has_bmak')} telemetry_len={len(telemetry or '')}")
        if not telemetry:
            return None
        sensor_data = telemetry_to_sensor_data(telemetry)
        sd_type = ",".join(sensor_data.split(",")[:6])
        r = s.post(
            akamai_js_url,
            headers={
                "Content-Type": "text/plain;charset=UTF-8",
                "Accept": "*/*",
                "Origin": KRAFTON_BASE,
                "Referer": referer,
                "User-Agent": UA,
            },
            data=json.dumps({"sensor_data": sensor_data}, separators=(",", ":")),
            timeout=30,
            allow_redirects=False,
        )
        save_json(ART / f"oidc_local_sensor_post_{label}.json", {**snap(r, include_body=False), "sd_type": sd_type, "stage": sec_cpt_cookie_stage(s)})
        print(f"[sensor:{label}] POST -> HTTP {r.status_code}, sd_type={sd_type}, stage={sec_cpt_cookie_stage(s)}")
        return sensor_data
    except Exception as e:
        print(f"[sensor:{label}] error: {type(e).__name__}: {e}")
        return None


def apply_browser_cookies(s: requests.Session, cookies: list[dict[str, Any]]) -> None:
    for c in cookies or []:
        name = c.get("name")
        value = c.get("value")
        if name and value:
            s.cookies.set(name, value, domain=c.get("domain"), path=c.get("path", "/"))


def browser_solve_sec_cpt_challenge(
    s: requests.Session,
    challenge: dict[str, Any],
    branding_url: str,
    referer: str,
    max_rounds: int = 40,
) -> bool:
    """让同一个无头浏览器上下文执行 sensor + /_sec/verify，再把 sec_cpt 回灌到 requests。"""
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        print(f"[sec-cpt-browser] Playwright unavailable: {e}")
        return False

    ch = dict(challenge)
    try:
        original_sec_cpt = s.cookies.get("sec_cpt") or ""
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                ctx = browser.new_context(locale="zh-CN")
                ctx.add_cookies(session_cookies_for_playwright(s))
                page = ctx.new_page()
                page.goto(branding_url, wait_until="domcontentloaded", timeout=45000)
                page.wait_for_timeout(2500)
                if original_sec_cpt:
                    ctx.add_cookies([{
                        "name": "sec_cpt",
                        "value": original_sec_cpt,
                        "domain": "accounts.krafton.com",
                        "path": "/",
                        "secure": True,
                    }])
                try:
                    page.mouse.move(180, 220)
                    page.mouse.move(420, 360, steps=8)
                    page.mouse.wheel(0, 280)
                    page.keyboard.press("Tab")
                    page.wait_for_timeout(500)
                except Exception:
                    pass

                provider = ch.get("provider") or "adaptive"
                verify_endpoint = f"{KRAFTON_BASE}/_sec/verify?provider={provider}"
                for round_idx in range(1, max_rounds + 1):
                    token = ch.get("token")
                    timestamp = ch.get("timestamp")
                    nonce = ch.get("nonce")
                    difficulty = int(ch.get("difficulty") or 0)
                    count = int(ch.get("count") or 1)
                    if not token or not timestamp or not nonce or not difficulty:
                        break
                    cookies = ctx.cookies(KRAFTON_BASE)
                    sec_val = original_sec_cpt or next((c.get("value") for c in cookies if c.get("name") == "sec_cpt"), "")
                    if not sec_val or "~" not in sec_val:
                        print("[sec-cpt-browser] no sec_cpt in browser context")
                        return False
                    sec_prefix = sec_val.split("~", 1)[0]
                    stage = sec_val.split("~")[1] if len(sec_val.split("~")) > 1 else None
                    print(f"[sec-cpt-browser] round={round_idx} difficulty={difficulty} count={count} stage={stage}")
                    answers = generate_sec_cpt_answers(sec_prefix, str(token), int(timestamp), str(nonce), difficulty, count)
                    body = page.evaluate(
                        """async ({url, token, answers}) => {
                            const r = await fetch(url, {
                                method: "POST",
                                credentials: "include",
                                headers: {"content-type": "text/plain;charset=UTF-8", "accept": "*/*"},
                                body: JSON.stringify({token, answers})
                            });
                            const txt = await r.text();
                            let data = txt;
                            try { data = JSON.parse(txt); } catch(e) {}
                            return {status: r.status, data};
                        }""",
                        {"url": verify_endpoint, "token": token, "answers": answers},
                    )
                    save_json(ART / f"oidc_local_sec_cpt_browser_round_{round_idx}.json", body)
                    bdata = body.get("data") if isinstance(body, dict) else None
                    cookies = ctx.cookies(KRAFTON_BASE)
                    sec_val = next((c.get("value") for c in cookies if c.get("name") == "sec_cpt"), "")
                    stage = sec_val.split("~")[1] if sec_val and len(sec_val.split("~")) > 1 else None
                    print(f"[sec-cpt-browser] verify -> HTTP {body.get('status') if isinstance(body, dict) else '?'} stage={stage}")
                    if not isinstance(bdata, dict) or bdata.get("success") is not True:
                        return False
                    if not bdata.get("token"):
                        verify_url = str(bdata.get("verify_url") or ch.get("verify_url") or "")
                        if verify_url:
                            try:
                                page.goto(verify_url, wait_until="domcontentloaded", timeout=30000)
                                page.wait_for_timeout(1200)
                            except Exception:
                                page.evaluate("url => fetch(url, {credentials:'include'}).catch(()=>null)", verify_url)
                        final_cookies = ctx.cookies(KRAFTON_BASE)
                        apply_browser_cookies(s, final_cookies)
                        sec_final = next((c.get("value") for c in final_cookies if c.get("name") == "sec_cpt"), "")
                        stage_final = sec_final.split("~")[1] if sec_final and len(sec_final.split("~")) > 1 else None
                        print(f"[sec-cpt-browser] final stage={stage_final}")
                        return stage_final in ("2", "3")
                    ch.update({
                        "token": bdata.get("token"),
                        "timestamp": bdata.get("timestamp"),
                        "nonce": bdata.get("nonce"),
                        "difficulty": bdata.get("difficulty"),
                        "count": bdata.get("count") or count,
                        "verify_url": bdata.get("verify_url") or ch.get("verify_url"),
                    })
                apply_browser_cookies(s, ctx.cookies(KRAFTON_BASE))
                return sec_cpt_cookie_stage(s) in ("2", "3")
            finally:
                browser.close()
    except Exception as e:
        print(f"[sec-cpt-browser] error: {type(e).__name__}: {e}")
        return False


def solve_sec_cpt_challenge_simple(
    s: requests.Session,
    challenge: dict[str, Any],
    referer: str,
    max_rounds: int = 80,
    sleep_first: bool = True,
) -> bool:
    """处理 /oidc/local 返回的 428 sec-cp-challenge，然后让上层重试原请求。"""
    ch = dict(challenge)
    branding_url = str(ch.get("branding_cust_url") or f"{KRAFTON_BASE}/v2/challenge/bot_challenge.html")
    if branding_url.startswith("/"):
        branding_url = urljoin(KRAFTON_BASE, branding_url)

    try:
        print(f"[sec-cpt] GET branding {branding_url}")
        rb = s.get(branding_url, headers={"User-Agent": UA, "Referer": referer}, timeout=30, allow_redirects=False)
        save_json(ART / "oidc_local_428_sec_cpt_branding.json", {**snap(rb, include_body=False), "body_text_len": len(rb.text or "")})
        assets = re.findall(r'<(?:script|link)[^>]+(?:src|href)=["\']([^"\']+)["\']', rb.text or "", flags=re.I)
        for idx, src in enumerate(assets[:20], 1):
            u = urljoin(branding_url, src)
            if "/v2/challenge/" not in u and "/Uomd" not in u:
                continue
            try:
                ra = s.get(u, headers={"User-Agent": UA, "Referer": branding_url}, timeout=30, allow_redirects=False)
                print(f"[sec-cpt] asset {idx} -> HTTP {ra.status_code} {u}")
            except Exception as e:
                print(f"[sec-cpt] asset error {u}: {e}")
    except Exception as e:
        print(f"[sec-cpt] branding preflight error: {e}")

    if sleep_first:
        duration = int(ch.get("chlg_duration") or 0)
        if duration > 0:
            print(f"[sec-cpt] wait chlg_duration={duration}s")
            time.sleep(duration)

    if browser_solve_sec_cpt_challenge(s, ch, branding_url, referer):
        return True

    akamai_js_url = discover_akamai_js(s, referer)
    if akamai_js_url:
        print(f"[sensor] Akamai JS {akamai_js_url}")
        collect_and_post_challenge_sensor(s, akamai_js_url, branding_url, branding_url, "before_verify")

    provider = ch.get("provider") or "adaptive"
    verify_endpoint = f"{KRAFTON_BASE}/_sec/verify?provider={provider}"
    headers = {
        "Accept": "*/*",
        "Content-Type": "text/plain;charset=UTF-8",
        "Origin": KRAFTON_BASE,
        "Referer": branding_url,
        "User-Agent": UA,
    }

    for round_idx in range(1, max_rounds + 1):
        token = ch.get("token")
        timestamp = ch.get("timestamp")
        nonce = ch.get("nonce")
        difficulty = int(ch.get("difficulty") or 0)
        count = int(ch.get("count") or 1)
        if not token or not timestamp or not nonce or not difficulty:
            print(f"[sec-cpt] no next token round={round_idx}, stage={sec_cpt_cookie_stage(s)}")
            return sec_cpt_cookie_stage(s) in ("2", "3")

        sec_prefix = get_sec_cpt_prefix(s)
        print(f"[sec-cpt] round={round_idx} difficulty={difficulty} count={count} stage={sec_cpt_cookie_stage(s)}")
        answers = generate_sec_cpt_answers(sec_prefix, str(token), int(timestamp), str(nonce), difficulty, count)
        r = s.post(
            verify_endpoint,
            headers=headers,
            data=json.dumps({"token": token, "answers": answers}),
            timeout=60,
            allow_redirects=False,
        )
        body = try_json(r)
        save_json(ART / f"oidc_local_sec_cpt_round_{round_idx}.json", {**snap(r, include_body=False), "body": body, "stage": sec_cpt_cookie_stage(s)})
        print(f"[sec-cpt] verify -> HTTP {r.status_code}, stage={sec_cpt_cookie_stage(s)}")

        if round_idx in (3, 12, 24):
            collect_and_post_challenge_sensor(s, akamai_js_url, branding_url, branding_url, f"after_round_{round_idx}")

        if not isinstance(body, dict):
            print(f"[sec-cpt] unexpected response: {str(body)[:500]}")
            return False
        if body.get("success") is not True:
            print(f"[sec-cpt] server returned non-success: {body}")
            return False

        verify_url = str(body.get("verify_url") or ch.get("verify_url") or "")
        if not body.get("token"):
            if verify_url:
                try:
                    rv = s.get(verify_url, headers={"User-Agent": UA, "Referer": branding_url}, timeout=30, allow_redirects=False)
                    save_json(ART / "oidc_local_sec_cpt_verify_url.json", {**snap(rv, include_body=False), "stage": sec_cpt_cookie_stage(s)})
                    print(f"[sec-cpt] GET verify_url -> HTTP {rv.status_code}, stage={sec_cpt_cookie_stage(s)}")
                except Exception as e:
                    print(f"[sec-cpt] verify_url error: {e}")
            collect_and_post_challenge_sensor(s, akamai_js_url, branding_url, branding_url, "final")
            return True

        ch = {
            "provider": provider,
            "token": body.get("token"),
            "timestamp": body.get("timestamp"),
            "nonce": body.get("nonce"),
            "difficulty": body.get("difficulty"),
            "count": body.get("count") or count,
            "verify_url": verify_url,
        }

    print(f"[sec-cpt] max rounds reached, stage={sec_cpt_cookie_stage(s)}")
    return sec_cpt_cookie_stage(s) in ("2", "3")


def solve_oidc_sec_cpt_like_pubg_cookie(s: requests.Session, challenge: dict[str, Any], referer: str, sleep_first: bool = False) -> bool:
    """优先完全复用 pubg_cookie_getter_http.py 调用的 krafton_pure_http_login.solve_sec_cpt_challenge。"""
    akamai_js_url = getattr(s, "_akamai_js_url", None) or discover_akamai_js(s, referer)
    if akamai_js_url:
        setattr(s, "_akamai_js_url", akamai_js_url)
    sensor_browser = os.environ.get("PUBG_HTTP_SENSOR_BROWSER") or os.environ.get("KRAFTON_SENSOR_BROWSER") or "playwright"
    kid.SENSOR_BROWSER_BACKEND = sensor_browser
    rounds = int(os.environ.get("PUBG_HTTP_SEC_CPT_ROUNDS", "80"))
    no_sensor = os.environ.get("PUBG_HTTP_NO_SENSOR_INTERLEAVE", "0") == "1"
    print(f"[sec-cpt] use pubg_cookie logic akamai_js={akamai_js_url} sensor={sensor_browser} rounds={rounds}")
    try:
        return bool(kid.solve_sec_cpt_challenge(
            s,
            challenge,
            max_rounds=rounds,
            sleep_first=sleep_first,
            akamai_js_url=akamai_js_url,
            session_proxy=None,
            sensor_interleave=not no_sensor,
            sensor_backend=sensor_browser,
            bitbrowser_profile_id=os.environ.get("BITBROWSER_PROFILE_ID") or None,
            bitbrowser_profile_name=os.environ.get("BITBROWSER_PROFILE_NAME") or "PUBG_Worker_50",
        ))
    except Exception as e:
        print(f"[sec-cpt] pubg_cookie logic failed: {type(e).__name__}: {e}")
        return False


def oidc_email_login(s: requests.Session, login_url: str, email_addr: str, password: str) -> str:
    """处理 heal-up 后跳到 /login-email?email=... 的 OIDC 本地登录分支。"""
    referer = login_url
    kpwd = password
    payload = {
        "email": email_addr,
        "password": kpwd,
        "faction": "",
        "trusted_device": False,
        "activationVersion": "v2",
    }
    print(f"[krafton] OIDC email login -> {email_addr}")
    r = s.post(
        f"{KRAFTON_BASE}/oidc/local",
        headers=krafton_headers(referer),
        json=payload,
        timeout=30,
        allow_redirects=False,
    )
    body = try_json(r)
    save_json(
        ART / "oidc_email_login_post.json",
        {**snap(r, include_body=False), "body": body, "request_payload": {**payload, "password": "***"}},
    )
    print(f"[krafton] POST /oidc/local -> HTTP {r.status_code}")
    if r.status_code == 428 and isinstance(body, dict) and body.get("sec-cp-challenge") == "true":
        print("[krafton] /oidc/local 触发 sec-cp-challenge，按 pubg_cookie_getter_http.py 逻辑解 challenge")
        if solve_oidc_sec_cpt_like_pubg_cookie(s, body, referer=referer, sleep_first=False):
            r = s.post(
                f"{KRAFTON_BASE}/oidc/local",
                headers=krafton_headers(referer),
                json=payload,
                timeout=30,
                allow_redirects=False,
            )
            body = try_json(r)
            save_json(
                ART / "oidc_email_login_post_retry.json",
                {
                    **snap(r, include_body=False),
                    "body": body,
                    "request_payload": {**payload, "password": "***"},
                    "sec_cpt_stage": sec_cpt_cookie_stage(s),
                },
            )
            print(f"[krafton] retry POST /oidc/local -> HTTP {r.status_code}, sec_cpt_stage={sec_cpt_cookie_stage(s)}")
        else:
            print("[krafton] sec-cp-challenge 未解开，保留原 428 错误")

    # 有些边缘节点第一轮 PoW 只返回 {"success": true}，sec_cpt 仍停在 stage=1；
    # 下一次 /oidc/local 会给新的 428 token。这里按浏览器二段挑战节奏继续解几轮，
    # 直到 sec_cpt 进入 stage=2/3 或 /oidc/local 不再 428。
    for challenge_idx in range(2, 9):
        if not (r.status_code == 428 and isinstance(body, dict) and body.get("sec-cp-challenge") == "true"):
            break
        print(f"[krafton] /oidc/local 仍是 428，继续第 {challenge_idx} 次 sec-cp-challenge，stage={sec_cpt_cookie_stage(s)}")
        if not solve_oidc_sec_cpt_like_pubg_cookie(s, body, referer=referer, sleep_first=False):
            break
        r = s.post(
            f"{KRAFTON_BASE}/oidc/local",
            headers=krafton_headers(referer),
            json=payload,
            timeout=30,
            allow_redirects=False,
        )
        body = try_json(r)
        save_json(
            ART / f"oidc_email_login_post_retry_{challenge_idx}.json",
            {
                **snap(r, include_body=False),
                "body": body,
                "request_payload": {**payload, "password": "***"},
                "sec_cpt_stage": sec_cpt_cookie_stage(s),
            },
        )
        print(f"[krafton] retry#{challenge_idx} POST /oidc/local -> HTTP {r.status_code}, sec_cpt_stage={sec_cpt_cookie_stage(s)}")
    if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
        return urljoin(r.url, r.headers["Location"])
    if isinstance(body, dict):
        value = body.get("value") if isinstance(body.get("value"), dict) else {}
        redirect = str(body.get("redirect") or value.get("redirect") or body.get("url") or "")
        if redirect:
            return urljoin(KRAFTON_BASE, redirect)
    if r.status_code == 200:
        # 有些成功响应只更新 session；从最近 trace 里找 interaction complete 继续。
        try:
            trace = json.loads((ART / "steam_oauth_krafton_follow_trace.json").read_text(encoding="utf-8"))
            for item in reversed(trace):
                u = str(item.get("url") or "")
                if "/oidc/interaction/" in u and not u.endswith("/complete"):
                    return u.rstrip("/") + "/complete"
        except Exception:
            pass
    raise RuntimeError(f"OIDC email login failed HTTP {r.status_code}: {str(body)[:1000]}")


def last_interaction_complete_url(fallback_url: str = "") -> str:
    try:
        trace = json.loads((ART / "steam_oauth_krafton_follow_trace.json").read_text(encoding="utf-8"))
        for item in reversed(trace):
            u = str(item.get("url") or "")
            if "/oidc/interaction/" in u:
                if u.endswith("/complete"):
                    return u
                return u.rstrip("/") + "/complete"
            if "/oidc/auth/" in u:
                return u
    except Exception:
        pass
    return fallback_url


def complete_email_mfa(s: requests.Session, mfa_url: str, email_addr: str) -> str:
    """补全信息后 KRAFTON 要求的邮箱验证码：请求验证码 -> 邮箱 API 拉取 -> 校验。"""
    print(f"[krafton] request MFA email code -> {email_addr}")
    r = s.post(
        f"{KRAFTON_BASE}/auth/mfa/request-email-code",
        headers=krafton_headers(mfa_url),
        json={},
        timeout=30,
        allow_redirects=False,
    )
    body = try_json(r)
    save_json(ART / "oidc_mfa_request_email_code.json", {**snap(r, include_body=False), "body": body})
    print(f"[krafton] POST /auth/mfa/request-email-code -> HTTP {r.status_code}")
    if r.status_code not in (200, 201, 204):
        raise RuntimeError(f"MFA request email code failed HTTP {r.status_code}: {str(body)[:800]}")
    code = poll_krafton_email_code(email_addr, retries=24, interval=5.0)
    r2 = s.post(
        f"{KRAFTON_BASE}/auth/mfa/verify-email-code",
        headers=krafton_headers(mfa_url),
        json={"code": code, "rememberMe": False},
        timeout=30,
        allow_redirects=False,
    )
    body2 = try_json(r2)
    save_json(ART / "oidc_mfa_verify_email_code.json", {**snap(r2, include_body=False), "body": body2, "request_payload": {"code": "***", "rememberMe": False}})
    print(f"[krafton] POST /auth/mfa/verify-email-code -> HTTP {r2.status_code}")
    if r2.status_code in (301, 302, 303, 307, 308) and r2.headers.get("Location"):
        return urljoin(r2.url, r2.headers["Location"])
    if isinstance(body2, dict):
        value = body2.get("value") if isinstance(body2.get("value"), dict) else {}
        redirect = str(body2.get("redirect") or value.get("redirect") or body2.get("url") or "")
        if redirect:
            return urljoin(KRAFTON_BASE, redirect)
    if r2.status_code in (200, 201, 204):
        return last_interaction_complete_url(mfa_url)
    raise RuntimeError(f"MFA verify email code failed HTTP {r2.status_code}: {str(body2)[:1000]}")


def complete_confirm_email(s: requests.Session, confirm_url: str, email_addr: str) -> str:
    """heal-up 后的账号邮箱激活页：邮箱 API 取 6 位字母数字验证码，POST /profile/v1/confirm/email。"""
    print(f"[krafton] confirm account email -> {email_addr}")
    code = poll_krafton_email_code(email_addr, retries=24, interval=5.0)
    last_body: Any = None
    for name, endpoint in [
        ("profile_v1_confirm_email", "/profile/v1/confirm/email"),
        ("profile_confirm_email", "/profile/confirm/email"),
    ]:
        r = s.post(
            f"{KRAFTON_BASE}{endpoint}",
            headers=krafton_headers(confirm_url),
            json={"code": code, "activationVersion": "v2"},
            timeout=30,
            allow_redirects=False,
        )
        body = try_json(r)
        last_body = body
        save_json(ART / f"oidc_{name}.json", {**snap(r, include_body=False), "body": body, "request_payload": {"code": "***", "activationVersion": "v2"}})
        print(f"[krafton] POST {endpoint} -> HTTP {r.status_code}")
        if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
            setattr(s, "_krafton_after_healup_needs_confirm_email", False)
            return urljoin(r.url, r.headers["Location"])
        if isinstance(body, dict):
            value = body.get("value") if isinstance(body.get("value"), dict) else {}
            redirect = str(body.get("redirect") or value.get("redirect") or body.get("url") or "")
            if redirect:
                setattr(s, "_krafton_after_healup_needs_confirm_email", False)
                return urljoin(KRAFTON_BASE, redirect)
        if r.status_code in (200, 201, 204):
            # 激活成功后通常进入 sms-setup；没有 redirect 时继续当前 interaction。
            setattr(s, "_krafton_after_healup_needs_confirm_email", False)
            return last_interaction_complete_url(confirm_url)
    raise RuntimeError(f"confirm email failed: {str(last_body)[:1000]}")


def complete_personal_info(s: requests.Session, info_url: str, country: str, dob: str) -> str:
    """处理 /personal-info-input?type=healup&country=HK，只补国家/生日。"""
    q = parse_qs(urlparse(info_url).query)
    type_value = (q.get("type") or ["healup"])[0] or "healup"
    country_value = (q.get("country") or [country or DEFAULT_HEAL_COUNTRY])[0] or DEFAULT_HEAL_COUNTRY
    dob_value = dob or DEFAULT_HEAL_DOB
    try:
        dob_ms = int(calendar.timegm(time.strptime(dob_value, "%Y-%m-%d"))) * 1000
    except Exception:
        raise RuntimeError(f"invalid heal DOB format, expected YYYY-MM-DD: {dob_value}")
    payload = {
        "country": country_value,
        "dob": dob_ms,
        "type": type_value,
        "activationVersion": "v2",
    }
    print(f"[heal] complete personal-info country={country_value} dob={dob_value} type={type_value}")
    r = s.post(
        f"{KRAFTON_BASE}/profile/healup-v2",
        headers=krafton_headers(info_url),
        json=payload,
        timeout=30,
        allow_redirects=False,
    )
    body = try_json(r)
    save_json(ART / "heal_personal_info_healup_v2.json", {**snap(r, include_body=False), "body": body, "request_payload": payload})
    print(f"[heal] POST /profile/healup-v2 personal-info -> HTTP {r.status_code}")
    if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
        return urljoin(r.url, r.headers["Location"])
    if isinstance(body, dict):
        value = body.get("value") if isinstance(body.get("value"), dict) else {}
        redirect = str(body.get("redirect") or value.get("redirect") or body.get("url") or "")
        if redirect:
            return urljoin(KRAFTON_BASE, redirect)
    if r.status_code in (200, 201, 204):
        return last_interaction_complete_url(info_url)
    raise RuntimeError(f"personal-info healup failed HTTP {r.status_code}: {str(body)[:1000]}")


def skip_sms_setup(s: requests.Session, sms_url: str) -> str:
    """手机号绑定页可跳过：POST /auth/sms/skip-setup，再取 post-login redirect。"""
    print("[krafton] skip SMS setup")
    r = s.post(
        f"{KRAFTON_BASE}/auth/sms/skip-setup",
        headers=krafton_headers(sms_url),
        json={},
        timeout=30,
        allow_redirects=False,
    )
    body = try_json(r)
    save_json(ART / "oidc_sms_skip_setup.json", {**snap(r, include_body=False), "body": body})
    print(f"[krafton] POST /auth/sms/skip-setup -> HTTP {r.status_code}")
    if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
        return urljoin(r.url, r.headers["Location"])
    if isinstance(body, dict):
        value = body.get("value") if isinstance(body.get("value"), dict) else {}
        redirect = str(body.get("redirect") or value.get("redirect") or body.get("url") or "")
        if redirect:
            return urljoin(KRAFTON_BASE, redirect)
    # 前端还有 getPostLoginRedirect()，跳过后主动取一次。
    rr = s.get(f"{KRAFTON_BASE}/auth/post-login-redirect", headers=krafton_headers(sms_url, json_body=False), timeout=30, allow_redirects=False)
    body2 = try_json(rr)
    save_json(ART / "oidc_post_login_redirect.json", {**snap(rr, include_body=False), "body": body2})
    print(f"[krafton] GET /auth/post-login-redirect -> HTTP {rr.status_code}")
    if rr.status_code in (301, 302, 303, 307, 308) and rr.headers.get("Location"):
        return urljoin(rr.url, rr.headers["Location"])
    if isinstance(body2, dict):
        value = body2.get("value") if isinstance(body2.get("value"), dict) else {}
        redirect = str(body2.get("redirect") or value.get("redirect") or body2.get("url") or "")
        if redirect:
            return urljoin(KRAFTON_BASE, redirect)
    return last_interaction_complete_url(sms_url)


def follow_with_post_login_steps(
    s: requests.Session,
    start_url: str,
    state: str,
    email_addr: str,
    password: str,
    heal_country: str = DEFAULT_HEAL_COUNTRY,
    heal_dob: str = DEFAULT_HEAL_DOB,
) -> str:
    """跟随 OIDC，并自动处理 heal 后常见的 email-login/MFA/SMS-skip 分支。"""
    url = start_url
    for _ in range(6):
        try:
            return follow_oauth_for_code(s, url, state)
        except OidcEmailLoginRequired as le:
            if getattr(s, "_krafton_after_healup_needs_confirm_email", False):
                print("[krafton] /login-email 处于 heal-up 后激活阶段，改走邮箱验证码确认")
                url = complete_confirm_email(s, le.url, email_addr)
            else:
                url = oidc_email_login(s, le.url, email_addr, password)
        except ConfirmEmailRequired as ce:
            url = complete_confirm_email(s, ce.url, email_addr)
        except EmailMfaRequired as me:
            url = complete_email_mfa(s, me.url, email_addr)
        except SmsSetupRequired as se:
            url = skip_sms_setup(s, se.url)
        except PersonalInfoRequired as pe:
            url = complete_personal_info(s, pe.url, heal_country, heal_dob)
    raise RuntimeError(f"post-login step loop exceeded, last_url={url}")


def extract_form_fields(html_text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for inp in re.findall(r"<input[^>]+>", html_text, re.I):
        nm = re.search(r'name=["\']([^"\']+)["\']', inp, re.I)
        val = re.search(r'value=["\']([^"\']*)["\']', inp, re.I)
        if nm:
            fields[nm.group(1)] = val.group(1) if val else ""
    for btn in re.findall(r"<button[^>]+>", html_text, re.I):
        nm = re.search(r'name=["\']([^"\']+)["\']', btn, re.I)
        val = re.search(r'value=["\']([^"\']*)["\']', btn, re.I)
        if nm and nm.group(1) not in fields:
            fields[nm.group(1)] = val.group(1) if val else ""
    return fields


def extract_game_id_from_foc(foc: Any) -> str:
    """从 PUBG Selfservice signin 返回里提取游戏 ID/昵称。"""
    if not isinstance(foc, dict):
        return ""
    accounts = foc.get("accounts")
    if isinstance(accounts, list) and accounts:
        for acc in accounts:
            if isinstance(acc, dict) and str(acc.get("gameName") or "").lower() == "pubg":
                return str(acc.get("nickname") or acc.get("gppUserId") or "")
        acc0 = accounts[0] if isinstance(accounts[0], dict) else {}
        return str(acc0.get("nickname") or acc0.get("gppUserId") or "")
    return str(foc.get("globalNickname") or "")


def print_final_login_summary(
    steam_user: str,
    steam_password: str,
    heal_email: str,
    heal_username: str,
    heal_password: str,
    game_id: str,
) -> None:
    print("[summary] ================= 登录/注册信息 =================")
    print(f"[summary] Steam账号: {steam_user}")
    print(f"[summary] Steam密码: {steam_password}")
    print(f"[summary] 注册邮箱: {heal_email}")
    print(f"[summary] 注册用户名: {heal_username}")
    print(f"[summary] 注册密码: {heal_password}")
    print(f"[summary] 游戏ID: {game_id or '(未查询到)'}")
    print("[summary] =================================================")


def exchange_krafton_token(s: requests.Session, oidc: dict[str, Any], code: str) -> dict[str, Any]:
    r = s.post(oidc["token_ep"], headers={"User-Agent": UA, "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded", "Origin": "https://www.pubgselfservice.com", "Referer": oidc["redirect_uri"]}, data={"grant_type": "authorization_code", "code": code, "redirect_uri": oidc["redirect_uri"], "client_id": pubg.PUBG_CLIENT_ID, "code_verifier": oidc["code_verifier"]}, timeout=30, allow_redirects=False)
    body = try_json(r)
    save_json(ART / "krafton_oidc_token_response.json", snap(r))
    print(f"[krafton] token HTTP {r.status_code}")
    if r.status_code != 200 or not isinstance(body, dict) or not body.get("access_token"):
        raise RuntimeError(f"KRAFTON token exchange failed HTTP {r.status_code}: {str(body)[:800]}")
    return body


def login_steam_to_kid_session(
    steam_user: str,
    steam_password: str,
    steam_token: str = "",
    proxy: str | None = None,
    steam_guard_type: str = "",
) -> tuple[requests.Session, dict[str, Any]]:
    """Log Steam into its linked KRAFTON account and return its live session."""
    steam_user = str(steam_user or "").strip()
    steam_password = str(steam_password or "")
    guard = str(steam_token or "").strip().replace(" ", "")
    if not steam_user or not steam_password:
        raise ValueError("Steam 账号或密码为空")
    if guard and (steam_guard_type != "email" and classify_steam_token(guard) == "unknown"):
        raise ValueError("Steam令牌应为 5 位手机令牌或 7 位备用码")

    # Portal requests keep credentials and sessions in memory only. The
    # ContextVar is isolated per request, so concurrent users do not block.
    with portal_steam_request():
        with contextlib.redirect_stdout(io.StringIO()):
            session = make_session(proxy)
            oidc = build_pubg_oidc_start(session, pubg.PUBG_HOME, prompt="consent")
            steam_oauth_url = get_steam_oauth_url_from_krafton(session, oidc)
            login_page = session.get(steam_oauth_url, headers={"User-Agent": UA}, timeout=30, allow_redirects=True)
            auth = begin_auth(session, steam_user, steam_password, login_page.url)
            allowed = auth.get("allowed_confirmations") or []
            confirmation_types = {
                str(item.get("confirmation_type") if isinstance(item, dict) else item)
                for item in allowed
            }
            # 2=邮箱验证码，3=手机令牌；其他项不需要用户输入验证码。
            if not guard and confirmation_types.intersection({"2", "3"}):
                email_confirmation = "2" in confirmation_types and "3" not in confirmation_types
                raise SteamGuardRequired(
                    "Steam email code verification is required"
                    if email_confirmation else "Steam token verification is required"
                )
            if guard:
                update_guard(session, auth, guard, steam_guard_type)
            polled = poll_auth(session, auth)
            steam_finalize_login(session, polled, steam_oauth_url)
            follow_with_post_login_steps(session, steam_oauth_url, oidc["state"], "", "")
            return session, {"steamid": str(auth.get("steamid") or auth.get("steam_id") or "")}


@contextlib.contextmanager
def portal_steam_request():
    """门户二维码会话不落盘 HTTP 工件或认证令牌。"""
    token = PORTAL_NO_PERSIST.set(True)
    try:
        yield
    finally:
        PORTAL_NO_PERSIST.reset(token)


def begin_steam_qr_login(proxy: str | None = None) -> tuple[requests.Session, dict[str, Any]]:
    """创建 Steam 官方移动端确认二维码，并返回仅供服务端保存的会话状态。"""
    with portal_steam_request():
        session = make_session(proxy)
        oidc = build_pubg_oidc_start(session, pubg.PUBG_HOME, prompt="consent")
        steam_oauth_url = get_steam_oauth_url_from_krafton(session, oidc)
        # Mirror the browser's pre-QR context. Steam binds the QR challenge to
        # the OAuth login page/session cookies and its ajaxrefresh handshake.
        login_page = session.get(
            steam_oauth_url,
            headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
            timeout=30,
            allow_redirects=True,
        )
        if login_page.status_code != 200:
            raise RuntimeError(f"Steam OAuth login page failed HTTP {login_page.status_code}")
        ajaxrefresh = session.post(
            f"{STEAM_LOGIN}/jwt/ajaxrefresh",
            headers={
                "User-Agent": UA,
                "Origin": STEAM_COMMUNITY,
                "Referer": login_page.url,
                "Accept": "application/json, text/javascript, */*; q=0.01",
            },
            data={"redir": steam_oauth_url},
            timeout=30,
            allow_redirects=False,
        )
        if ajaxrefresh.status_code not in (200, 204):
            raise RuntimeError(f"Steam ajaxrefresh failed HTTP {ajaxrefresh.status_code}")
        payload = {
            "device_friendly_name": UA,
            "platform_type": DEFAULT_STEAM_PLATFORM_TYPE,
            "website_id": "Community",
            "device_details": {
                "device_friendly_name": UA,
                "platform_type": DEFAULT_STEAM_PLATFORM_TYPE,
            },
            "language": 6,
            "qos_level": 2,
        }
        response = unwrap_response(
            post_steam_api(session, "BeginAuthSessionViaQR", payload, referer=login_page.url)
        )
        if not response.get("client_id") or not response.get("request_id") or not response.get("challenge_url"):
            raise RuntimeError("Steam 二维码创建失败：未返回有效挑战地址")
        return session, {"auth": response, "oidc": oidc, "oauth_url": steam_oauth_url, "login_url": login_page.url}


def poll_steam_qr_login(session: requests.Session, state: dict[str, Any], complete_login: bool = True) -> dict[str, Any] | None:
    """轮询一次扫码会话；确认后可选择在当前请求或后台完成 KID 登录。"""
    auth = state["auth"]
    with portal_steam_request():
        body = post_steam_api(
            session,
            "PollAuthSessionStatus",
            {"client_id": str(auth["client_id"]), "request_id": str(auth["request_id"])},
            referer=state.get("login_url") or STEAM_COMMUNITY,
        )
        response = unwrap_response(body)
        response_headers = body.get("_headers") if isinstance(body, dict) else {}
        error_code = (
            response.get("error_code")
            or response.get("eresult")
            or (response_headers or {}).get("X-eresult")
        )
        error_message = (
            response.get("extended_error_message")
            or response.get("error_message")
            or response.get("error")
            or (response_headers or {}).get("X-error_message")
        )
        if error_code is not None and str(error_code).strip().lower() not in {"", "0", "1", "ok"}:
            raise RuntimeError(f"Steam QR login rejected EResult={error_code}: {error_message or 'remote confirmation denied'}")
        if error_message and not (response.get("refresh_token") or response.get("access_token")):
            raise RuntimeError(f"Steam QR login rejected: {error_message}")
        if not (response.get("refresh_token") or response.get("access_token")):
            return None
        if not complete_login:
            return {"poll_response": response}
        return complete_steam_qr_login(session, state, response)


def complete_steam_qr_login(session: requests.Session, state: dict[str, Any], poll_response: dict[str, Any]) -> dict[str, Any]:
    """完成 Steam 登录态转移和 KRAFTON OAuth。"""
    auth = state["auth"]
    with portal_steam_request():
        finalized = steam_finalize_login(session, poll_response, state["oauth_url"])
        follow_with_post_login_steps(session, state["oauth_url"], state["oidc"]["state"], "", "")
    steamid = (
        finalized.get("steamID")
        or finalized.get("steamid")
        or poll_response.get("steamid")
        or poll_response.get("steam_id")
        or auth.get("steamid")
        or auth.get("steam_id")
        or ""
    )
    return {"steamid": str(steamid)}


def main() -> int:
    ap = argparse.ArgumentParser(description="PUBG Selfservice Steam HTTP 登录获取 focToken")
    ap.add_argument("--steam-user", default=os.environ.get("STEAM_USER") or DEFAULT_STEAM_USER)
    ap.add_argument("--steam-password", default=os.environ.get("STEAM_PASSWORD") or DEFAULT_STEAM_PASSWORD)
    ap.add_argument("--steam-token", default=os.environ.get("STEAM_TOKEN") or DEFAULT_STEAM_TOKEN, help="自动判断：5位手机令牌，7位备用令牌")
    ap.add_argument("--steam-guard", default=os.environ.get("STEAM_GUARD"), help="兼容旧参数：5位手机令牌")
    ap.add_argument("--backup-code", default=os.environ.get("STEAM_BACKUP_CODE"), help="兼容旧参数：7位备用令牌/恢复码")
    ap.add_argument("--use-steam-refresh", action="store_true", default=os.environ.get("USE_STEAM_REFRESH", "").lower() in {"1", "true", "yes", "on"}, help="启用 Steam refresh_token 复用；默认关闭")
    ap.add_argument("--steam-refresh-token", default=os.environ.get("STEAM_REFRESH_TOKEN") or None, help="可选：指定 Steam refresh_token；仅在 --use-steam-refresh 时使用")
    ap.add_argument("--steam-refresh-file", default=str(STEAM_REFRESH_FILE), help="Steam refresh_token 缓存文件；仅在 --use-steam-refresh 时读取")
    ap.add_argument("--proxy", default=os.environ.get("HTTP_PROXY_URL") or DEFAULT_PROXY or None)
    ap.add_argument("--steam-platform-type", type=int, default=DEFAULT_STEAM_PLATFORM_TYPE, help="Steam platform_type，默认 3=WebBrowser")
    ap.add_argument("--redirect-uri", default=pubg.PUBG_HOME)
    ap.add_argument("--no-prompt-consent", action="store_true")
    ap.add_argument("--print-full-token", action="store_true", default=DEFAULT_PRINT_FULL_TOKEN)
    ap.add_argument("--no-heal", action="store_true", help="遇到 heal-up-game-platform 时不自动补全/绑定 KRAFTON 账号")
    ap.add_argument("--heal-email", default=os.environ.get("HEAL_EMAIL") or DEFAULT_HEAL_EMAIL)
    ap.add_argument("--heal-email-password", default=os.environ.get("HEAL_EMAIL_PASSWORD") or DEFAULT_HEAL_EMAIL_PASSWORD)
    ap.add_argument("--heal-username", default=os.environ.get("HEAL_USERNAME") or DEFAULT_HEAL_USERNAME)
    ap.add_argument("--heal-krafton-password", default=os.environ.get("HEAL_KRAFTON_PASSWORD") or DEFAULT_HEAL_KRAFTON_PASSWORD)
    ap.add_argument("--heal-inbox-url", default=os.environ.get("HEAL_INBOX_URL") or DEFAULT_HEAL_INBOX_URL)
    ap.add_argument("--heal-country", default=os.environ.get("HEAL_COUNTRY") or DEFAULT_HEAL_COUNTRY)
    ap.add_argument("--heal-dob", default=os.environ.get("HEAL_DOB") or DEFAULT_HEAL_DOB, help="生日，格式 YYYY-MM-DD，用于 personal-info-input")
    args = ap.parse_args()

    ART.mkdir(parents=True, exist_ok=True)
    if args.use_steam_refresh and not args.steam_refresh_token:
        try:
            args.steam_refresh_token = Path(args.steam_refresh_file).read_text(encoding="utf-8").strip()
        except Exception:
            args.steam_refresh_token = ""
    use_refresh = bool(args.use_steam_refresh and args.steam_refresh_token)
    if (not args.steam_user or not args.steam_password) and not use_refresh:
        raise SystemExit("缺少 Steam 账号密码：请修改脚本顶部 DEFAULT_STEAM_USER / DEFAULT_STEAM_PASSWORD，或传 --steam-user/--steam-password")
    guard = (args.steam_token or args.steam_guard or args.backup_code or "").strip().replace(" ", "")
    kind = classify_steam_token(guard)
    if use_refresh:
        print(f"[steam] reuse_refresh_token=True len={len(args.steam_refresh_token)}")
    elif guard:
        print(f"[steam] token_kind={kind} len={len(guard)}")
    else:
        print("[steam] token_kind=none len=0；按未绑定令牌账号流程尝试直接登录")
    s = make_session(args.proxy)
    result: dict[str, Any] = {"ts": int(time.time()), "status": "error"}
    try:
        prewarm_akamai_like_pubg_cookie(s, proxy=args.proxy)
        oidc = build_pubg_oidc_start(s, args.redirect_uri, prompt=None if args.no_prompt_consent else "consent")
        steam_oauth_url = get_steam_oauth_url_from_krafton(s, oidc)
        auth: dict[str, Any] = {}
        if use_refresh:
            polled = {"refresh_token": args.steam_refresh_token}
            print("[steam.success] 使用本地 Steam refresh_token，跳过 Guard")
        else:
            r0 = s.get(steam_oauth_url, headers={"User-Agent": UA}, timeout=30, allow_redirects=True)
            save_json(ART / "steam_oauth_loginform_initial.json", snap(r0, include_body=False))
            print(f"[steam] loginform HTTP {r0.status_code} url={r0.url}")
            auth = begin_auth(s, args.steam_user, args.steam_password, r0.url, platform_type=args.steam_platform_type)
            print(f"[steam.success] BeginAuthSessionViaCredentials 成功 steamid={auth.get('steamid')} client_id={auth.get('client_id')}")
            allowed = auth.get("allowed_confirmations") or []
            if guard:
                update_guard(s, auth, guard)
                print("[steam.success] Steam令牌校验成功")
            else:
                print(f"[steam] 未提供Steam令牌，直接 poll 登录状态；allowed_confirmations={allowed}")
            polled = poll_auth(s, auth)
            print(f"[steam.success] PollAuthSessionStatus 成功 access={bool(polled.get('access_token'))} refresh={bool(polled.get('refresh_token'))}")
            save_steam_refresh_token(str(polled.get("refresh_token") or ""))
        fin = steam_finalize_login(s, polled, steam_oauth_url)
        if not auth and (fin.get("steamID") or fin.get("steamid")):
            auth["steamid"] = fin.get("steamID") or fin.get("steamid")
        print(f"[steam.success] finalizelogin 成功 transfers={len(fin.get('transfer_info') or [])}")
        heal_password = args.heal_krafton_password or args.heal_email_password
        if not valid_krafton_password(heal_password):
            heal_password = derive_krafton_password(heal_password)
        try:
            code = follow_with_post_login_steps(s, steam_oauth_url, oidc["state"], args.heal_email, heal_password, args.heal_country, args.heal_dob)
        except HealUpRequired as h:
            if args.no_heal:
                raise
            if not args.heal_email:
                raise RuntimeError("需要补全 KRAFTON 账号，但未提供 --heal-email")
            next_url = perform_heal_up(
                s,
                h.url,
                args.heal_email,
                args.heal_email_password,
                args.heal_username,
                args.heal_krafton_password,
                args.heal_inbox_url,
            )
            code = follow_with_post_login_steps(s, next_url, oidc["state"], args.heal_email, heal_password, args.heal_country, args.heal_dob)
        print(f"[krafton.success] 获取 authorization code 成功 len={len(code)}")
        token = exchange_krafton_token(s, oidc, code)
        foc = pubg.foc_signin(s, token["access_token"])
        foc_token = str(foc.get("focToken") or "") if isinstance(foc, dict) else ""
        if not foc_token:
            raise RuntimeError(f"FOC missing focToken: {str(foc)[:500]}")
        game_id = extract_game_id_from_foc(foc)
        registered_username = normalize_username(args.heal_username, args.heal_email)
        login_summary = {
            "steam_user": args.steam_user,
            "steam_password": args.steam_password,
            "registered_email": args.heal_email,
            "registered_username": registered_username,
            "registered_password": heal_password,
            "game_id": game_id,
            "steamid": auth.get("steamid"),
        }
        result.update({
            "status": "success",
            "steamid": auth.get("steamid"),
            "access_token_len": len(token.get("access_token", "")),
            "focToken": foc_token,
            "foc": foc,
            "token_payload": token,
            "login_summary": login_summary,
        })
        save_json(OUT, result if args.print_full_token else summarize(result))
        print(f"[pubg.success] FOC signin 成功 focToken_len={len(foc_token)}")
        print_final_login_summary(
            args.steam_user,
            args.steam_password,
            args.heal_email,
            registered_username,
            heal_password,
            game_id,
        )
        if args.print_full_token:
            print(foc_token)
        print(f"[saved] {OUT}")
        return 0
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        save_json(OUT, summarize(result))
        print(f"[-] {result['error']}")
        print(f"[saved] {OUT}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
