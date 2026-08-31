#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PUBG Selfservice HTTP token 获取器。

链路：
  1) 复用 krafton_pure_http_login.py 跑通 accounts.krafton.com 登录态
  2) 走 pubgselfservice.com 配置的 KRAFTON OIDC Authorization Code + PKCE
  3) 用 kid access_token 调 api-foc.krafton.com/auth/kid/signin 换 focToken

注意：浏览器只在 KRAFTON Akamai sec-cpt sensor 阶段作为遥测生成器；OIDC/token/FOC 全部 requests HTTP。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import string
import sys
import time
from html import unescape
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse, parse_qs, urlunparse

import requests

from . import krafton_pure_http_login as kid

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts" / "pubgselfservice"
TOKEN_FILE = ART / "pubgselfservice_http_token.json"
OIDC_TRACE_FILE = ART / "pubgselfservice_oidc_trace.json"

PUBG_HOME = "https://www.pubgselfservice.com/home"
OIDC_DISCOVERY = "https://accounts.krafton.com/oidc/.well-known/openid-configuration"
PUBG_CLIENT_ID = "dfc653db-7761-4ff0-927c-3a13ec51fdfc"
PUBG_SCOPE = "openid gamelinks nickname offline_access"
FOC_SIGNIN = "https://api-foc.krafton.com/auth/kid/signin"


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def try_json(r: requests.Response) -> Any:
    try:
        return r.json()
    except Exception:
        return r.text[:12000]


def snap(r: requests.Response, include_body: bool = True) -> dict[str, Any]:
    out = {
        "ts": int(time.time()),
        "status_code": r.status_code,
        "reason": r.reason,
        "url": r.url,
        "headers": dict(r.headers),
    }
    if include_body:
        out["body"] = try_json(r)
    return out


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def rand_urlsafe(nbytes: int = 32) -> str:
    return b64url(secrets.token_bytes(nbytes))


def pkce_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def redact_token(v: Any, keep: int = 10) -> Any:
    if not isinstance(v, str) or len(v) < 30:
        return v
    return v[:keep] + "..." + v[-6:]


def token_summary(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: (redact_token(v) if "token" in k.lower() or k.lower() in {"authorization"} else token_summary(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [token_summary(x) for x in obj]
    return obj


def login_krafton_session(args: argparse.Namespace) -> tuple[requests.Session, str]:
    s = kid.make_session(load_saved=not args.no_saved_cookies, proxy=args.http_proxy)
    r0 = kid.bootstrap(s)
    print(f"[kid] bootstrap -> HTTP {r0.status_code}")
    akamai_js_url = args.akamai_js_url or kid.discover_akamai_js(r0.text)
    print(f"[kid] akamai_js={akamai_js_url}")

    # 如果已有 cookie 还有效，先直接验一下，省掉一次登录。
    rp = kid.profile(s)
    print(f"[kid] profile(pre) -> HTTP {rp.status_code}")
    if rp.status_code == 200:
        return s, akamai_js_url

    kid.prewarm_login_route(s)
    rl = kid.login(s, args.email, args.password, trusted=args.trusted)
    kid.print_short("auth/local", rl)

    if rl.status_code == 428:
        body = kid.try_json(rl)
        ok = kid.solve_sec_cpt_challenge(
            s,
            body,
            max_rounds=args.sec_cpt_rounds,
            sleep_first=not args.no_sec_cpt_wait,
            akamai_js_url=akamai_js_url,
            session_proxy=args.http_proxy,
            sensor_interleave=not args.no_sensor_interleave,
        )
        print(f"[kid] sec-cpt solved={ok} stage={kid.sec_cpt_cookie_stage(s)}")
        kid.prewarm_login_route(s)
        rl = kid.login(s, args.email, args.password, trusted=args.trusted)
        kid.print_short("auth/local(retry)", rl)

    if rl.status_code != 200:
        raise RuntimeError(f"KRAFTON login failed: HTTP {rl.status_code} {str(kid.try_json(rl))[:500]}")

    rp = kid.profile(s)
    kid.print_short("settings/profile", rp)
    if rp.status_code != 200:
        raise RuntimeError(f"KRAFTON profile check failed: HTTP {rp.status_code} {str(kid.try_json(rp))[:500]}")
    return s, akamai_js_url


def get_discovery(s: requests.Session) -> dict[str, Any]:
    r = s.get(OIDC_DISCOVERY, headers={"Accept": "application/json", "User-Agent": kid.UA}, timeout=30)
    save_json(ART / "oidc_discovery.json", snap(r))
    if r.status_code != 200:
        raise RuntimeError(f"OIDC discovery failed: HTTP {r.status_code}")
    return r.json()


def strip_fragment(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))


def extract_first_form(html: str, base_url: str) -> tuple[str, str, dict[str, str]] | None:
    m = re.search(r"<form\b([^>]*)>(.*?)</form>", html, re.I | re.S)
    if not m:
        return None
    attrs = m.group(1)
    inner = m.group(2)
    action_m = re.search(r"\baction\s*=\s*(['\"])(.*?)\1", attrs, re.I | re.S)
    method_m = re.search(r"\bmethod\s*=\s*(['\"])(.*?)\1", attrs, re.I | re.S)
    action = unescape(action_m.group(2)) if action_m else base_url
    method = (method_m.group(2) if method_m else "GET").upper()
    action = urljoin(base_url, action)
    fields: dict[str, str] = {}
    for im in re.finditer(r"<input\b([^>]*)>", inner, re.I | re.S):
        ia = im.group(1)
        nm = re.search(r"\bname\s*=\s*(['\"])(.*?)\1", ia, re.I | re.S)
        if not nm:
            continue
        vm = re.search(r"\bvalue\s*=\s*(['\"])(.*?)\1", ia, re.I | re.S)
        fields[unescape(nm.group(2))] = unescape(vm.group(2)) if vm else ""
    return method, action, fields


def get_last_login_info(s: requests.Session, referer: str) -> list[dict[str, Any]]:
    r = s.get(
        "https://accounts.krafton.com/profile/trusted-devices/last-login-info",
        headers={
            "User-Agent": kid.UA,
            "Accept": "application/json, text/plain, */*",
            "Referer": referer,
        },
        timeout=30,
        allow_redirects=False,
    )
    save_json(ART / "last_login_info.json", snap(r))
    print(f"[oidc] last-login-info -> HTTP {r.status_code}")
    body = try_json(r)
    if r.status_code != 200 or not isinstance(body, list):
        raise RuntimeError(f"last-login-info failed: HTTP {r.status_code} {str(body)[:500]}")
    return body


def oidc_login_confirm(
    s: requests.Session,
    args: argparse.Namespace,
    akamai_js_url: str,
    referer: str,
) -> str | None:
    """在 OIDC interaction 的 login-main 页面提交 /oidc/local。返回下一跳 URL 或 None。"""

    def post_oidc_local() -> requests.Response:
        headers = {
            "Origin": kid.BASE,
            "Referer": referer,
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "User-Agent": kid.UA,
        }
        payload = {
            "email": args.email,
            "password": args.password,
            "faction": "",
            "trusted_device": bool(args.trusted),
        }
        r = s.post(f"{kid.BASE}/oidc/local", headers=headers, json=payload, timeout=30, allow_redirects=False)
        save_json(ART / "oidc_local_login_response.json", kid.snapshot(r))
        kid.save_cookies(s)
        return r

    print("[oidc] login-main reached, submit /oidc/local inside OIDC interaction")
    rl = post_oidc_local()
    kid.print_short("oidc/local", rl)
    sec_cpt_attempts = 0
    while rl.status_code == 428:
        sec_cpt_attempts += 1
        body = kid.try_json(rl)
        ok = kid.solve_sec_cpt_challenge(
            s,
            body,
            max_rounds=args.sec_cpt_rounds,
            sleep_first=not args.no_sec_cpt_wait,
            akamai_js_url=akamai_js_url,
            session_proxy=args.http_proxy,
            sensor_interleave=not args.no_sensor_interleave,
        )
        print(f"[oidc] sec-cpt attempt={sec_cpt_attempts} solved={ok} stage={kid.sec_cpt_cookie_stage(s)}")
        rl = post_oidc_local()
        kid.print_short("oidc/local(retry)", rl)
        if rl.status_code == 428:
            print(f"[oidc] sec-cpt attempt={sec_cpt_attempts} still requires challenge; retrying")
    if rl.status_code != 200:
        raise RuntimeError(f"OIDC /oidc/local failed: HTTP {rl.status_code} {str(kid.try_json(rl))[:500]}")

    body = kid.try_json(rl)
    if isinstance(body, dict) and body.get("redirect"):
        return urljoin(referer, str(body["redirect"]))
    if rl.headers.get("Location"):
        return urljoin(rl.url, rl.headers["Location"])
    return None


def oidc_authorize_and_token(
    s: requests.Session,
    args: argparse.Namespace,
    akamai_js_url: str,
    redirect_uri: str,
    prompt: str | None = "consent",
) -> dict[str, Any]:
    discovery = get_discovery(s)
    auth_ep = discovery.get("authorization_endpoint") or "https://accounts.krafton.com/oidc/auth"
    token_ep = discovery.get("token_endpoint") or "https://accounts.krafton.com/oidc/token"

    code_verifier = rand_urlsafe(48)
    state = rand_urlsafe(24)
    nonce = rand_urlsafe(24)
    params = {
        "client_id": PUBG_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": PUBG_SCOPE,
        "state": state,
        "nonce": nonce,
        "code_challenge": pkce_challenge(code_verifier),
        "code_challenge_method": "S256",
    }
    if prompt:
        params["prompt"] = prompt

    start_url = auth_ep + "?" + urlencode(params)
    trace: list[dict[str, Any]] = []
    url = start_url
    method = "GET"
    data: dict[str, str] | None = None
    code = None
    returned_state = None

    for step in range(1, 25):
        headers = {
            "User-Agent": kid.UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Referer": PUBG_HOME if step == 1 else trace[-1].get("url", PUBG_HOME),
        }
        if method == "POST":
            r = s.post(url, data=data or {}, headers=headers, timeout=30, allow_redirects=False)
        else:
            r = s.get(url, headers=headers, timeout=30, allow_redirects=False)
        kid.save_cookies(s)
        item = snap(r, include_body=False)
        item["location"] = r.headers.get("Location")
        trace.append(item)
        print(f"[oidc] step={step} {method} -> HTTP {r.status_code} {r.url}")

        # redirect_uri 上出现 code/error 即终点。
        check_urls = [r.url]
        if r.headers.get("Location"):
            check_urls.append(urljoin(r.url, r.headers["Location"]))
        for cu in check_urls:
            p = urlparse(cu)
            q = parse_qs(p.query)
            if "code" in q:
                code = q["code"][0]
                returned_state = q.get("state", [None])[0]
                trace[-1]["terminal_code_url"] = strip_fragment(cu)
                break
            if "error" in q:
                raise RuntimeError(f"OIDC authorize error: {q}")
        if code:
            break

        if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
            url = urljoin(r.url, r.headers["Location"])
            method = "GET"
            data = None
            continue

        ctype = r.headers.get("Content-Type", "")
        if r.status_code == 200 and "text/html" in ctype:
            save_json(ART / f"oidc_html_step_{step}.json", {"url": r.url, "html": r.text[:50000]})
            # KRAFTON OIDC interaction 的 “继续使用上次账号” 是前端 JS：
            #   GET /profile/trusted-devices/last-login-info
            #   location.href = /oidc/selector/confirm?loginBy=...&email=...
            # 纯 HTTP 这里直接复现这两个动作。
            if "/last-login-account" in urlparse(r.url).path:
                infos = get_last_login_info(s, r.url)
                if not infos:
                    raise RuntimeError("last-login-account page has no account candidate")
                acc = infos[0]
                login_by = acc.get("loginBy") or "local"
                if login_by == "sms":
                    qs = urlencode({"loginBy": login_by, "phone": acc.get("phoneNumber") or ""})
                else:
                    qs = urlencode({"loginBy": login_by, "email": acc.get("email") or args.email})
                url = f"https://accounts.krafton.com/oidc/selector/confirm?{qs}"
                method = "GET"
                data = None
                print(f"[oidc] selector confirm -> {url}")
                continue

            # selector/confirm 后可能落到 login-main 要求再次确认密码；继续复用
            # 已跑通的 /auth/local + Akamai sec-cpt 解法。
            if "/login-main" in urlparse(r.url).path:
                next_url = oidc_login_confirm(s, args, akamai_js_url, r.url)
                if next_url:
                    # /auth/local 的通用成功返回经常是账号设置页；这只说明 KID
                    # 登录态已刷新，不是 OIDC 的 code 回跳。此时重新请求 authorize，
                    # 让 interaction 重新判定登录态。
                    if "/settings/" in urlparse(next_url).path:
                        url = start_url
                        method = "GET"
                        data = None
                        print("[oidc] KID login refreshed, restart authorize")
                        continue
                    url = next_url
                    method = "GET"
                    data = None
                    print(f"[oidc] after login redirect -> {url}")
                    continue
                # 没有显式下一跳时，重新打一次 authorize，interaction cookie 会决定后续分支。
                url = start_url
                method = "GET"
                data = None
                print("[oidc] after login no redirect, restart authorize")
                continue

            form = extract_first_form(r.text, r.url)
            if form:
                method, url, data = form
                print(f"[oidc] auto-submit form method={method} action={url} fields={list((data or {}).keys())}")
                continue
            raise RuntimeError(f"OIDC returned HTML without auto-submittable form, saved oidc_html_step_{step}.json")

        raise RuntimeError(f"OIDC unexpected response: HTTP {r.status_code} {r.url} {r.text[:300]}")

    save_json(OIDC_TRACE_FILE, trace)
    if not code:
        raise RuntimeError("OIDC authorize did not return code")
    if returned_state != state:
        raise RuntimeError(f"OIDC state mismatch: expected {state}, got {returned_state}")

    token_headers = {
        "User-Agent": kid.UA,
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "https://www.pubgselfservice.com",
        "Referer": redirect_uri,
    }
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": PUBG_CLIENT_ID,
        "code_verifier": code_verifier,
    }
    rt = s.post(token_ep, headers=token_headers, data=token_data, timeout=30, allow_redirects=False)
    save_json(ART / "oidc_token_response.json", snap(rt))
    print(f"[oidc] token -> HTTP {rt.status_code}")
    body = try_json(rt)
    if rt.status_code != 200 or not isinstance(body, dict) or not body.get("access_token"):
        raise RuntimeError(f"OIDC token failed: HTTP {rt.status_code} {str(body)[:800]}")
    body["_meta"] = {"token_endpoint": token_ep, "redirect_uri": redirect_uri, "state": state, "expires_at": int(time.time()) + int(body.get("expires_in") or 0)}
    return body


def foc_signin(s: requests.Session, access_token: str) -> dict[str, Any]:
    headers = {
        "User-Agent": kid.UA,
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": "https://pubg.com",
        "Referer": "https://pubg.com/",
        "service-game": "pubg",
        "service-lang": "zh-cn",
        "service-namespace": "PUBG_OFFICIAL",
    }
    payload = {"kidToken": access_token}
    r = s.post(FOC_SIGNIN, headers=headers, json=payload, timeout=30, allow_redirects=False)
    save_json(ART / "foc_signin_response.json", snap(r))
    print(f"[foc] signin -> HTTP {r.status_code}")
    body = try_json(r)
    if r.status_code != 200 or not isinstance(body, dict):
        raise RuntimeError(f"FOC signin failed: HTTP {r.status_code} {str(body)[:800]}")
    return body


def main() -> int:
    ap = argparse.ArgumentParser(description="PUBG Selfservice HTTP OIDC/focToken 获取器")
    ap.add_argument("--email", default=os.environ.get("KRAFTON_EMAIL"), required=not os.environ.get("KRAFTON_EMAIL"))
    ap.add_argument("--password", default=os.environ.get("KRAFTON_PASSWORD"), required=not os.environ.get("KRAFTON_PASSWORD"))
    ap.add_argument("--http-proxy", default=os.environ.get("HTTP_PROXY_URL") or None, help="requests/Playwright 共用代理，例如 http://host:port")
    ap.add_argument("--redirect-uri", default=PUBG_HOME)
    ap.add_argument("--no-prompt-consent", action="store_true", help="OIDC authorize 不带 prompt=consent")
    ap.add_argument("--trusted", action="store_true")
    ap.add_argument("--no-saved-cookies", action="store_true")
    ap.add_argument("--sec-cpt-rounds", type=int, default=80)
    ap.add_argument("--no-sec-cpt-wait", action="store_true")
    ap.add_argument("--no-sensor-interleave", action="store_true")
    ap.add_argument("--akamai-js-url")
    ap.add_argument("--print-full-tokens", action="store_true")
    args = ap.parse_args()

    ART.mkdir(parents=True, exist_ok=True)
    s, _ = login_krafton_session(args)
    token = oidc_authorize_and_token(
        s,
        args,
        _,
        args.redirect_uri,
        prompt=None if args.no_prompt_consent else "consent",
    )
    foc = foc_signin(s, token["access_token"])

    result = {
        "ts": int(time.time()),
        "email": args.email,
        "redirect_uri": args.redirect_uri,
        "oidc": token,
        "foc": foc,
    }
    save_json(TOKEN_FILE, result)

    nickname = None
    accounts = foc.get("accounts") if isinstance(foc, dict) else None
    if isinstance(accounts, list) and accounts:
        nickname = accounts[0].get("nickname")
    print(f"[ok] saved: {TOKEN_FILE}")
    print(f"[ok] nickname={nickname!r} focToken_len={len(str(foc.get('focToken') or ''))}")
    shown = result if args.print_full_tokens else token_summary(result)
    print(json.dumps(shown, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
