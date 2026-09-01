#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PUBG HTTP Authorization 获取器。

用于替代 pubg_cookie_getter_v2.py 的浏览器版本：
    from pubg_cookie_getter_http import PUBGCookieGetter

特性：
- 保持 PUBGCookieGetter 类名和常用方法：add_account/get_all_accounts/update_account_auth/get_authorization/renew_token 等。
- get_authorization(username, password, gui_instance=None) 返回 PUBG FOC token，也就是 GUI 保存的 authorization。
- 纯 HTTP 跑 accounts.krafton.com 登录 -> PUBG Selfservice OIDC -> api-foc.krafton.com/auth/kid/signin。
- 多线程安全：每个账号独立 requests.Session；全局复用一颗 seed _abck；用锁保护 seed 初始化。
- 并发完全由 GUI 的 QThreadPool.setMaxThreadCount(...) 控制；本文件不额外限流。

依赖：
- 本目录中的 krafton_pure_http_login.py
- 本目录中的 pubgselfservice_http_token.py
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional

import requests

try:
    from .refresh_token import refresh_token
except Exception:  # pragma: no cover
    refresh_token = None

from . import krafton_pure_http_login as kid
from . import krafton_soop_http_link as soop_link
from . import pubgselfservice_http_token as pubg_http

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("pubg_cookie_http.log", encoding="utf-8")],
)
logger = logging.getLogger(__name__)
SOOP_INVENTORY_COOKIE_EXPIRED_MESSAGE = "SOOP 库存账号登录状态已过期，请在后台更新该库存账号的登录信息后重试。"


def profile_has_soop_authentication(profile_body: Any) -> bool:
    """Return whether the documented profile authentication list contains SOOP."""
    if not isinstance(profile_body, dict):
        return False
    authentications = profile_body.get("authentications")

    def is_soop(entry: Any) -> bool:
        if isinstance(entry, str):
            return entry.strip().casefold() == "soop"
        if isinstance(entry, (list, tuple)):
            return any(is_soop(value) for value in entry)
        if not isinstance(entry, dict):
            return False
        return any(is_soop(value) for value in entry.values())

    return is_soop(authentications)


def unbind_soop_if_linked(session: requests.Session, profile_body: Any) -> bool:
    """Unlink SOOP from the logged-in KRAFTON session and verify the result."""
    if not profile_has_soop_authentication(profile_body):
        return False

    try:
        response = session.delete(
            f"{kid.BASE}/auth/soop",
            headers={
                "Accept": "application/json, text/plain, */*",
                "Referer": f"{kid.BASE}/v2/en/settings/connections-accounts",
                "User-Agent": kid.UA,
            },
            timeout=30,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise RuntimeError("SOOP 解绑失败，请稍后重试。") from exc

    logger.info("SOOP unlink response http=%s", response.status_code)
    if response.status_code not in (200, 204):
        raise RuntimeError("SOOP 解绑失败，请稍后重试。")

    try:
        verified_profile = kid.profile(session)
    except requests.RequestException as exc:
        raise RuntimeError("SOOP 解绑失败，请稍后重试。") from exc
    logger.info("SOOP unlink verification response http=%s", verified_profile.status_code)
    if verified_profile.status_code != 200:
        raise RuntimeError("SOOP 解绑失败，请稍后重试。")
    if profile_has_soop_authentication(kid.try_json(verified_profile)):
        raise RuntimeError("SOOP 解绑失败，请稍后重试。")
    return True


def bind_soop_to_session(
    session: requests.Session,
    soop_cookie: str,
    trace: Optional[Dict[str, Any]] = None,
) -> None:
    """Bind SOOP to the logged-in KRAFTON session.

    The profile API is diagnostic only: it may lag behind the connection page
    and must not block redemption after a completed callback.
    """
    if trace is not None:
        trace["detail_stage"] = "soop_bind_link"
    try:
        result = soop_link.link_soop(soop_cookie=soop_cookie, confirm=True, krafton_session=session)
    except (soop_link.LinkError, requests.RequestException) as exc:
        if isinstance(exc, soop_link.LinkError) and "did not return to KRAFTON" in str(exc):
            raise RuntimeError(SOOP_INVENTORY_COOKIE_EXPIRED_MESSAGE) from exc
        raise RuntimeError("SOOP 绑定失败，请稍后重试。") from exc
    if result.status != "linked":
        raise RuntimeError("SOOP 绑定失败，请稍后重试。")
    if trace is not None:
        trace["soop_bind_linked"] = True
    try:
        profile_response = kid.profile(session)
        profile_linked = (
            profile_response.status_code == 200
            and profile_has_soop_authentication(kid.try_json(profile_response))
        )
        if trace is not None:
            trace["soop_bind_profile_status"] = profile_response.status_code
            trace["soop_bind_profile_linked"] = profile_linked
        logger.info(
            "SOOP bind callback completed profile_http=%s profile_linked=%s",
            profile_response.status_code, profile_linked,
        )
    except requests.RequestException as exc:
        if trace is not None:
            trace["soop_bind_profile_error"] = type(exc).__name__
        logger.warning("SOOP bind callback completed but profile verification request failed")


def soop_cookie_from_session(session: requests.Session, fallback_cookie: str) -> str:
    """Build the claim Cookie header using the domains valid for Drops.

    OAuth can set a host-only cookie for ``openapi.sooplive.com`` with the
    same name as the domain cookie needed by ``drops.sooplive.com``.  Flattening
    cookies by name leaks that host-only value into the Drops request and breaks
    the SOOP account context after a successful KRAFTON callback.
    """
    request = requests.Request(
        "POST", "https://drops.sooplive.com/api/get_drops_use_info.php",
    ).prepare()
    cookie_header = requests.cookies.get_cookie_header(session.cookies, request)
    if not cookie_header:
        cookie_header = fallback_cookie
    names = sorted(name for name, _ in soop_link._cookie_items(cookie_header))
    logger.info("SOOP Drops session cookies prepared names=%s", names)
    return cookie_header


# 登录相关错误映射：后端 message -> 前端 key -> 中文提示 -> 含义
LOGIN_ERROR_MAP: Dict[str, Dict[str, str]] = {
    "invalid-csrf-token": {
        "backend_message": "error.invalid-csrf-token",
        "frontend_key": "invalid-csrf-token",
        "zh_tip": "请刷新并重试。",
        "meaning": "CSRF/session 状态不完整",
    },
    "invalid-password": {
        "backend_message": "error.invalid-password",
        "frontend_key": "invalid-password",
        "zh_tip": "密码错误。",
        "meaning": "密码错误",
    },
    "auth-error-old-password-used-period-few-days": {
        "backend_message": "error.auth-error-old-password-used-period-few-days",
        "frontend_key": "auth-error-old-password-used-period-few-days",
        "zh_tip": "您输入的是几天前更改过的密码。",
        "meaning": "输入了几天前已更改的旧密码",
    },
    "auth-error-old-password-used-period-1-month": {
        "backend_message": "error.auth-error-old-password-used-period-1-month",
        "frontend_key": "auth-error-old-password-used-period-1-month",
        "zh_tip": "您输入的是一个月内更改过的密码。",
        "meaning": "输入了一个月内已更改的旧密码",
    },
    "auth-error-old-password-used-period-3-weeks": {
        "backend_message": "error.auth-error-old-password-used-period-3-weeks",
        "frontend_key": "auth-error-old-password-used-period-3-weeks",
        "zh_tip": "您输入的是三周内更改过的密码。",
        "meaning": "输入了三周内已更改的旧密码",
    },
    "auth-error-old-password-used-period": {
        "backend_message": "",
        "frontend_key": "auth-error-old-password-used-period",
        "zh_tip": "您输入的是近期更改过的旧密码。",
        "meaning": "输入了近期已更改的旧密码",
    },
    "login-denied": {
        "backend_message": "error.login-denied",
        "frontend_key": "login-denied",
        "zh_tip": "无法找到使用该电子邮箱和密码的账号。",
        "meaning": "邮箱或密码不匹配 / 账号不存在",
    },
    "login-ip-rate-limit": {
        "backend_message": "error.login-ip-rate-limit",
        "frontend_key": "login-ip-rate-limit",
        "zh_tip": "很抱歉，您尝试登录的次数已达上限。请稍后再试。",
        "meaning": "IP 登录频率限制",
    },
    "login-rate-limit": {
        "backend_message": "error.login-rate-limit",
        "frontend_key": "login-rate-limit",
        "zh_tip": "登录似乎遇到问题。请等待20分钟后再试一次。",
        "meaning": "账号/登录行为限流",
    },
    "login-locked": {
        "backend_message": "error.login-locked",
        "frontend_key": "login-locked",
        "zh_tip": "由于尝试登录失败次数过多，此账号已被锁定。",
        "meaning": "账号被锁",
    },
    "login-need-to-verify-mfa": {
        "backend_message": "error.login-need-to-verify-mfa",
        "frontend_key": "login-need-to-verify-mfa",
        "zh_tip": "已设置双因素验证。请关闭双因素验证。",
        "meaning": "需要 MFA",
    },
    "login-required": {
        "backend_message": "error.login-required",
        "frontend_key": "login-required",
        "zh_tip": "您必须先登录才能执行该操作。",
        "meaning": "cookie 失效 / 未登录",
    },
    "session-expired": {
        "backend_message": "error.session-expired",
        "frontend_key": "session-expired",
        "zh_tip": "会话已过期。",
        "meaning": "session 过期",
    },
    "local-auth-validate-failed": {
        "backend_message": "error.local-auth-validate-failed",
        "frontend_key": "local-auth-validate-failed",
        "zh_tip": "无法验证证书。",
        "meaning": "本地账号认证校验失败",
    },
    "invalid-request": {
        "backend_message": "error.invalid-request",
        "frontend_key": "invalid-request",
        "zh_tip": "请求无效。",
        "meaning": "请求参数/状态无效",
    },
    "invalid-token": {
        "backend_message": "error.invalid-token",
        "frontend_key": "invalid-token",
        "zh_tip": "无效令牌。",
        "meaning": "token 无效",
    },
    "token-expired": {
        "backend_message": "error.token-expired",
        "frontend_key": "token-expired",
        "zh_tip": "令牌已过期。",
        "meaning": "token 过期",
    },
    "email-invalid": {
        "backend_message": "error.email-invalid",
        "frontend_key": "email-invalid",
        "zh_tip": "请输入有效的电子邮箱。",
        "meaning": "邮箱格式错误",
    },
    "email-required": {
        "backend_message": "error.email-required",
        "frontend_key": "email-required",
        "zh_tip": "电子邮箱必填。",
        "meaning": "缺邮箱",
    },
    "password-required": {
        "backend_message": "error.password-required",
        "frontend_key": "password-required",
        "zh_tip": "密码必填。",
        "meaning": "缺密码",
    },
    "provider-locked": {
        "backend_message": "error.provider-locked",
        "frontend_key": "provider-locked",
        "zh_tip": "该KRAFTON ID已与其他第三方账号绑定。",
        "meaning": "第三方绑定冲突",
    },
    "set-password-first": {
        "backend_message": "error.set-password-first",
        "frontend_key": "set-password-first",
        "zh_tip": "如果您尚未设置密码，请先进行设置。",
        "meaning": "第三方创建账号未设置本地密码",
    },
    "email-not-found-for-account": {
        "backend_message": "error.email-not-found-for-account",
        "frontend_key": "email-not-found-for-account",
        "zh_tip": "未找到此账户的邮箱地址。",
        "meaning": "账号缺邮箱",
    },
}

# 已确认 176 对应“近期使用过的旧密码”类错误；具体 message 优先于该兜底映射。
LOGIN_ERROR_NUMERIC_CODE_MAP: Dict[str, str] = {
    "176": "auth-error-old-password-used-period",
}


class _AbckPool:
    """进程级 seed _abck 复用池。

    队列策略：
    - 初始化同步填充到 queue_target_size（默认2）
    - 可用 seed 数量降到 queue_min_available（默认1）时，后台补充到目标值
    - RiskByPass seed 可按次数复用（默认最多9次，含首次）
    """

    _lock = threading.RLock()
    _cond = threading.Condition(_lock)
    _seed_abck: Optional[str] = None
    _akamai_js_url: Optional[str] = None
    _seed_ts: float = 0.0
    _ttl_s: int = int(os.environ.get("PUBG_HTTP_ABCK_TTL", "3600"))
    _seed_hits: int = 0
    _seed_source: str = "none"
    _seed_queue = deque()
    _realtime_params_mode: bool = os.environ.get("PUBG_RISKBYPASS_REALTIME_PARAMS", "0") == "1"
    _queue_target_size: int = max(1, int(os.environ.get("PUBG_RISKBYPASS_QUEUE_TARGET", "2")))
    _queue_min_available: int = max(0, int(os.environ.get("PUBG_RISKBYPASS_QUEUE_MIN", "1")))
    _sync_fill_in_progress: bool = False
    _refill_thread: Optional[threading.Thread] = None
    _last_refill_error: Optional[str] = None
    _riskbypass_enabled: bool = os.environ.get("PUBG_ENABLE_RISKBYPASS", "0") == "1"
    _riskbypass_seed_max_uses: int = max(1, int(os.environ.get("PUBG_RISKBYPASS_SEED_MAX_USES", "9")))
    _browser_seed_max_uses: int = max(1, int(os.environ.get("PUBG_BROWSER_SEED_MAX_USES", "12")))
    _browser_seed_backend: str = os.environ.get("PUBG_HTTP_SENSOR_BROWSER") or os.environ.get("KRAFTON_SENSOR_BROWSER") or "playwright"
    _browser_seed_wait_ms: int = max(500, int(os.environ.get("PUBG_BROWSER_SEED_WAIT_MS", "2500")))
    _riskbypass_proxy: str = os.environ.get("PUBG_RISKBYPASS_PROXY", "http://42.96.18.62:1311")
    _riskbypass_page_fp: Optional[str] = os.environ.get("PUBG_RISKBYPASS_PAGE_FP") or None
    _riskbypass_target_url: Optional[str] = os.environ.get("PUBG_RISKBYPASS_TARGET_URL") or None

    @classmethod
    def _prune_expired_queue_locked(cls, now: float) -> None:
        kept = deque()
        for entry in cls._seed_queue:
            if now - float(entry.get("seed_ts", now)) < cls._ttl_s:
                kept.append(entry)
        cls._seed_queue = kept

    @classmethod
    def _fetch_seed_entry(cls, proxy: Optional[str] = None) -> Dict[str, Any]:
        """获取一条 Akamai seed；浏览器模式通过 Playwright 采集，或使用 RiskByPass 服务。"""
        s = kid.make_session(load_saved=False, proxy=proxy)
        r = kid.bootstrap(s)
        akamai_js_url = kid.discover_akamai_js(r.text)
        seed_source = "browser"
        akamai_cookies: Dict[str, str] = {}

        if cls._riskbypass_enabled:
            abck = cls._get_seed_from_riskbypass(akamai_js_url=akamai_js_url)
            seed_source = "riskbypass"
            if not abck:
                raise RuntimeError("RiskByPass 未返回有效 _abck")
            akamai_cookies = {"_abck": abck}
            max_uses = 1 if cls._realtime_params_mode else cls._riskbypass_seed_max_uses
        else:
            lang = os.environ.get("PUBG_HTTP_LOGIN_LANG", "zh_CN")
            login_url = f"{kid.BASE}/v2/{lang}/web/login-main"
            kid.prewarm_login_route(s)
            sensor = kid.collect_and_post_sensor(
                s,
                akamai_js_url,
                target_url=login_url,
                referer=login_url,
                label="pubg_http_seed_prelogin",
                session_proxy=proxy,
                wait_ms=cls._browser_seed_wait_ms,
                interact=True,
                sensor_backend=cls._browser_seed_backend,
                sync_akamai_cookies=True,
            )
            for name in ("_abck", "bm_sz", "ak_bmsc"):
                val = s.cookies.get(name)
                if val:
                    akamai_cookies[name] = val
            if not akamai_cookies.get("_abck"):
                raise RuntimeError("浏览器采集 Akamai seed 时未获得 _abck")
            max_uses = 1 if cls._realtime_params_mode else cls._browser_seed_max_uses
            logger.info("浏览器采集 seed 成功 backend=%s sensor_len=%s cookies=%s _abck_len=%s", cls._browser_seed_backend, len(sensor or ""), ",".join(sorted(akamai_cookies)), len(akamai_cookies.get("_abck", "")))

        abck = akamai_cookies.get("_abck", "")
        return {
            "abck": abck,
            "akamai_cookies": akamai_cookies,
            "akamai_js_url": akamai_js_url,
            "seed_source": seed_source,
            "seed_ts": time.time(),
            "remaining_uses": max_uses,
            "total_uses": 0,
        }

    @classmethod
    def _start_refill_worker_locked(cls, proxy: Optional[str]) -> None:
        if cls._refill_thread is not None and cls._refill_thread.is_alive():
            return

        def _worker() -> None:
            while True:
                with cls._lock:
                    cls._prune_expired_queue_locked(time.time())
                    if len(cls._seed_queue) >= cls._queue_target_size:
                        cls._refill_thread = None
                        return
                try:
                    entry = cls._fetch_seed_entry(proxy=proxy)
                except Exception as e:
                    cls._last_refill_error = str(e)
                    logger.warning("后台补充 seed 队列失败: %s", e)
                    with cls._lock:
                        cls._refill_thread = None
                    return

                with cls._lock:
                    cls._seed_queue.append(entry)
                    cls._last_refill_error = None
                    logger.info(
                        "后台补充 seed 成功 source=%s queue=%s/%s",
                        entry.get("seed_source"),
                        len(cls._seed_queue),
                        cls._queue_target_size,
                    )

        cls._refill_thread = threading.Thread(target=_worker, name="abck-seed-refill", daemon=True)
        cls._refill_thread.start()

    @classmethod
    def _get_seed_from_riskbypass(cls, akamai_js_url: Optional[str] = None) -> Optional[str]:
        runtime_login_lang = os.environ.get("PUBG_HTTP_LOGIN_LANG", "zh_CN")
        runtime_target_url = (
            os.environ.get("PUBG_RISKBYPASS_TARGET_URL")
            or cls._riskbypass_target_url
            or f"{kid.BASE}/v2/{runtime_login_lang}/web/login-main"
        )
        runtime_page_fp = os.environ.get("PUBG_RISKBYPASS_PAGE_FP")
        try:
            import abck as riskbypass_abck  # type: ignore
        except Exception as e:
            logger.warning("RiskByPass 模块不可用: %s", e)
            return None

        payload = None
        try:
            default_payload = getattr(riskbypass_abck, "DEFAULT_PAYLOAD", None)
            if isinstance(default_payload, dict):
                payload = dict(default_payload)
                payload["proxy"] = cls._riskbypass_proxy
                payload["target_url"] = runtime_target_url
                # 每次注入当前会话最新的 Akamai JS URL，避免使用过期静态值。
                if akamai_js_url:
                    payload["akamai_js_url"] = akamai_js_url
                # page_fp 仅在本次调用显式提供时注入，避免落回静态模板值。
                payload.pop("page_fp", None)
                if runtime_page_fp:
                    payload["page_fp"] = runtime_page_fp
        except Exception:
            payload = None

        try:
            if payload is not None:
                logger.info("RiskByPass request payload = %s", json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
                abck_value = riskbypass_abck.get_abck_value(payload=payload)
            else:
                logger.info("RiskByPass request payload = <DEFAULT_PAYLOAD from abck.py>")
                abck_value = riskbypass_abck.get_abck_value()
        except Exception as e:
            logger.warning("RiskByPass 获取 seed _abck 失败: %s", e)
            return None

        if isinstance(abck_value, str) and abck_value.strip():
            return abck_value.strip()

        logger.warning("RiskByPass 返回空 _abck")
        return None

    @classmethod
    def get_seed_entry(cls, proxy: Optional[str] = None, force_refresh: bool = False) -> Dict[str, Any]:
        """获取一条 seed entry，其中包含完整的 Akamai cookie。"""
        if force_refresh:
            with cls._cond:
                cls._seed_queue.clear(); cls._seed_abck = None; cls._akamai_js_url = None; cls._seed_ts = 0.0
                cls._seed_hits = 0; cls._seed_source = "none"; cls._last_refill_error = None; cls._sync_fill_in_progress = False
                cls._cond.notify_all()
        while True:
            with cls._cond:
                now = time.time(); cls._prune_expired_queue_locked(now)
                if cls._seed_queue:
                    entry = cls._seed_queue[0]
                    entry["total_uses"] = int(entry.get("total_uses", 0)) + 1
                    entry["remaining_uses"] = int(entry.get("remaining_uses", 0)) - 1
                    cls._seed_abck = str(entry.get("abck") or ""); cls._akamai_js_url = str(entry.get("akamai_js_url") or "")
                    cls._seed_ts = float(entry.get("seed_ts") or now); cls._seed_source = str(entry.get("seed_source") or "unknown")
                    cls._seed_hits = max(0, int(entry.get("total_uses", 1)) - 1)
                    out = dict(entry)
                    if int(entry.get("remaining_uses", 0)) <= 0: cls._seed_queue.popleft()
                    if len(cls._seed_queue) <= cls._queue_min_available: cls._start_refill_worker_locked(proxy)
                    return out
                if cls._sync_fill_in_progress:
                    cls._cond.wait(); continue
                cls._sync_fill_in_progress = True
            sync_error: Optional[Exception] = None
            try:
                entry = cls._fetch_seed_entry(proxy=proxy)
                with cls._cond:
                    cls._seed_queue.append(entry); cls._last_refill_error = None
                    logger.info("同步填充 seed 成功 source=%s queue=%s/%s", entry.get("seed_source"), len(cls._seed_queue), cls._queue_target_size)
                    cls._cond.notify_all()
            except Exception as e:
                sync_error = e
                with cls._cond: cls._last_refill_error = str(e)
            finally:
                with cls._cond:
                    cls._sync_fill_in_progress = False; cls._cond.notify_all()
            if sync_error: raise sync_error

    @classmethod
    def get_seed(cls, proxy: Optional[str] = None, force_refresh: bool = False) -> tuple[str, str]:
        entry = cls.get_seed_entry(proxy=proxy, force_refresh=force_refresh)
        return str(entry.get("abck") or ""), str(entry.get("akamai_js_url") or "")

    @classmethod
    def status(cls) -> Dict[str, Any]:
        with cls._lock:
            return {
                "has_seed": bool(cls._seed_abck),
                "seed_len": len(cls._seed_abck or ""),
                "seed_head": (cls._seed_abck or "")[:32],
                "akamai_js_url": cls._akamai_js_url,
                "seed_age_s": int(time.time() - cls._seed_ts) if cls._seed_ts else None,
                "seed_hits": cls._seed_hits,
                "ttl_s": cls._ttl_s,
                "seed_source": cls._seed_source,
                "seed_total_uses": (1 + cls._seed_hits) if cls._seed_abck else 0,
                "realtime_params_mode": cls._realtime_params_mode,
                "riskbypass_enabled": cls._riskbypass_enabled,
                "riskbypass_seed_max_uses": cls._riskbypass_seed_max_uses,
                "browser_seed_max_uses": cls._browser_seed_max_uses,
                "browser_seed_backend": cls._browser_seed_backend,
                "browser_seed_wait_ms": cls._browser_seed_wait_ms,
                "queue_size": len(cls._seed_queue),
                "queue_target_size": cls._queue_target_size,
                "queue_min_available": cls._queue_min_available,
                "sync_fill_in_progress": cls._sync_fill_in_progress,
                "queue_refill_in_progress": bool(cls._refill_thread is not None and cls._refill_thread.is_alive()),
                "last_refill_error": cls._last_refill_error,
                "riskbypass_proxy": cls._riskbypass_proxy,
                "riskbypass_page_fp": os.environ.get("PUBG_RISKBYPASS_PAGE_FP") or None,
                "riskbypass_target_url": (
                    os.environ.get("PUBG_RISKBYPASS_TARGET_URL")
                    or cls._riskbypass_target_url
                    or f"{kid.BASE}/v2/{os.environ.get('PUBG_HTTP_LOGIN_LANG', 'zh_CN')}/web/login-main"
                ),
            }


class PUBGCookieGetter:
    # 并发由 GUI 控制；这里不做额外限流。

    def __init__(self):
        self.db_path = os.environ.get("PUBG_ACCOUNTS_DB", "pubg_accounts.db")
        self.init_database()
        self.last_login_info: Optional[Dict[str, Any]] = None
        self._last_kid_login_trace: Dict[str, Any] = {}
        self.http_proxy = os.environ.get("PUBG_HTTP_PROXY") or os.environ.get("HTTP_PROXY_URL") or None
        self.sec_cpt_rounds = int(os.environ.get("PUBG_HTTP_SEC_CPT_ROUNDS", "80"))
        self.no_sec_cpt_wait = os.environ.get("PUBG_HTTP_SEC_CPT_WAIT", "0") != "1"
        # 默认不等 chlg_duration，和已验证脚本一致；如需等待，设置 PUBG_HTTP_SEC_CPT_WAIT=1
        self.no_sec_cpt_wait = True if os.environ.get("PUBG_HTTP_NO_SEC_CPT_WAIT", "1") == "1" else False
        self.no_sensor_interleave = os.environ.get("PUBG_HTTP_NO_SENSOR_INTERLEAVE", "0") == "1"
        self.sensor_browser = os.environ.get("PUBG_HTTP_SENSOR_BROWSER") or os.environ.get("KRAFTON_SENSOR_BROWSER") or "playwright"
        kid.SENSOR_BROWSER_BACKEND = self.sensor_browser
        _AbckPool._browser_seed_backend = self.sensor_browser
        self.bitbrowser_profile_id = os.environ.get("BITBROWSER_PROFILE_ID") or None
        self.bitbrowser_profile_name = os.environ.get("BITBROWSER_PROFILE_NAME") or "PUBG_Worker_50"
        self.redirect_uri = os.environ.get("PUBG_HTTP_REDIRECT_URI", pubg_http.PUBG_HOME)
        self.no_prompt_consent = os.environ.get("PUBG_HTTP_NO_PROMPT_CONSENT", "0") == "1"

    # ------------------------- DB methods: compatible with v2 -------------------------
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                authorization TEXT,
                last_update DATETIME,
                name TEXT NOT NULL
            )
            """
        )
        conn.commit()
        conn.close()

    def add_account(self, username, password, name):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO accounts (username, password, name) VALUES (?, ?, ?)",
            (username, password, name),
        )
        conn.commit()
        conn.close()

    def get_all_accounts(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, authorization, last_update, name FROM accounts")
        accounts = cursor.fetchall()
        conn.close()
        return accounts

    def update_account(self, account_id, username, password, name, authorization=None):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            if authorization is not None:
                cursor.execute(
                    """
                    UPDATE accounts
                    SET username = ?, password = ?, name = ?, authorization = ?, last_update = ?
                    WHERE id = ?
                    """,
                    (username, password, name, authorization, datetime.now(), account_id),
                )
            else:
                cursor.execute(
                    """
                    UPDATE accounts
                    SET username = ?, password = ?, name = ?
                    WHERE id = ?
                    """,
                    (username, password, name, account_id),
                )
            updated = cursor.rowcount > 0
            conn.commit()
            conn.close()
            return updated
        except Exception as e:
            logger.error("更新账号失败: %s", e)
            return False

    def update_account_auth(self, account_id, auth):
        update_time = datetime.now()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE accounts
            SET authorization = ?, last_update = ?
            WHERE id = ?
            """,
            (auth, update_time, account_id),
        )
        conn.commit()
        conn.close()
        return update_time

    def delete_account(self, account_id):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
            deleted = cursor.rowcount > 0
            conn.commit()
            conn.close()
            return deleted
        except Exception as e:
            logger.error("删除账号失败: %s", e)
            return False

    # ------------------------- GUI/log helpers -------------------------
    def _gui_log(self, gui_instance, message: str, level: str = "INFO") -> None:
        logger.info("[%s] %s", level, message)
        if gui_instance is not None:
            try:
                if hasattr(gui_instance, "write_log_threadsafe"):
                    gui_instance.write_log_threadsafe(message, level)
                elif hasattr(gui_instance, "write_log"):
                    gui_instance.write_log(message, level)
            except Exception:
                pass

    @staticmethod
    def _normalize_error_code(raw: str) -> str:
        code = raw.strip().lower()
        if code.startswith("error."):
            code = code[len("error.") :]
        return code

    @staticmethod
    def _format_user_tag(username: str, display_name: Optional[str] = None) -> str:
        name = str(display_name).strip() if display_name is not None else ""
        if name and name != username:
            return f"{name} | {username}"
        return username

    def _extract_known_login_error_code(self, payload: Any) -> Optional[str]:
        """从响应体或异常文本中提取已知登录错误码（返回不带 error. 的 key）。"""
        candidates: list[str] = []

        if isinstance(payload, dict):
            for key in ("message", "error", "code", "errorCode", "error_code", "key", "name"):
                value = payload.get(key)
                if isinstance(value, (str, int)) and str(value).strip():
                    candidates.append(str(value).strip())
        elif payload is not None:
            candidates.append(str(payload))

        # 先做精确匹配
        for value in candidates:
            norm = self._normalize_error_code(value)
            if norm in LOGIN_ERROR_MAP:
                return norm

        # 精确 message 未命中时，按服务端数字错误码回退。
        for value in candidates:
            mapped_code = LOGIN_ERROR_NUMERIC_CODE_MAP.get(value)
            if mapped_code:
                return mapped_code

        # 再做包含匹配（覆盖异常字符串拼接场景）
        joined = "\n".join(candidates).lower()
        for key in LOGIN_ERROR_MAP:
            if key in joined or f"error.{key}" in joined:
                return key

        return None

    def _gui_log_login_error_mapping(
        self,
        gui_instance,
        username: str,
        error_code: str,
        display_name: Optional[str] = None,
        raw_message: Optional[str] = None,
    ) -> None:
        mapping = LOGIN_ERROR_MAP.get(error_code)
        if not mapping:
            return

        tip = mapping.get("zh_tip") or raw_message or "登录失败，请稍后重试。"
        user_tag = self._format_user_tag(username, display_name)
        self._gui_log(gui_instance, f"{user_tag}----登录失败: {tip}", "ERROR")

    def get_last_login_info(self) -> Optional[Dict[str, Any]]:
        """给 GUI 或调试代码读取上一次 HTTP 登录/取 token 的完整摘要。"""
        return self.last_login_info

    @classmethod
    def get_abck_pool_status(cls) -> Dict[str, Any]:
        return _AbckPool.status()

    @classmethod
    def refresh_abck_seed(cls, proxy: Optional[str] = None) -> Dict[str, Any]:
        _AbckPool.get_seed(proxy=proxy, force_refresh=True)
        return _AbckPool.status()

    # ------------------------- HTTP login/token flow -------------------------
    def _make_seeded_session(self, seed: Any) -> requests.Session:
        s = kid.make_session(load_saved=False, proxy=self.http_proxy)
        # 优先恢复完整 Akamai cookie，兼容只传入 _abck 的旧调用方式。
        if isinstance(seed, dict):
            cookies = seed.get("akamai_cookies") if isinstance(seed.get("akamai_cookies"), dict) else seed
            for name in ("_abck", "bm_sz", "ak_bmsc"):
                val = cookies.get(name) if isinstance(cookies, dict) else None
                if val:
                    s.cookies.set(name, val, domain=".krafton.com", path="/", secure=True)
        elif seed:
            s.cookies.set("_abck", str(seed), domain=".krafton.com", path="/", secure=True)
        return s

    def _login_krafton(
        self,
        s: requests.Session,
        username: str,
        password: str,
        akamai_js_url: str,
        soop_cookie: str = "",
        gui_instance=None,
        display_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        trace: Dict[str, Any] = {}
        self._last_kid_login_trace = trace
        user_tag = self._format_user_tag(username, display_name)
        trace["detail_stage"] = "bootstrap"
        r0 = kid.bootstrap(s)
        trace["bootstrap_status"] = r0.status_code
        try:
            akamai_js_url = akamai_js_url or kid.discover_akamai_js(r0.text)
        except Exception:
            pass

        trace["detail_stage"] = "password_login"
        kid.prewarm_login_route(s)
        r = kid.login(s, username, password, trusted=False)
        body = kid.try_json(r)
        trace["first_login_status"] = r.status_code
        trace["first_login_body"] = body if isinstance(body, dict) else str(body)[:500]

        sec_cpt_attempts = 0
        while r.status_code == 428:
            trace["detail_stage"] = "akamai_sec_cpt"
            sec_cpt_attempts += 1
            logger.info("%s----触发 Akamai sec-cpt，开始第 %s 次 HTTP 解题", user_tag, sec_cpt_attempts)
            ok = kid.solve_sec_cpt_challenge(
                s,
                body,
                max_rounds=self.sec_cpt_rounds,
                sleep_first=not self.no_sec_cpt_wait,
                akamai_js_url=akamai_js_url,
                session_proxy=self.http_proxy,
                sensor_interleave=not self.no_sensor_interleave,
                sensor_backend=self.sensor_browser,
                bitbrowser_profile_id=self.bitbrowser_profile_id,
                bitbrowser_profile_name=self.bitbrowser_profile_name,
            )
            trace["sec_cpt_ok"] = ok
            trace["sec_cpt_stage"] = kid.sec_cpt_cookie_stage(s)
            trace["sec_cpt_attempts"] = sec_cpt_attempts
            trace["detail_stage"] = "password_login_retry"
            kid.prewarm_login_route(s)
            r = kid.login(s, username, password, trusted=False)
            body = kid.try_json(r)
            trace["retry_login_status"] = r.status_code
            trace["retry_login_body"] = body if isinstance(body, dict) else str(body)[:500]
            if r.status_code == 428:
                logger.warning("%s----Akamai sec-cpt 第 %s 次解题后仍需挑战，继续重试", user_tag, sec_cpt_attempts)

        if r.status_code != 200:
            msg = body.get("message") if isinstance(body, dict) else str(body)[:200]
            display_tip = ""
            if r.status_code == 404:
                display_tip = "无法找到使用该电子邮箱的账号。"
                self._gui_log(gui_instance, f"{user_tag}----登录失败: {display_tip}", "ERROR")
            else:
                mapped_code = self._extract_known_login_error_code(body if isinstance(body, dict) else msg)
                if mapped_code:
                    self._gui_log_login_error_mapping(
                        gui_instance,
                        username,
                        mapped_code,
                        display_name=display_name,
                        raw_message=msg,
                    )
                    mapped = LOGIN_ERROR_MAP[mapped_code]
                    display_tip = mapped.get("zh_tip", "")
                else:
                    info = kid.classify_response(r, body)
                    if info:
                        display_tip = info.get("zh") or info.get("meaning") or ""
                    if not display_tip:
                        display_tip = msg or "登录失败，请稍后重试。"
                    self._gui_log(gui_instance, f"{user_tag}----登录失败: {display_tip}", "ERROR")

            raise RuntimeError(f"KRAFTON 登录失败 HTTP {r.status_code}: {display_tip}")

        trace["detail_stage"] = "profile_before_soop"
        rp = kid.profile(s)
        pbody = kid.try_json(rp)
        trace["profile_status"] = rp.status_code
        if rp.status_code != 200:
            raise RuntimeError(f"KRAFTON profile 验证失败 HTTP {rp.status_code}")
        trace["detail_stage"] = "soop_unbind"
        trace["soop_unbound"] = unbind_soop_if_linked(s, pbody)
        if soop_cookie:
            bind_soop_to_session(s, soop_cookie, trace=trace)
            trace["soop_bound"] = True
            trace["soop_claim_cookie"] = soop_cookie_from_session(s, soop_cookie)
        trace["detail_stage"] = "krafton_login_complete"
        return trace

    def get_authorization_info(
        self,
        username: str,
        password: str,
        gui_instance=None,
        display_name: Optional[str] = None,
        soop_cookie: str = "",
        require_game_authorization: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """Return account information; game authorization is optional for SOOP-only flows."""
        start = time.time()
        user_tag = self._format_user_tag(username, display_name)
        stage = "akamai_seed"
        try:
            seed_entry = _AbckPool.get_seed_entry(proxy=self.http_proxy)
            seed_abck = str(seed_entry.get("abck") or "")
            akamai_js_url = str(seed_entry.get("akamai_js_url") or "")
            s = self._make_seeded_session(seed_entry)
            initial_cookies = [c.name for c in s.cookies]
            logger.info("%s----HTTP 开始获取 Authorization，seed_source=%s seed_abck=%s...", user_tag, seed_entry.get("seed_source"), seed_abck[:12])

            stage = "krafton_login"
            self._last_kid_login_trace = {}
            kid_trace = self._login_krafton(
                s,
                username,
                password,
                akamai_js_url,
                soop_cookie=soop_cookie,
                gui_instance=gui_instance,
                display_name=display_name,
            )

            if not require_game_authorization:
                soop_claim_cookie = kid_trace.pop("soop_claim_cookie", "")
                info = {
                    "status": "success",
                    "username": username,
                    "nickname": None,
                    "globalNickname": None,
                    "gameName": None,
                    "soop_claim_cookie": soop_claim_cookie,
                    "kid": kid_trace,
                    "elapsed_s": round(time.time() - start, 2),
                }
                self.last_login_info = info
                logger.info("%s----KRAFTON/SOOP connection ready; game authorization skipped", user_tag)
                return info

            oidc_args = SimpleNamespace(
                email=username,
                password=password,
                trusted=False,
                http_proxy=self.http_proxy,
                sec_cpt_rounds=self.sec_cpt_rounds,
                no_sec_cpt_wait=self.no_sec_cpt_wait,
                no_sensor_interleave=self.no_sensor_interleave,
            )
            stage = "oidc_authorize"
            try:
                token = pubg_http.oidc_authorize_and_token(
                    s,
                    oidc_args,
                    akamai_js_url,
                    self.redirect_uri,
                    prompt=None if self.no_prompt_consent else "consent",
                )
            except Exception as exc:
                raise RuntimeError(f"OIDC authorization failed: {exc}") from exc
            stage = "foc_signin"
            try:
                foc = pubg_http.foc_signin(s, token["access_token"])
            except Exception as exc:
                raise RuntimeError(f"FOC signin failed: {exc}") from exc
            foc_token = foc.get("focToken") if isinstance(foc, dict) else None
            if not foc_token:
                raise RuntimeError("FOC signin failed: missing focToken")

            stage = "authorization_result"
            accounts = foc.get("accounts") if isinstance(foc, dict) else None
            account0 = accounts[0] if isinstance(accounts, list) and accounts else {}
            nickname = account0.get("nickname")
            global_nickname = foc.get("globalNickname")
            game_name = account0.get("gameName")

            info: Dict[str, Any] = {
                "status": "success",
                "username": username,
                "authorization": foc_token,
                "focToken": foc_token,
                "nickname": nickname,
                "globalNickname": global_nickname,
                "gameName": game_name,
                "platformType": account0.get("platformType"),
                "expiresAt": foc.get("expiresAt"),
                "oidc": {
                    "access_token_len": len(token.get("access_token", "")),
                    "expires_in": token.get("expires_in"),
                    "scope": token.get("scope"),
                },
                "kid": kid_trace,
                "abck": {
                    "seed_len": len(seed_abck),
                    "seed_head": seed_abck[:32],
                    "initial_cookies": initial_cookies,
                    "final_abck_len": len(s.cookies.get("_abck") or ""),
                    "final_abck_same_as_seed": (s.cookies.get("_abck") or "") == seed_abck,
                    "pool": _AbckPool.status(),
                },
                "elapsed_s": round(time.time() - start, 2),
            }
            self.last_login_info = info

            # 登录成功后，仅输出游戏ID与成功信息。
            self._gui_log(gui_instance, f"{user_tag}----游戏ID: {nickname or '未获取到'}", "SUCCESS")

            self._gui_log(gui_instance, f"{user_tag}----Authorization 获取成功，用时 {info['elapsed_s']}s", "SUCCESS")
            return info
        except Exception as e:
            # 非 KRAFTON 登录阶段的异常，也尽量尝试做错误码映射。
            error_text = str(e)
            kid_trace = self._last_kid_login_trace
            safe_kid_trace = {
                key: value for key, value in kid_trace.items()
                if not key.endswith("_body")
            }
            detail_stage = safe_kid_trace.get("detail_stage")
            logger.error(
                "%s----Authorization failed stage=%s detail_stage=%s trace=%s error=%s",
                user_tag, stage, detail_stage or "-", safe_kid_trace, error_text,
            )
            failure = {
                "status": "error", "username": username, "error": error_text,
                "stage": stage, "detail_stage": detail_stage,
                "kid": safe_kid_trace, "elapsed_s": round(time.time() - start, 2),
            }
            if error_text in ("SOOP 解绑失败，请稍后重试。", "SOOP 绑定失败，请稍后重试。"):
                self.last_login_info = failure
                logger.warning("%s----SOOP account connection failed", user_tag)
                raise
            self.last_login_info = failure

            # 登录失败提示已在 _login_krafton 中输出，不再重复刷技术细节到 GUI。
            if "KRAFTON 登录失败 HTTP" in error_text:
                logger.warning("%s----HTTP Authorization 获取失败: %s", user_tag, e)
                return None

            mapped_code = self._extract_known_login_error_code(error_text)
            if mapped_code:
                self._gui_log_login_error_mapping(
                    gui_instance,
                    username,
                    mapped_code,
                    display_name=display_name,
                    raw_message=error_text,
                )
                logger.warning("%s----HTTP Authorization 获取失败: %s", user_tag, e)
                return None

            err = f"{user_tag}----HTTP Authorization 获取失败: {e}"
            self._gui_log(gui_instance, err, "ERROR")
            logger.exception(err)
            return None

    def get_authorization(self, username, password, gui_instance=None, display_name: Optional[str] = None):
        """兼容 pubg_cookie_getter_v2：返回 authorization/focToken 字符串。"""
        info = self.get_authorization_info(
            username,
            password,
            gui_instance=gui_instance,
            display_name=display_name,
        )
        if info and info.get("authorization"):
            return str(info["authorization"])
        return None

    def get_authorization_abck(self, username, password, gui_instance=None, display_name: Optional[str] = None):
        # 老接口名保留；HTTP 版统一走当前实现。
        return self.get_authorization(
            username,
            password,
            gui_instance=gui_instance,
            display_name=display_name,
        )

    def renew_token(self, username, token):
        try:
            if refresh_token is None:
                logger.error("refresh_token 模块不可用")
                return None
            logger.info("开始刷新 token: %s", username)
            new_token = refresh_token(token)
            if new_token:
                logger.info("Token 刷新成功: %s", username)
                return f"{new_token}"
            logger.error("Token 刷新失败: %s", username)
            return None
        except Exception as e:
            logger.error("Token 刷新发生错误: %s", e)
            return None


def main():
    import argparse

    ap = argparse.ArgumentParser(description="PUBG HTTP Authorization getter")
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    getter = PUBGCookieGetter()
    info = getter.get_authorization_info(args.email, args.password)
    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=2))
    else:
        print(info.get("authorization") if info else "")
    return 0 if info and info.get("authorization") else 1


if __name__ == "__main__":
    raise SystemExit(main())

