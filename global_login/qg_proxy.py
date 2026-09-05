"""QG overseas short-lived HTTP proxy provider."""
from __future__ import annotations
import os
import logging
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

QG_ENDPOINT = "https://overseas.proxy.qg.net/get"
QG_KEY = os.environ.get("GIFT_PORTAL_QG_PROXY_KEY", "6OSRJCT0")
# QG Authpwd; override with GIFT_PORTAL_QG_PROXY_PASSWORD when needed.
QG_PASSWORD = os.environ.get("GIFT_PORTAL_QG_PROXY_PASSWORD", "2D2A926D37F1")
logger = logging.getLogger("gift_portal.qg_proxy")
STEAM_PROBE_URL = "https://steamcommunity.com/oauth/login"

class QGProxyError(RuntimeError):
    pass

def fetch_proxies(*, key: str | None = None, count: int = 5, timeout: float = 10.0) -> list[str]:
    requested_count = max(1, int(count))
    params = {"key": key or QG_KEY, "num": max(requested_count * 4, 20), "area": "", "isp": 0, "format": "json", "distinct": "false", "keep_alive": 1}
    if not params["key"]:
        raise QGProxyError("QG proxy key is empty")
    try:
        api_session = requests.Session()
        api_session.trust_env = False
        response = api_session.get(QG_ENDPOINT, params=params, timeout=timeout)
        body = response.json()
    except (requests.RequestException, ValueError) as exc:
        logger.warning("QG proxy request failed error=%s", type(exc).__name__)
        raise QGProxyError("QG proxy request failed") from exc
    if response.status_code >= 400 or not isinstance(body, dict) or body.get("code") != "SUCCESS":
        code = body.get("code") if isinstance(body, dict) else response.status_code
        logger.warning("QG proxy response http=%s code=%s", response.status_code, code)
        raise QGProxyError(f"QG proxy unavailable: {code}")
    data = body.get("data")
    if not isinstance(data, list) or not data:
        logger.warning("QG proxy response http=%s code=SUCCESS missing_server", response.status_code)
        raise QGProxyError("QG proxy response has no valid server")
    password = os.environ.get("GIFT_PORTAL_QG_PROXY_PASSWORD", QG_PASSWORD)
    username = os.environ.get("GIFT_PORTAL_QG_PROXY_USERNAME", params["key"])
    proxies = []
    for item in data:
        server = item.get("server") if isinstance(item, dict) else ""
        if not isinstance(server, str) or server.count(":") != 1:
            continue
        host, port = server.rsplit(":", 1)
        if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
            continue
        if password:
            proxy = f"http://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}"
        else:
            proxy = f"http://{host}:{port}"
        proxies.append(proxy)
        logger.info("QG proxy response http=%s code=SUCCESS server=%s auth=%s", response.status_code, server, "enabled" if password else "disabled")
    if not proxies:
        raise QGProxyError("QG proxy response has no valid server")

    def probe(proxy: str) -> tuple[str, int, float]:
        successes = 0
        elapsed_total = 0.0
        for _ in range(3):
            started = time.perf_counter()
            try:
                response = requests.get(
                    STEAM_PROBE_URL,
                    proxies={"http": proxy, "https": proxy},
                    timeout=min(float(timeout), 8.0),
                    headers={"User-Agent": "Mozilla/5.0"},
                    allow_redirects=False,
                )
                elapsed_total += time.perf_counter() - started
                if response.status_code in (200, 301, 302, 303, 307, 308):
                    successes += 1
                else:
                    break
            except requests.RequestException:
                break
        return proxy, successes, elapsed_total / successes if successes else float("inf")

    qualified = []
    with ThreadPoolExecutor(max_workers=min(20, len(proxies))) as executor:
        futures = [executor.submit(probe, proxy) for proxy in proxies]
        for future in as_completed(futures):
            proxy, successes, average = future.result()
            if successes == 3:
                qualified.append((average, proxy))
            else:
                logger.info("Steam proxy quality rejected proxy=%s success=%s/3", proxy, successes)
    qualified.sort(key=lambda item: item[0])
    selected = qualified[:requested_count]
    logger.info(
        "Steam proxy quality complete candidates=%s qualified=%s selected=%s fastest=%s",
        len(proxies), len(qualified), len(selected),
        ",".join(f"{proxy.rsplit(':', 1)[-1]}:{average:.2f}s" for average, proxy in selected),
    )
    if not selected:
        raise QGProxyError("QG returned no proxy passing 3/3 Steam login checks")
    return [proxy for _average, proxy in selected]


def fetch_proxy(*, key: str | None = None, timeout: float = 10.0) -> str:
    return fetch_proxies(key=key, count=1, timeout=timeout)[0]

