"""QG overseas short-lived HTTP proxy provider."""
from __future__ import annotations
import os
import logging
import requests
from urllib.parse import quote

QG_ENDPOINT = "https://overseas.proxy.qg.net/get"
QG_KEY = os.environ.get("GIFT_PORTAL_QG_PROXY_KEY", "S6MKC1DW")
# QG Authpwd; override with GIFT_PORTAL_QG_PROXY_PASSWORD when needed.
QG_PASSWORD = os.environ.get("GIFT_PORTAL_QG_PROXY_PASSWORD", "ADDD480E87B7")
logger = logging.getLogger("gift_portal.qg_proxy")

class QGProxyError(RuntimeError):
    pass

def fetch_proxy(*, key: str | None = None, timeout: float = 10.0) -> str:
    params = {"key": key or QG_KEY, "num": 1, "area": "", "isp": 0, "format": "json", "distinct": "false", "keep_alive": 1}
    if not params["key"]:
        raise QGProxyError("QG proxy key is empty")
    try:
        response = requests.get(QG_ENDPOINT, params=params, timeout=timeout)
        body = response.json()
    except (requests.RequestException, ValueError) as exc:
        logger.warning("QG proxy request failed error=%s", type(exc).__name__)
        raise QGProxyError("QG proxy request failed") from exc
    if response.status_code >= 400 or not isinstance(body, dict) or body.get("code") != "SUCCESS":
        code = body.get("code") if isinstance(body, dict) else response.status_code
        logger.warning("QG proxy response http=%s code=%s", response.status_code, code)
        raise QGProxyError(f"QG proxy unavailable: {code}")
    data = body.get("data")
    server = data[0].get("server") if isinstance(data, list) and data and isinstance(data[0], dict) else ""
    if not isinstance(server, str) or server.count(":") != 1:
        logger.warning("QG proxy response http=%s code=SUCCESS missing_server", response.status_code)
        raise QGProxyError("QG proxy response has no valid server")
    host, port = server.rsplit(":", 1)
    if not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        logger.warning("QG proxy response http=%s code=SUCCESS invalid_server", response.status_code)
        raise QGProxyError("QG proxy response has invalid server")
    password = os.environ.get("GIFT_PORTAL_QG_PROXY_PASSWORD", QG_PASSWORD)
    username = os.environ.get("GIFT_PORTAL_QG_PROXY_USERNAME", params["key"])
    if password:
        proxy = f"http://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}"
        logger.info("QG proxy response http=%s code=SUCCESS server=%s auth=enabled", response.status_code, server)
    else:
        proxy = f"http://{host}:{port}"
        logger.info("QG proxy response http=%s code=SUCCESS server=%s auth=disabled", response.status_code, server)
    return proxy
