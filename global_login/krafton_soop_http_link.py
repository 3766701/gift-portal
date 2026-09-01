"""Direct HTTP flow for linking a KRAFTON account to SOOP.

The KRAFTON account center starts the provider OAuth flow at
``/v2/auth/soop``.  This module deliberately keeps the final redirect behind
an explicit confirmation so a connectivity check cannot change an account.

The KRAFTON access token must be a KID/accounts.krafton.com token.  A PUBG
FOC token is intended for api-foc.krafton.com and is not a replacement for an
account-center session.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from typing import Iterable
from urllib.parse import urlparse

import requests


KRAFTON_HOST = "accounts.krafton.com"
SOOP_SUFFIX = ".sooplive.com"
LINK_URL = "https://accounts.krafton.com/v2/auth/soop"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36"


class LinkError(RuntimeError):
    """The provider flow could not be started or completed."""


@dataclass(frozen=True)
class LinkResult:
    status: str
    message: str
    hops: tuple[tuple[int, str], ...]

    def to_dict(self) -> dict:
        return asdict(self)


def _cookie_items(raw_cookie: str) -> Iterable[tuple[str, str]]:
    for item in raw_cookie.replace("\r", " ").replace("\n", " ").split(";"):
        name, separator, value = item.strip().partition("=")
        if separator and name and value:
            yield name, value


def _add_domain_cookies(session: requests.Session, raw_cookie: str, domain: str) -> None:
    for name, value in _cookie_items(raw_cookie):
        session.cookies.set(name, value, domain=domain, path="/")


def _host_path(url: str) -> str:
    """Expose redirect progress without returning OAuth code or state values."""
    parsed = urlparse(url)
    return f"{parsed.netloc}{parsed.path}"


def _request(session: requests.Session, url: str, headers: dict[str, str]) -> requests.Response:
    return session.get(url, headers=headers, allow_redirects=False, timeout=20)


def link_soop(
    *,
    kid_access_token: str = "",
    krafton_session_cookie: str = "",
    soop_cookie: str,
    confirm: bool = False,
) -> LinkResult:
    """Start or complete a KRAFTON-to-SOOP OAuth link.

    ``confirm=False`` validates whether KRAFTON will start the provider flow.
    Set ``confirm=True`` only after the user has approved completing the
    binding.  The function never returns tokens, cookies, authorization codes,
    or OAuth state values.
    """
    if not soop_cookie.strip():
        raise LinkError("SOOP Cookie is required.")
    if not kid_access_token.strip() and not krafton_session_cookie.strip():
        raise LinkError("A KRAFTON KID token or accounts.krafton.com session cookie is required.")

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
    _add_domain_cookies(session, soop_cookie, SOOP_SUFFIX)
    _add_domain_cookies(session, krafton_session_cookie, KRAFTON_HOST)

    krafton_headers = {"Referer": "https://accounts.krafton.com/v2/en/settings/connections-accounts"}
    if kid_access_token.strip():
        krafton_headers["Authorization"] = f"Bearer {kid_access_token.strip()}"

    response = _request(session, LINK_URL, krafton_headers)
    hops = [(response.status_code, _host_path(response.url))]
    redirect = response.headers.get("Location")
    if response.status_code not in (301, 302, 303, 307, 308) or not redirect:
        raise LinkError(f"KRAFTON did not start the SOOP OAuth flow (HTTP {response.status_code}).")
    if not confirm:
        return LinkResult("ready", "KRAFTON accepted the account session. Confirm to follow the SOOP callback.", tuple(hops))

    next_url = requests.compat.urljoin(response.url, redirect)
    for _ in range(8):
        host = urlparse(next_url).hostname or ""
        headers = {"Referer": "https://accounts.krafton.com/"}
        if host == KRAFTON_HOST and kid_access_token.strip():
            headers["Authorization"] = f"Bearer {kid_access_token.strip()}"
        response = _request(session, next_url, headers)
        hops.append((response.status_code, _host_path(response.url)))
        redirect = response.headers.get("Location")
        if response.status_code not in (301, 302, 303, 307, 308) or not redirect:
            break
        next_url = requests.compat.urljoin(response.url, redirect)
    else:
        raise LinkError("SOOP OAuth redirect limit exceeded.")

    if urlparse(response.url).hostname != KRAFTON_HOST:
        raise LinkError("SOOP authorization did not return to KRAFTON; the SOOP Cookie may be expired.")
    return LinkResult("linked", "SOOP authorization returned to KRAFTON.", tuple(hops))


if __name__ == "__main__":
    result = link_soop(
        kid_access_token=os.environ.get("KRAFTON_KID_ACCESS_TOKEN", ""),
        krafton_session_cookie=os.environ.get("KRAFTON_SESSION_COOKIE", ""),
        soop_cookie=os.environ.get("SOOP_COOKIE", ""),
        confirm=os.environ.get("KRAFTON_SOOP_CONFIRM") == "1",
    )
    print(result.to_dict())
