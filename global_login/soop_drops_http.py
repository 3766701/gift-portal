"""HTTP client for the official SOOP Drops claim endpoint."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any
import json
import logging

import requests


BASE_URL = "https://drops.sooplive.com/api"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36"
logger = logging.getLogger("soop.drops")


def _redact_response_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if re.search(r"cookie|token|ticket|authori[sz]ation|secret|password", str(key), re.I)
            else _redact_response_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_response_value(item) for item in value]
    return value


def _response_summary(body: Any, limit: int = 4000) -> str:
    """Serialize response data while omitting credential-like fields."""
    if isinstance(body, dict):
        text = json.dumps(_redact_response_value(body), ensure_ascii=False, separators=(",", ":"))
    else:
        text = str(body)
    return text[:limit]


class DropsError(RuntimeError):
    pass


def load_cookie_file(path: str | Path) -> str:
    """Read a cookie file containing one ``name=value`` pair per line or a header."""
    raw = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    parts = []
    for line in raw.replace("\r", "\n").split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith("cookie:"):
            line = line.split(":", 1)[1].strip()
        parts.append(line)
    return "; ".join(parts)


def normalize_cookie_header(raw_cookie: str) -> str:
    """Normalize copied multiline Cookie text into a valid HTTP Cookie header."""
    parts = []
    for item in re.split(r"[;\r\n]+", raw_cookie):
        name, separator, value = item.strip().partition("=")
        if separator and name:
            parts.append(f"{name}={value}")
    return "; ".join(parts)


@dataclass
class DropsClient:
    cookie: str
    timeout: float = 20.0

    def __post_init__(self) -> None:
        self.cookie = normalize_cookie_header(self.cookie)
        if not self.cookie:
            raise DropsError("SOOP Cookie is empty.")
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.6",
            "Origin": "https://drops.sooplive.com",
            "Referer": "https://drops.sooplive.com/inventory",
            "Cookie": self.cookie,
        })

    def _json(self, method: str, endpoint: str, *, log_body: bool = True, **kwargs: Any) -> dict[str, Any]:
        response = self.session.request(method, f"{BASE_URL}/{endpoint}", timeout=self.timeout, **kwargs)
        try:
            body = response.json()
        except ValueError as exc:
            logger.warning("SOOP response endpoint=%s http=%s body=%s", endpoint, response.status_code, response.text[:500])
            raise DropsError(f"SOOP returned non-JSON HTTP {response.status_code}.") from exc
        if log_body:
            logger.info("SOOP response endpoint=%s http=%s body=%s", endpoint, response.status_code, _response_summary(body))
        if response.status_code >= 400:
            raise DropsError(f"SOOP returned HTTP {response.status_code}: {body.get('message', '')}")
        if not isinstance(body, dict):
            raise DropsError("SOOP returned an unexpected response shape.")
        return body

    def get_inventory_items(self) -> dict[str, dict[str, Any]]:
        """Fetch the current inventory once and index it by itemCodeIdx."""
        body = self._json(
            "POST",
            "get_drops_list.php",
            json={"pageNo": 1, "prePageNo": 200, "division": None},
            log_body=False,
        )
        items = body.get("data")
        if not isinstance(items, list):
            raise DropsError("SOOP inventory returned an unexpected data shape.")
        return {
            str(item["itemCodeIdx"]): item
            for item in items
            if isinstance(item, dict) and item.get("itemCodeIdx") is not None
        }

    def get_mission_list(self) -> dict[str, Any]:
        """Fetch the Drops mission list, including watch-task completion state."""
        return self._json("GET", "get_drops_mission_list.php", log_body=False)

    @staticmethod
    def log_inventory_preflight(item_code_idx: str | int, item: dict[str, Any]) -> None:
        logger.info(
            "SOOP inventory preflight item=%s type=%s item_type=%s acct_connected=%s used=%s expired=%s renewal=%s",
            item_code_idx, item.get("type"), item.get("itemType"), item.get("acctConn"), item.get("useFlag"),
            item.get("expFlag"), item.get("renewFlag"),
        )

    @staticmethod
    def require_claimable(item: dict[str, Any]) -> None:
        if str(item.get("type", "")).lower() != "krafton":
            raise DropsError("SOOP inventory item is not a KRAFTON reward.")
        if str(item.get("itemType")) == "4" and item.get("acctConn") is not True:
            raise DropsError("SOOP game account connection is not active for this inventory item.")
        if str(item.get("useFlag")) == "Y":
            raise DropsError("SOOP inventory item has already been claimed.")

    def claim(
        self,
        item_code_idx: str | int,
        *,
        confirm: bool = False,
        inventory_item: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Claim one eligible item. This changes SOOP inventory state."""
        if not confirm:
            raise DropsError("Claim requires confirm=True.")
        if inventory_item is None:
            inventory_item = self.get_inventory_items().get(str(item_code_idx))
            if inventory_item is None:
                raise DropsError("SOOP inventory did not contain the requested item.")
        self.log_inventory_preflight(item_code_idx, inventory_item)
        self.require_claimable(inventory_item)
        body = self._json("POST", "get_drops_use_info.php", json={"itemCodeIdx": item_code_idx})
        if body.get("result") != 1:
            raise DropsError(f"SOOP claim was rejected: {body.get('message', 'unknown result')}")
        return body


if __name__ == "__main__":
    import argparse, json
    ap = argparse.ArgumentParser()
    ap.add_argument("--cookie-file", default="soop_cookie_new.txt")
    ap.add_argument("--claim", required=True, help="SOOP itemCodeIdx to claim")
    ap.add_argument("--confirm", action="store_true")
    args = ap.parse_args()
    client = DropsClient(load_cookie_file(args.cookie_file))
    result = client.claim(args.claim, confirm=True)
    print(json.dumps(result, ensure_ascii=False))
