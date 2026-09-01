"""HTTP client for the official SOOP Drops inventory and claim endpoints."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests


BASE_URL = "https://drops.sooplive.com/api"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36"


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


@dataclass
class DropsClient:
    cookie: str
    timeout: float = 20.0

    def __post_init__(self) -> None:
        if not self.cookie.strip():
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

    def _json(self, method: str, endpoint: str, **kwargs: Any) -> dict[str, Any]:
        response = self.session.request(method, f"{BASE_URL}/{endpoint}", timeout=self.timeout, **kwargs)
        try:
            body = response.json()
        except ValueError as exc:
            raise DropsError(f"SOOP returned non-JSON HTTP {response.status_code}.") from exc
        if response.status_code >= 400:
            raise DropsError(f"SOOP returned HTTP {response.status_code}: {body.get('message', '')}")
        if not isinstance(body, dict):
            raise DropsError("SOOP returned an unexpected response shape.")
        return body

    def inventory(self, page_no: int = 1, page_size: int = 20, division: str = "all") -> dict[str, Any]:
        """Return the authenticated account's Drops inventory."""
        payload = {"pageNo": int(page_no), "prePageNo": int(page_size), "division": None if division == "all" else division}
        return self._json("POST", "get_drops_list.php", json=payload)

    def missions(self) -> dict[str, Any]:
        return self._json("GET", "get_drops_mission_list.php")

    def claim(self, item_code_idx: str | int, *, confirm: bool = False) -> dict[str, Any]:
        """Claim one eligible item. This changes SOOP inventory state."""
        if not confirm:
            raise DropsError("Claim requires confirm=True.")
        return self._json("POST", "get_drops_use_info.php", json={"itemCodeIdx": item_code_idx})


if __name__ == "__main__":
    import argparse, json
    ap = argparse.ArgumentParser()
    ap.add_argument("--cookie-file", default="soop_cookie_new.txt")
    ap.add_argument("--claim", default="")
    ap.add_argument("--confirm", action="store_true")
    args = ap.parse_args()
    client = DropsClient(load_cookie_file(args.cookie_file))
    result = client.claim(args.claim, confirm=True) if args.claim else client.inventory()
    print(json.dumps(result, ensure_ascii=False))
