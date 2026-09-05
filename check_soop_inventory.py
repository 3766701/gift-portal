"""查询已完成观看任务的 SOOP Drops，并输出后台可导入库存数据（只查询，不领取）。"""
from __future__ import annotations

import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

from global_login.soop_drops_http import DropsClient, DropsError

REWARD_LABELS = {"W": "W", "S": "S"}


def decode_item_name(value: Any) -> str:
    """将接口中偶发返回的字面量 Unicode 转义显示为中文。"""
    text = str(value or "未命名奖励")
    return text


def read_cookies(path: Path) -> list[str]:
    """读取每行 Cookie JSON，也兼容“账号<Tab>Cookie JSON”格式。"""
    cookies: list[str] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        raw_cookie = line.rsplit("\t", 1)[-1].strip()
        if not raw_cookie:
            raise ValueError(f"第 {line_number} 行缺少 SOOP Cookie。")
        cookies.append(raw_cookie)
    if not cookies:
        raise ValueError("输入文件没有可查询的账号。")
    return cookies


def cookie_header(raw_cookie: str) -> str:
    """将 Cookie JSON 或文本标准化为请求头格式。"""
    raw_cookie = raw_cookie.strip()
    if not raw_cookie.startswith("{"):
        return raw_cookie
    try:
        cookies = json.loads(raw_cookie)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Cookie JSON 格式错误：{exc.msg}") from exc
    if not isinstance(cookies, dict):
        raise ValueError("Cookie JSON 必须为对象。")
    return "; ".join(f"{key}={'' if value is None else value}" for key, value in cookies.items() if str(key).strip())


def completed_watch_reward_summary(missions: Any) -> str:
    """仅汇总 KRAFTON 已完成观看奖励；未完成奖励不写入商品名称。"""
    summary: dict[datetime, dict[str, int]] = {}
    for mission in missions if isinstance(missions, list) else []:
        if not isinstance(mission, dict) or str(mission.get("typeNm", "")).lower() != "krafton":
            continue
        tasks = [task for task in mission.get("itemList", []) if isinstance(task, dict)]
        if not tasks:
            continue
        try:
            date = datetime.strptime(str(mission.get("startDate", ""))[:10], "%Y-%m-%d")
        except ValueError:
            continue
        counts = summary.setdefault(date, {"W": 0, "S": 0})
        for task in tasks:
            if task.get("missionSuccess") is not True:
                continue
            name = decode_item_name(task.get("itemName")).casefold()
            if "welchis" in name or "웰치스" in name:
                counts["W"] += 1
            elif "soop" in name:
                counts["S"] += 1
    return "".join(
        f"{date.month}.{date.day}号"
        + "".join(
            f"{count[reward]}个{REWARD_LABELS[reward]}"
            for reward in ("W", "S")
            if count[reward]
        )
        for date, count in sorted(summary.items())
        if count["W"] or count["S"]
    )


def import_line(created_by: str, product_name: str, raw_cookie: str) -> str:
    """生成与后台库存导入完全一致的单行数据。"""
    return f"{created_by}|{product_name}|{raw_cookie}"


def s_box_count(product_name: str) -> int:
    """计算汇总商品名称中的已完成 S 宝箱数量。"""
    return sum(int(count) for count in re.findall(r"(\d+)个S", product_name))


def query_completed_rewards(raw_cookie: str, timeout: float, retries: int) -> str:
    """查询单个账号；网络或接口失败后最多重试指定次数。"""
    cookie = cookie_header(raw_cookie)
    last_error: DropsError | OSError | None = None
    for attempt in range(retries + 1):
        try:
            client = DropsClient(cookie, timeout=timeout)
            return completed_watch_reward_summary(client.get_mission_list().get("data"))
        except (DropsError, OSError) as exc:
            last_error = exc
            if attempt < retries:
                print(f"查询失败，正在重试（{attempt + 1}/{retries}）…", file=sys.stderr)
    assert last_error is not None
    raise last_error


def main() -> int:
    parser = argparse.ArgumentParser(description="仅查询 SOOP 已完成观看任务，并生成后台库存导入文件。")
    parser.add_argument("--input", default="soop_accounts.txt", help="源 TXT（每行 Cookie JSON；兼容账号 + Tab + Cookie JSON），默认 soop_accounts.txt")
    parser.add_argument("--output", default="soop_claimable_import.txt", help="后台库存导入 TXT，默认 soop_claimable_import.txt")
    parser.add_argument("--created-by", default="n1ck", help="输出库存的录入人，默认 n1ck")
    parser.add_argument("--timeout", type=float, default=20, help="SOOP 请求超时秒数，默认 20")
    parser.add_argument("--workers", type=int, default=10, help="并发查询线程数，默认 10")
    parser.add_argument("--retries", type=int, default=3, help="单个账号失败后的重试次数，默认 3")
    args = parser.parse_args()

    try:
        cookies = read_cookies(Path(args.input))
    except (OSError, ValueError) as exc:
        print(f"读取输入失败：{exc}", file=sys.stderr)
        return 2

    completed_records: list[tuple[int, str, str]] = []
    total_completed = 0
    created_by = args.created_by.strip() or "n1ck"
    workers = max(1, min(args.workers, len(cookies)))
    retries = max(0, args.retries)
    results: dict[int, tuple[str, str | None]] = {}
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="soop-query") as executor:
        futures = {
            executor.submit(query_completed_rewards, raw_cookie, args.timeout, retries): (index, raw_cookie)
            for index, raw_cookie in enumerate(cookies, start=1)
        }
        for future in as_completed(futures):
            index, raw_cookie = futures[future]
            try:
                results[index] = (raw_cookie, future.result())
            except (DropsError, OSError, ValueError) as exc:
                results[index] = (raw_cookie, None)
                print(f"第 {index} 条 Cookie 查询失败：{exc}", file=sys.stderr)

    for index in range(1, len(cookies) + 1):
        raw_cookie, product_name = results.get(index, (cookies[index - 1], None))
        if not product_name:
            print(f"第 {index} 条 Cookie：未识别到已完成观看任务，跳过。")
            continue
        total_completed += 1
        completed_records.append((index, product_name, raw_cookie))
        print(f"第 {index} 条 Cookie：已写入汇总库存：{product_name}")

    output = Path(args.output)
    completed_records.sort(key=lambda record: (-s_box_count(record[1]), record[0]))
    output_lines = [import_line(created_by, product_name, raw_cookie) for _, product_name, raw_cookie in completed_records]
    output.write_text("\n".join(output_lines) + ("\n" if output_lines else ""), encoding="utf-8")
    print(f"查询完成：{output.resolve()}（合计完成 {total_completed} 项）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
