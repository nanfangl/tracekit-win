"""CI 断言：检查一次轻量记录是否真的抓到了数据，并生成了报告。

    python tools/ci_assert.py ci-run
"""
from __future__ import annotations

import os
import sqlite3
import sys


def main(run_dir: str) -> int:
    db = os.path.join(run_dir, "events.sqlite")
    if not os.path.exists(db):
        print(f"FAIL: 没有 {db}")
        return 1
    conn = sqlite3.connect(db)
    counts = dict(conn.execute("select cat, count(*) from events group by cat"))
    conn.close()
    print("事件计数:", counts)
    required = ("proc", "file", "mark")
    missing = [c for c in required if counts.get(c, 0) <= 0]
    if missing:
        print("FAIL: 缺少类别", missing)
        return 1
    report = os.path.join(run_dir, "报告.md")
    if not os.path.exists(report):
        print("FAIL: 没有生成 报告.md")
        return 1
    with open(report, encoding="utf-8-sig") as fh:
        head = fh.read(400)
    if "TraceKit" not in head:
        print("FAIL: 报告内容异常")
        return 1
    print("SMOKE OK  ->", os.path.abspath(run_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "ci-run"))
