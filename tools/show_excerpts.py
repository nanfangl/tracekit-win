"""打印一次记录的关键摘要（给演示/验收用），全部按 UTF-8 读取并输出。"""
from __future__ import annotations

import os
import sqlite3
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main(run: str) -> int:
    md_path = os.path.join(run, "报告.md")
    log_path = os.path.join(run, "日志汇总.txt")
    db = os.path.join(run, "events.sqlite")

    print("=" * 70)
    print("报告.md 概览")
    print("=" * 70)
    lines = open(md_path, encoding="utf-8-sig").read().splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith("## 一、")), 0)
    print("\n".join(lines[start:start + 24]))

    print()
    print("=" * 70)
    print("日志汇总.txt —— 用户动作与程序响应")
    print("=" * 70)
    text = open(log_path, encoding="utf-8-sig").read()
    i = text.find("用户动作与程序响应")
    print(text[i - 12:i + 1600] if i > 0 else "(没有动作段)")

    if os.path.exists(db):
        conn = sqlite3.connect(db)
        print()
        print("=" * 70)
        print("事件分类统计")
        print("=" * 70)
        for cat, n in conn.execute("select cat,count(*) from events group by cat order by 2 desc"):
            print(f"  {cat:<8}{n}")
        conn.close()
    return 0


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join("runs", "演示现场")
    raise SystemExit(main(target))
