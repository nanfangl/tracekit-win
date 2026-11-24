"""CI 断言：检查一次轻量记录是否真的抓到了数据，并生成了报告。

带完整诊断：任何一步失败都会把目录清单、事件计数、报告开头、异常栈全部打出来，
CI 页面上直接能看到原因（不用去下载日志）。
"""
from __future__ import annotations

import os
import sqlite3
import sys
import traceback

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def dump(run_dir: str) -> None:
    print(f"[诊断] run_dir = {os.path.abspath(run_dir)}")
    if not os.path.isdir(run_dir):
        print("[诊断] 目录不存在")
        return
    for name in sorted(os.listdir(run_dir)):
        path = os.path.join(run_dir, name)
        if os.path.isfile(path):
            print(f"[诊断]   {name}  {os.path.getsize(path)} B")
        else:
            try:
                n = len(os.listdir(path))
            except OSError:
                n = -1
            print(f"[诊断]   [{name}] {n} 个")


def main(run_dir: str) -> int:
    try:
        db = os.path.join(run_dir, "events.sqlite")
        if not os.path.exists(db):
            dump(run_dir)
            print("FAIL: 没有 events.sqlite")
            return 1
        conn = sqlite3.connect(db)
        counts = dict(conn.execute("select cat, count(*) from events group by cat"))
        conn.close()
        print("事件计数:", counts)
        if counts.get("mark", 0) <= 0:
            dump(run_dir)
            print("FAIL: 缺少 mark 事件")
            return 1
        if counts.get("proc", 0) <= 0 and counts.get("file", 0) <= 0:
            dump(run_dir)
            print("FAIL: proc 与 file 都是 0，说明记录器没挂上")
            return 1

        report = os.path.join(run_dir, "报告.md")
        if not os.path.exists(report):
            dump(run_dir)
            print("FAIL: 没有生成 报告.md（报告层出错，检查上面步骤输出）")
            return 1
        with open(report, encoding="utf-8-sig", errors="replace") as fh:
            head = fh.read(400)
        print("[诊断] 报告开头:", head.splitlines()[0][:80] if head else "(空)")
        if "TraceKit" not in head:
            print("FAIL: 报告内容异常")
            return 1
        print("SMOKE OK  ->", os.path.abspath(run_dir))
        return 0
    except Exception:
        dump(run_dir)
        traceback.print_exc()
        print("FAIL: 断言脚本异常")
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "ci-run"))
