"""通用查询：对某次记录的 events.sqlite 跑一句 SQL，输出成文本。

    python tools/q.py runs\\演示现场-xxx "select act,path from events where act='tcp_send' limit 5"
"""
from __future__ import annotations

import os
import sqlite3
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    run = sys.argv[1] if len(sys.argv) > 1 else "."
    sql = sys.argv[2] if len(sys.argv) > 2 else "select cat,count(*) from events group by cat"
    db = os.path.join(run, "events.sqlite")
    conn = sqlite3.connect(db)
    cur = conn.execute(sql)
    cols = [d[0] for d in cur.description]
    print(" | ".join(cols))
    for row in cur.fetchmany(40):
        print(" | ".join("" if v is None else str(v)[:160] for v in row))
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
