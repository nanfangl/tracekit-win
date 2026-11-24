"""命令行速查：打印一次记录的事件分类、样例、新产物清单。"""
from __future__ import annotations

import glob
import json
import os
import sqlite3
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main(run: str) -> int:
    db = os.path.join(run, "events.sqlite")
    print("RUN:", run)
    if not os.path.exists(db):
        print("没有 events.sqlite")
        return 2
    conn = sqlite3.connect(db)
    print("\n=== 按 cat/act 计数 ===")
    for cat, act, n in conn.execute(
            "select cat, act, count(*) from events group by cat, act order by cat, act desc"):
        print(f"  {cat:<8}{act:<16}{n}")

    print("\n=== 新增层面样例 ===")
    for cat, act in (("ui", "tree_new"), ("clip", "copy_image"), ("clip", "copy_files"),
                     ("module", "load"), ("sys", "added"), ("sys", "changed"),
                     ("file", "snapshot"), ("net", "host"), ("net", "host_unknown")):
        rows = list(conn.execute(
            "select ts, pid, proc, path, detail from events where cat=? and act=? limit 2",
            (cat, act)))
        if not rows:
            continue
        for ts, pid, proc, path, detail in rows:
            try:
                d = json.loads(detail or "{}")
            except Exception:
                d = {}
            if cat == "ui" and act.startswith("tree"):
                print(f"  [{cat}/{act}] {ts[11:23]} 窗口={path} "
                      f"菜单={d.get('menu_count')} 控件={d.get('control_count')}")
                menu_txt = [m.get("text") for m in (d.get("menus") or [])][:6]
                if menu_txt:
                    print(f"      菜单栏: {menu_txt}")
            elif cat == "clip":
                print(f"  [{cat}/{act}] {ts[11:23]} {path[:60]} files={d.get('file_count')} "
                      f"image={d.get('image')}")
            elif cat == "module":
                print(f"  [{cat}/{act}] {ts[11:23]} {proc} <- {os.path.basename(path or '')}")
            elif cat == "file":
                print(f"  [{cat}/{act}] {ts[11:23]} {path} -> {d.get('copy')} "
                      f"({d.get('size')}B)")
            else:
                print(f"  [{cat}/{act}] {ts[11:23]} {path} {str(d)[:100]}")

    print("\n=== 产物 ===")
    for name in sorted(os.listdir(run)):
        p = os.path.join(run, name)
        if os.path.isfile(p):
            print(f"  {name:<22}{os.path.getsize(p) / 1024:8.1f} KB")
        else:
            print(f"  [{name}]  {len(os.listdir(p))} 个")
    conn.close()
    return 0


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else sorted(glob.glob("runs/*"))[-1]
    raise SystemExit(main(target))
