"""Self-test helper: click controls of the demo window like a user would.

    python tools/click_demo.py --button 开始处理 --times 2
    python tools/click_demo.py --button 启用记录 --times 1

It looks the form up by its window class (default WTWindow), resolves the child
control by caption, moves the real cursor and synthesises a click, so the
global low level hook in TraceKit sees it exactly like a human click.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tracekit import winapi  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--class", dest="cls", default="WTWindow")
    ap.add_argument("--title", default=None)
    ap.add_argument("--button", default="开始处理", help="控件标题（子串匹配）")
    ap.add_argument("--times", type=int, default=1)
    ap.add_argument("--gap", type=float, default=0.9)
    ap.add_argument("--list", action="store_true", help="只列出控件，不点击")
    ap.add_argument("--type", default=None, help="点击后往焦点控件输入的文本")
    args = ap.parse_args()

    found = winapi.find_window(args.cls, args.title)
    if not found:
        print(f"没找到窗口 class={args.cls} title={args.title}")
        return 2
    hwnd, title, cls, pid = found
    print(f"窗口: {title!r} class={cls} pid={pid} hwnd={hwnd}")
    ok = winapi.activate(hwnd)
    winapi.set_topmost(hwnd, True)
    time.sleep(0.6)
    fg = winapi.foreground_info()
    print(f"激活: {ok}  前台={fg['title']!r} pid={fg['pid']}")

    controls = winapi.enum_children(hwnd)
    for child, ccls, ctext, rect in controls:
        print(f"  [{ccls:<16}] id={winapi.user32.GetDlgCtrlID(child):<6} "
              f"{(ctext or '')[:40]!r} {rect}")
    if args.list:
        return 0

    target = None
    for child, ccls, ctext, rect in controls:
        if ctext and args.button in ctext:
            target = (child, ccls, ctext, rect)
            break
    if not target:
        print(f"没找到标题含 {args.button!r} 的控件")
        return 3
    child, ccls, ctext, rect = target
    x = rect["left"] + rect["width"] // 2
    y = rect["top"] + rect["height"] // 2
    print(f"点击 {ccls}「{ctext}」 at ({x},{y}) x{args.times}")
    for i in range(max(1, args.times)):
        winapi.click_at(x, y)
        print(f"  click {i + 1}")
        time.sleep(args.gap)

    if args.type:
        time.sleep(0.3)
        for ch in args.type:
            vk = ord(ch.upper())
            winapi.user32.keybd_event(vk, 0, 0, 0) if hasattr(winapi.user32, "keybd_event") else None
        print(f"typed {args.type!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
