"""检查一次记录产出的文件：名字、编码、中文完整性（是否是乱码）。

    python tools/verify_outputs.py runs\\selftest

输出全部用 ascii 转义打印，避免终端编码干扰判断。
"""
from __future__ import annotations

import os
import sys

HUMAN = (".md", ".txt")
MACHINE = (".jsonl", ".html", ".json", ".sqlite", ".log")


def check(run_dir: str) -> int:
    if not os.path.isdir(run_dir):
        print("目录不存在:", run_dir)
        return 2
    problems = []
    print("=== 文件清单 ===")
    for name in sorted(os.listdir(run_dir)):
        path = os.path.join(run_dir, name)
        if os.path.isdir(path):
            n = len(os.listdir(path))
            print(f"  [目录] {ascii(name):<28} {n} 个文件")
            continue
        raw = open(path, "rb").read()
        bom = raw.startswith(b"\xef\xbb\xbf")
        kind = "UTF8+BOM" if bom else "UTF8"
        print(f"  {ascii(name):<28} {kind:<9} {len(raw) / 1024:8.1f} KB")
        if name.endswith(HUMAN) and not bom:
            problems.append(f"{name} 缺少 BOM（记事本可能按 GBK 打开）")
        if name.endswith(MACHINE) and name.endswith(".jsonl") and bom:
            problems.append(f"{name} 不应有 BOM")

    print("\n=== 中文内容抽样（unicode 转义，便于核对）===")
    for name in sorted(os.listdir(run_dir)):
        path = os.path.join(run_dir, name)
        if not os.path.isfile(path) or not name.endswith((".md", ".txt", ".html", ".jsonl")):
            continue
        txt = open(path, "rb").read().decode("utf-8-sig", "replace")
        if "\ufffd" in txt:
            problems.append(f"{name} 含替换符 U+FFFD（乱码）x{txt.count(chr(0xFFFD))}")
        cjk = sum(1 for ch in txt if "\u4e00" <= ch <= "\u9fff")
        print(f"  {ascii(name):<28} 中文字符 {cjk:>6}")
        for line in [l for l in txt.splitlines() if any("\u4e00" <= c <= "\u9fff" for c in l)][:2]:
            print("      ", ascii(line)[:130])

    print("\n=== 结论 ===")
    if problems:
        for p in problems:
            print("  [问题]", p)
        return 1
    print("  全部文件编码正确、无乱码、中文可读")
    return 0


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join("runs", "selftest")
    raise SystemExit(check(target))
