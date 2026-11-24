"""检查 README 里引用的本地图片是否真的存在（防止 GitHub 上 404）。

    python tools/check_readme_images.py
"""
from __future__ import annotations

import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

IMG = re.compile(r"!\[[^\]]*\]\(([^)\s]+)")
LINK = re.compile(r"\]\((?!https?://)([^)\s]+)\)")


def main(readme: str = "README.md") -> int:
    if not os.path.exists(readme):
        print(f"FAIL: 找不到 {readme}")
        return 2
    text = open(readme, encoding="utf-8-sig", errors="replace").read()
    missing = []
    checked = 0
    for ref in IMG.findall(text):
        if ref.startswith(("http://", "https://", "data:")):
            continue
        checked += 1
        path = ref.split("#")[0].split("?")[0]
        ok = os.path.exists(path)
        print(f"  {'OK ' if ok else '404'}  {ref}")
        if not ok:
            missing.append(ref)
    # 顺带看看普通相对链接（文档互链）有没有断
    for ref in LINK.findall(text):
        if ref.startswith(("http://", "https://", "#", "mailto:")):
            continue
        path = ref.split("#")[0].split("?")[0]
        if path and not os.path.exists(path):
            print(f"  LINK-404  {ref}")
            missing.append(ref)
    print(f"\n检查了 {checked} 张本地图片，缺失 {len(missing)} 个")
    if missing:
        print("FAIL:", ", ".join(missing))
        return 1
    print("README 图片/链接全部存在")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "README.md"))
