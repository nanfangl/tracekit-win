"""把指定的文本文件统一成 UTF-8 带 BOM + CRLF（记事本友好）。"""
from __future__ import annotations

import sys


def convert(path: str) -> None:
    with open(path, "rb") as fh:
        raw = fh.read()
    text = raw.decode("utf-8-sig", "replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        fh.write(text)
    with open(path, "rb") as fh:
        head = fh.read(3)
    print(f"{path}: bom={head == b'\xef\xbb\xbf'} bytes={len(text.encode('utf-8'))}")


if __name__ == "__main__":
    for p in sys.argv[1:] or ["使用说明.txt"]:
        convert(p)
