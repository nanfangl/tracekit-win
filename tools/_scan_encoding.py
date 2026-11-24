"""扫描：哪些地方在读写文本时没显式指定 encoding（en-US runner 上是 cp1252，会炸）。"""
from __future__ import annotations

import io
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")


def main(root: str = "tracekit", extra=("tools",)) -> int:
    hits = 0
    for base in (root,) + tuple(extra):
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for name in filenames:
                if not name.endswith(".py"):
                    continue
                path = os.path.join(dirpath, name)
                for i, line in enumerate(io.open(path, encoding="utf-8"), 1):
                    code = line.split("#", 1)[0]
                    if "encoding" in code:
                        continue
                    if "open(" in code and ("read" in code or "write" in code or '"r"' in code
                                            or "'r'" in code or '"w"' in code or "'w'" in code
                                            or "'a'" in code or '"a"' in code):
                        print(f"{path}:{i}: {line.strip()[:120]}")
                        hits += 1
                    if "read_text(" in code or "write_text(" in code:
                        print(f"{path}:{i}: {line.strip()[:120]}")
                        hits += 1
    print(f"\n可疑点合计: {hits}")
    return 0 if hits == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(*(sys.argv[1:2] or ["tracekit"])))
