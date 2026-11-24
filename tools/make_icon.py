"""生成 TraceKit.exe 的图标（不依赖外部素材）。"""
from __future__ import annotations

import os

from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "assets")
SIZE = 256


def build() -> str:
    os.makedirs(OUT, exist_ok=True)
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # 圆角深色底
    d.rounded_rectangle([6, 6, SIZE - 6, SIZE - 6], radius=48, fill=(18, 24, 32, 255),
                        outline=(0, 168, 232, 255), width=6)

    # 日志行
    for i, (w, c) in enumerate((
        (96, (90, 200, 255, 255)),
        (132, (60, 160, 220, 255)),
        (78, (90, 200, 255, 255)),
        (120, (60, 160, 220, 255)),
    )):
        y = 54 + i * 30
        d.rounded_rectangle([34, y, 34 + w, y + 12], radius=6, fill=c)

    # 放大镜
    d.ellipse([128, 120, 236, 228], outline=(255, 196, 64, 255), width=14)
    d.line([96, 196, 138, 154], fill=(255, 196, 64, 255), width=16)
    # 镜片里的高光
    d.arc([150, 142, 214, 206], start=200, end=290, fill=(255, 255, 255, 190), width=8)

    ico = os.path.join(OUT, "tracekit.ico")
    img.save(ico, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64),
                         (128, 128), (256, 256)])
    png = os.path.join(OUT, "tracekit.png")
    img.save(png)
    return ico


if __name__ == "__main__":
    path = build()
    print(path, os.path.getsize(path))
