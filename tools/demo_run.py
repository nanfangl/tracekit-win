"""当面演示脚本：用 TraceKit.exe 录内置演示程序，真人式点按钮/打字，并截图留证。

    python tools/demo_run.py --seconds 30

流程：
  1. 启动 TraceKit.exe run ... -- TraceKitDemo.exe
  2. 等演示窗口出现 → 置顶 → 截「启动」
  3. 点【启用记录】→ 截「勾选」；点【开始处理】两次 → 截「按钮响应」
  4. 点日志框 → 敲 TRACE → 截「按键」
  5. 等记录器退出，打印统计与产物路径
"""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import time
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tracekit import winapi  # noqa: E402

SHOTS = os.path.join(ROOT, "演示截图")
DEMO = os.path.join(os.path.dirname(ROOT), "TraceKitDemo.exe")
TK = os.path.join(os.path.dirname(ROOT), "TraceKit.exe")


def dpi_aware() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # per-monitor
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def find_demo_window(timeout: float = 20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        f = winapi.find_window("WTWindow", "演示程序")
        if f:
            return f
        time.sleep(0.3)
    return None


def crop(hwnd, name: str) -> str | None:
    try:
        from PIL import ImageGrab
    except Exception:
        return None
    rect = winapi.window_rect(hwnd)
    if not rect or rect["width"] <= 0:
        return None
    pad = 8
    bbox = (rect["left"] - pad, rect["top"] - pad,
            rect["left"] + rect["width"] + pad, rect["top"] + rect["height"] + pad)
    img = ImageGrab.grab(bbox=bbox, all_screens=True)
    os.makedirs(SHOTS, exist_ok=True)
    path = os.path.join(SHOTS, name)
    img.save(path)
    print(f"  截图 -> {path}  {img.size}")
    return path


def click_control(hwnd, caption: str, settle: float = 1.0) -> bool:
    for child, ccls, ctext, rect in winapi.enum_children(hwnd):
        if ctext and caption in ctext:
            x = rect["left"] + rect["width"] // 2
            y = rect["top"] + rect["height"] // 2
            winapi.click_at(x, y, settle=settle)
            print(f"  点击 {ccls}「{ctext}」 @({x},{y})")
            return True
    print(f"  !! 没找到控件 {caption!r}")
    return False


def type_keys(text: str) -> None:
    for ch in text:
        vk = ord(ch.upper())
        winapi.user32.keybd_event(vk, 0, 0, 0)
        time.sleep(0.09)
        winapi.user32.keybd_event(vk, 0, 2, 0)
        time.sleep(0.06)
    print(f"  输入按键 {text}")


def put_image_on_clipboard() -> bool:
    """把一张图片放进剪贴板（CF_DIB），验证多格式剪贴板记录。"""
    try:
        import io as _io

        from PIL import Image, ImageDraw

        img = Image.new("RGB", (280, 140), (250, 250, 252))
        d = ImageDraw.Draw(img)
        d.rectangle([8, 8, 272, 132], outline=(200, 40, 40), width=3)
        d.text((20, 22), "TraceKit clipboard image test", fill=(20, 20, 20))
        d.text((20, 46), "CF_DIB -> 剪贴板图片\\", fill=(60, 60, 60))
        buf = _io.BytesIO()
        img.save(buf, "BMP")
        dib = buf.getvalue()[14:]          # 去掉 14 字节 BMP 头就是 DIB

        k32 = ctypes.windll.kernel32
        u32 = ctypes.windll.user32
        k32.GlobalAlloc.restype = ctypes.c_void_p
        k32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
        k32.GlobalLock.restype = ctypes.c_void_p
        k32.GlobalLock.argtypes = [ctypes.c_void_p]
        u32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
        u32.SetClipboardData.restype = ctypes.c_void_p

        handle = k32.GlobalAlloc(0x0002, len(dib))
        ptr = k32.GlobalLock(handle)
        ctypes.memmove(ptr, dib, len(dib))
        k32.GlobalUnlock(handle)
        if not u32.OpenClipboard(None):
            return False
        u32.EmptyClipboard()
        u32.SetClipboardData(8, handle)    # CF_DIB
        u32.CloseClipboard()
        print("  剪贴板放入一张图片 (CF_DIB)")
        return True
    except Exception as exc:
        print("  剪贴板图片失败:", exc)
        return False


def main() -> int:
    dpi_aware()
    for proc in ("TraceKitDemo", "TraceKit"):
        subprocess.call(["taskkill", "/F", "/IM", f"{proc}.exe"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    seconds = 30
    if "--seconds" in sys.argv:
        seconds = int(sys.argv[sys.argv.index("--seconds") + 1])
    workdir = os.path.join(ROOT, "演示数据")
    os.makedirs(workdir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join(ROOT, "runs", f"演示现场-{stamp}")

    via = "exe"
    if "--via" in sys.argv:
        via = sys.argv[sys.argv.index("--via") + 1]
    prof = None
    if "--profile" in sys.argv:
        prof = sys.argv[sys.argv.index("--profile") + 1]
    base = [sys.executable, "-m", "tracekit"] if via == "python" else [TK]
    cmd = base + ["run", "--name", "演示现场", "--watch-dir", workdir,
                  "--out", run_dir, "--shot-interval", "20", "--exclude-dir", SHOTS]
    if prof:
        cmd += ["--profile", prof]
    cmd += ["--", DEMO, "--workdir", workdir, "--seconds", str(seconds)]
    print("启动:", " ".join(cmd))
    log_path = os.path.join(os.environ.get("TEMP", "."), f"tracekit_demo_console-{stamp}.log")
    os.makedirs(SHOTS, exist_ok=True)
    log_fh = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=log_fh, stderr=subprocess.STDOUT)

    found = find_demo_window()
    if not found:
        print("!! 演示窗口没出现，查看", log_path)
        proc.terminate()
        return 2
    hwnd, title, cls, pid = found
    print(f"窗口就绪: {title!r} pid={pid}")
    winapi.activate(hwnd)
    winapi.set_topmost(hwnd, True)
    time.sleep(1.0)

    crop(hwnd, "01-启动.png")

    click_control(hwnd, "启用记录", settle=0.2)
    time.sleep(1.2)
    crop(hwnd, "02-勾选复选框.png")

    click_control(hwnd, "开始处理", settle=0.2)
    time.sleep(0.6)
    click_control(hwnd, "开始处理", settle=0.2)
    time.sleep(1.4)
    crop(hwnd, "03-点按钮两次.png")

    # 点日志框再打字：验证「按键落在哪个控件」
    for child, ccls, ctext, rect in winapi.enum_children(hwnd):
        if (ccls or "").lower() == "edit":
            winapi.click_at(rect["left"] + 80, rect["top"] + 60, settle=0.4)
            break
    type_keys("TRACE")
    time.sleep(1.2)
    crop(hwnd, "04-打字按键.png")

    put_image_on_clipboard()
    time.sleep(1.4)
    crop(hwnd, "05-剪贴板之后.png")

    print("等待目标系软件自己跑完并收尾 ...")
    try:
        proc.wait(timeout=seconds + 60)
    except subprocess.TimeoutExpired:
        proc.terminate()
    log_fh.close()

    print("\n=== 记录器控制台尾部 ===")
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        for line in fh.read().splitlines()[-12:]:
            print("  " + line)

    print("\n=== 产物 ===")
    for name in sorted(os.listdir(run_dir)) if os.path.isdir(run_dir) else []:
        p = os.path.join(run_dir, name)
        if os.path.isfile(p):
            print(f"  {name:<22}{os.path.getsize(p) / 1024:8.1f} KB")
        else:
            print(f"  [{name}]  {len(os.listdir(p))} 个文件")
    print("\nRUN_DIR=" + run_dir)
    print("SHOTS=" + SHOTS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
