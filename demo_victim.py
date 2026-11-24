"""A stand-in for the real target, used to prove every TraceKit recorder works.

It mimics the shape of an EasyLanguage (易语言) desktop program:

  * a Win32 window whose class is `WTWindow` (the class EasyLanguage uses)
  * a multiline EDIT control that holds the program's own "运行日志" text
  * file create / write / append / rename / delete inside its working folder
  * a .ini style config in the registry (HKCU\\Software\\TraceKitDemo)
  * a TCP listener + loopback client, and a UDP packet
  * console output (stdout) and a spawned child process

Usage:
    python demo_victim.py --workdir C:\\temp\\tkdemo --seconds 30
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import os
import random
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

WS_OVERLAPPEDWINDOW = 0x00CF0000
WS_CHILD = 0x40000000
WS_VISIBLE = 0x10000000
WS_VSCROLL = 0x00200000
ES_MULTILINE = 0x0004
ES_AUTOVSCROLL = 0x0040
SW_SHOW = 5
WM_DESTROY = 0x0002
WM_SETTEXT = 0x000C
WM_COMMAND = 0x0111
WM_CLOSE = 0x0010
BS_AUTOCHECKBOX = 0x0003
ID_BTN_START = 1001
ID_CHK_RECORD = 1002

WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.UINT), ("style", wt.UINT), ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
        ("hInstance", wt.HINSTANCE), ("hIcon", wt.HICON), ("hCursor", wt.HANDLE),
        ("hbrBackground", wt.HBRUSH), ("lpszMenuName", wt.LPCWSTR),
        ("lpszClassName", wt.LPCWSTR), ("hIconSm", wt.HICON),
    ]


user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
user32.CreateWindowExW.restype = wt.HWND
user32.CreateWindowExW.argtypes = [
    wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, ctypes.c_int, ctypes.c_int,
    ctypes.c_int, ctypes.c_int, wt.HWND, wt.HMENU, wt.HINSTANCE, wt.LPVOID,
]
user32.DefWindowProcW.restype = ctypes.c_ssize_t
user32.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
user32.ShowWindow.argtypes = [wt.HWND, ctypes.c_int]
user32.SendMessageW.restype = wt.LPARAM
user32.SendMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, ctypes.c_void_p]
user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]

lines: list[str] = []
_lock = threading.Lock()
edit_hwnd = None
status_hwnd = None
btn_hwnd = None
chk_hwnd = None
click_count = 0
record_enabled = False
workdir_global = os.path.join(os.getcwd(), "demo-work")
form_hwnd = None


def set_text(hwnd, text) -> None:
    if not hwnd:
        return
    cbuf = ctypes.c_wchar_p(text)
    user32.SendMessageW(hwnd, WM_SETTEXT, 0, ctypes.cast(cbuf, ctypes.c_void_p))


def on_button_start() -> None:
    """What the app does when the user presses 【开始处理】."""
    global click_count
    click_count += 1
    set_text(status_hwnd, f"已点击 {click_count} 次")
    ui_log(f"按钮点击 -> 第 {click_count} 次处理")
    try:
        os.makedirs(os.path.join(workdir_global, "data"), exist_ok=True)
        with open(os.path.join(workdir_global, "data", f"button_{click_count}.txt"),
                  "w", encoding="utf-8") as fh:
            fh.write(f"button_click={click_count}\nrecord_enabled={record_enabled}\n")
    except OSError:
        pass


def ui_log(text: str) -> None:
    """Append a line to the on-screen log control (what TraceKit reads back)."""
    stamp = datetime.now().strftime("%H:%M:%S")
    with _lock:
        lines.append(f"[{stamp}] {text}")
        if len(lines) > 200:
            del lines[:-200]
        blob = "\r\n".join(lines)
    if edit_hwnd:
        cbuf = ctypes.c_wchar_p(blob)
        user32.SendMessageW(edit_hwnd, WM_SETTEXT, 0, ctypes.cast(cbuf, ctypes.c_void_p))


def console(text: str) -> None:
    print(f"[APP] {text}", flush=True)


def workload(workdir: str, seconds: float) -> None:
    import winreg

    os.makedirs(workdir, exist_ok=True)
    data_dir = os.path.join(workdir, "data")
    os.makedirs(data_dir, exist_ok=True)
    log_path = os.path.join(workdir, "app.log")
    ini_path = os.path.join(workdir, "config.ini")
    tmp_file = os.path.join(os.environ.get("TEMP", workdir), "tracekit_demo_read.txt")

    with open(ini_path, "w", encoding="utf-8") as fh:
        fh.write("[main]\nserver=127.0.0.1\nport=8080\nmode=demo\n")
    with open(tmp_file, "w", encoding="utf-8") as fh:
        fh.write("this file is only read, never written\n")

    # registry: this is what a real EasyLanguage app does for its settings
    try:
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, r"Software\TraceKitDemo",
                                 0, winreg.KEY_ALL_ACCESS)
        counter = 0
        for i in range(6):
            counter += 1
            winreg.SetValueEx(key, "RunCount", 0, winreg.REG_DWORD, counter)
            winreg.SetValueEx(key, "LastRun", 0, winreg.REG_SZ,
                              datetime.now().isoformat(timespec="seconds"))
            time.sleep(0.4)
        winreg.SetValueEx(key, "DeviceId", 0, winreg.REG_SZ, "DEMO-0001")
        winreg.CloseKey(key)
    except Exception as exc:
        console(f"registry failed: {exc}")

    # network: listener + loopback client + udp
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]
    ui_log(f"监听端口 {port}")

    def _serve():
        for _ in range(3):
            try:
                conn, _addr = srv.accept()
                with conn:
                    data = conn.recv(256)
                    conn.sendall(b"HTTP/1.1 200 OK\r\n\r\nok:" + data[:32])
            except OSError:
                break

    threading.Thread(target=_serve, daemon=True).start()

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.sendto(b"demo-beacon", ("127.0.0.1", port))

    subprocess.Popen(
        [os.environ.get("COMSPEC", "cmd.exe"), "/c", "echo tracekit-child >",
         os.path.join(data_dir, "child.txt")],
        creationflags=0x08000000,
    )
    ui_log("已启动子进程 cmd.exe")

    started = time.time()
    n = 0
    while time.time() - started < seconds:
        n += 1
        msg = f"第 {n} 轮：读取配置、写入数据、刷新界面"
        console(msg)
        ui_log(msg)
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now().isoformat(timespec='seconds')} {msg}\n")
        path = os.path.join(data_dir, f"record_{n:03d}.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"round={n}\nvalue={random.random():.6f}\n")
        with open(tmp_file, "r", encoding="utf-8") as fh:
            fh.read()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0) as cli:
                cli.sendall(f"GET /round/{n} HTTP/1.0\r\n\r\n".encode())
                cli.recv(128)
        except OSError:
            pass
        if n % 3 == 0 and n > 1:
            old = os.path.join(data_dir, f"record_{n - 1:03d}.txt")
            new = os.path.join(data_dir, f"record_{n - 1:03d}.bak")
            try:
                os.replace(old, new)
                ui_log(f"重命名 {os.path.basename(old)} -> {os.path.basename(new)}")
            except OSError:
                pass
        if n % 4 == 0:
            victim = os.path.join(data_dir, f"temp_{n:03d}.tmp")
            with open(victim, "w", encoding="utf-8") as fh:
                fh.write("temporary")
            os.remove(victim)
            ui_log("删除临时文件")
        time.sleep(1.6)
    ui_log("任务结束，退出")
    console("bye")
    time.sleep(0.8)
    # PostQuitMessage must run on the thread that owns the message loop, so ask
    # the window to close and let WM_DESTROY do it
    if form_hwnd:
        user32.PostMessageW(form_hwnd, WM_CLOSE, 0, 0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", default=os.path.join(os.getcwd(), "demo-work"))
    ap.add_argument("--seconds", type=float, default=25.0)
    args = ap.parse_args()
    global workdir_global
    workdir_global = args.workdir

    global form_hwnd, edit_hwnd, status_hwnd, btn_hwnd, chk_hwnd
    hinst = kernel32.GetModuleHandleW(None)

    @WNDPROC
    def _wndproc(hwnd, msg, wp, lp):
        global record_enabled
        if msg == WM_COMMAND:
            cid = int(wp) & 0xFFFF
            if cid == ID_BTN_START:
                on_button_start()
                return 0
            if cid == ID_CHK_RECORD:
                record_enabled = not record_enabled
                ui_log(f"复选框【启用记录】{'勾选' if record_enabled else '取消'}")
                return 0
        if msg == WM_CLOSE:
            ui_log("窗口关闭请求")
        if msg == WM_DESTROY:
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, msg, wp, lp)

    global edit_hwnd
    wc = WNDCLASSEXW()
    wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
    wc.lpfnWndProc = _wndproc
    wc.hInstance = hinst
    wc.lpszClassName = "WTWindow"          # EasyLanguage window class
    wc.hbrBackground = gdi32.CreateSolidBrush(0x00F0F0F0)
    if not user32.RegisterClassExW(ctypes.byref(wc)):
        print("register class failed", ctypes.get_last_error())
        return 1

    hwnd = user32.CreateWindowExW(
        0, "WTWindow", "演示程序 - 易语言风格窗口 VMP 模拟", WS_OVERLAPPEDWINDOW,
        120, 120, 760, 560, None, None, hinst, None,
    )
    if not hwnd:
        print("create window failed", ctypes.get_last_error())
        return 1
    edit_hwnd = user32.CreateWindowExW(
        0, "EDIT", "运行日志：\r\n",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL,
        10, 10, 720, 440, hwnd, None, hinst, None,
    )
    status_hwnd = user32.CreateWindowExW(
        0, "STATIC", "已点击 0 次", WS_CHILD | WS_VISIBLE,
        10, 458, 200, 22, hwnd, 1003, hinst, None,
    )
    btn_hwnd = user32.CreateWindowExW(
        0, "BUTTON", "开始处理", WS_CHILD | WS_VISIBLE | 0x00000000,
        230, 456, 140, 30, hwnd, ID_BTN_START, hinst, None,
    )
    chk_hwnd = user32.CreateWindowExW(
        0, "BUTTON", "启用记录", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        390, 460, 160, 24, hwnd, ID_CHK_RECORD, hinst, None,
    )
    form_hwnd = hwnd
    # 菜单栏：用来验证「界面结构」能抓到菜单树
    user32.CreateMenu.restype = wt.HMENU
    user32.CreatePopupMenu.restype = wt.HMENU
    user32.AppendMenuW.argtypes = [wt.HMENU, wt.UINT, ctypes.c_size_t, wt.LPCWSTR]
    user32.SetMenu.argtypes = [wt.HWND, wt.HMENU]
    menubar = user32.CreateMenu()
    for title, items in (
        ("文件", [("打开(&O)", 2001), ("保存(&S)", 2002), ("退出(&X)", 2003)]),
        ("编辑", [("复制(&C)", 2011), ("粘贴(&V)", 2012), ("全选(&A)", 2013)]),
        ("帮助", [("使用说明(&H)", 2021), ("关于(&A)", 2022)]),
    ):
        sub = user32.CreatePopupMenu()
        for text, cmd in items:
            user32.AppendMenuW(sub, 0x0000, cmd, text)
        user32.AppendMenuW(menubar, 0x0010, sub, title)
    user32.SetMenu(hwnd, menubar)
    user32.ShowWindow(hwnd, SW_SHOW)
    ui_log("程序启动，加载配置")

    threading.Thread(target=workload, args=(args.workdir, args.seconds), daemon=True).start()

    msg = wt.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        user32.TranslateMessage(ctypes.byref(msg))
        user32.DispatchMessageW(ctypes.byref(msg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
