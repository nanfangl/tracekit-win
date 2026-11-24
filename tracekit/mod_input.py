"""Global keyboard / mouse / clipboard recorder.

A WH_KEYBOARD_LL + WH_MOUSE_LL hook is installed in this process (no injection
into the target), so it keeps working against a VMProtect packed EasyLanguage
binary - the hook lives above the target and sees every key the *user* sends to
it, together with the window that had focus at that instant.

Each key event carries:
  vk        virtual key code
  key       readable name (VK_RETURN -> ENTER, letters as-is)
  char      the character produced by the active keyboard layout (ToUnicodeEx)
  mods      ctrl/alt/shift/win state
  injected  True when another program synthesised the key
  win       {pid, proc, title, class} of the focused window

Mouse moves are ignored (millions of events); clicks and wheel steps are kept.
"""
from __future__ import annotations

import ctypes
import os
import threading
import time

from . import winapi

VK_NAMES = {
    0x08: "BACKSPACE", 0x09: "TAB", 0x0D: "ENTER", 0x10: "SHIFT", 0x11: "CTRL",
    0x12: "ALT", 0x13: "PAUSE", 0x14: "CAPSLOCK", 0x1B: "ESC", 0x20: "SPACE",
    0x21: "PAGEUP", 0x22: "PAGEDOWN", 0x23: "END", 0x24: "HOME", 0x25: "LEFT",
    0x26: "UP", 0x27: "RIGHT", 0x28: "DOWN", 0x2C: "PRINTSCREEN", 0x2D: "INSERT",
    0x2E: "DELETE", 0x5B: "LWIN", 0x5C: "RWIN", 0x5D: "APPS",
    0x90: "NUMLOCK", 0x91: "SCROLLLOCK", 0xA0: "LSHIFT", 0xA1: "RSHIFT",
    0xA2: "LCTRL", 0xA3: "RCTRL", 0xA4: "LALT", 0xA5: "RALT",
    0xBA: ";", 0xBB: "=", 0xBC: ",", 0xBD: "-", 0xBE: ".", 0xBF: "/",
    0xC0: "`", 0xDB: "[", 0xDC: "\\", 0xDD: "]", 0xDE: "'",
}
for _i in range(0x30, 0x3A):
    VK_NAMES[_i] = chr(_i)
for _i in range(0x41, 0x5B):
    VK_NAMES[_i] = chr(_i)
for _i in range(0x60, 0x6A):
    VK_NAMES[_i] = f"NUM{_i - 0x60}"
for _i in range(1, 25):
    VK_NAMES[0x6F + _i] = f"F{_i}"


class _FocusCache:
    """Cached foreground window info - keeps the hook callback cheap."""

    def __init__(self, tree_provider, ttl: float = 0.8):
        self._tree = tree_provider
        self._ttl = ttl
        self._hwnd = None
        self._stamp = 0.0
        self._info = {}

    def get(self) -> dict:
        now = time.time()
        hwnd = winapi.user32.GetForegroundWindow()
        if hwnd == self._hwnd and (now - self._stamp) < self._ttl:
            return self._info
        pid = winapi.window_pid(hwnd) if hwnd else None
        info = {
            "hwnd": int(hwnd) if hwnd else None,
            "title": winapi.window_title(hwnd) if hwnd else "",
            "class": winapi.window_class(hwnd) if hwnd else "",
            "pid": pid,
            "proc": (self._tree.name(pid) if self._tree else None) if pid else None,
        }
        self._hwnd, self._stamp, self._info = hwnd, now, info
        return info


class InputRecorder:
    """Owns the two hook threads plus the clipboard poller."""

    def __init__(self, bus, tree, run_dir=None, logger=print, want_keyboard=True,
                 want_mouse=True, want_clipboard=True):
        self.bus = bus
        self.log = logger
        self.run_dir = run_dir
        self.clips_dir = os.path.join(run_dir, "剪贴板图片") if run_dir else None
        self.want_keyboard = want_keyboard
        self.want_mouse = want_mouse
        self.want_clipboard = want_clipboard
        self.focus = _FocusCache(tree)
        self._threads = []
        self._stopped = threading.Event()
        self._kb_struct = winapi.KBDLLHOOKSTRUCT
        self._ms_struct = winapi.MSLLHOOKSTRUCT
        self._clip_n = 0
        self.counts = {"key": 0, "click": 0, "clip": 0}

    # ------------------------------------------------------------------ hooks
    def start(self) -> dict:
        status = {}
        if self.want_keyboard:
            t = threading.Thread(target=self._keyboard_loop, name="kb-hook", daemon=True)
            t.start()
            self._threads.append(t)
            status["keyboard"] = True
        if self.want_mouse:
            t = threading.Thread(target=self._mouse_loop, name="ms-hook", daemon=True)
            t.start()
            self._threads.append(t)
            status["mouse"] = True
        if self.want_clipboard:
            t = threading.Thread(target=self._clipboard_loop, name="clip-poll", daemon=True)
            t.start()
            self._threads.append(t)
            status["clipboard"] = True
        return status

    def stop(self) -> None:
        self._stopped.set()
        # unposting a WM_QUIT is enough to break GetMessage
        for t in self._threads:
            try:
                ctypes.windll.user32.PostThreadMessageW(t.ident, 0x0012, 0, 0)
            except Exception:
                pass
        for t in self._threads:
            t.join(timeout=2)

    # --------------------------------------------------------------- keyboard
    def _keyboard_loop(self) -> None:
        HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int, winapi.wintypes.WPARAM,
                                      winapi.wintypes.LPARAM)

        def _proc(nCode, wParam, lParam):
            if nCode == winapi.HC_ACTION and wParam in (winapi.WM_KEYDOWN, winapi.WM_SYSKEYDOWN):
                try:
                    self._on_key(lParam)
                except Exception:
                    pass
            return winapi.user32.CallNextHookEx(None, nCode, wParam, lParam)

        self._kb_proc = HOOKPROC(_proc)  # keep alive
        hook = winapi.user32.SetWindowsHookExW(
            winapi.WH_KEYBOARD_LL, self._kb_proc, winapi.kernel32.GetModuleHandleW(None), 0
        )
        if not hook:
            self.log(f"[input] keyboard hook failed (err={ctypes.get_last_error()})")
            return
        self.log("[input] keyboard hook active")
        msg = winapi.MSG()
        while not self._stopped.is_set():
            r = winapi.user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if r in (0, -1):
                break
            winapi.user32.TranslateMessage(ctypes.byref(msg))
            winapi.user32.DispatchMessageW(ctypes.byref(msg))
        winapi.user32.UnhookWindowsHookEx(hook)

    def _on_key(self, lParam) -> None:
        kb = ctypes.cast(lParam, ctypes.POINTER(self._kb_struct)).contents
        vk = int(kb.vkCode)
        scan = int(kb.scanCode)
        mods = []
        if winapi.user32.GetKeyState(0x11) & 0x8000:
            mods.append("ctrl")
        if winapi.user32.GetKeyState(0x12) & 0x8000:
            mods.append("alt")
        if winapi.user32.GetKeyState(0x10) & 0x8000:
            mods.append("shift")
        if winapi.user32.GetKeyState(0x5B) & 0x8000 or winapi.user32.GetKeyState(0x5C) & 0x8000:
            mods.append("win")
        focus = self.focus.get()
        hkl = winapi.user32.GetKeyboardLayout(0)
        char = None
        try:
            buf = ctypes.create_unicode_buffer(8)
            arr = (ctypes.c_ubyte * 256)()
            n = winapi.user32.ToUnicodeEx(vk, scan, arr, buf, len(buf), 0, hkl)
            if n > 0:
                char = buf.value[:n]
        except Exception:
            pass
        name = VK_NAMES.get(vk, f"VK_{vk:02X}")
        self.counts["key"] += 1
        injected = bool(int(kb.flags) & 0x10)
        self.bus.emit(
            "input", "key",
            pid=focus.get("pid"), proc=focus.get("proc"),
            path=f"{name}" + (f" '{char}'" if char and char.isprintable() else ""),
            detail={
                "vk": vk, "key": name, "char": char, "scan": scan,
                "mods": mods, "injected": injected,
                "window": focus.get("title"), "window_class": focus.get("class"),
                "hwnd": focus.get("hwnd"),
            },
        )

    # ------------------------------------------------------------------ mouse
    def _mouse_loop(self) -> None:
        HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int, winapi.wintypes.WPARAM,
                                      winapi.wintypes.LPARAM)

        def _proc(nCode, wParam, lParam):
            if nCode == winapi.HC_ACTION and wParam in (
                winapi.WM_LBUTTONDOWN, winapi.WM_RBUTTONDOWN,
                winapi.WM_MBUTTONDOWN, winapi.WM_MOUSEWHEEL, winapi.WM_MOUSEHWHEEL,
            ):
                try:
                    self._on_mouse(wParam, lParam)
                except Exception:
                    pass
            return winapi.user32.CallNextHookEx(None, nCode, wParam, lParam)

        self._ms_proc = HOOKPROC(_proc)
        hook = winapi.user32.SetWindowsHookExW(
            winapi.WH_MOUSE_LL, self._ms_proc, winapi.kernel32.GetModuleHandleW(None), 0
        )
        if not hook:
            self.log(f"[input] mouse hook failed (err={ctypes.get_last_error()})")
            return
        self.log("[input] mouse hook active")
        msg = winapi.MSG()
        while not self._stopped.is_set():
            r = winapi.user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if r in (0, -1):
                break
            winapi.user32.TranslateMessage(ctypes.byref(msg))
            winapi.user32.DispatchMessageW(ctypes.byref(msg))
        winapi.user32.UnhookWindowsHookEx(hook)

    def _on_mouse(self, wParam, lParam) -> None:
        ms = ctypes.cast(lParam, ctypes.POINTER(self._ms_struct)).contents
        button = {
            winapi.WM_LBUTTONDOWN: "left", winapi.WM_RBUTTONDOWN: "right",
            winapi.WM_MBUTTONDOWN: "middle",
        }.get(wParam)
        delta = 0
        if wParam in (winapi.WM_MOUSEWHEEL, winapi.WM_MOUSEHWHEEL):
            delta = ctypes.c_short((int(ms.mouseData) >> 16) & 0xFFFF).value
            button = "wheel"
        focus = self.focus.get()
        self.counts["click"] += 1
        # resolve the control under the cursor right now: the earlier we look,
        # the more likely the window under the mouse is the one being clicked
        try:
            under = winapi.window_at(ms.pt.x, ms.pt.y)
        except Exception:
            under = None
        mods = []
        if winapi.user32.GetKeyState(0x11) & 0x8000:
            mods.append("ctrl")
        if winapi.user32.GetKeyState(0x12) & 0x8000:
            mods.append("alt")
        if winapi.user32.GetKeyState(0x10) & 0x8000:
            mods.append("shift")
        self.bus.emit(
            "input", "click" if button != "wheel" else "wheel",
            pid=focus.get("pid"), proc=focus.get("proc"),
            path=f"({ms.pt.x},{ms.pt.y})",
            detail={
                "button": button, "x": ms.pt.x, "y": ms.pt.y, "delta": delta,
                "window": focus.get("title"), "window_class": focus.get("class"),
                "hwnd": focus.get("hwnd"),
                "hwnd_under": under,
                "mods": mods,
                "injected": bool(int(ms.flags) & 0x1),
            },
        )

    # -------------------------------------------------------------- clipboard
    def _clipboard_loop(self) -> None:
        last_seq = 0
        last_sig = None
        while not self._stopped.is_set():
            try:
                seq = int(winapi.user32.GetClipboardSequenceNumber())
                if seq != last_seq:
                    last_seq = seq
                    self._capture_clipboard()
            except Exception:
                pass
            self._stopped.wait(0.4)

    def _capture_clipboard(self) -> None:
        """抓一次剪贴板：文本 + 文件列表 + 图片 + HTML，按格式分别记录。"""
        formats = winapi.clipboard_formats()
        text = winapi.clipboard_text()
        files = winapi.clipboard_dropfiles()
        html = None
        if any((f.get("name") or "").lower() == "html format" for f in formats):
            html = winapi.clipboard_html()
        image_path = None
        if self.clips_dir:
            dib = winapi.clipboard_dib()
            if dib:
                try:
                    os.makedirs(self.clips_dir, exist_ok=True)
                    self._clip_n += 1
                    name = f"剪贴板图片_{self._clip_n:04d}.bmp"
                    full = os.path.join(self.clips_dir, name)
                    with open(full, "wb") as fh:
                        fh.write(winapi.dib_to_bmp(dib))
                    image_path = name
                except OSError:
                    pass

        if not text and not files and not image_path and not html:
            return
        focus = self.focus.get()
        names = [f.get("name") for f in formats if f.get("name")]
        detail = {
            "formats": names[:12],
            "length": len(text or ""),
            "text": (text or "")[:4000],
            "files": files[:50],
            "file_count": len(files),
            "image": image_path,
            "html_len": len(html or ""),
            "window": focus.get("title"),
        }
        if html:
            detail["html"] = html[:2000]
        act = "copy_image" if (image_path and not text) else (
            "copy_files" if (files and not text) else "copy")
        preview = (text or "").replace("\r\n", " | ")[:120]
        if not preview and files:
            preview = "文件: " + "; ".join(os.path.basename(f) for f in files[:3])
        if not preview and image_path:
            preview = f"[图片] {image_path}"
        self.counts["clip"] += 1
        self.bus.emit("clip", act,
                      pid=focus.get("pid"), proc=focus.get("proc"),
                      path=preview[:200], detail=detail)
