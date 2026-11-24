"""Control-text recorder: captures what the target paints inside its own UI.

EasyLanguage (易语言) programs almost always show their "运行日志" inside a
standard Win32 control (Edit / ListBox / Static / SysListView32) on the main
form.  WM_GETTEXT is marshalled by the OS, so we can read that text out of
another process *without* injecting a single byte - which matters when the
target is VMProtect packed and would object to foreign modules.

Every change of a control's text becomes a `ui/text` event carrying the new
content (truncated for storage, full length kept in `detail.length`).
"""
from __future__ import annotations

import threading

from . import winapi

TEXT_CLASSES = {
    "edit", "richedit", "richedit20a", "richedit20w", "richedit50w",
    "static", "listbox", "combobox", "syslistview32", "systreeview32",
    "button", "msctls_statusbar32", "msctls_progress32", "wtlib_edit",
    "wtlib_richedit", "windowsui",
}
SKIP_CLASSES = {"tooltips_class32", "msctls_trackbar32"}


class ControlTextRecorder(threading.Thread):
    def __init__(self, bus, tree, interval: float = 1.0, max_chars: int = 20000,
                 logger=print):
        super().__init__(name="uictl-recorder", daemon=True)
        self.bus = bus
        self.tree = tree
        self.interval = max(0.25, interval)
        self.max_chars = max_chars
        self.log = logger
        self._stopped = threading.Event()
        self._cache: dict[tuple, str] = {}
        self._known_controls: set[tuple] = set()
        self.counts = {"changed": 0}

    def stop(self) -> None:
        self._stopped.set()

    def run(self) -> None:
        while not self._stopped.is_set():
            try:
                self._tick()
            except Exception as exc:
                self.log(f"[ui] tick failed: {exc!r}")
            self._stopped.wait(self.interval)

    def _tick(self) -> None:
        scope = self.tree.scope()
        if not scope:
            return
        for hwnd, title, cls, pid in winapi.enum_windows():
            if pid not in scope:
                continue
            controls = winapi.enum_children(hwnd)
            for child, ccls, ctext, rect in controls:
                low = (ccls or "").lower()
                if low in SKIP_CLASSES:
                    continue
                if not ctext:
                    continue
                if low not in TEXT_CLASSES and len(ctext) < 4:
                    continue
                key = (hwnd, child)
                prev = self._cache.get(key)
                if prev == ctext:
                    continue
                self._cache[key] = ctext
                is_new = key not in self._known_controls
                self._known_controls.add(key)
                payload = ctext[: self.max_chars]
                self.counts["changed"] += 1
                self.bus.emit(
                    "ui", "text_new" if is_new else "text",
                    pid=pid, ppid=self.tree.ppid(pid), proc=self.tree.name(pid),
                    path=(payload[:200].replace("\r\n", " | ") if payload else ""),
                    detail={
                        "window": title, "window_hwnd": hwnd,
                        "control_class": ccls, "control_hwnd": child,
                        "length": len(ctext), "text": payload,
                        "rect": rect,
                        "first_seen": is_new,
                        "prev_length": len(prev) if prev is not None else None,
                    },
                )
        # forget controls whose window vanished
        alive = {k for k in self._cache if winapi.user32.IsWindow(k[1])}
        for key in set(self._cache) - alive:
            self._cache.pop(key, None)
