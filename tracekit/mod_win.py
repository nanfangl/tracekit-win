"""Window / focus / screenshot recorder.

* every focus change is recorded with window title + class + owning process, so
  the timeline shows "what the user was looking at" when a file appeared
* new top level windows opened by the target family (dialogs, message boxes,
  secondary forms) are recorded as soon as they become visible
* optional periodic screenshots (or one per focus change) let you see the
  actual rendered UI of a packed binary - the cheapest way to know what a
  VMProtect'ed EasyLanguage form is displaying
"""
from __future__ import annotations

import os
import threading
import time

from . import winapi


class WindowRecorder(threading.Thread):
    def __init__(self, bus, tree, run_dir=None, interval: float = 0.25,
                 shot_interval: float = 0.0, shot_on_focus: bool = True,
                 logger=print):
        super().__init__(name="win-recorder", daemon=True)
        self.bus = bus
        self.tree = tree
        self.run_dir = run_dir
        self.interval = max(0.1, interval)
        self.shot_interval = shot_interval
        self.shot_on_focus = shot_on_focus
        self.log = logger
        self._stopped = threading.Event()
        self._last_focus = None
        self._known_windows: set[int] = set()
        self._shot_n = 0
        self._last_shot = 0.0
        self.shots_dir = os.path.join(run_dir, "shots") if run_dir else None
        if self.shots_dir:
            os.makedirs(self.shots_dir, exist_ok=True)

    def stop(self) -> None:
        self._stopped.set()

    def run(self) -> None:
        self._scan_windows(initial=True)
        while not self._stopped.is_set():
            try:
                self._tick()
            except Exception as exc:
                self.log(f"[win] tick failed: {exc!r}")
            self._stopped.wait(self.interval)

    # ------------------------------------------------------------------ ticks
    def _tick(self) -> None:
        info = winapi.foreground_info()
        if info:
            key = (info["hwnd"], info["title"])
            if key != self._last_focus:
                changed = True
                first = self._last_focus is None
                self._last_focus = key
                proc = self.tree.name(info["pid"])
                self.bus.emit(
                    "win", "focus",
                    pid=info["pid"], ppid=self.tree.ppid(info["pid"]), proc=proc,
                    path=info["title"],
                    detail={
                        "hwnd": info["hwnd"], "class": info["class"],
                        "in_scope": self.tree.in_scope(info["pid"]),
                        "first": first,
                    },
                )
                if changed and self.shot_on_focus:
                    self._screenshot(reason="focus")
        self._scan_windows()
        if self.shot_interval and (time.time() - self._last_shot) >= self.shot_interval:
            self._screenshot(reason="interval")

    def _scan_windows(self, initial: bool = False) -> None:
        windows = winapi.enum_windows()
        scope = self.tree.scope()
        current = set()
        for hwnd, title, cls, pid in windows:
            if pid not in scope:
                continue
            current.add(hwnd)
            if hwnd in self._known_windows:
                continue
            self.bus.emit(
                "win", "window_open" if not initial else "window_seen",
                pid=pid, ppid=self.tree.ppid(pid), proc=self.tree.name(pid),
                path=title,
                detail={"hwnd": hwnd, "class": cls, "rect": winapi.window_rect(hwnd)},
            )
        for hwnd in self._known_windows - current:
            self.bus.emit(
                "win", "window_close", path="",
                detail={"hwnd": hwnd},
            )
        self._known_windows = current

    # ------------------------------------------------------------- screenshot
    def _screenshot(self, reason: str = "interval", crop_to_focus: bool = False) -> None:
        if not self.shots_dir:
            return
        try:
            from PIL import ImageGrab  # Pillow ships with DSH runtime
        except Exception:
            return
        try:
            bbox = None
            if crop_to_focus and self._last_focus:
                rect = winapi.window_rect(self._last_focus[0])
                if rect and rect["width"] > 0 and rect["height"] > 0:
                    bbox = (
                        rect["left"], rect["top"],
                        rect["left"] + rect["width"], rect["top"] + rect["height"],
                    )
            img = ImageGrab.grab(bbox=bbox, all_screens=True) if bbox else ImageGrab.grab(all_screens=True)
            self._shot_n += 1
            name = f"shot_{self._shot_n:06d}.png"
            path = os.path.join(self.shots_dir, name)
            img.save(path, optimize=True)
            self._last_shot = time.time()
            self.bus.emit(
                "shot", "screenshot", path=name,
                detail={"reason": reason, "size": list(img.size), "file": path,
                        "focus": self._last_focus[1] if self._last_focus else None},
            )
        except Exception as exc:
            self.log(f"[win] screenshot failed: {exc!r}")
