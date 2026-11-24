"""Control-level action recorder: which control was pressed, and how the program answered.

The global mouse/keyboard hook tells us *where* and *when*; this module turns
that into a UI-level record:

  ui/click     every click inside the target's windows, resolved to
               class + caption + control id + owner form, plus menu item caption
               and click count / modifiers
  ui/key_target which control had keyboard focus when a key was pressed
  ui/response  the visible reaction: control state / text diffs of the same form,
               taken shortly after the action (button caption, checkbox state,
               combo selection, log box content, new windows)

Three threads keep this fast:
  * `run()`      consumes actions and emits the click/key event immediately,
                 using only cheap Win32 calls (no messages into the target)
  * `_sweeper`   keeps a rolling "before" snapshot of control states
  * `_responder` takes the "after" snapshot and computes the diff

Nothing is injected into the target and every message uses SendMessageTimeout,
so a hung or VMProtect-protected UI can never stall the recorder.
"""
from __future__ import annotations

import queue
import threading
import time

from . import winapi

RESPONSE_DELAY = 0.7          # when the "after" snapshot is taken
MAX_CONTROLS_PER_FORM = 80
STATE_SWEEP_BUDGET = 0.6      # seconds per sweep, keeps the recorder responsive
STATE_CLASSES = ("button", "combobox", "listbox", "static", "edit", "richedit",
                 "richedit20a", "richedit20w", "richedit50w", "checkbox",
                 "radiobutton", "syslistview32")


class UiActionRecorder(threading.Thread):
    def __init__(self, bus, tree, interval: float = 1.0,
                 response_delay: float = RESPONSE_DELAY, logger=print):
        super().__init__(name="uiact-recorder", daemon=True)
        self.bus = bus
        self.tree = tree
        self.interval = max(0.4, interval)
        self.response_delay = max(0.2, response_delay)
        self.log = logger
        self._stopped = threading.Event()
        self._actions: queue.Queue = queue.Queue(maxsize=8192)
        self._responses: queue.Queue = queue.Queue(maxsize=4096)
        self._snap: dict[int, dict] = {}
        self._snap_lock = threading.Lock()
        self._last_click = (0.0, 0, 0)
        self._click_count = 0
        self.counts = {"click": 0, "response": 0, "key": 0}
        self._threads: list[threading.Thread] = []

    # ------------------------------------------------------------------ input
    def subscribe(self) -> None:
        """Listen on the bus for mouse/keyboard events produced by mod_input."""
        def _on_event(ev):
            if ev.get("cat") != "input":
                return
            if ev.get("act") == "click":
                try:
                    self._actions.put_nowait(("click", ev))
                except queue.Full:
                    pass
            elif ev.get("act") == "key":
                try:
                    self._actions.put_nowait(("key", ev))
                except queue.Full:
                    pass
        self.bus.subscribe(_on_event)

    def stop(self) -> None:
        self._stopped.set()

    # ------------------------------------------------------------------- loop
    def start(self) -> None:
        for name, target in (("uiact-sweep", self._sweep_loop),
                             ("uiact-resp", self._respond_loop)):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self._threads.append(t)
        super().start()

    def run(self) -> None:
        while not self._stopped.is_set():
            try:
                kind, ev = self._actions.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                if kind == "click":
                    self._handle_click(ev)
                else:
                    self._handle_key(ev)
            except Exception as exc:
                self.log(f"[uiact] handle failed: {exc!r}")

    # --------------------------------------------------------------- sweeping
    def _sweep_loop(self) -> None:
        while not self._stopped.is_set():
            try:
                self._sweep()
            except Exception as exc:
                self.log(f"[uiact] sweep failed: {exc!r}")
            self._stopped.wait(self.interval)

    def _form_state(self, top: int, budget: float | None = None):
        state = {}
        deadline = (time.time() + budget) if budget else None
        try:
            controls = winapi.enum_children(top)
        except Exception:
            return state
        for child, ccls, ctext, _rect in controls[:MAX_CONTROLS_PER_FORM]:
            if deadline and time.time() > deadline:
                break
            if (ccls or "").lower() not in STATE_CLASSES:
                continue
            try:
                st = winapi.control_state(child, ccls)
            except Exception:
                st = None
            if st is None:
                continue
            state[child] = {"class": ccls, "state": st, "text": (ctext or "")[:120]}
        return state

    def _sweep(self) -> None:
        scope = self.tree.scope()
        if not scope:
            return
        alive = set()
        for hwnd, _title, _cls, pid in winapi.enum_windows():
            if pid not in scope:
                continue
            alive.add(hwnd)
            state = self._form_state(hwnd, budget=STATE_SWEEP_BUDGET)
            with self._snap_lock:
                self._snap[hwnd] = state
        with self._snap_lock:
            for hwnd in list(self._snap):
                if hwnd not in alive:
                    self._snap.pop(hwnd, None)

    # ----------------------------------------------------------------- actions
    def _handle_click(self, ev: dict) -> None:
        detail = ev.get("detail") or {}
        x, y = int(detail.get("x") or 0), int(detail.get("y") or 0)
        hwnd = detail.get("hwnd_under")
        # cheap identity only: no WM_GETTEXT here, this path must stay instant
        info = winapi.control_info(hwnd, with_text=False) if hwnd else None
        if not info:
            return
        if not self.tree.in_scope(info.get("top_pid")):
            return

        now = time.time()
        last_t, lx, ly = self._last_click
        if now - last_t <= 0.5 and abs(lx - x) <= 4 and abs(ly - y) <= 4:
            self._click_count += 1
        else:
            self._click_count = 1
        self._last_click = (now, x, y)

        cls_low = (info.get("class") or "").lower()
        menu_item = None
        if cls_low in ("#32768", "menu", "tooltips_class32"):
            menu_item = winapi.menu_item_at(info["top_hwnd"], x, y)

        # caption comes from the cheap rolling snapshot; only if we have never
        # seen this control do we pay for one short WM_GETTEXT
        info["text"] = self._caption(hwnd, info)

        self.counts["click"] += 1
        self.bus.emit(
            "ui", "click",
            pid=info.get("top_pid"), ppid=self.tree.ppid(info.get("top_pid")),
            proc=self.tree.name(info.get("top_pid")),
            path=self._label(info, menu_item),
            detail={
                "control": info,
                "menu_item": menu_item,
                "x": x, "y": y,
                "button": detail.get("button"),
                "click_count": self._click_count,
                "mods": detail.get("mods") or [],
                "injected": detail.get("injected"),
                "form": info.get("top_title"),
            },
        )
        self._queue_response("click", info, x, y)

    def _handle_key(self, ev: dict) -> None:
        detail = ev.get("detail") or {}
        focus = winapi.focused_control()
        info = winapi.control_info(focus, with_text=False) if focus else None
        if not info or not self.tree.in_scope(info.get("top_pid")):
            top = detail.get("hwnd")
            if top and self.tree.in_scope(winapi.window_pid(top)):
                info = winapi.control_info(top, with_text=False)
        if not info:
            return
        info["text"] = self._caption(focus or info.get("hwnd"), info)
        self.counts["key"] += 1
        self.bus.emit(
            "ui", "key_target",
            pid=info.get("top_pid"), ppid=self.tree.ppid(info.get("top_pid")),
            proc=self.tree.name(info.get("top_pid")),
            path=self._label(info, None),
            detail={
                "control": info,
                "vk": detail.get("vk"),
                "char": detail.get("char"),
                "form": info.get("top_title"),
            },
        )
        self._queue_response("key", info, None, None)

    @staticmethod
    def _label(info: dict, menu_item: str | None) -> str:
        if menu_item:
            return f"菜单「{menu_item}」"
        text = info.get("text") or ""
        return f"{info.get('class')}「{text}」" if text else str(info.get("class"))

    def _caption(self, hwnd, info: dict) -> str:
        """Cheap caption lookup: snapshot first, one short message only if unknown."""
        top = info.get("top_hwnd")
        with self._snap_lock:
            cached = (self._snap.get(top) or {}).get(hwnd)
        if cached:
            return (cached.get("text") or "")[:200]
        try:
            return (winapi.control_text(hwnd, 256, timeout=80) or "")[:200]
        except Exception:
            return ""

    # ---------------------------------------------------------------- responses
    def _queue_response(self, trigger: str, info: dict, x, y) -> None:
        top = info.get("top_hwnd")
        if not top:
            return
        with self._snap_lock:
            before = {k: dict(v) for k, v in (self._snap.get(top) or {}).items()}
        try:
            self._responses.put_nowait({
                "due": time.time() + self.response_delay,
                "trigger": trigger,
                "top": top,
                "control": info,
                "before": before,
                "windows_before": self._window_ids(),
                "x": x, "y": y,
            })
        except queue.Full:
            pass

    def _window_ids(self) -> set:
        try:
            return {hwnd for hwnd, _t, _c, _p in winapi.enum_windows()}
        except Exception:
            return set()

    def _respond_loop(self) -> None:
        while not self._stopped.is_set():
            try:
                item = self._responses.get(timeout=0.2)
            except queue.Empty:
                continue
            wait = item["due"] - time.time()
            if wait > 0:
                time.sleep(min(wait, 2.0))
            try:
                self._emit_response(item)
            except Exception as exc:
                self.log(f"[uiact] response failed: {exc!r}")

    def _emit_response(self, item: dict) -> None:
        top = item["top"]
        if not winapi.user32.IsWindow(top):
            return
        after = self._form_state(top, budget=STATE_SWEEP_BUDGET)
        before = item["before"]

        changes = []
        for child, cur in after.items():
            prev = before.get(child)
            if prev is None:
                changes.append({"kind": "control_appeared", "class": cur["class"],
                                "hwnd": child, "after": cur["state"]})
                continue
            if prev.get("state") != cur.get("state") or prev.get("text") != cur.get("text"):
                changes.append({
                    "kind": "state_changed", "class": cur["class"], "hwnd": child,
                    "before": prev.get("state"), "after": cur["state"],
                    "text_before": prev.get("text"), "text_after": cur.get("text"),
                })
        for child, prev in before.items():
            if child not in after:
                changes.append({"kind": "control_gone", "class": prev.get("class"),
                                "hwnd": child, "before": prev.get("state")})

        new_windows = []
        try:
            now_ids = self._window_ids()
            for hwnd, title, cls, pid in winapi.enum_windows():
                if hwnd in item["windows_before"]:
                    continue
                if self.tree.in_scope(pid) or hwnd == top:
                    new_windows.append({"hwnd": hwnd, "title": title, "class": cls, "pid": pid})
            closed = len(item["windows_before"] - now_ids)
        except Exception:
            closed = 0

        with self._snap_lock:
            self._snap[top] = after

        if not changes and not new_windows and not closed:
            return
        self.counts["response"] += 1
        info = item["control"]
        self.bus.emit(
            "ui", "response",
            pid=info.get("top_pid"), ppid=self.tree.ppid(info.get("top_pid")),
            proc=self.tree.name(info.get("top_pid")),
            path=self._label(info, None),
            detail={
                "trigger": item["trigger"],
                "form": info.get("top_title"),
                "changes": changes[:40],
                "change_count": len(changes),
                "new_windows": new_windows[:10],
                "closed_windows": closed,
            },
        )
