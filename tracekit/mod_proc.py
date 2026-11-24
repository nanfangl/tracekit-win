"""Process recorder: catches starts/exits of the target and everything it spawns.

Polling is used instead of a WMI/ETW subscription because it needs no COM and
survives the target dying.  0.35s is fine for interactive programs; lower it
with --proc-interval when the target forks in tight bursts.
"""
from __future__ import annotations

import threading
import time

from . import winapi
from .proctree import ProcessTree


class ProcessRecorder(threading.Thread):
    def __init__(self, bus, tree: ProcessTree, interval: float = 0.35, logger=print):
        super().__init__(name="proc-recorder", daemon=True)
        self.bus = bus
        self.tree = tree
        self.interval = max(0.1, interval)
        self.log = logger
        self._stopped = threading.Event()
        self._first_seen: dict[int, float] = {}
        self._known: set[int] = set()
        self._name_cache: dict[int, str] = {}
        self._path_cache: dict[int, str | None] = {}

    def stop(self) -> None:
        self._stopped.set()

    # ------------------------------------------------------------------ work
    def run(self) -> None:
        self.tree.refresh()
        self._known = set(self.tree.scope())
        for pid in sorted(self._known):
            self._first_seen[pid] = time.time()
        now = time.time()
        self.bus.emit(
            "mark", "start",
            path="process snapshot",
            detail={"pids": sorted(self._known), "count": len(self._known)},
        )
        # the target itself was started before we attached: describe it properly
        for pid in sorted(self.tree.roots):
            if pid in self._known:
                self._emit_create(pid, now, initial=True)
        while not self._stopped.is_set():
            try:
                self._tick()
            except Exception as exc:  # keep recording even if one pass fails
                self.log(f"[proc] tick failed: {exc!r}")
            self._stopped.wait(self.interval)

    def _tick(self) -> None:
        alive = self.tree.refresh()
        scope = self.tree.scope()
        now = time.time()

        new = scope - self._known
        for pid in sorted(new):
            self._first_seen[pid] = now
            self._emit_create(pid, now)
        gone = self._known - alive
        for pid in sorted(gone):
            started = self._first_seen.pop(pid, None)
            self.bus.emit(
                "proc", "exit",
                pid=pid, ppid=self.tree.ppid(pid),
                proc=self._name_cache.get(pid) or self.tree.name(pid),
                path=self._path_cache.get(pid) or self.tree.path(pid),
                detail={
                    "lifetime_s": round(now - started, 3) if started else None,
                    "still_tracked": pid in scope,
                },
            )
        self._known = (self._known & alive) | new

    def _emit_create(self, pid: int, now: float, initial: bool = False) -> None:
        info = winapi.process_cmdline(pid) or {}
        exe = info.get("image") or self.tree.path(pid)
        self.tree._paths[pid] = exe
        ppid = self.tree.ppid(pid)
        name = self.tree.name(pid)
        self._name_cache[pid] = name
        self._path_cache[pid] = exe
        self.bus.emit(
            "proc", "create",
            pid=pid, ppid=ppid, proc=name, path=exe,
            detail={
                "cmdline": info.get("cmdline"),
                "cwd": info.get("cwd"),
                "bits": info.get("bits"),
                "parent_proc": self.tree.name(ppid),
                "is_root": pid in self.tree.roots,
                "already_running": initial,
            },
        )
