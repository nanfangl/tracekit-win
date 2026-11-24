"""Process tree bookkeeping shared by the recorders.

`ProcessTree` answers three questions all the other modules ask:

  * which pid's belong to the target's family (the target + every child it
    spawns, and their children, transitively)
  * what is the image name / image path of a pid
  * what did the family look like a moment ago (for create/exit events)

Because a child can outlive its parent (and get reparented to explorer.exe),
pids that were ever seen inside the family stay "tracked" for the rest of the
session.
"""
from __future__ import annotations

import threading

from . import winapi


class ProcessTree:
    def __init__(self, roots=()):
        self._lock = threading.RLock()
        self._procs: dict[int, tuple[int, str]] = {}   # pid -> (ppid, name)
        self._paths: dict[int, str | None] = {}
        self._tracked: set[int] = set(int(r) for r in roots if r)
        self._roots: set[int] = set(self._tracked)
        self._missing: dict[int, int] = {}             # pid -> 连续未见次数

    # ------------------------------------------------------------------ state
    @property
    def roots(self) -> set[int]:
        with self._lock:
            return set(self._roots)

    def add_root(self, pid: int) -> None:
        with self._lock:
            self._tracked.add(int(pid))
            self._roots.add(int(pid))

    def refresh(self) -> set[int]:
        procs = {}
        for pid, ppid, name in winapi.iter_processes():
            procs[pid] = (ppid, name)
        with self._lock:
            self._procs = procs
            alive = set(procs)
            # 目标刚 Popen 出来的那一瞬，Toolhelp 快照可能还没包含它。
            # 直接 self._tracked &= alive 会把 root 永久踢掉（后面就再也跟不到），
            # 所以给 root 与最近见过的 pid 一个宽限期：连续几轮都见不到才真丢。
            keep: set[int] = set()
            for pid in self._tracked:
                if pid in alive:
                    self._missing.pop(pid, None)
                    keep.add(pid)
                    continue
                miss = self._missing.get(pid, 0) + 1
                self._missing[pid] = miss
                if pid in self._roots and miss <= 10:
                    keep.add(pid)          # root：最多容忍 10 轮（≈2 秒）
                elif miss <= 2:
                    keep.add(pid)          # 子进程：容忍 2 轮
            self._tracked = keep
            for pid in list(self._missing):
                if pid not in keep:
                    self._missing.pop(pid, None)
            self._paths = {k: v for k, v in self._paths.items() if k in alive or k in keep}
        return alive

    def _children_map(self) -> dict[int, list[int]]:
        children: dict[int, list[int]] = {}
        for pid, (ppid, _name) in self._procs.items():
            children.setdefault(ppid, []).append(pid)
        return children

    def scope(self) -> set[int]:
        """Every pid belonging to the tracked family right now."""
        with self._lock:
            children = self._children_map()
            seen = set()
            stack = [p for p in self._tracked if p in self._procs]
            while stack:
                pid = stack.pop()
                if pid in seen:
                    continue
                seen.add(pid)
                stack.extend(children.get(pid, ()))
            self._tracked |= seen
            return seen

    def in_scope(self, pid: int | None) -> bool:
        if not pid:
            return False
        with self._lock:
            if pid in self._tracked:
                return True
        return pid in self.scope()

    def name(self, pid: int | None) -> str | None:
        if not pid:
            return None
        with self._lock:
            item = self._procs.get(int(pid))
        return item[1] if item else None

    def ppid(self, pid: int | None) -> int | None:
        if not pid:
            return None
        with self._lock:
            item = self._procs.get(int(pid))
        return item[0] if item else None

    def path(self, pid: int | None) -> str | None:
        if not pid:
            return None
        with self._lock:
            if pid in self._paths:
                return self._paths[pid]
        p = winapi.process_image_path(int(pid))
        with self._lock:
            self._paths[int(pid)] = p
        return p
