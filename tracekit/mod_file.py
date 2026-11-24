"""File system recorder built on ReadDirectoryChangesW.

One thread per watched root, recursive.  Windows reports create / delete /
modify / rename; a compile-and-run loop can produce thousands of MODIFIED
events for a single file, so events are coalesced per (path, action) and
flushed when the path has been quiet for a moment - each emitted event carries
`count` and the observed time span.

Note: this API reports *directory* activity, not the pid that did it, and it
cannot see read() - use mod_etw for per-pid and read() coverage.
"""
from __future__ import annotations

import ctypes
import os
import threading
import time

from . import winapi

ACTION_NAMES = {
    winapi.FILE_ACTION_ADDED: "create",
    winapi.FILE_ACTION_REMOVED: "delete",
    winapi.FILE_ACTION_MODIFIED: "modify",
    winapi.FILE_ACTION_RENAMED_OLD_NAME: "rename_from",
    winapi.FILE_ACTION_RENAMED_NEW_NAME: "rename_to",
}

BUFSIZE = 64 * 1024


class _Watch(threading.Thread):
    def __init__(self, root, on_event, logger=print, label=""):
        super().__init__(name=f"filewatch:{root}", daemon=True)
        self.root = root
        self.on_event = on_event
        self.log = logger
        self.label = label
        self._stopped = threading.Event()

    def stop(self):
        self._stopped.set()

    def run(self):
        handle = winapi.kernel32.CreateFileW(
            self.root,
            winapi.FILE_LIST_DIRECTORY,
            winapi.FILE_SHARE_READ | winapi.FILE_SHARE_WRITE | winapi.FILE_SHARE_DELETE,
            None,
            winapi.OPEN_EXISTING,
            winapi.FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if not handle or handle == winapi.INVALID_HANDLE_VALUE:
            self.log(f"[file] cannot watch {self.root} (err={ctypes.get_last_error()})")
            return
        buf = ctypes.create_string_buffer(BUFSIZE)
        returned = winapi.wintypes.DWORD(0)
        try:
            while not self._stopped.is_set():
                ok = winapi.kernel32.ReadDirectoryChangesW(
                    handle,
                    buf,
                    BUFSIZE,
                    True,
                    winapi.FILE_NOTIFY_CHANGE_ALL,
                    ctypes.byref(returned),
                    None,
                    None,
                )
                if not ok:
                    err = ctypes.get_last_error()
                    if err == 1022:  # ERROR_NOTIFY_ENUM_DIR: buffer overflow
                        self.on_event("file", "overflow", self.root, {"root": self.root})
                        continue
                    if self._stopped.is_set():
                        break
                    self.log(f"[file] watch {self.root} stopped (err={err})")
                    break
                self._parse(buf.raw[: returned.value], time.time())
        finally:
            winapi.kernel32.CloseHandle(handle)

    def _parse(self, raw: bytes, now: float) -> None:
        off = 0
        while True:
            if off + 12 > len(raw):
                break
            next_off = int.from_bytes(raw[off: off + 4], "little")
            action = int.from_bytes(raw[off + 4: off + 8], "little")
            name_len = int.from_bytes(raw[off + 8: off + 12], "little")
            name = raw[off + 12: off + 12 + name_len].decode("utf-16-le", "replace")
            full = os.path.join(self.root, name)
            act = ACTION_NAMES.get(action, f"action_{action}")
            self.on_event("file", act, full, {"root": self.root, "raw_action": action})
            if next_off == 0:
                break
            off += next_off


class FileRecorder:
    """Spawns one watcher per root plus a coalescing flusher."""

    def __init__(self, bus, roots, logger=print, quiet: float = 0.4, include_hidden=True,
                 exclude=None):
        self.bus = bus
        self.log = logger
        self.exclude = [os.path.abspath(e).lower().rstrip("\\") for e in (exclude or []) if e]
        self.roots = []
        seen = set()
        for r in roots or []:
            if not r:
                continue
            r = os.path.abspath(os.path.expandvars(r))
            if not os.path.isdir(r):
                self.log(f"[file] skip missing dir: {r}")
                continue
            key = r.lower()
            if key in seen:
                continue
            seen.add(key)
            self.roots.append(r)
        self.quiet = quiet
        self._pending = {}
        self._lock = threading.Lock()
        self._stopped = threading.Event()
        self._watches: list[_Watch] = []
        self._flusher = threading.Thread(target=self._flush_loop, name="file-flush", daemon=True)

    # ------------------------------------------------------------------ api
    def start(self) -> bool:
        if not self.roots:
            return False
        for root in self.roots:
            w = _Watch(root, self._on_event, logger=self.log)
            w.start()
            self._watches.append(w)
        self._flusher.start()
        self.log(f"[file] watching {len(self.roots)} root(s): {', '.join(self.roots)}")
        return True

    def stop(self) -> None:
        self._stopped.set()
        for w in self._watches:
            w.stop()
        self._flush_all()
        self._flusher.join(timeout=3)

    # -------------------------------------------------------------- internal
    def _on_event(self, cat, act, path, detail):
        if self.exclude:
            low = path.lower()
            for prefix in self.exclude:
                if low == prefix or low.startswith(prefix + "\\"):
                    return
        key = (path.lower(), act)
        now = time.time()
        with self._lock:
            slot = self._pending.get(key)
            if slot is None:
                self._pending[key] = [now, now, 1, act, path, detail, cat]
            else:
                slot[1] = now
                slot[2] += 1

    def _flush_loop(self) -> None:
        while not self._stopped.is_set():
            time.sleep(0.25)
            self._flush_due()

    def _flush_due(self) -> None:
        now = time.time()
        ready = []
        with self._lock:
            for key, slot in list(self._pending.items()):
                if now - slot[1] >= self.quiet:
                    ready.append(slot)
                    del self._pending[key]
        for slot in ready:
            self._emit(slot)

    def _flush_all(self) -> None:
        with self._lock:
            ready = list(self._pending.values())
            self._pending.clear()
        for slot in ready:
            self._emit(slot)

    def _emit(self, slot) -> None:
        first_t, last_t, count, act, path, detail, cat = slot
        extra = dict(detail)
        extra["count"] = count
        extra["first_ts"] = first_t
        extra["last_ts"] = last_t
        try:
            if os.path.exists(path):
                st = os.stat(path)
                extra["size"] = st.st_size
                extra["is_dir"] = os.path.isdir(path)
                extra["mtime"] = st.st_mtime
        except OSError:
            pass
        self.bus.emit(cat, act, path=path, detail=extra)
