"""Log-file tailer: turns the target's own text output into structured events.

For an EasyLanguage / VMProtect program you usually cannot read its "日志" from
stdout (GUI subsystem, no console).  What it does leave behind are files:
*.log, *.txt, *.ini, *.json, *.csv.  This recorder follows those files inside
the watched directories and emits one event per appended line, so the report
contains the *content*, not just "file modified".
"""
from __future__ import annotations

import os
import threading
import time

DEFAULT_PATTERNS = (".log", ".txt", ".ini", ".csv", ".json", ".xml", ".md")
MAX_FILE = 64 * 1024 * 1024
MAX_LINES_PER_FLUSH = 2000


def _decode(raw: bytes):
    """Return (text, consumed_byte_count).

    A chunk can end in the middle of a multi-byte character; in that case the
    incomplete tail is left for the next round instead of being turned into
    mojibake.  UTF-8 is tried first (modern logs), then gb18030 (the encoding
    most Chinese EasyLanguage programs write in).
    """
    for enc in ("utf-8", "gb18030"):
        try:
            return raw.decode(enc), len(raw)
        except UnicodeDecodeError as exc:
            if enc == "utf-8" and 0 < len(raw) - exc.start <= 4:
                try:
                    return raw[: exc.start].decode("utf-8"), exc.start
                except UnicodeDecodeError:
                    pass
    return raw.decode("utf-8", "replace"), len(raw)


class LogTailRecorder(threading.Thread):
    def __init__(self, bus, roots, patterns=DEFAULT_PATTERNS, interval: float = 0.8,
                 depth: int = 3, start_ts: float | None = None, logger=print,
                 max_line_chars: int = 4000, exclude=None):
        super().__init__(name="log-tail", daemon=True)
        self.bus = bus
        self.exclude = [os.path.abspath(e).lower().rstrip("\\") for e in (exclude or []) if e]
        self.roots = [os.path.abspath(r) for r in roots if r and os.path.isdir(r)]
        self.patterns = tuple(p.lower() for p in patterns)
        self.interval = max(0.3, interval)
        self.depth = depth
        self.start_ts = start_ts or time.time()
        self.log = logger
        self.max_line_chars = max_line_chars
        self._stopped = threading.Event()
        self._state: dict[str, int] = {}
        self._lines_seen: dict[str, int] = {}
        self._noisy: set[str] = set()
        self.max_lines_per_file = 20000
        self.counts = {"lines": 0}

    def stop(self) -> None:
        self._stopped.set()

    def run(self) -> None:
        if not self.roots:
            return
        self.log(f"[tail] following text files under {len(self.roots)} root(s)")
        while not self._stopped.is_set():
            try:
                self._tick()
            except Exception as exc:
                self.log(f"[tail] tick failed: {exc!r}")
            self._stopped.wait(self.interval)

    def _files(self):
        for root in self.roots:
            base_depth = root.rstrip("\\").count("\\")
            for dirpath, dirnames, filenames in os.walk(root):
                if dirpath.count("\\") - base_depth >= self.depth:
                    dirnames[:] = []
                dirnames[:] = [d for d in dirnames if d.lower() not in
                               ("node_modules", ".git", "__pycache__", "$recycle.bin")]
                for name in filenames:
                    if self.patterns and not name.lower().endswith(self.patterns):
                        continue
                    full = os.path.join(dirpath, name)
                    if self.exclude:
                        low = full.lower()
                        if any(low.startswith(p + "\\") for p in self.exclude):
                            continue
                    yield full

    def _tick(self) -> None:
        for path in self._files():
            if path in self._noisy:
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            if st.st_size > MAX_FILE:
                continue
            offset = self._state.get(path)
            if offset is None:
                # skip content that predates the recording session
                offset = st.st_size if st.st_mtime < self.start_ts else 0
                self._state[path] = offset
                if offset == 0:
                    self.bus.emit("log", "open", path=path, detail={"size": st.st_size})
            if st.st_size < offset:
                self.bus.emit("log", "truncated", path=path,
                              detail={"old_offset": offset, "new_size": st.st_size})
                offset = 0
            if st.st_size == offset:
                continue
            try:
                with open(path, "rb") as fh:
                    fh.seek(offset)
                    raw = fh.read(min(st.st_size - offset, 4 * 1024 * 1024))
            except OSError:
                continue
            self._state[path] = offset + len(raw)
            text, consumed = _decode(raw)
            if text.endswith("\r"):
                # a partial line, re-read next tick
                consumed -= 1
                text = text[:-1]
            self._state[path] = offset + consumed
            lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
            for line in lines[:MAX_LINES_PER_FLUSH]:
                if not line.strip():
                    continue
                self.counts["lines"] += 1
                seen = self._lines_seen.get(path, 0) + 1
                self._lines_seen[path] = seen
                if seen > self.max_lines_per_file:
                    # 典型的放大回路：记录器自己的控制台日志被写进了被监视目录
                    self._noisy.add(path)
                    self.bus.emit(
                        "log", "too_noisy", path=path,
                        detail={"stopped_after_lines": seen,
                                "reason": "单文件日志量异常（可能是记录器自身输出被监视）"},
                    )
                    break
                shown = line[: self.max_line_chars]
                self.bus.emit(
                    "log", "line", path=path,
                    detail={"line": shown, "length": len(line),
                            "encoding_guessed": True},
                )
            if len(lines) > MAX_LINES_PER_FLUSH:
                self.bus.emit("log", "dropped", path=path,
                              detail={"lines": len(lines) - MAX_LINES_PER_FLUSH})
