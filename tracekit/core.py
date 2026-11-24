"""Event bus + persistence for TraceKit.

Every recorder module talks to a single `Bus`.  The bus timestamps the event,
stamps a global sequence number and hands it to a `Store`, which buffers and
flushes to two places:

  * events.jsonl  - one JSON object per line, append only, easy to grep
  * events.sqlite - indexed table, used by report.py for aggregation

A single flusher thread owns both writers so the hook callbacks (keyboard /
window events) never touch the disk synchronously.
"""
from __future__ import annotations

import json
import os
import queue
import sqlite3
import threading
import time
from datetime import datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY,
  t REAL NOT NULL,
  ts TEXT NOT NULL,
  cat TEXT NOT NULL,
  act TEXT NOT NULL,
  pid INTEGER,
  ppid INTEGER,
  proc TEXT,
  path TEXT,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_cat ON events(cat);
CREATE INDEX IF NOT EXISTS idx_events_t ON events(t);
CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid);
CREATE INDEX IF NOT EXISTS idx_events_path ON events(path);
"""


def decode_bytes(raw: bytes, prefer: tuple[str, ...] = ("utf-8", "gb18030")) -> str:
    """把目标程序吐出来的字节流解成正确的字符串。

    中文 Windows 上的程序（尤其易语言/老 VB）走管道时通常是 GBK，直接按 UTF-8
    解会得到一堆 U+FFFD（也就是“乱码”）。所以逐个编码严格试，全都失败才兜底
    替换——宁可留一个坏字符，也不要把整段中文变成 ���。
    """
    if not raw:
        return ""
    for enc in prefer:
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode(prefer[0] if prefer else "utf-8", "replace")


def now_iso(t: float | None = None) -> str:
    dt = datetime.fromtimestamp(t if t is not None else time.time())
    return dt.isoformat(timespec="milliseconds")


def open_human_text(path: str, mode: str = "a"):
    """Open a human-facing text file as UTF-8 with a BOM once.

    记事本 / WPS / Excel 在中文 Windows 上默认按 ANSI(GBK) 猜编码，没有 BOM 的
    UTF-8 会被显示成乱码。所以报告、日志汇总这类给人看的文件统一带 BOM；
    数据库、JSONL、HTML 这类给程序看的文件保持无 BOM 的纯 UTF-8。
    """
    new = not os.path.exists(path) or os.path.getsize(path) == 0
    fh = open(path, mode, encoding="utf-8-sig" if new else "utf-8", newline="")
    return fh


def add_bom_if_missing(path: str) -> bool:
    """给 report.py 之类外部写入的文本补 BOM（不改变内容）。"""
    try:
        with open(path, "rb") as fh:
            head = fh.read(3)
        if head == b"\xef\xbb\xbf":
            return False
        with open(path, "rb") as fh:
            data = fh.read()
        with open(path, "wb") as fh:
            fh.write(b"\xef\xbb\xbf" + data)
        return True
    except Exception:
        return False


class Store:
    """Buffered writer for events.jsonl + events.sqlite."""

    def __init__(self, run_dir: str):
        self.run_dir = run_dir
        os.makedirs(run_dir, exist_ok=True)
        self.jsonl_path = os.path.join(run_dir, "events.jsonl")
        self.db_path = os.path.join(run_dir, "events.sqlite")
        self._q: queue.Queue = queue.Queue(maxsize=500000)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._fh = open(self.jsonl_path, "a", encoding="utf-8", buffering=1)
        self._stop = threading.Event()
        self._flush_lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, name="store-flush", daemon=True)
        self._written = 0
        self._dropped = 0
        self._thread.start()

    def write(self, ev: dict) -> None:
        try:
            self._q.put_nowait(ev)
        except queue.Full:
            self._dropped += 1

    def _run(self) -> None:
        batch = []
        last = time.time()
        while not self._stop.is_set() or not self._q.empty() or batch:
            try:
                batch.append(self._q.get(timeout=0.25))
                while len(batch) < 2000:
                    batch.append(self._q.get_nowait())
            except queue.Empty:
                pass
            if batch and (len(batch) >= 500 or (time.time() - last) >= 0.5):
                self._flush(batch)
                batch = []
                last = time.time()
        self._flush(batch)
        self._conn.commit()

    def _flush(self, batch) -> None:
        if not batch:
            return
        with self._flush_lock:
            self._write_batch(batch)

    def _write_batch(self, batch) -> None:
        lines = []
        rows = []
        for ev in batch:
            lines.append(json.dumps(ev, ensure_ascii=False, default=str))
            rows.append(
                (
                    ev.get("seq"),
                    ev.get("t"),
                    ev.get("ts"),
                    ev.get("cat"),
                    ev.get("act"),
                    ev.get("pid"),
                    ev.get("ppid"),
                    ev.get("proc"),
                    ev.get("path"),
                    json.dumps(ev.get("detail") or {}, ensure_ascii=False, default=str)
                    if ev.get("detail")
                    else None,
                )
            )
        try:
            self._fh.write("\n".join(lines) + "\n")
        except Exception:
            pass
        try:
            with self._conn:
                self._conn.executemany(
                    "INSERT OR REPLACE INTO events"
                    "(seq,t,ts,cat,act,pid,ppid,proc,path,detail) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    rows,
                )
        except Exception:
            pass
        self._written += len(rows)

    def counts(self) -> dict:
        try:
            cur = self._conn.execute("SELECT cat, COUNT(*) FROM events GROUP BY cat")
            return {c: n for c, n in cur.fetchall()}
        except Exception:
            return {}

    def flush_now(self, timeout: float = 10.0) -> int:
        """Block until every queued event is on disk, then return the count."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._flush_lock:
                batch = []
                while True:
                    try:
                        batch.append(self._q.get_nowait())
                    except queue.Empty:
                        break
                if batch:
                    self._write_batch(batch)
                if self._q.empty():
                    return self._written
            time.sleep(0.05)
        return self._written

    def close(self) -> dict:
        """Flush everything, stop the writer thread, return per-category counts."""
        self.flush_now()
        self._stop.set()
        self._thread.join(timeout=15)
        with self._flush_lock:
            rest = []
            while True:
                try:
                    rest.append(self._q.get_nowait())
                except queue.Empty:
                    break
            if rest:
                self._write_batch(rest)
        counts = self.counts()
        try:
            self._conn.commit()
            self._conn.close()
        except Exception:
            pass
        try:
            self._fh.close()
        except Exception:
            pass
        return counts


class Bus:
    """Thread safe event emitter.  `emit` is the only API modules need."""

    def __init__(self, store: Store | None = None, clock=time.time):
        self.store = store
        self._clock = clock
        self._seq = 0
        self._lock = threading.Lock()
        self._filters = []  # callables event -> bool, True = keep
        self._subscribers = []

    # ------------------------------------------------------------------ core
    def emit(self, cat: str, act: str, pid=None, ppid=None, proc=None, path=None,
             detail=None, **extra) -> dict:
        with self._lock:
            self._seq += 1
            seq = self._seq
        t = self._clock()
        ev = {
            "seq": seq,
            "t": t,
            "ts": now_iso(t),
            "cat": cat,
            "act": act,
            "pid": int(pid) if pid else None,
            "ppid": int(ppid) if ppid else None,
            "proc": proc,
            "path": path,
            "detail": detail or {},
        }
        if extra:
            ev["detail"].update(extra)
        for f in self._subscribers:
            try:
                f(ev)
            except Exception:
                pass
        if self.store is not None:
            self.store.write(ev)
        return ev

    def mark(self, text: str) -> dict:
        return self.emit("mark", "note", path=text)

    def subscribe(self, fn) -> None:
        self._subscribers.append(fn)


class NullBus(Bus):
    """Bus that keeps events in memory only - handy for self tests."""

    def __init__(self):
        super().__init__(store=None)
        self.events = []

    def emit(self, cat: str, act: str, **kw) -> dict:
        ev = super().emit(cat, act, **kw)
        self.events.append(ev)
        return ev


def write_meta(run_dir: str, meta: dict) -> str:
    path = os.path.join(run_dir, "run_meta.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=2, default=str)
    os.replace(tmp, path)
    return path


def read_meta(run_dir: str) -> dict:
    path = os.path.join(run_dir, "run_meta.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}
