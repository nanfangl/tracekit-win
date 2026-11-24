r"""文件快照：把目标生成/改写的文件本身留下来（不只是路径和大小）。

只记录“它写了 C:\x\a.ini（123 字节）”对排查帮助有限——真正要的是那个 a.ini 的
内容。这个模块订阅文件事件，把新出现/被改动的文件复制到 `run_dir\\文件副本\\`，
算 SHA1 去重，并把文本类文件的前若干字符塞进事件里，报告与时间线里直接可读。

限制（都可以用参数调）：
  * 单文件上限（默认 2 MB）
  * 会话总量上限（默认 200 MB）
  * 同一路径在 min_delay 秒内重复变化只留最后一次
  * 跳过明显的系统噪声路径（页面文件、缓存、编译器中间产物目录）
"""
from __future__ import annotations

import hashlib
import os
import queue
import shutil
import threading
import time

TEXT_EXT = {
    ".txt", ".log", ".ini", ".cfg", ".conf", ".json", ".xml", ".csv", ".tsv",
    ".md", ".html", ".htm", ".yaml", ".yml", ".sql", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".py", ".reg", ".inf", ".dat", ".db", ".sqlite", ".properties",
}
SKIP_DIR_PARTS = (
    "\\windows\\winsxs", "\\windows\\assembly", "\\$recycle.bin",
    "\\appdata\\local\\temp\\dsh-", "__pycache__", "\\.git\\objects",
)
SKIP_NAMES = {"pagefile.sys", "hiberfil.sys", "swapfile.sys", "ntuser.dat.log1",
              "ntuser.dat.log2", "desktop.ini", "thumbs.db"}


def _looks_text(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        pass
    try:
        sample.decode("gb18030")
        return True
    except UnicodeDecodeError:
        return False


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "gb18030"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


class FileSnapshotRecorder(threading.Thread):
    def __init__(self, bus, run_dir, max_file: int = 2 * 1024 * 1024,
                 max_total: int = 200 * 1024 * 1024, min_delay: float = 0.4,
                 preview_chars: int = 1200, roots=None, logger=print):
        super().__init__(name="filesnap", daemon=True)
        self.bus = bus
        self.dir = os.path.join(run_dir, "文件副本")
        self.max_file = int(max_file)
        self.max_total = int(max_total)
        self.roots = [os.path.abspath(r).lower().rstrip("\\") for r in (roots or [])]
        self.min_delay = min_delay
        self.preview_chars = preview_chars
        self.log = logger
        self._stopped = threading.Event()
        self._q: queue.Queue = queue.Queue(maxsize=10000)
        self._pending: dict[str, float] = {}
        self._seen_hash: dict[str, str] = {}   # path -> sha1（内容没变就不再复制）
        self._hashes: set[str] = set()
        self.total_bytes = 0
        self.copied = 0
        self.skipped = 0
        self.manifest: list[tuple] = []

    # ------------------------------------------------------------------ wiring
    def subscribe(self) -> None:
        def _on_event(ev):
            if ev.get("cat") != "file":
                return
            act = ev.get("act")
            if act not in ("create", "modify", "rename_to", "rename_from"):
                return
            path = ev.get("path")
            if not path:
                return
            low = path.lower()
            if low.rsplit("\\", 1)[-1] in SKIP_NAMES:
                return
            if any(part in low for part in SKIP_DIR_PARTS):
                return
            # ETW 会把全盘的文件事件都给过来（含系统 DLL 的装载）。这类只在
            # 目标自己的监视目录内才有必要留副本，否则会把 System32 抄一遍。
            if (ev.get("detail") or {}).get("source") == "etw":
                if not self.roots:
                    return
                if not any(low.startswith(r + "\\") or low == r for r in self.roots):
                    return
            now = time.time()
            last = self._pending.get(path)
            if last is not None and now - last < self.min_delay:
                self._pending[path] = now
                return
            self._pending[path] = now
            try:
                self._q.put_nowait(path)
            except queue.Full:
                self.skipped += 1
        self.bus.subscribe(_on_event)

    def stop(self) -> None:
        self._stopped.set()

    # -------------------------------------------------------------------- work
    def run(self) -> None:
        while not self._stopped.is_set():
            try:
                path = self._q.get(timeout=0.3)
            except queue.Empty:
                continue
            # 同一路径正在被反复写：等它安静下来再抄
            while time.time() - self._pending.get(path, 0) < self.min_delay:
                time.sleep(0.05)
                if self._stopped.is_set():
                    return
            try:
                self._handle(path)
            except Exception as exc:
                self.log(f"[filesnap] {path} 失败: {exc!r}")

    def _handle(self, path: str) -> None:
        if self.total_bytes >= self.max_total:
            if not getattr(self, "_cap_warned", False):
                self._cap_warned = True
                self.bus.emit("mark", "filesnap_capped",
                              detail={"max_total_mb": self.max_total // (1024 * 1024),
                                      "copied": self.copied})
            return
        try:
            st = os.stat(path)
        except OSError:
            return
        if not os.path.isfile(path) or st.st_size == 0 or st.st_size > self.max_file:
            self.skipped += 1
            return
        try:
            with open(path, "rb") as fh:
                data = fh.read(self.max_file)
        except OSError:
            return
        sha1 = hashlib.sha1(data).hexdigest()
        if self._seen_hash.get(path) == sha1:
            return
        self._seen_hash[path] = sha1

        ext = os.path.splitext(path)[1].lower()
        is_text = ext in TEXT_EXT or _looks_text(data)
        preview = ""
        if is_text:
            preview = _decode(data)[: self.preview_chars]

        os.makedirs(self.dir, exist_ok=True)
        base = os.path.basename(path) or "file"
        stamp = time.strftime("%H%M%S")
        target = os.path.join(self.dir, f"{stamp}-{sha1[:8]}-{base}")
        n = 1
        while os.path.exists(target):
            target = os.path.join(self.dir, f"{stamp}-{sha1[:8]}-{n}-{base}")
            n += 1
        try:
            shutil.copyfile(path, target)
        except OSError as exc:
            self.log(f"[filesnap] 复制失败 {path}: {exc}")
            return
        self.copied += 1
        self.total_bytes += st.st_size
        self._hashes.add(sha1)
        rel = os.path.relpath(target, os.path.dirname(self.dir))
        self.manifest.append((rel, path, st.st_size, sha1, stamp))
        self.bus.emit(
            "file", "snapshot",
            path=path,
            detail={
                "copy": rel,
                "size": st.st_size,
                "sha1": sha1,
                "is_text": is_text,
                "content": preview,
                "mtime": st.st_mtime,
            },
        )
