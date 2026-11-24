"""模块加载（DLL）记录：目标进程家族里每个进程装了哪些模块、什么时候装/卸的。

用 CreateToolhelp32Snapshot(TH32CS_SNAPMODULE) 轮询 —— 只读枚举，不注入、不挂钩、
不改目标的加载器。这是能看清"它到底用了哪个版本的库、有没有临时 LoadLibrary 一个
可疑 DLL"的最轻办法。

事件契约::

    module / load          进程还活着，本轮新看到某个模块
    module / unload        进程还活着，但某模块从它的模块表里消失了（真的被 FreeLibrary）
    module / process_exit  进程整体消失 —— 只发一条汇总，不把整表模块逐个 unload

边界：
  * 受保护进程 / 已退出进程 / 位数不匹配的进程会返回空列表 —— 当作失败计数，
    连续失败 3 次就不再碰这个 pid（避免每轮白跑还刷日志）
  * 轮询有间隔，活得比一个 interval 还短的模块可能在两次采样之间生灭，
    这种只能靠报告里的"首次/末次出现"时间戳去推断

`模块清单.txt` 基于**累计历史**（每个 pid 见过的所有模块并集，带首次/末次时间、
末次见到的基址与大小），所以哪怕目标在 stop() 之前就退出了，清单也不会是空的。
"""
from __future__ import annotations

import os
import threading
import time

from . import winapi

FAILS_BEFORE_SKIP = 3          # 同一 pid 连续失败几次后放弃


def _clock_text(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts if ts else time.time()))


class ModuleRecorder(threading.Thread):
    """每 interval 秒枚举一次 `tree.scope()` 里每个 pid 的模块表，做 diff + 记历史。"""

    def __init__(self, bus, tree, run_dir, interval: float = 2.5, logger=print):
        super().__init__(name="module-recorder", daemon=True)
        self.bus = bus
        self.tree = tree
        self.run_dir = run_dir
        self.interval = max(0.5, float(interval))
        self.log = logger or (lambda *_a, **_k: None)
        self.report_path = os.path.join(run_dir, "模块清单.txt")

        self._stopped = threading.Event()
        self._lock = threading.RLock()
        # 当前这一轮的实时模块表: pid -> {(name, base): info}
        self._mods: dict[int, dict] = {}
        # 累计历史: pid -> {name,path,first_seen,first_seen_t,last_seen,last_seen_t,
        #                  alive,exited_at,mods{(name,base): info}}
        self._history: dict[int, dict] = {}
        self._fails: dict[int, int] = {}       # pid -> 连续失败次数
        self._skipped: set[int] = set()        # 放弃采样的 pid

        self.loads = 0
        self.unloads = 0
        self.exits = 0
        self.ticks = 0
        self.started_at = None

    # ------------------------------------------------------------------ 生命周期
    def stop(self) -> None:
        """让轮询线程尽快退出，然后按累计历史写 模块清单.txt。可重复调用。"""
        self._stopped.set()
        if self.is_alive() and threading.current_thread() is not self:
            self.join(timeout=max(3.0, self.interval + 3.0))
        try:
            self._write_report()
        except Exception as exc:
            self.log(f"[modules] 报告写入失败: {exc!r}")

    def run(self) -> None:
        self.started_at = _clock_text()
        while not self._stopped.is_set():
            try:
                self._tick()
            except Exception as exc:
                self.log(f"[modules] tick 失败: {exc!r}")
            self._stopped.wait(self.interval)

    # ---------------------------------------------------------------------- 轮询
    def _scope(self) -> set:
        try:
            scope = set(self.tree.scope())
        except Exception as exc:
            self.log(f"[modules] scope 取不到: {exc!r}")
            return set()
        if not scope:
            # ProcessTree 要先 refresh() 才知道 pid 家族；别的记录器没在跑时自己补一次
            try:
                self.tree.refresh()
                scope = set(self.tree.scope())
            except Exception:
                scope = set()
        return scope

    def _modules(self, pid: int):
        """当前模块表 {(name, base): info}；取不到返回 None（失败计数 +1）。"""
        if pid in self._skipped:
            return None
        try:
            raw = winapi.module_list(pid) or []
        except Exception as exc:
            raw = []
            self.log(f"[modules] pid {pid} 枚举异常: {exc!r}")
        if not raw:
            fails = self._fails.get(pid, 0) + 1
            self._fails[pid] = fails
            if fails >= FAILS_BEFORE_SKIP:
                self._skipped.add(pid)
                self.log(f"[modules] pid {pid} 连续 {fails} 次取不到模块表"
                         f"（已退出或受保护），本会话不再采样该进程")
            return None
        self._fails.pop(pid, None)

        now = time.time()
        with self._lock:
            prev = self._mods.get(pid) or {}
        out: dict = {}
        for item in raw:
            name = str(item.get("name") or "")
            if not name:
                continue
            base = int(item.get("base") or 0)
            key = (name, base)
            old = prev.get(key)
            if old is not None:
                out[key] = old            # 首次出现时间要留着，不要每轮刷新
                continue
            out[key] = {
                "name": name,
                "path": str(item.get("path") or ""),
                "base": base,
                "base_hex": "0x%X" % base,
                "size": int(item.get("size") or 0),
                "first_seen_t": now,
                "first_seen": _clock_text(now),
            }
        return out

    def _tick(self) -> None:
        self.ticks += 1
        with self._lock:
            prev = self._mods
        scope = self._scope()
        current: dict[int, dict] = {}
        for pid in sorted(scope):
            mods = self._modules(pid)
            if mods is not None:
                current[pid] = mods
            elif pid in prev:
                # 本轮枚举失败（进程忙 / 受保护）：沿用上一轮的表，
                # 否则会把"取不到"误判成"全部卸载 + 又全部重新加载"
                current[pid] = prev[pid]

        now = time.time()
        with self._lock:
            self._mods = current
            history = self._history

        # 1) 还活着的进程：刷新历史，diff 出 load / unload
        for pid, mods in current.items():
            old = prev.get(pid) or {}
            proc = self.tree.name(pid)
            image = self.tree.path(pid)
            entry = history.get(pid)
            if entry is None:
                entry = {
                    "name": proc, "path": image,
                    "first_seen": _clock_text(now), "first_seen_t": now,
                    "last_seen": _clock_text(now), "last_seen_t": now,
                    "alive": True, "exited_at": None, "mods": {},
                }
                history[pid] = entry
            else:
                entry["alive"] = True
                entry["exited_at"] = None
                entry["last_seen"] = _clock_text(now)
                entry["last_seen_t"] = now
                entry["name"] = proc or entry.get("name")
                entry["path"] = image or entry.get("path")
            seen = entry["mods"]
            ppid = self.tree.ppid(pid)

            for key, info in mods.items():
                item = seen.get(key)
                if item is None:
                    seen[key] = {
                        "name": info["name"], "path": info["path"],
                        "base": info["base"], "base_hex": info["base_hex"],
                        "size": info["size"],
                        "first_seen": info["first_seen"], "first_seen_t": info["first_seen_t"],
                        "last_seen": _clock_text(now), "last_seen_t": now,
                        "loaded": True, "cycles": 1,
                    }
                    if key not in old:
                        # 新看到的模块（含进程第一次被采样时的全量装载表）
                        self.loads += 1
                        self.bus.emit(
                            "module", "load",
                            pid=pid, ppid=ppid, proc=proc,
                            path=info["path"] or info["name"],
                            detail={"name": info["name"], "base": info["base_hex"],
                                    "size": info["size"], "first_seen": True},
                        )
                else:
                    item["last_seen"] = _clock_text(now)
                    item["last_seen_t"] = now
                    item["base"] = info["base"]
                    item["base_hex"] = info["base_hex"]
                    item["size"] = info["size"]
                    if not item["loaded"]:
                        item["cycles"] += 1
                        self.loads += 1
                        self.bus.emit(
                            "module", "load",
                            pid=pid, ppid=ppid, proc=proc,
                            path=info["path"] or info["name"],
                            detail={"name": info["name"], "base": info["base_hex"],
                                    "size": info["size"], "first_seen": False,
                                    "reloaded": True},
                        )
                    item["loaded"] = True

            for key, info in old.items():
                if key in mods:
                    continue
                # 进程还活着、枚举也成功，模块却没了 -> 真的被卸载
                item = seen.get(key)
                if item is not None:
                    item["loaded"] = False
                self.unloads += 1
                self.bus.emit(
                    "module", "unload",
                    pid=pid, ppid=ppid, proc=proc, path=info["path"] or info["name"],
                    detail={"name": info["name"], "base": info["base_hex"],
                            "size": info["size"], "first_seen": False,
                            "lifetime_s": round(now - info["first_seen_t"], 1)},
                )

        # 2) 这一轮完全没再出现的进程：一条 process_exit 汇总，不逐个 unload
        for pid in prev:
            if pid in current or pid in scope:
                continue          # 还在 scope 里 => 只是本轮枚举失败，不算退出
            self._mark_exit(pid, now)

    def _mark_exit(self, pid: int, now: float) -> None:
        with self._lock:
            entry = self._history.get(pid)
        if entry is None:
            return
        entry["alive"] = False
        entry["exited_at"] = _clock_text(now)
        loaded = [item for item in entry["mods"].values() if item.get("loaded")]
        for item in loaded:
            item["loaded"] = False
        self.exits += 1
        self.bus.emit(
            "module", "process_exit",
            pid=pid, proc=entry.get("name"), path=entry.get("path"),
            detail={"modules": len(loaded), "reason": "process_exit",
                    "first_seen": entry.get("first_seen"),
                    "last_seen": entry.get("last_seen")},
        )

    # ---------------------------------------------------------------------- 报告
    def _state_text(self, item: dict, alive: bool) -> str:
        if not item.get("loaded"):
            return "运行中已卸载" if alive else "随进程退出"
        return "加载中" if alive else "随进程退出"

    def _write_report(self) -> None:
        with self._lock:
            history = {
                pid: {
                    "meta": {k: v for k, v in entry.items() if k != "mods"},
                    "mods": dict(entry["mods"]),
                }
                for pid, entry in self._history.items()
            }
            skipped = sorted(self._skipped)

        total_entries = sum(len(h["mods"]) for h in history.values())
        alive_now = sum(1 for h in history.values() if h["meta"].get("alive"))

        lines: list[str] = []

        def add(text: str = "") -> None:
            lines.append(text)

        add("# 模块清单（DLL 加载记录）")
        add()
        add("采集开始: %s" % (self.started_at or "(未开始)"))
        add("采集结束: %s" % _clock_text())
        add("轮询间隔: %g 秒    轮询次数: %d" % (self.interval, self.ticks))
        add("目标进程数: %d    模块条目总数: %d（累计历史，含已退出进程）"
            % (len(history), total_entries))
        add("装载事件: %d    卸载事件: %d    进程退出事件: %d"
            % (self.loads, self.unloads, self.exits))
        if skipped:
            add("放弃采样的 pid（采不到模块表）: %s" % ", ".join(str(p) for p in skipped))
        add()

        if not history:
            add("（记录期间没有采到任何进程的模块表）")
            add()
        for pid in sorted(history, key=lambda p: (history[p]["meta"].get("first_seen_t") or 0, p)):
            meta = history[pid]["meta"]
            mods = history[pid]["mods"]
            alive = bool(meta.get("alive"))
            if alive:
                title = "## pid %d  %s  [采集结束时仍存活]" % (pid, meta.get("name") or "(名字未知)")
            else:
                title = "## pid %d  %s  [已退出 %s]" % (
                    pid, meta.get("name") or "(名字未知)", meta.get("exited_at") or "?")
            add(title)
            add("   映像: %s" % (meta.get("path") or "(取不到路径)"))
            add("   首次见到: %s    最后见到: %s" % (meta.get("first_seen"), meta.get("last_seen")))
            still = sum(1 for item in mods.values() if item.get("loaded"))
            add("   模块条目: %d（其中采集结束时仍加载 %d）" % (len(mods), still))
            add()
            add("%-30s  %-18s  %10s  %-19s  %-19s  %-12s  %s" % (
                "模块名", "基址(末次)", "大小", "首次出现", "末次出现", "状态", "完整路径"))
            for item in sorted(mods.values(),
                               key=lambda i: (i.get("base") or 0, (i.get("name") or "").lower())):
                add("%-30s  %-18s  %10s  %-19s  %-19s  %-12s  %s" % (
                    item.get("name"), item.get("base_hex"),
                    format(item.get("size") or 0, ","),
                    item.get("first_seen"), item.get("last_seen"),
                    self._state_text(item, alive),
                    item.get("path") or "(无路径)"))
            add()

        add("收尾时刻仍存活的进程 %d 个" % alive_now)

        folder = os.path.dirname(self.report_path)
        if folder:
            os.makedirs(folder, exist_ok=True)
        with open(self.report_path, "w", encoding="utf-8-sig", newline="") as fh:
            fh.write("\r\n".join(lines) + "\r\n")
