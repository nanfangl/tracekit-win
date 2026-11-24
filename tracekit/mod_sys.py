"""系统改动面快照：服务 / 自启动 / 计划任务 / 启动文件夹。

目标程序"落地"时（装服务、写 Run 键、注册计划任务、往启动文件夹扔快捷方式）
往往不在文件事件或网络事件里留下明显痕迹——这类持久化手法只能靠对比系统改动面发现。
本模块在 start() 时于后台线程采一份基线，stop() 时再采一份做 diff，把新增 / 删除 /
修改发到总线，同时写一份给人看的中文报告 `run_dir\\系统改动.txt`。

设计取舍：
  * 全部只读：不写注册表、不改 ACL，读不到的子键就跳过（普通用户权限即可运行）
  * 基线在后台线程跑，start() 立即返回，不拖慢目标启动；采集只 stat 不读文件内容
  * 注册表视图固定为 64 位（KEY_WOW64_64KEY），这样哪怕用 32 位 Python 运行，
    HKLM\\SOFTWARE\\...\\Run 与显式的 WOW6432Node 路径也各自读到自己那份，
    不会因为重定向把两个面读成同一个面
"""
from __future__ import annotations

import os
import threading
import time
import winreg
from datetime import datetime

SURFACES = ("service", "autorun", "task", "startup")
SURFACE_LABELS = {
    "service": "服务",
    "autorun": "自启动",
    "task": "计划任务",
    "startup": "启动文件夹",
}
SURFACE_MARKS = {"added": "新增", "removed": "删除", "changed": "修改"}

SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"
SERVICE_FIELDS = ("ImagePath", "Start", "Type", "DisplayName")

WINLOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
WINLOGON_VALUES = ("Shell", "Userinit")

KEY_WOW64_64 = getattr(winreg, "KEY_WOW64_64KEY", 0x0100)

# (标签, 根键, 子键, 注册表视图) —— 标签直接进事件 path 与报告
AUTORUN_LOCATIONS = (
    ("HKLM Run", winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", KEY_WOW64_64),
    ("HKLM RunOnce", winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", KEY_WOW64_64),
    ("HKLM Run (WOW64)", winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", KEY_WOW64_64),
    ("HKCU Run", winreg.HKEY_CURRENT_USER,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", None),
    ("HKCU RunOnce", winreg.HKEY_CURRENT_USER,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", None),
)

MAX_TASKS = 20000        # 计划任务目录的采集上限（防病态机器）
MAX_LABEL = 300          # 事件 path 的长度上限，别把整条命令塞进 path


def _now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _as_text(value):
    """注册表值 -> JSON 可序列化的标量（多字符串转 list）。"""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        for enc in ("utf-16-le", "gb18030", "utf-8"):
            try:
                return value.decode(enc, "strict").rstrip("\x00")
            except Exception:
                continue
        return value.decode("utf-16-le", "replace").rstrip("\x00")
    if isinstance(value, (list, tuple)):
        return [_as_text(v) for v in value]
    return value


def _open_key(hive, sub: str, view: int | None = None):
    """打开只读键；带视图失败时退化成默认视图，仍然失败返回 None。"""
    if view:
        try:
            return winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | view)
        except OSError:
            pass
    try:
        return winreg.OpenKey(hive, sub, 0, winreg.KEY_READ)
    except OSError:
        return None


def _clip(text: str) -> str:
    text = str(text)
    return text if len(text) <= MAX_LABEL else text[:MAX_LABEL] + "..."


class SystemSurfaceRecorder:
    """服务 / 自启动 / 计划任务 / 启动文件夹 的 基线-收尾 两次快照 diff。

    典型用法（cli.py 里就是这么接的）::

        sr = SystemSurfaceRecorder(bus, run_dir, logger=log)
        sr.start()                       # 立即返回，基线在后台线程采
        ...
        sr.stop()                        # 收尾快照 + diff + 发事件 + 写报告
    """

    def __init__(self, bus, run_dir, logger=print, include_services: bool = True,
                 include_autoruns: bool = True, include_tasks: bool = True):
        self.bus = bus
        self.run_dir = run_dir
        self.log = logger or (lambda *_a, **_k: None)
        self.include_services = include_services
        self.include_autoruns = include_autoruns
        self.include_tasks = include_tasks

        self.report_path = os.path.join(run_dir, "系统改动.txt")
        self._lock = threading.RLock()
        self._thread = None
        self._started = False
        self._finished = False
        self._baseline_done = threading.Event()

        self._before = None
        self._before_notes: list[str] = []
        self._after_notes: list[str] = []
        self.baseline_seconds = 0.0
        self.after_seconds = 0.0
        self.started_at = None
        self.finished_at = None
        self.stats: dict = {}

    # ------------------------------------------------------------------ 生命周期
    def start(self) -> bool:
        """启动后台基线采集。立即返回（不阻塞调用方），重复调用无副作用。"""
        with self._lock:
            if self._started:
                return True
            self._started = True
        self.started_at = _now_text()
        self._thread = threading.Thread(
            target=self._baseline_worker, name="sys-surface-baseline", daemon=True
        )
        self._thread.start()
        return True

    def wait_baseline(self, timeout: float = 10.0) -> bool:
        """等基线采完（selftest / 想立刻造改动的场景用）。True = 基线可用。"""
        ok = self._baseline_done.wait(max(0.1, float(timeout)))
        with self._lock:
            return bool(ok and self._before is not None)

    def stop(self) -> dict:
        """收尾快照 + diff + 发事件 + 写报告。可重复调用，只有第一次生效。"""
        with self._lock:
            if self._finished:
                return dict(self.stats)
            self._finished = True

        self.wait_baseline(timeout=8.0)
        started = time.perf_counter()
        try:
            after, after_notes = self._collect()
        except Exception as exc:
            self.log(f"[sys] 收尾快照失败: {exc!r}")
            after, after_notes = None, []
        self.after_seconds = time.perf_counter() - started
        self._after_notes = after_notes

        with self._lock:
            before = self._before
            before_notes = list(self._before_notes)

        changes = []
        if before is not None and after is not None:
            changes = self._diff(before, after)
            for surface, act, key, old, new in changes:
                try:
                    self.bus.emit(
                        "sys", act,
                        path=self._label(surface, key, old, new),
                        detail={"surface": surface, "before": old, "after": new},
                    )
                except Exception as exc:
                    self.log(f"[sys] 发事件失败 ({surface}/{act}): {exc!r}")
        else:
            self.log("[sys] 基线或收尾快照缺失，跳过 diff（报告只给规模）")

        self.finished_at = _now_text()
        sizes_after = self._sizes(after) if after is not None else {k: 0 for k in SURFACES}
        counts = {act: 0 for act in SURFACE_MARKS}
        for _surface, act, _k, _o, _n in changes:
            counts[act] = counts.get(act, 0) + 1
        self.stats = {
            "service": sizes_after["service"],
            "autorun": sizes_after["autorun"],
            "task": sizes_after["task"],
            "startup": sizes_after["startup"],
            "added": counts["added"],
            "removed": counts["removed"],
            "changed": counts["changed"],
            "baseline_seconds": round(self.baseline_seconds, 2),
            "report": self.report_path,
        }

        try:
            self._write_report(before, after, changes,
                               before_notes + [n for n in after_notes if n not in before_notes])
        except Exception as exc:
            self.log(f"[sys] 报告写入失败: {exc!r}")

        self.log(
            "[sys] 系统改动面: 新增 %d / 删除 %d / 修改 %d  报告: %s"
            % (counts["added"], counts["removed"], counts["changed"], self.report_path)
        )
        return dict(self.stats)

    # -------------------------------------------------------------- 基线后台线程
    def _baseline_worker(self) -> None:
        started = time.perf_counter()
        try:
            snap, notes = self._collect()
        except Exception as exc:
            self.log(f"[sys] 基线采集失败: {exc!r}")
            snap, notes = None, []
        self.baseline_seconds = time.perf_counter() - started
        with self._lock:
            self._before = snap
            self._before_notes = notes
        self._baseline_done.set()
        if snap is not None:
            size = self._sizes(snap)
            self.log(
                "[sys] 基线完成 %.2fs：服务 %d / 自启动 %d / 计划任务 %d / 启动文件夹 %d"
                % (self.baseline_seconds, size["service"], size["autorun"],
                   size["task"], size["startup"])
            )

    # ---------------------------------------------------------------- 采集四个面
    def _collect(self):
        """采一份完整快照 -> (snapshot, notes)。notes 记读不到的面，进报告。"""
        notes: list[str] = []
        snap = {"service": {}, "autorun": {}, "task": {}, "startup": {}}
        if self.include_services:
            snap["service"] = self._snapshot_services(notes)
        if self.include_autoruns:
            snap["autorun"] = self._snapshot_autoruns(notes)
        if self.include_tasks:
            snap["task"] = self._snapshot_tasks(notes)
        snap["startup"] = self._snapshot_startup(notes)
        return snap, notes

    def _note(self, notes: list, surface: str, text: str) -> None:
        notes.append("%s: %s" % (SURFACE_LABELS.get(surface, surface), text))

    def _snapshot_services(self, notes: list) -> dict:
        out: dict = {}
        root = _open_key(winreg.HKEY_LOCAL_MACHINE, SERVICES_KEY)
        if root is None:
            self._note(notes, "service", "打不开 HKLM\\%s（权限不足或键不存在）" % SERVICES_KEY)
            return out
        try:
            index = 0
            while True:
                try:
                    name = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                try:
                    with winreg.OpenKey(root, name, 0, winreg.KEY_READ) as sub:
                        item = {}
                        for field in SERVICE_FIELDS:
                            try:
                                value, _vtype = winreg.QueryValueEx(sub, field)
                            except OSError:
                                continue
                            item[field] = _as_text(value)
                        if item:
                            out[name] = item
                except OSError:
                    # 个别服务的 ACL 是 SYSTEM-only，读不到就跳过，不算错误
                    continue
        finally:
            try:
                root.Close()
            except Exception:
                pass
        return out

    def _snapshot_autoruns(self, notes: list) -> dict:
        # 键用 (位置标签, 值名) 二元组，值就是原始字符串，diff 只看字符串
        out: dict = {}
        for label, hive, sub, view in AUTORUN_LOCATIONS:
            key = _open_key(hive, sub, view)
            if key is None:
                self._note(notes, "autorun", "%s 打不开 %s（不存在或缺权限）" % (label, sub))
                continue
            try:
                index = 0
                while True:
                    try:
                        name, value, _vtype = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
                    out[(label, name or "(默认)")] = _as_text(value)
            finally:
                try:
                    key.Close()
                except Exception:
                    pass

        key = _open_key(winreg.HKEY_LOCAL_MACHINE, WINLOGON_KEY, KEY_WOW64_64)
        if key is None:
            self._note(notes, "autorun", "Winlogon 打不开 %s" % WINLOGON_KEY)
        else:
            try:
                for name in WINLOGON_VALUES:
                    try:
                        value, _vtype = winreg.QueryValueEx(key, name)
                    except OSError:
                        continue
                    out[("Winlogon", name)] = _as_text(value)
            finally:
                try:
                    key.Close()
                except Exception:
                    pass
        return out

    def _snapshot_tasks(self, notes: list) -> dict:
        out: dict = {}
        windir = os.environ.get("WINDIR") or r"C:\Windows"
        root = os.path.join(windir, "System32", "Tasks")
        if not os.path.isdir(root):
            self._note(notes, "task", "目录不存在 %s" % root)
            return out
        prefix = root.rstrip("\\") + "\\"
        capped = False
        denied: list = []

        def _onerror(exc):
            if len(denied) < 3:
                denied.append(exc)

        for dirpath, _dirnames, filenames in os.walk(root, onerror=_onerror):
            for filename in filenames:
                full = os.path.join(dirpath, filename)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                out[full[len(prefix):]] = {
                    "size": int(st.st_size),
                    "mtime": round(float(st.st_mtime), 3),
                }
                if len(out) >= MAX_TASKS:
                    capped = True
                    break
            if capped:
                break
        if capped:
            self._note(notes, "task", "超过 %d 个文件，只记前 %d 个" % (MAX_TASKS, MAX_TASKS))
        elif denied:
            # 实测：非管理员（受限令牌）枚举 System32\Tasks 会被 ACL 挡住，
            # 结果是 0 项。必须写进采集说明，否则会被误读成"机器上没计划任务"。
            self._note(notes, "task",
                       "枚举被拒（%s）；非管理员看不到 %s，计划任务一面按 0 项计"
                       % (denied[0], root))
        elif not out:
            self._note(notes, "task", "一个任务文件都没枚举到（%s）" % root)
        return out

    def _snapshot_startup(self, notes: list) -> dict:
        out: dict = {}
        folders = []
        appdata = os.environ.get("APPDATA")
        if appdata:
            folders.append(("用户启动", os.path.join(
                appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")))
        programdata = os.environ.get("ProgramData")
        if programdata:
            folders.append(("公共启动", os.path.join(
                programdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")))
        if not folders:
            self._note(notes, "startup", "APPDATA / ProgramData 环境变量缺失")
        for _label, path in folders:
            if not os.path.isdir(path):
                self._note(notes, "startup", "目录不存在 %s" % path)
                continue
            try:
                entries = list(os.scandir(path))
            except OSError as exc:
                self._note(notes, "startup", "读取失败 %s (%s)" % (path, exc))
                continue
            for entry in entries:
                try:
                    st = entry.stat()
                except OSError:
                    continue
                out[entry.path] = {
                    "size": int(st.st_size),
                    "mtime": round(float(st.st_mtime), 3),
                }
        return out

    # -------------------------------------------------------------------- diff
    def _diff(self, before: dict, after: dict) -> list:
        """[(surface, act, key, before_value, after_value)]，顺序固定便于报告复现。"""
        changes = []
        for surface in SURFACES:
            old = before.get(surface) or {}
            new = after.get(surface) or {}
            if old == new:
                continue
            for key in sorted(set(old) | set(new), key=str):
                if key not in old:
                    changes.append((surface, "added", key, None, new[key]))
                elif key not in new:
                    changes.append((surface, "removed", key, old[key], None))
                elif old[key] != new[key]:
                    changes.append((surface, "changed", key, old[key], new[key]))
        return changes

    # -------------------------------------------------------------- 文本格式化
    def _key_text(self, surface: str, key) -> str:
        if surface == "service":
            return "服务: %s" % key
        if surface == "autorun":
            if isinstance(key, tuple):
                label, name = key
            else:  # 兜底，正常不会走到
                label, name = str(key), ""
            return "自启动(%s): %s" % (label, name)
        if surface == "task":
            return "计划任务: \\%s" % key
        return "启动文件夹: %s" % key

    def _value_text(self, surface: str, value) -> str:
        if value is None:
            return "(不存在)"
        if surface == "service" and isinstance(value, dict):
            parts = ["%s=%s" % (f, value[f]) for f in SERVICE_FIELDS if f in value]
            return ", ".join(parts) if parts else "(无字段)"
        if surface in ("task", "startup") and isinstance(value, dict):
            try:
                stamp = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(float(value.get("mtime") or 0))
                )
            except Exception:
                stamp = "?"
            return "%s 字节, 修改于 %s" % (value.get("size"), stamp)
        return str(value)

    def _label(self, surface: str, key, before, after) -> str:
        """事件 path：人类可读的单行标识。"""
        value = after if after is not None else before
        if surface == "service":
            image = ""
            if isinstance(value, dict):
                image = str(value.get("ImagePath") or "")
            return _clip("服务: %s (ImagePath=%s)" % (key, image or "未知"))
        return _clip("%s = %s" % (self._key_text(surface, key), self._value_text(surface, value)))

    @staticmethod
    def _sizes(snapshot) -> dict:
        if not snapshot:
            return {k: 0 for k in SURFACES}
        return {k: len(snapshot.get(k) or {}) for k in SURFACES}

    # -------------------------------------------------------------------- 报告
    def _write_report(self, before, after, changes: list, notes) -> None:
        size_before = self._sizes(before)
        size_after = self._sizes(after) if after is not None else {k: 0 for k in SURFACES}
        counts = {act: 0 for act in SURFACE_MARKS}
        for _surface, act, _k, _o, _n in changes:
            counts[act] = counts.get(act, 0) + 1

        lines: list[str] = []

        def add(text: str = "") -> None:
            lines.append(text)

        add("# 系统改动面报告")
        add()
        add("基线采集: %s%s" % (
            self.started_at or "(未开始)",
            ("  耗时 %.2f 秒" % self.baseline_seconds) if self.baseline_seconds else "",
        ))
        add("收尾采集: %s%s" % (
            self.finished_at or "(未结束)",
            ("  耗时 %.2f 秒" % self.after_seconds) if self.after_seconds else "",
        ))
        add("记录目录: %s" % os.path.abspath(self.run_dir))
        add("差异合计: 新增 %d / 删除 %d / 修改 %d"
            % (counts["added"], counts["removed"], counts["changed"]))
        add()

        if before is None:
            add("> 基线快照缺失（采集未完成或被中断），本次只输出规模，未做 diff。")
            add()
        if not changes:
            add("未检测到改动：服务 / 自启动 / 计划任务 / 启动文件夹 在记录期间"
                "均无新增、删除、修改。")
            add()

        for surface in SURFACES:
            add("## %s（surface=%s）" % (SURFACE_LABELS[surface], surface))
            for act in ("added", "removed", "changed"):
                rows = [c for c in changes if c[0] == surface and c[1] == act]
                add("### %s %d" % (SURFACE_MARKS[act], len(rows)))
                if not rows:
                    add("（无）")
                else:
                    for _s, _a, key, old, new in rows:
                        if act == "changed":
                            add("- %s: %s -> %s" % (
                                self._key_text(surface, key),
                                self._value_text(surface, old),
                                self._value_text(surface, new),
                            ))
                        elif act == "added":
                            add("+ %s: %s" % (
                                self._key_text(surface, key),
                                self._value_text(surface, new),
                            ))
                        else:
                            add("- %s: %s" % (
                                self._key_text(surface, key),
                                self._value_text(surface, old),
                            ))
                add()
            add()

        if notes:
            add("## 采集说明")
            seen = set()
            for note in notes:
                if note in seen:
                    continue
                seen.add(note)
                add("- %s" % note)
            add()

        add("## 基线规模")
        add("- 服务 %d 项%s" % (
            size_before["service"],
            ("（收尾 %d 项）" % size_after["service"]) if after is not None else "",
        ))
        add("- 自启动 %d 项%s" % (
            size_before["autorun"],
            ("（收尾 %d 项）" % size_after["autorun"]) if after is not None else "",
        ))
        add("- 计划任务 %d 项%s" % (
            size_before["task"],
            ("（收尾 %d 项）" % size_after["task"]) if after is not None else "",
        ))
        add("- 启动文件夹 %d 项%s" % (
            size_before["startup"],
            ("（收尾 %d 项）" % size_after["startup"]) if after is not None else "",
        ))
        add()

        folder = os.path.dirname(self.report_path)
        if folder:
            os.makedirs(folder, exist_ok=True)
        # 记事本按 ANSI 猜编码会乱码 -> UTF-8 带 BOM，换行固定 CRLF
        with open(self.report_path, "w", encoding="utf-8-sig", newline="") as fh:
            fh.write("\r\n".join(lines) + "\r\n")
