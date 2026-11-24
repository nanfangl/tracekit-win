"""TraceKit - record everything a program does, from outside the program.

    # 1) 体检：是不是易语言、是不是 VMP 壳、32/64 位
    python -m tracekit probe "C:\\path\\app.exe"

    # 2) 录一遍：启动目标 + 全套记录器
    python -m tracekit run --name 目标软件 --watch-dir "D:\\data" "C:\\path\\app.exe"

    # 3) 已经开着？直接挂上去（按进程名或 PID）
    python -m tracekit attach --name 目标软件 --pid 4321

    # 4) 出报告（run 结束时自动出一份）
    python -m tracekit report runs\\目标软件-20261124-213000

Everything is passive: no injection, no patching, no debugger attached, so a
VMProtect packed EasyLanguage binary keeps running exactly as it would
normally while its behaviour lands in events.jsonl / events.sqlite.
"""
from __future__ import annotations

import argparse
import ctypes
import io
import json
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime

from . import core, detect, winapi
from .proctree import ProcessTree
from .mod_proc import ProcessRecorder
from .mod_file import FileRecorder
from .mod_reg import RegistryRecorder
from .mod_net import NetworkRecorder
from .mod_win import WindowRecorder
from .mod_uictl import ControlTextRecorder
from .mod_uiact import UiActionRecorder
from .mod_uitree import UiTreeRecorder
from .mod_filesnap import FileSnapshotRecorder
from .mod_input import InputRecorder
from .mod_tail import LogTailRecorder, DEFAULT_PATTERNS

LIVE_SKIP = {"shot"}          # keep the console readable
BANNER = r"""
 _____              _  __ _  _
|_   _| _ _ __ _ __| |/ /(_)| |_
  | |  | '_/ _` / _| ' < | |  _|
  |_|  |_| \__,_\__|_|\_\|_|\__|   software behaviour recorder
"""


def log(msg: str) -> None:
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def setup_console() -> None:
    """UTF-8 console so Chinese paths / EasyLanguage text survive the trip."""
    try:
        kernel32 = ctypes.WinDLL("kernel32")
        kernel32.SetConsoleOutputCP(65001)
        kernel32.SetConsoleCP(65001)
    except Exception:
        pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


# --------------------------------------------------------------- run context
class Session:
    def __init__(self, run_dir, name, exe, pid, meta, bus, store):
        self.run_dir = run_dir
        self.name = name
        self.exe = exe
        self.pid = pid
        self.meta = meta
        self.bus = bus
        self.store = store
        self.tree = ProcessTree([pid] if pid else [])
        self.starters = []   # (label, start_callable, stop_callable)
        self.proc_handle = None

    def add(self, label, start, stop):
        self.starters.append((label, start, stop))


def _stdout_pump(proc, bus, run_dir, tag, stream, sink_file):
    import io

    path = os.path.join(run_dir, sink_file)
    sink = io.open(path, "a", encoding="utf-8", newline="")
    if os.path.getsize(path) == 0:
        sink.write("\ufeff")  # 记事本友好：只加一次 BOM
    try:
        for raw in iter(stream.readline, b""):
            text = core.decode_bytes(raw).rstrip("\r\n")
            if not text:
                continue
            sink.write(text + "\r\n")
            bus.emit(tag, "line", pid=proc.pid, path=text[:200],
                     detail={"line": text[:4000]})
    except Exception:
        pass
    finally:
        try:
            sink.close()
        except Exception:
            pass


def _live_printer(bus):
    def _print(ev):
        if ev["cat"] in LIVE_SKIP:
            return
        proc = ev.get("proc") or "-"
        path = ev.get("path") or ""
        if len(path) > 110:
            path = path[:107] + "..."
        detail = ev.get("detail") or {}
        extra = ""
        if ev["cat"] == "ui":
            extra = f" ({detail.get('control_class')})"
        elif ev["cat"] == "proc" and detail.get("cmdline"):
            extra = f" cmd={detail['cmdline'][:80]}"
        elif ev["cat"] == "log":
            extra = " :: " + (detail.get("line") or "")[:100]
        print(f"  {ev['ts'][11:23]} {ev['cat']:<6} {ev['act']:<12} {proc:<18} {path}{extra}",
              flush=True)
    bus.subscribe(_print)


# ------------------------------------------------------------------- launching
def build_watch_dirs(exe, extra, include_temp=False, drives=None, removable=True):
    dirs = []
    for d in extra or []:
        dirs.append(d)
    if exe:
        d = os.path.dirname(os.path.abspath(exe))
        if d:
            dirs.append(d)
    cwd = os.getcwd()
    dirs.append(cwd)
    if include_temp:
        tmp = os.environ.get("TEMP")
        if tmp:
            dirs.append(tmp)
    # U盘 / 移动硬盘：经常是"导出文件"的目的地
    if removable:
        try:
            import ctypes as _ct

            mask = _ct.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if not (mask >> i) & 1:
                    continue
                root = f"{chr(ord('A') + i)}:\\"
                if _ct.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) == 2:
                    dirs.append(root)
        except Exception:
            pass
    for d in drives or []:
        d = d.strip().rstrip("\\/")
        if not d:
            continue
        if len(d) == 1:
            d = d + ":\\"
        dirs.append(d)
    out, seen = [], set()
    for d in dirs:
        if not d:
            continue
        a = os.path.abspath(os.path.expandvars(d))
        if not os.path.isdir(a):
            continue
        if a.lower() in seen:
            continue
        seen.add(a.lower())
        out.append(a)
    return out


def finalize_outputs(run_dir: str) -> dict:
    """把机器用文件整理成中文可读产物。

    report.py 写的是 report.md / timeline.html / shots/，这里统一改成中文名并对
    文件内部引用同步改名，再给给人看的文件补 UTF-8 BOM（记事本不乱码）。
    机器用文件（events.jsonl / events.sqlite / run_meta.json）保持原名与原编码。
    """
    import shutil

    out = {}
    md_src = os.path.join(run_dir, "report.md")
    html_src = os.path.join(run_dir, "timeline.html")
    md = os.path.join(run_dir, "报告.md")
    html = os.path.join(run_dir, "时间线.html")

    shots_src = os.path.join(run_dir, "shots")
    shots = os.path.join(run_dir, "截图")
    if os.path.isdir(shots_src):
        try:
            if os.path.isdir(shots):
                shutil.rmtree(shots, ignore_errors=True)
            os.replace(shots_src, shots)
        except OSError:
            pass

    def _rewrite(src, dst, extra=None):
        if not os.path.exists(src):
            return None
        with open(src, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        text = text.replace("timeline.html", "时间线.html").replace("shots/", "截图/")
        if extra:
            for a, b in extra:
                text = text.replace(a, b)
        with open(dst, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        try:
            os.remove(src)
        except OSError:
            pass
        return dst

    if _rewrite(md_src, md):
        extra_md = _extra_sections(run_dir)
        if extra_md:
            with open(md, "a", encoding="utf-8", newline="") as fh:
                fh.write(extra_md)
        core.add_bom_if_missing(md)
        out["report"] = md
    if _rewrite(html_src, html):
        out["timeline"] = html
    return out


def _extra_sections(run_dir: str) -> str:
    """把新增采集面（界面结构/模块/系统改动/文件副本/剪贴板/主机/崩溃）补进报告。"""
    import sqlite3

    db = os.path.join(run_dir, "events.sqlite")
    if not os.path.exists(db):
        return ""
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    except Exception:
        return ""

    def one(sql, default=0):
        try:
            row = conn.execute(sql).fetchone()
            return row[0] if row and row[0] is not None else default
        except Exception:
            return default

    try:
        trees = one("select count(*) from events where cat='ui' and act in ('tree','tree_new')")
        menus = one("select count(*) from events where cat='ui' and act='tree' and detail like '%\"menus\": [{%'")
        snap = one("select count(*) from events where cat='file' and act='snapshot'")
        snap_kb = one("select sum(json_extract(detail,'$.size')) from events where cat='file' and act='snapshot'", 0) or 0
        mods = one("select count(*) from events where cat='module' and act='load'")
        pids = one("select count(distinct pid) from events where cat='module' and act='load'")
        sys_add = one("select count(*) from events where cat='sys' and act='added'")
        sys_rm = one("select count(*) from events where cat='sys' and act='removed'")
        sys_ch = one("select count(*) from events where cat='sys' and act='changed'")
        clips = one("select count(*) from events where cat='clip'")
        clip_img = one("select count(*) from events where cat='clip' and act='copy_image'")
        clip_files = one("select count(*) from events where cat='clip' and act='copy_files'")
        hosts = one("select count(*) from events where cat='net' and act='host'")
        hosts_bad = one("select count(*) from events where cat='net' and act='host_unknown'")
        crashes = one("select count(*) from events where cat='crash'")
    except Exception:
        conn.close()
        return ""
    conn.close()

    def line(label, value, note=""):
        return f"| {label} | {value} | {note} |\n"

    md = ["\n## 十、扩展采集面\n\n",
          "| 采集面 | 数量 | 明细文件 |\n", "| --- | --- | --- |\n"]
    md.append(line("界面结构事件", trees, "`界面结构.txt`（窗口/菜单栏/控件树）"))
    md.append(line("含菜单栏的窗口结构", menus, "菜单项 id 与层级都在事件 detail 里"))
    md.append(line("文件副本", f"{snap} 个 / {snap_kb / 1024:.1f} KB", "`文件副本\\`（SHA1 去重）"))
    md.append(line("DLL 模块加载", f"{mods} 条 / {pids} 个进程", "`模块清单.txt`"))
    md.append(line("系统改动", f"新增 {sys_add} / 删除 {sys_rm} / 修改 {sys_ch}", "`系统改动.txt`（服务/自启动/计划任务/启动夹）"))
    md.append(line("剪贴板", f"{clips} 次（图片 {clip_img}、文件 {clip_files}）", "`剪贴板图片\\`"))
    md.append(line("远端主机解析", f"成功 {hosts} / 未解析 {hosts_bad}", "时间线里筛 `net/host`"))
    md.append(line("崩溃证据", crashes, "`崩溃信息.txt`（有才生成）"))
    md.append("\n> 说明：以上是扩展层，详细原始数据在 `events.jsonl` / `events.sqlite` 与 `时间线.html` 里。\n")
    return "".join(md)


def export_logs(run_dir: str) -> str | None:
    """Rebuild the target's own logs as one readable text file.

    `log` events are incremental file lines, `ui` events are full snapshots of
    an on-screen control - so the file gets: every log line in time order, then
    the last text of each captured control (the "运行日志" box as it ended).
    """
    import sqlite3

    db = os.path.join(run_dir, "events.sqlite")
    if not os.path.exists(db):
        return None
    out = os.path.join(run_dir, "日志汇总.txt")
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    except Exception:
        return None
    try:
        groups: dict[str, list[tuple[str, str]]] = {}
        for ts, path, detail in conn.execute(
            "SELECT ts, path, detail FROM events WHERE cat='log' AND act='line' ORDER BY seq"
        ):
            try:
                line = (json.loads(detail) or {}).get("line", "")
            except Exception:
                line = ""
            if not line:
                continue
            groups.setdefault(path or "(unknown)", []).append((ts, line))
        finals: dict[str, tuple] = {}
        for ts, path, detail, act in conn.execute(
            "SELECT ts, path, detail, act FROM events WHERE cat='ui' ORDER BY seq"
        ):
            try:
                d = json.loads(detail) or {}
            except Exception:
                d = {}
            key = f"{d.get('control_class')}#{d.get('control_hwnd')}"
            if d.get("control_hwnd"):
                finals[key] = (ts, d.get("text") or "", d.get("length") or 0)
        actions = list(conn.execute(
            "SELECT ts, act, path, detail FROM events WHERE cat='ui' "
            "AND act IN ('click','response','key_target') ORDER BY seq"
        ))
        with io.open(out, "w", encoding="utf-8", newline="") as fh:
            fh.write("\ufeff")
            fh.write("# TraceKit 日志汇总\r\n")
            fh.write(f"# 生成时间: {datetime.now().isoformat(timespec='seconds')}\r\n")
            for path, rows in groups.items():
                fh.write(f"\r\n===== 文件: {path} （{len(rows)} 行）=====\r\n")
                for ts, line in rows:
                    fh.write(f"{ts[11:23]}  {line}\r\n")
            if actions:
                fh.write("\r\n===== 用户动作与程序响应 =====\r\n")
                for ts, act, path, detail in actions:
                    try:
                        d = json.loads(detail) or {}
                    except Exception:
                        d = {}
                    ctl = d.get("control") or {}
                    where = d.get("form") or ctl.get("top_title") or ""
                    head = f"{ts[11:23]}  "
                    if act == "click":
                        fh.write(f"{head}点击 {path}  (id={ctl.get('ctrl_id')}"
                                 f"{', 双击/连击 x' + str(d.get('click_count')) if (d.get('click_count') or 1) > 1 else ''}"
                                 f", 窗口={where})\n")
                    elif act == "key_target":
                        fh.write(f"{head}按键 vk={d.get('vk')} 落在 {path}  (窗口={where})\n")
                    else:
                        fh.write(f"{head}响应 {path}  ({d.get('change_count')} 项变化)\n")
                        for chg in (d.get("changes") or [])[:8]:
                            if chg.get("kind") == "state_changed":
                                fh.write(f"        - {chg.get('class')}: {chg.get('before')} -> {chg.get('after')}\n")
                            elif chg.get("kind") == "control_appeared":
                                fh.write(f"        - {chg.get('class')} 出现: {str(chg.get('after'))[:120]}\n")
                            else:
                                fh.write(f"        - {chg.get('class')} 消失\n")
                        for win in (d.get("new_windows") or [])[:5]:
                            fh.write(f"        - 新窗口: {win.get('class')} 「{win.get('title')}」\n")
            if finals:
                fh.write("\r\n===== 界面控件最终文本 =====\r\n")
                for key, (ts, text, length) in finals.items():
                    fh.write(f"\n--- {key}  ({length} 字符, 末次 {ts[11:23]}) ---\n")
                    fh.write(text.replace("\r\n", "\n").replace("\n", "\r\n") + "\r\n")
        return out
    finally:
        conn.close()


def apply_profile(modules: dict, profile: str | None) -> dict:
    """命令行预设：在默认开关之上整体调档，用户显式 --no-xxx 仍然生效。"""
    presets = {
        "light": {
            "ui": False, "uiact": False, "input": False, "etw": False,
            "uitree": False, "filesnap": False, "sys": False,
            "modules": False, "dns": False, "tail": True,
        },
        "standard": {
            "filesnap": True,
        },
        "full": {
            "ui": True, "uiact": True, "input": True, "etw": True,
            "uitree": True, "filesnap": True, "sys": True,
            "modules": True, "dns": True, "tail": True,
        },
    }
    if profile in presets:
        modules.update(presets[profile])
    return modules


def check_crashes(bus, run_dir: str, proc_name: str, since: float) -> list[dict]:
    """目标退出后回头看有没有崩溃证据：WER 转储 / 错误报告目录 / 事件日志。"""
    found: list[dict] = []
    if not proc_name:
        return found
    stem = proc_name.lower().replace(".exe", "")
    roots = []
    local = os.environ.get("LOCALAPPDATA")
    if local:
        roots.append(os.path.join(local, "CrashDumps"))
        roots.append(os.path.join(local, "Microsoft", "Windows", "WER", "ReportArchive"))
        roots.append(os.path.join(local, "Microsoft", "Windows", "WER", "ReportQueue"))
    for root in roots:
        if not os.path.isdir(root):
            continue
        try:
            for name in os.listdir(root)[:2000]:
                low = name.lower()
                if stem not in low:
                    continue
                full = os.path.join(root, name)
                try:
                    mtime = os.path.getmtime(full)
                except OSError:
                    continue
                if mtime < since - 5:
                    continue
                size = 0
                try:
                    size = os.path.getsize(full)
                except OSError:
                    pass
                found.append({"kind": os.path.basename(os.path.dirname(full)),
                              "path": full, "size": size, "mtime": mtime})
        except OSError:
            continue
    for item in found:
        bus.emit("crash", "evidence", path=item["path"],
                 detail={"kind": item["kind"], "size": item["size"],
                         "note": "目标进程可能崩溃（WER 证据）"})
    if found:
        try:
            with io.open(os.path.join(run_dir, "崩溃信息.txt"), "w",
                         encoding="utf-8-sig", newline="") as fh:
                fh.write("\ufeff崩溃证据\r\n")
                for item in found:
                    fh.write(f"{item['kind']}  {item['size']} B  {item['path']}\r\n")
        except OSError:
            pass
    return found



def start_session(args, external_stop=None) -> int:
    print(BANNER)
    busy_log = log
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_name = f"{args.name or 'run'}-{ts}"
    run_dir = os.path.abspath(args.out or os.path.join("runs", run_name))
    os.makedirs(run_dir, exist_ok=True)

    exe = os.path.abspath(args.target) if getattr(args, "target", None) else None
    if exe and not os.path.exists(exe):
        busy_log(f"目标不存在: {exe}")
        return 2

    # --- static triage
    target_info = {}
    if exe:
        log("PE/壳 体检中 ...")
        target_info = detect.analyze(exe)
        print(detect.summary(target_info))
        for line in detect.summary(target_info).splitlines():
            pass

    # --- process to record
    if getattr(args, "pid", None):
        pid = int(args.pid)
        exe = exe or winapi.process_image_path(pid)
    else:
        pid = None

    started_at = datetime.now().astimezone().isoformat(timespec="seconds")
    modules = {
        "proc": True, "file": not args.no_file, "reg": not args.no_reg,
        "net": not args.no_net, "win": not args.no_win, "ui": not args.no_ui,
        "input": not args.no_input, "tail": not args.no_tail, "etw": not args.no_etw,
        "uiact": not args.no_uiact, "uitree": not args.no_uitree,
        "filesnap": not args.no_keep_files, "sys": not args.no_sys,
        "modules": not args.no_modules, "dns": not args.no_dns,
    }
    modules = apply_profile(modules, getattr(args, "profile", None))
    watch_dirs = build_watch_dirs(exe, args.watch_dir, include_temp=args.watch_temp,
                                  drives=getattr(args, "watch_drive", None),
                                  removable=not getattr(args, "no_removable", False))
    meta = {
        "run_id": run_name,
        "name": args.name or (os.path.basename(exe) if exe else "unknown"),
        "started_at": started_at,
        "ended_at": None,
        "exe": exe,
        "pid": pid,
        "watch_dirs": watch_dirs,
        "modules": modules,
        "target_info": target_info,
        "counters": {},
        "notes": "",
        "tool": "TraceKit",
        "admin": winapi.is_admin(),
    }
    core.write_meta(run_dir, meta)
    store = core.Store(run_dir)
    bus = core.Bus(store)
    session = Session(run_dir, meta["name"], exe, pid, meta, bus, store)
    if not args.quiet:
        _live_printer(bus)
    bus.emit("mark", "session_start", path=meta["name"],
             detail={"exe": exe, "watch_dirs": watch_dirs,
                     "admin": winapi.is_admin(),
                     "target_info": {k: target_info.get(k) for k in
                                     ("machine", "bits", "likely_vmprotect",
                                      "likely_easy_language", "import_count")}})

    # --- recorders：先把监听器挂上，再启动目标，避免目标秒退漏掉早期事件
    excludes = [run_dir, os.path.join(os.getcwd(), "runs")]
    excludes += [os.path.abspath(d) for d in (args.exclude_dir or []) if d]

    if modules["file"]:
        fr = FileRecorder(bus, watch_dirs, logger=log, exclude=excludes)
        if fr.start():
            session.add("file", lambda: True, fr.stop)
        else:
            modules["file"] = False

    if modules["tail"]:
        tr = LogTailRecorder(bus, watch_dirs, patterns=tuple(args.tail_pattern),
                             start_ts=time.time(), logger=log, exclude=excludes)
        tr.start()
        session.add("tail", lambda: True, tr.stop)

    if modules["reg"]:
        rr = RegistryRecorder(bus, roots=args.reg_root, depth=args.reg_depth, logger=log)
        if rr.start():
            session.add("reg", lambda: True, rr.stop)
        else:
            modules["reg"] = False

    if modules["net"]:
        nr = NetworkRecorder(bus, session.tree, interval=args.net_interval, logger=log)
        nr.start()
        session.add("net", lambda: True, nr.stop)

    if modules["win"]:
        wr = WindowRecorder(bus, session.tree, run_dir=run_dir,
                            shot_interval=args.shot_interval,
                            shot_on_focus=not args.no_shot_on_focus, logger=log)
        wr.start()
        session.add("win", lambda: True, wr.stop)

    if modules["ui"]:
        ur = ControlTextRecorder(bus, session.tree, interval=args.ui_interval, logger=log)
        ur.start()
        session.add("ui", lambda: True, ur.stop)

    if modules["uiact"]:
        ua = UiActionRecorder(bus, session.tree, interval=args.uiact_interval,
                              response_delay=args.response_delay, logger=log)
        ua.subscribe()
        ua.start()
        session.add("uiact", lambda: True, ua.stop)

    if modules["input"]:
        ir = InputRecorder(bus, session.tree, run_dir=run_dir, logger=log)
        ir.start()
        session.add("input", lambda: True, ir.stop)

    if modules["filesnap"]:
        fs = FileSnapshotRecorder(bus, run_dir,
                                  max_file=args.keep_max_mb * 1024 * 1024,
                                  max_total=args.keep_total_mb * 1024 * 1024,
                                  roots=watch_dirs, logger=log)
        fs.subscribe()
        fs.start()
        session.add("filesnap", lambda: True, fs.stop)

    if modules["uitree"]:
        ut = UiTreeRecorder(bus, session.tree, run_dir=run_dir,
                            interval=args.uitree_interval, logger=log)
        ut.subscribe()
        ut.start()

        def _stop_uitree():
            ut.stop()
            ut.join(timeout=5)

        session.add("uitree", lambda: True, _stop_uitree)

    if modules["modules"]:
        try:
            from .mod_modules import ModuleRecorder
            mr = ModuleRecorder(bus, session.tree, run_dir, logger=log)
            mr.start()
            session.add("modules", lambda: True, mr.stop)
        except Exception as exc:
            modules["modules"] = False
            log(f"[modules] 未启用: {exc!r}")

    if modules["sys"]:
        try:
            from .mod_sys import SystemSurfaceRecorder
            sr = SystemSurfaceRecorder(bus, run_dir, logger=log)
            sr.start()
            session.add("sys", lambda: True, sr.stop)
        except Exception as exc:
            modules["sys"] = False
            log(f"[sys] 未启用: {exc!r}")

    if modules["dns"]:
        try:
            from .mod_dns import HostResolver
            hr = HostResolver(bus, session.tree, logger=log)
            hr.subscribe()
            hr.start()
            session.add("dns", lambda: True, hr.stop)
        except Exception as exc:
            modules["dns"] = False
            log(f"[dns] 未启用: {exc!r}")
    etw = None
    if modules["etw"]:
        try:
            from .mod_etw import EtwCapture, EtwUnavailable

            class _ScopePids:
                """Live pid set = the target's whole process family right now.

                ETW is a system wide source, so every kernel event is checked
                against this before it reaches the bus; the set follows new
                children as they spawn instead of freezing at start.
                """

                def __init__(self, tree, ttl: float = 1.0):
                    self._tree = tree
                    self._ttl = ttl
                    self._t = 0.0
                    self._set = set()

                def __contains__(self, pid) -> bool:
                    now = time.time()
                    if now - self._t >= self._ttl:
                        try:
                            self._set = self._tree.scope()
                        except Exception:
                            self._set = set()
                        self._t = now
                    return int(pid) in self._set

                def __len__(self) -> int:
                    return len(self._set)

            etw = EtwCapture(
                bus, os.path.join(run_dir, "etw"), logger=log,
                write_etl=bool(args.etw_etl),
                pid_filter={pid} if args.etw_all else None,
            )
            if not args.etw_all:
                # swap the frozen set for a live one so children are covered too
                etw.pid_filter = _ScopePids(session.tree)
            ok = etw.start_capture()
            if ok:
                session.add("etw", lambda: True, etw.stop_capture)
                scope_txt = "全系统" if args.etw_all else "仅目标进程树"
                log(f"[etw] 内核级 FileIO/Registry/Network 已开启（{scope_txt}；可记录读文件与字节数）")
            else:
                modules["etw"] = False
        except Exception as exc:
            modules["etw"] = False
            log(f"[etw] 未启用: {exc}")

    meta["modules"] = modules
    core.write_meta(run_dir, meta)
    log(f"记录中 -> {run_dir}")
    log("按 Ctrl+C 结束记录（或等目标进程退出）")

    # --- launch the target (or attach)
    proc = None
    if getattr(args, "launch", False):
        cmd = [exe] + list(args.app_args or [])
        cwd = args.cwd or os.path.dirname(exe)
        log(f"启动目标: {' '.join(cmd)}  (cwd={cwd})")
        creationflags = 0
        if args.inherit_stdio:
            proc = subprocess.Popen(cmd, cwd=cwd, creationflags=creationflags)
        else:
            proc = subprocess.Popen(
                cmd, cwd=cwd, creationflags=creationflags,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        pid = proc.pid
        session.pid = pid
        session.proc_handle = proc
        session.tree.add_root(pid)
        meta["pid"] = pid
        core.write_meta(run_dir, meta)
        bus.emit("mark", "target_launched", pid=pid, proc=os.path.basename(exe),
                 path=exe, detail={"cmdline": " ".join(cmd), "cwd": cwd})
        if not args.inherit_stdio:
            threading.Thread(target=_stdout_pump,
                             args=(proc, bus, run_dir, "stdout", proc.stdout, "stdout.log"),
                             daemon=True).start()
            threading.Thread(target=_stdout_pump,
                             args=(proc, bus, run_dir, "stderr", proc.stderr, "stderr.log"),
                             daemon=True).start()
    else:
        log(f"挂载已运行进程 pid={pid} ({winapi.process_image_path(pid)})")
        bus.emit("mark", "target_attached", pid=pid, proc=os.path.basename(exe or ""),
                 path=exe, detail={"pid": pid})

    # --- 进程记录器与运行时分型（需要目标 pid，只能放在启动之后）
    proc_rec = ProcessRecorder(bus, session.tree, interval=args.proc_interval, logger=log)
    proc_rec.start()
    session.add("proc", lambda: True, proc_rec.stop)
    session.tree.refresh()

    def _classify():
        time.sleep(2.5)
        try:
            rt = detect.runtime_triage(pid)
            meta["runtime"] = rt
            core.write_meta(run_dir, meta)
            bus.emit("mark", "runtime_classified", pid=pid,
                     proc=os.path.basename(exe or ""), path="运行时判定",
                     detail=rt)
            if rt.get("easy_language"):
                log(f"[detect] 运行时为易语言程序，证据: {', '.join(rt.get('evidence') or [])}")
        except Exception as exc:
            log(f"[detect] 运行时判定失败: {exc!r}")

    threading.Thread(target=_classify, daemon=True).start()
    # --- main wait loop
    stop = threading.Event()

    def _on_sigint(_sig, _frm):
        stop.set()

    try:
        signal.signal(signal.SIGINT, _on_sigint)
    except Exception:
        pass

    deadline = time.time() + args.duration if args.duration else None
    grace_until = None
    while not stop.is_set() and not (external_stop is not None and external_stop.is_set()):
        if deadline and time.time() > deadline:
            log("到达 --duration 上限，停止。")
            break
        if proc is not None:
            rc = proc.poll()
            if rc is not None:
                if grace_until is None:
                    log(f"目标进程已退出 (code={rc})，收尾中 ...")
                    grace_until = time.time() + args.grace
                elif time.time() > grace_until:
                    break
        else:
            alive = session.tree.in_scope(pid)
            if not alive:
                if grace_until is None:
                    log("目标进程已退出，收尾中 ...")
                    grace_until = time.time() + args.grace
                elif time.time() > grace_until:
                    break
        time.sleep(0.4)

    # --- teardown
    log("停止各记录器 ...")
    bus.mark("session_stop")
    for label, _start, stopfn in reversed(session.starters):
        try:
            stopfn()
        except Exception as exc:
            log(f"[{label}] 停止失败: {exc!r}")
    try:
        if proc is not None:
            check_crashes(bus, run_dir, os.path.basename(exe or ""), time.time() - 3600)
    except Exception as exc:
        log(f"[crash] 取证失败: {exc!r}")
    counts = store.close()
    meta["ended_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
    meta["counts"] = counts
    meta["modules"] = modules
    core.write_meta(run_dir, meta)
    store.close()
    log(f"事件总数: {sum(counts.values())}  {counts}")
    print()
    for label in ("file", "reg", "net", "win", "ui", "uiact", "uitree",
                  "input", "tail", "modules", "sys", "dns", "filesnap", "etw"):
        print(f"  {label:<8} {'on' if modules.get(label) else 'off'}")

    if not args.no_report:
        try:
            from .report import build_report
            md, html = build_report(run_dir)
            fixed = finalize_outputs(run_dir)
            log(f"报告: {fixed.get('report', md)}")
            log(f"时间线: {fixed.get('timeline', html)}")
        except Exception as exc:
            log(f"[report] 生成失败: {exc!r}")
    logs = export_logs(run_dir)
    if logs:
        log(f"日志汇总: {logs}")
    log(f"原始数据: {os.path.join(run_dir, 'events.jsonl')} / events.sqlite")
    return 0


# ------------------------------------------------------------------------ cli
def run_selftest(args) -> int:
    """Drive demo_victim.py through a full recording and assert every layer fired."""
    import sqlite3
    import tempfile

    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    demo = os.path.join(here, "demo_victim.py")
    demo_exe = os.path.join(here, "TraceKitDemo.exe")
    if not os.path.exists(demo):
        # frozen (PyInstaller onefile): the demo rides along as bundled data
        base = getattr(sys, "_MEIPASS", "")
        for cand in ("TraceKitDemo.exe", "demo_victim.py"):
            if base and os.path.exists(os.path.join(base, cand)):
                if cand.endswith(".exe"):
                    demo_exe = os.path.join(base, cand)
                    demo = demo_exe
                else:
                    demo = os.path.join(base, cand)
                here = base
                break
    if not os.path.exists(demo):
        print(f"缺少演练程序: {demo}")
        return 2
    workdir = os.path.join(tempfile.gettempdir(), "tracekit_selftest_work")
    os.makedirs(workdir, exist_ok=True)
    root_dir = os.path.dirname(os.path.abspath(sys.executable)) if getattr(sys, "frozen", False) else here
    out_dir = os.path.join(root_dir, "runs", "selftest")
    cmd = [sys.executable]
    if not getattr(sys, "frozen", False):
        cmd += ["-m", "tracekit"]
    cmd += [
        "run",
        "--name", "selftest", "--watch-dir", workdir, "--cwd", here,
        "--duration", str(args.seconds + 6), "--shot-interval", "4",
        "--quiet", "--no-report", "--out", out_dir,
    ]
    if args.no_etw:
        cmd.append("--no-etw")
    # 非冻结：python demo_victim.py；冻结：内置的 TraceKitDemo.exe（同参数语义）
    if os.path.exists(demo_exe) and getattr(sys, "frozen", False):
        target_cmd = [demo_exe]
    else:
        target_cmd = [sys.executable, demo]
    cmd += ["--"] + target_cmd + ["--workdir", workdir, "--seconds", str(args.seconds)]
    print(" ".join(cmd))
    rc = subprocess.call(cmd, cwd=here)
    if rc != 0:
        print(f"记录进程返回 {rc}")
        return rc

    db = os.path.join(out_dir, "events.sqlite")
    conn = sqlite3.connect(db)
    counts = dict(conn.execute("SELECT cat, COUNT(*) FROM events GROUP BY cat"))
    conn.close()
    required = ["file", "log", "ui", "reg", "proc", "mark"]
    optional = ["net", "win", "input", "shot", "stdout"]
    print("\n=== 自测结果 ===")
    ok = True
    for cat in required:
        n = counts.get(cat, 0)
        flag = "PASS" if n else "FAIL"
        if not n:
            ok = False
        print(f"  [{flag}] {cat:<8} {n}")
    for cat in optional:
        n = counts.get(cat, 0)
        print(f"  [{'PASS' if n else 'skip'}] {cat:<8} {n}")
    print(f"\n事件总数 {sum(counts.values())}  输出目录 {out_dir}")
    try:
        from .report import build_report
        md, html = build_report(out_dir)
        fixed = finalize_outputs(out_dir)
        md = fixed.get("report", md)
        html = fixed.get("timeline", html)
        print(f"报告 {os.path.getsize(md) / 1024:.0f} KB / 时间线 {os.path.getsize(html) / 1024:.0f} KB")
    except Exception as exc:
        print(f"报告生成失败: {exc!r}")
        ok = False
    print("SELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main(argv=None, external_stop=None) -> int:
    setup_console()
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = argparse.ArgumentParser(prog="tracekit", description="软件行为记录器")
    sub = ap.add_subparsers(dest="cmd")

    def add_common(p):
        p.add_argument("--name", help="被测软件名（用于目录和报告标题）")
        p.add_argument("--out", help="输出目录（默认 runs\\<name>-<时间>）")
        p.add_argument("--watch-dir", action="append", default=[],
                       help="额外监视的目录，可重复")
        p.add_argument("--watch-temp", action="store_true",
                       help="把 %%TEMP%% 也纳入监视（噪声大，默认不监视）")
        p.add_argument("--exclude-dir", action="append", default=[],
                       help="不监视的目录，可重复")
        p.add_argument("--reg-root", action="append", default=None,
                       help="注册表根，如 HKCU\\Software（可重复，默认只 HKCU\\Software）")
        p.add_argument("--reg-depth", type=int, default=4)
        p.add_argument("--proc-interval", type=float, default=0.2,
                       help="进程快照间隔（越小越不漏短命子进程，CPU 略高）")
        p.add_argument("--net-interval", type=float, default=1.0)
        p.add_argument("--ui-interval", type=float, default=1.0)
        p.add_argument("--shot-interval", type=float, default=0.0,
                       help="定时截图间隔（秒，0=只在焦点切换时截）")
        p.add_argument("--no-shot-on-focus", action="store_true")
        p.add_argument("--tail-pattern", action="append", default=list(DEFAULT_PATTERNS),
                       help="日志文件后缀，可重复")
        p.add_argument("--duration", type=float, default=0, help="最长记录秒数，0=直到目标退出")
        p.add_argument("--grace", type=float, default=2.5)
        p.add_argument("--profile", choices=("light", "standard", "full"),
                       default="standard",
                       help="预设：light=只录基础面；standard=默认；full=全部打开（含文件副本）")
        p.add_argument("--no-uitree", action="store_true", help="不抓界面结构（窗口/控件/菜单树）")
        p.add_argument("--uitree-interval", type=float, default=3.0)
        p.add_argument("--no-keep-files", action="store_true",
                       help="不留文件副本（默认 standard 会留，单文件 2MB / 总量 200MB 上限）")
        p.add_argument("--keep-max-mb", type=float, default=2.0)
        p.add_argument("--keep-total-mb", type=float, default=200.0)
        p.add_argument("--no-sys", action="store_true", help="不做服务/启动项/计划任务改动快照")
        p.add_argument("--no-modules", action="store_true", help="不记录 DLL 模块加载")
        p.add_argument("--no-dns", action="store_true", help="不做远端 IP 反查主机名")
        p.add_argument("--watch-drive", action="append", default=[],
                       help="监视整个盘，如 C 或 D:（很重，按需）")
        p.add_argument("--no-removable", action="store_true", help="不自动监视 U 盘/移动硬盘")
        p.add_argument("--quiet", action="store_true")
        p.add_argument("--no-file", action="store_true")
        p.add_argument("--no-reg", action="store_true")
        p.add_argument("--no-net", action="store_true")
        p.add_argument("--no-win", action="store_true")
        p.add_argument("--no-ui", action="store_true")
        p.add_argument("--no-input", action="store_true")
        p.add_argument("--no-uiact", action="store_true", help="不记录控件级点击/响应（只保留原始坐标）")
        p.add_argument("--uiact-interval", type=float, default=0.8)
        p.add_argument("--response-delay", type=float, default=0.7, help="动作后多久抓响应快照（秒）")
        p.add_argument("--no-tail", action="store_true")
        p.add_argument("--no-etw", action="store_true")
        p.add_argument("--etw-all", action="store_true", help="ETW 记录全系统事件（默认只留目标进程树，噪声很大）")
        p.add_argument("--etw-etl", action="store_true", help="同时保留 ETL 原始文件（默认不写，避免大文件）")
        p.add_argument("--no-report", action="store_true")

    p_run = sub.add_parser("run", help="启动目标并记录")
    add_common(p_run)
    p_run.add_argument("target", help="目标 exe 路径")
    p_run.add_argument("--cwd")
    p_run.add_argument("--inherit-stdio", action="store_true",
                       help="不接管目标 stdout（GUI 程序一般无输出）")
    p_run.add_argument("app_args", nargs=argparse.REMAINDER, help="-- 之后是目标自己的参数")

    p_att = sub.add_parser("attach", help="挂到已运行的进程")
    add_common(p_att)
    p_att.add_argument("--pid", type=int)
    p_att.add_argument("--exe", help="按 exe 路径匹配")
    p_att.add_argument("--title", help="按窗口标题关键字匹配")

    p_probe = sub.add_parser("probe", help="静态体检：易语言/壳/位数/导入表")
    p_probe.add_argument("target")

    p_rep = sub.add_parser("report", help="从已有 run 目录重新出报告")
    p_rep.add_argument("dir")

    p_test = sub.add_parser("selftest", help="用演练程序自测：各记录器是否都出数据")
    p_test.add_argument("--seconds", type=float, default=16)
    p_test.add_argument("--no-etw", action="store_true")

    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 1

    if args.cmd == "probe":
        info = detect.analyze(args.target)
        print(detect.summary(info))
        print("\n节区:")
        for sec in info.get("sections", []):
            print(f"  {sec['name']:<10} vsize=0x{sec['vsize']:<8X} raw=0x{sec['rawsize']:<8X} "
                  f"entropy={sec['entropy']:<6} exec={sec['executable']} write={sec['writable']}")
        print("\n导入:")
        for dll, funcs in (info.get("imports") or {}).items():
            print(f"  {dll}: {len(funcs)} -> {', '.join(funcs[:12])}"
                  + (" ..." if len(funcs) > 12 else ""))
        return 0

    if args.cmd == "report":
        from .report import build_report
        md, html = build_report(args.dir)
        fixed = finalize_outputs(args.dir)
        print(f"报告: {fixed.get('report', md)}")
        print(f"时间线: {fixed.get('timeline', html)}")
        return 0

    if args.cmd == "selftest":
        return run_selftest(args)

    # run / attach -> normalize
    args.launch = args.cmd == "run"
    if args.launch:
        app_args = list(args.app_args or [])
        if app_args and app_args[0] == "--":
            app_args = app_args[1:]
        # relative paths given on our command line stay meaningful even though the
        # target starts in its own directory
        base = os.getcwd()
        resolved = []
        for a in app_args:
            if a and not a.startswith("-") and not os.path.isabs(a):
                cand = os.path.join(base, a)
                if os.path.exists(cand):
                    resolved.append(os.path.abspath(cand))
                    continue
            resolved.append(a)
        args.app_args = resolved
    else:
        args.cwd = None
        args.app_args = []
        if not (args.pid or args.exe or args.title):
            # pick by name guess: match against running processes
            if args.name:
                for pid, _ppid, name in winapi.iter_processes():
                    if name.lower().startswith(args.name.lower()):
                        args.pid = pid
                        log(f"按名字匹配到 pid={pid} ({name})")
                        break
            if not args.pid:
                print("attach 需要 --pid / --exe / --title / --name 之一")
                return 2
        elif args.exe and not args.pid:
            want = os.path.abspath(args.exe).lower()
            for pid, _ppid, name in winapi.iter_processes():
                image = winapi.process_image_path(pid)
                if image and image.lower() == want:
                    args.pid = pid
                    break
            if not args.pid:
                print(f"没找到正在运行的 {args.exe}")
                return 2
        elif args.title and not args.pid:
            want = args.title.lower()
            for hwnd, title, _cls, pid in winapi.enum_windows():
                if want in title.lower():
                    args.pid = pid
                    break
            if not args.pid:
                print(f"没找到标题包含 {args.title!r} 的窗口")
                return 2

    return start_session(args, external_stop)


if __name__ == "__main__":
    raise SystemExit(main())
