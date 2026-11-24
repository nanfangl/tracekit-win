# -*- coding: utf-8 -*-
"""TraceKit 报告生成模块（零第三方依赖）。

只使用标准库：sqlite3 / json / html / pathlib / datetime / collections / re / os。

对外接口
--------
build_report(run_dir) -> tuple[str, str]
    读取 run_dir 下的记录数据（events.sqlite / run_meta.json / stdout.log /
    stderr.log / shots/），在同目录生成：
        report.md      中文 Markdown 分析报告
        timeline.html  单文件自包含（CSS/JS 内联）的可交互时间线
    返回 (md_path, html_path)。

设计要点
--------
* 事件只从 sqlite 读一遍，聚合结果（A 字典）同时喂给 Markdown 与 HTML 渲染器。
* 大 run（10 万条以上）全部走"分页渲染"：HTML 内联数据用紧凑数组编码，
  前端每页 500 条，只渲染当前页，避免一次性插入十万个 <tr>。
* HTML 里内联 JSON 时把 "</" 转义成 "<\\/"，既防止 </script> 提前闭合，也
  防注入；渲染层一律走 textContent，不用 innerHTML 拼数据。
"""

from __future__ import annotations

import html as _html
import json
import os
import re
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path

__all__ = ["build_report"]

# --------------------------------------------------------------------------
# 常量
# --------------------------------------------------------------------------

CAT_NAMES = {
    "proc": "进程",
    "file": "文件",
    "reg": "注册表",
    "win": "窗口",
    "ui": "界面",
    "input": "输入",
    "clip": "剪贴板",
    "stdout": "标准输出",
    "stderr": "标准错误",
    "log": "日志",
    "shot": "截图",
    "mark": "标记",
    "net": "网络",
}

CAT_ORDER = [
    "proc", "file", "reg", "net", "win", "ui",
    "input", "clip", "stdout", "stderr", "log", "shot", "mark",
]

CAT_COLORS = {
    "proc": "#2563eb",
    "file": "#059669",
    "reg": "#7c3aed",
    "net": "#0891b2",
    "win": "#db2777",
    "ui": "#a21caf",
    "input": "#ea580c",
    "clip": "#ca8a04",
    "stdout": "#475569",
    "stderr": "#b91c1c",
    "log": "#57534e",
    "shot": "#0d9488",
    "mark": "#6b7280",
}

# 注册表动作名（TraceKit 采集器用长名）→ 报告里更好读的中文
REG_ACT_NAMES = {
    "reg_key_create": "键创建",
    "reg_key_delete": "键删除",
    "reg_value_create": "值创建",
    "reg_value_delete": "值删除",
    "reg_value_set": "值修改",
    "set": "值设置",
    "delete": "删除",
    "create_key": "键创建",
    "query": "读取",
    "read": "读取",
}

FILE_GROUPS = ["写", "创建", "删除", "改名", "读", "其他"]

# 路径归属：系统 / 临时目录特征（统一小写 + 反斜杠后匹配）
SYS_HINTS = (
    "\\windows\\", "\\windows", "\\system32", "\\syswow64", "\\winsxs",
    "\\program files", "\\programdata", "\\appdata", "\\temp\\", "\\temp",
    "\\tmp\\", "\\$recycle.bin", "\\system volume information",
    "\\etc\\", "\\usr\\", "\\var\\", "\\bin\\", "\\lib\\", "\\proc\\",
    "\\pagefile.sys", "\\hiberfil.sys",
)

CLIP_MAX = 200            # 剪贴板长文本截断
STDOUT_LINES = 200        # stdout.log 摘录行数
STDERR_LINES = 30         # stderr.log 摘录行数
TIMELINE_MAX = 400        # 时间线最多行数
TIMELINE_PER_CAT = 140    # 单类别进入时间线候选上限
HTML_PAGE_SIZE = 500      # 前端每页条数
MAX_HTML_EVENTS = 200000  # 内联进 HTML 的事件上限（超出截断并提示）
MAX_INLINE_DETAIL = 20000  # 单条 detail 内联进 HTML 的字符上限
MAX_INLINE_CHARS = 32 * 1024 * 1024  # 内联事件文本总预算（防止 HTML 膨胀成几百 MB）
MAX_SHOT_THUMBS = 600     # 缩略图上限
TOP_FILES = 30            # 写入文件 Top N
DETAIL_TOP = 20           # 每个文件分组明细行数

SHOT_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp", ".gif"}

_PROC_CREATE_ACTS = {
    "create", "start", "started", "exec", "execve", "spawn", "launch",
    "fork", "process_start", "open",
}
_PROC_EXIT_ACTS = {"exit", "terminate", "terminated", "quit", "stop", "end", "process_exit"}

_FILE_WRITE = {"write", "append", "modify", "save", "set", "writefile", "write_file", "put", "edit", "truncate"}
_FILE_CREATE = {"create", "new", "mkdir", "touch", "createfile", "create_file", "create_dir", "open_write"}
_FILE_DELETE = {"delete", "remove", "unlink", "rmdir", "del", "rm", "erase"}
_FILE_RENAME = {"rename", "move", "mv", "renamefile", "rename_file", "moved"}
_FILE_READ = {"read", "open", "load", "access", "stat", "query", "open_read", "readfile", "read_file"}

_NET_HOST_KEYS = (
    "remote", "remote_addr", "remoteaddr", "raddr", "dst", "dest", "destination",
    "endpoint", "host", "ip", "peer", "addr", "address", "remote_ip", "server",
)
_NET_PORT_KEYS = ("port", "dport", "dst_port", "remote_port", "rport", "dest_port")

_REG_NAME_KEYS = ("name", "value_name", "valuename", "key_name", "reg_name", "valuenam")
_REG_DATA_KEYS = ("data", "value", "new_value", "content", "old_value", "dat")

_SIZE_KEYS = ("size", "bytes", "new_size", "length", "file_size", "count")
_CMD_KEYS = ("cmdline", "command_line", "commandline", "command", "cmd", "argv", "args", "image")
_TITLE_KEYS = ("title", "window", "window_title", "caption", "name", "class")
_CLIP_KEYS = ("text", "content", "data", "clip", "value")


# --------------------------------------------------------------------------
# 小工具
# --------------------------------------------------------------------------

def _first(d, keys, default=None):
    """按顺序取 detail 里第一个非空字段。"""
    if not d:
        return default
    for k in keys:
        v = d.get(k)
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        if isinstance(v, (list, tuple, dict)) and not v:
            continue
        return v
    return default


def _as_text(v, limit=None):
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        s = " ".join(str(x) for x in v)
    elif isinstance(v, dict):
        try:
            s = json.dumps(v, ensure_ascii=False)
        except (TypeError, ValueError):
            s = str(v)
    else:
        s = str(v)
    if limit is not None and len(s) > limit:
        s = s[:limit] + "…"
    return s


def _clip(s, n):
    """单行截断（换行压成 ⏎）。"""
    s = "" if s is None else str(s)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    if len(s) <= n:
        return s
    return s[:n] + "…"


def _multiline_clip(s, n):
    """保持换行的截断，用于剪贴板。"""
    s = "" if s is None else str(s)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    if len(s) <= n:
        return s
    return s[:n] + "…"


def _fmt_ts(ts, t=None):
    """把 ISO8601 字符串规整成 'YYYY-MM-DD HH:MM:SS[.mmm]'。"""
    if isinstance(ts, str) and ts.strip():
        s = ts.strip().replace("T", " ")
        if s.endswith("Z"):
            s = s[:-1]
        if len(s) > 19:
            s = re.sub(r"[+-]\d{2}:?\d{2}$", "", s)
        if "." in s:
            head, frac = s.split(".", 1)
            digits = re.sub(r"\D", "", frac)
            return head + ("." + digits[:3] if digits else "")
        return s
    if t is not None:
        try:
            return datetime.fromtimestamp(float(t)).strftime("%Y-%m-%d %H:%M:%S")
        except (OverflowError, OSError, ValueError, TypeError):
            return "-"
    return "-"


def _parse_iso(s):
    if not isinstance(s, str) or not s.strip():
        return None
    txt = s.strip()
    if txt.endswith("Z"):
        txt = txt[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(txt)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y%m%d%H%M%S"):
        try:
            return datetime.strptime(s.strip(), fmt)
        except ValueError:
            continue
    return None


def _iso_text(dt):
    if dt is None:
        return "—"
    try:
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError):
        return "—"


def _seconds_between(a, b):
    if a is None or b is None:
        return None
    if (a.tzinfo is None) != (b.tzinfo is None):
        a = a.replace(tzinfo=None)
        b = b.replace(tzinfo=None)
    try:
        return (b - a).total_seconds()
    except (TypeError, OverflowError):
        return None


def _human_dur(sec):
    if sec is None:
        return "—"
    neg = sec < 0
    sec = abs(float(sec))
    if sec < 1:
        out = "%.0f 毫秒" % (sec * 1000)
    elif sec < 60:
        out = "%.1f 秒" % sec
    elif sec < 3600:
        out = "%d 分 %.0f 秒" % (sec // 60, sec % 60)
    elif sec < 86400:
        out = "%d 小时 %d 分" % (sec // 3600, (sec % 3600) // 60)
    else:
        out = "%d 天 %d 小时" % (sec // 86400, (sec % 86400) // 3600)
    return ("-" + out) if neg else out


def _pct(n, total):
    if not total:
        return "0.0%"
    return "%.1f%%" % (n * 100.0 / total)


def _parse_detail(raw):
    """detail -> (dict, 是否解析失败)。"""
    if raw is None:
        return {}, False
    if isinstance(raw, (dict, list)):
        return (raw if isinstance(raw, dict) else {"value": raw}), False
    s = str(raw).strip()
    if not s:
        return {}, False
    try:
        v = json.loads(s)
    except (ValueError, TypeError):
        return {}, True
    if isinstance(v, dict):
        return v, False
    return {"value": v}, False


def _md_cell(v, limit=400):
    if v is None:
        return ""
    s = str(v)
    s = s.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " ⏎ ")
    s = s.replace("|", "\\|")
    # 中和 "看起来像标签" 的尖括号，避免 report.md 被 Markdown 渲染器当 HTML 执行
    s = re.sub(r"<(?=[A-Za-z/!?])", "&lt;", s)
    if len(s) > limit:
        s = s[:limit] + "…"
    return s


def _md_table(headers, rows, limit=400):
    out = ["| " + " | ".join(_md_cell(h, 80) for h in headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for r in rows:
        out.append("| " + " | ".join(_md_cell(c, limit) for c in r) + " |")
    return "\n".join(out)


def _code_path(p, limit=160):
    if not p:
        return "—"
    return "`" + _md_cell(_clip(p, limit), limit + 8) + "`"


def _read_lines(path, limit, tail=False):
    """读文本文件的前/后 limit 行；不存在或不可读返回 (lines, err)。"""
    if not path.exists():
        return [], "文件不存在"
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            lines = [ln.rstrip("\n") for ln in fh]
    except OSError as exc:
        return [], "读取失败：%s" % exc
    if tail:
        return lines[-limit:], ""
    return lines[:limit], ""


def _detail_for_html(raw):
    """detail 原文进 HTML 前的长度保护（防止单条 detail 把文件撑爆）。"""
    if raw is None:
        return ""
    s = raw if isinstance(raw, str) else str(raw)
    if len(s) > MAX_INLINE_DETAIL:
        return s[:MAX_INLINE_DETAIL] + "…（detail 超长已截断，完整内容见 report.md 或 events.sqlite）"
    return s


def _json_for_script(obj):
    """序列化并做 script 上下文转义。"""
    s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    s = s.replace("</", "<\\/")
    s = s.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return s


# --------------------------------------------------------------------------
# 数据加载
# --------------------------------------------------------------------------

class _Ev:
    """一条事件（轻量对象，避免 10 万条 dict 的开销）。"""

    __slots__ = ("seq", "t", "ts", "tsd", "cat", "act", "pid", "ppid",
                 "proc", "path", "detail", "d", "bad")

    def __init__(self, row):
        seq, t, ts, cat, act, pid, ppid, proc, path, detail = (list(row) + [None] * 10)[:10]
        self.seq = seq
        try:
            self.t = float(t)
        except (TypeError, ValueError):
            self.t = 0.0
        self.ts = ts
        self.tsd = _fmt_ts(ts, t)
        self.cat = (cat or "").strip().lower()
        self.act = (act or "").strip()
        self.pid = pid
        self.ppid = ppid
        self.proc = proc
        self.path = path
        self.detail = detail
        self.d, self.bad = _parse_detail(detail)


def _load_meta(run: Path):
    p = run / "run_meta.json"
    if not p.exists():
        return {}
    try:
        with p.open("r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (ValueError, OSError):
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            return data if isinstance(data, dict) else {}
        except (ValueError, OSError):
            return {}


def _load_events(db: Path):
    evs = []
    integ = {"total": 0, "bad_detail": 0, "null_path": 0, "db_error": ""}
    if not db.exists():
        integ["db_error"] = "缺少 events.sqlite"
        return evs, integ
    con = None
    sql = ("SELECT seq, t, ts, cat, act, pid, ppid, proc, path, detail "
           "FROM events ORDER BY seq")
    try:
        try:
            con = sqlite3.connect("file:%s?mode=ro" % db.as_posix(), uri=True, timeout=15.0)
            con.execute("SELECT 1 FROM events LIMIT 1")
        except sqlite3.Error:
            if con is not None:
                con.close()
            con = sqlite3.connect(str(db), timeout=15.0)
        cur = con.execute(sql)
        for row in cur:
            e = _Ev(row)
            if e.bad:
                integ["bad_detail"] += 1
            if not e.path:
                integ["null_path"] += 1
            evs.append(e)
    except sqlite3.Error as exc:
        integ["db_error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        if con is not None:
            try:
                con.close()
            except sqlite3.Error:
                pass
    integ["total"] = len(evs)
    return evs, integ


# --------------------------------------------------------------------------
# 分类 / 归属
# --------------------------------------------------------------------------

def _file_group(act):
    a = (act or "").strip().lower().replace("-", "_").replace(" ", "_")
    if a in _FILE_DELETE:
        return "删除"
    if a in _FILE_RENAME:
        return "改名"
    if a in _FILE_WRITE:
        return "写"
    if a in _FILE_CREATE:
        return "创建"
    if a in _FILE_READ:
        return "读"
    if any(k in a for k in ("delete", "remove", "unlink", "rmdir")):
        return "删除"
    if any(k in a for k in ("rename", "move")):
        return "改名"
    if any(k in a for k in ("write", "append", "modify", "save", "truncate")):
        return "写"
    if any(k in a for k in ("create", "mkdir", "new")):
        return "创建"
    if any(k in a for k in ("read", "open", "load", "access", "stat")):
        return "读"
    return "其他"


def _norm_watch(watch_dirs):
    """预先把监视目录规整成 (原值, 小写反斜杠形式)，避免逐事件重复格式化。"""
    out = []
    for w in watch_dirs or ():
        wl = str(w or "").lower().replace("/", "\\").rstrip("\\")
        if wl:
            out.append((w, wl))
    return out


def _path_bucket_norm(pl, norm_watch):
    """pl 必须是已小写、已把 / 换成 \\ 的路径。返回 (归属, 命中的监视目录或 None)。"""
    for w, wl in norm_watch:
        if pl == wl or pl.startswith(wl + "\\"):
            return "记录目录内", w
    if any(h in pl for h in SYS_HINTS):
        return "系统/临时目录", None
    return "其他", None


def _path_bucket(path, norm_watch):
    """norm_watch 必须来自 _norm_watch()。"""
    if not path:
        return "其他"
    return _path_bucket_norm(str(path).lower().replace("/", "\\"), norm_watch)[0]


def _file_path(e):
    p = e.path
    if p:
        return p
    return _as_text(_first(e.d, ("path", "target", "file", "name", "filepath")))


def _file_size(e):
    v = _first(e.d, _SIZE_KEYS)
    if v is None:
        return None
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def _net_endpoint(e):
    d = e.d
    host = _as_text(_first(d, _NET_HOST_KEYS))
    port = _as_text(_first(d, _NET_PORT_KEYS))
    if not host:
        host = e.path or ""
    if host:
        host = re.sub(r"^(?:tcp|udp|http|https|ws|wss|icmp)://", "", str(host), flags=re.I)
        host = host.rstrip("/")
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", host)
        if m:
            host = m.group(1)
            if not port and m.group(2):
                port = m.group(2)
        elif not port and host.count(":") == 1:
            h, p = host.rsplit(":", 1)
            if p.isdigit():
                host, port = h, p
    return (host or "(未知)", port)


def _human_size(n):
    if n is None:
        return "—"
    v = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or unit == "TB":
            if unit == "B":
                return "%d B" % int(v)
            return "%.1f %s" % (v, unit)
        v /= 1024.0
    return "—"


# --------------------------------------------------------------------------
# 聚合分析
# --------------------------------------------------------------------------

def _proc_tree(events):
    nodes = {}
    order = []
    for e in events:
        if e.cat != "proc" or e.pid is None:
            continue
        pid = e.pid
        n = nodes.get(pid)
        if n is None:
            n = nodes[pid] = {
                "pid": pid, "ppid": e.ppid, "proc": e.proc or "(未知进程)",
                "first": e.tsd, "t0": e.t, "last": e.tsd, "t1": e.t,
                "cmdline": "", "exit": "", "acts": Counter(), "n": 0,
            }
            order.append(pid)
        n["n"] += 1
        n["acts"][e.act or "?"] += 1
        if n["ppid"] is None and e.ppid is not None:
            n["ppid"] = e.ppid
        if e.t < n["t0"]:
            n["t0"], n["first"] = e.t, e.tsd
        if e.t > n["t1"]:
            n["t1"], n["last"] = e.t, e.tsd
        if not n["cmdline"]:
            cmd = _as_text(_first(e.d, _CMD_KEYS))
            if cmd:
                n["cmdline"] = cmd
        act_l = (e.act or "").lower()
        if act_l in _PROC_EXIT_ACTS or "exit" in act_l or "terminat" in act_l:
            if not n["exit"]:
                n["exit"] = e.tsd

    # 计算树深度
    def depth_of(pid):
        seen = set()
        cur = pid
        d = 0
        while d < 24 and cur in nodes and cur not in seen:
            seen.add(cur)
            ppid = nodes[cur].get("ppid")
            if ppid is None or ppid == cur or ppid not in nodes:
                break
            cur = ppid
            d += 1
        return d

    children = {}
    roots = []
    for pid in order:
        n = nodes[pid]
        n["depth"] = depth_of(pid)
        ppid = n.get("ppid")
        if ppid is not None and ppid != pid and ppid in nodes:
            children.setdefault(ppid, []).append(pid)
        else:
            roots.append(pid)

    ordered = []
    stack = list(reversed(sorted(roots, key=lambda p: nodes[p]["t0"])))
    guard = 0
    while stack and guard < len(nodes) * 3 + 10:
        guard += 1
        pid = stack.pop()
        n = nodes.get(pid)
        if n is None or n.get("_out"):
            continue
        n["_out"] = True
        ordered.append(n)
        kids = sorted(children.get(pid, []), key=lambda p: nodes[p]["t0"])
        stack.extend(reversed(kids))
    for pid in order:                     # 兜底：环 / 孤儿
        n = nodes[pid]
        if not n.get("_out"):
            n["_out"] = True
            ordered.append(n)

    # 没有 proc 事件但出现在其它类别里的进程
    seen_pids = Counter()
    meta_pids = {}
    for e in events:
        if e.cat == "proc" or e.pid is None:
            continue
        seen_pids[e.pid] += 1
        if e.pid not in meta_pids and e.proc:
            meta_pids[e.pid] = e.proc
    others = []
    for pid, cnt in seen_pids.most_common():
        if pid in nodes:
            continue
        others.append((pid, meta_pids.get(pid) or "?", cnt))

    return ordered, others


def _analyze_files(events, norm_watch):
    groups = {g: {} for g in FILE_GROUPS}
    bucket = Counter()
    watch_hits = Counter()
    write_n = Counter()
    write_size = {}
    renames = Counter()
    total = 0

    for e in events:
        if e.cat != "file":
            continue
        total += 1
        path = _file_path(e) or "(未知路径)"
        g = _file_group(e.act)
        slot = groups[g].get(path)
        if slot is None:
            slot = groups[g][path] = {"n": 0, "first": e.tsd, "last": e.tsd,
                                      "t0": e.t, "t1": e.t, "procs": set()}
        slot["n"] += 1
        if e.t < slot["t0"]:
            slot["t0"], slot["first"] = e.t, e.tsd
        if e.t > slot["t1"]:
            slot["t1"], slot["last"] = e.t, e.tsd
        if e.proc:
            slot["procs"].add(e.proc)
        pl = str(path).lower().replace("/", "\\")
        kind, hit = _path_bucket_norm(pl, norm_watch)
        bucket[kind] += 1
        if hit is not None:
            watch_hits[hit] += 1
        if g in ("写", "创建"):
            write_n[path] += 1
            sz = _file_size(e)
            if sz is not None:
                write_size[path] = sz
        if g == "改名":
            dst = _as_text(_first(e.d, ("target", "to", "new_path", "newname", "dst")))
            if dst:
                renames[(path, dst)] += 1

    top_written = [(p, n, write_size.get(p)) for p, n in write_n.most_common(TOP_FILES)]
    return {
        "total": total,
        "groups": groups,
        "bucket": bucket,
        "watch_hits": watch_hits,
        "top_written": top_written,
        "renames": renames,
        "paths": len({p for g in groups.values() for p in g}),
    }


def _analyze_reg(events):
    rows = {}
    acts = Counter()
    for e in events:
        if e.cat != "reg":
            continue
        key = e.path or _as_text(_first(e.d, ("key", "path", "reg_key"))) or "(未知键)"
        name = _as_text(_first(e.d, _REG_NAME_KEYS))
        data = _as_text(_first(e.d, _REG_DATA_KEYS))
        acts[e.act or "?"] += 1
        k = (key, name, e.act or "?")
        slot = rows.get(k)
        if slot is None:
            slot = rows[k] = {"n": 0, "first": e.tsd, "last": e.tsd,
                              "t0": e.t, "t1": e.t, "data": "", "procs": set()}
        slot["n"] += 1
        if e.t < slot["t0"]:
            slot["t0"], slot["first"] = e.t, e.tsd
        if e.t > slot["t1"]:
            slot["t1"], slot["last"] = e.t, e.tsd
        if data:
            slot["data"] = data
        if e.proc:
            slot["procs"].add(e.proc)
    lst = sorted(rows.items(), key=lambda kv: (kv[0][0].lower(), kv[0][1].lower(), kv[0][2]))
    keys = {k[0] for k in rows}
    names = {(k[0], k[1]) for k in rows}
    return {"rows": lst, "acts": acts, "keys": len(keys), "names": len(names),
            "total": sum(acts.values())}


def _analyze_net(events):
    groups = {}
    bad = 0
    acts = Counter()
    for e in events:
        if e.cat != "net":
            continue
        acts[e.act or "?"] += 1
        host, port = _net_endpoint(e)
        if host == "(未知)":
            bad += 1
        proc = e.proc or ("pid %s" % e.pid if e.pid is not None else "?")
        endpoint = host if not port else "%s:%s" % (host, port)
        k = (proc, endpoint, port)
        slot = groups.get(k)
        if slot is None:
            slot = groups[k] = {"n": 0, "first": e.tsd, "last": e.tsd,
                                "t0": e.t, "t1": e.t, "acts": Counter()}
        slot["n"] += 1
        slot["acts"][e.act or "?"] += 1
        if e.t < slot["t0"]:
            slot["t0"], slot["first"] = e.t, e.tsd
        if e.t > slot["t1"]:
            slot["t1"], slot["last"] = e.t, e.tsd
    rows = sorted(groups.items(), key=lambda kv: (-kv[1]["n"], kv[0][1]))
    remote = Counter()
    for (proc, endpoint, port), slot in groups.items():
        remote[endpoint] += slot["n"]
    procs = {k[0] for k in groups}
    return {"rows": rows, "bad": bad, "acts": acts, "remote": remote,
            "procs": len(procs), "total": sum(s["n"] for s in groups.values())}


def _analyze_ui(events):
    focus = []
    key_counts = Counter()
    click_targets = Counter()
    input_acts = Counter()
    clip_items = []
    ui_texts = []
    ui_acts = Counter()
    prev_title = None

    for e in events:
        if e.cat == "win":
            title = e.path or _as_text(_first(e.d, _TITLE_KEYS)) or "(无标题)"
            if title != prev_title:
                focus.append((e.tsd, title, e.proc or "?", e.act or ""))
                prev_title = title
        elif e.cat == "ui":
            ui_acts[e.act or "?"] += 1
            txt = e.path or _as_text(_first(e.d, ("text", "value", "content", "name")))
            ui_texts.append((e.tsd, e.proc or "?", e.act or "", _clip(txt, 120)))
        elif e.cat == "input":
            act_l = (e.act or "").lower()
            input_acts[act_l or "?"] += 1
            if "key" in act_l or act_l in ("press", "hotkey", "keydown", "keyup"):
                k = e.path or _as_text(_first(e.d, ("key", "vk", "code", "name", "key_name")))
                if not k:
                    k = "(未知按键)"
                key_counts[k] += 1
            elif "click" in act_l or "mouse" in act_l or act_l in ("press", "tap"):
                t = e.path or _as_text(_first(e.d, ("target", "window", "control", "title", "name")))
                if not t:
                    x, y = _first(e.d, ("x",)), _first(e.d, ("y",))
                    t = "(%s,%s)" % (x if x is not None else "?", y if y is not None else "?")
                click_targets[t] += 1
        elif e.cat == "clip":
            txt = e.path or _as_text(_first(e.d, _CLIP_KEYS))
            clip_items.append({
                "ts": e.tsd,
                "proc": e.proc or "?",
                "act": e.act or "",
                "len": len(txt or ""),
                "text": _multiline_clip(txt, CLIP_MAX),
                "truncated": bool(txt) and len(txt) > CLIP_MAX,
            })
    return {"focus": focus, "keys": key_counts, "clicks": click_targets,
            "input_acts": input_acts, "clips": clip_items,
            "ui_texts": ui_texts, "ui_acts": ui_acts}


def _build_timeline(events):
    """每类挑重要事件，按时间正序；返回 (rows, 候选数, 是否截断)。"""
    keep_acts = {
        "proc": lambda a: a.lower() in _PROC_CREATE_ACTS or a.lower() in _PROC_EXIT_ACTS
                          or "exit" in a.lower() or "start" in a.lower(),
        "file": lambda a: _file_group(a) in ("写", "创建", "删除", "改名"),
        "reg": lambda a: True,
        "net": lambda a: True,
        "win": lambda a: True,
        "ui": lambda a: True,
        "input": lambda a: "click" in a.lower(),
        "clip": lambda a: True,
        "mark": lambda a: True,
        "shot": lambda a: True,
        "log": lambda a: a.lower() in ("open", "truncated", "dropped", "error"),
        "stdout": lambda a: False,
        "stderr": lambda a: False,
    }
    per_cat = Counter()
    picked = []
    for e in events:
        pred = keep_acts.get(e.cat)
        if pred is None or not pred(e.act or ""):
            continue
        if per_cat[e.cat] >= TIMELINE_PER_CAT:
            continue
        per_cat[e.cat] += 1
        picked.append(e)
    candidates = len(picked)
    picked.sort(key=lambda e: (e.t, e.seq if isinstance(e.seq, int) else 0))
    truncated = len(picked) > TIMELINE_MAX
    return picked[:TIMELINE_MAX], candidates, truncated


def _shots_list(run: Path):
    d = run / "shots"
    items = []
    if d.is_dir():
        try:
            entries = sorted(os.listdir(d))
        except OSError:
            entries = []
        for name in entries:
            p = d / name
            if p.is_file() and p.suffix.lower() in SHOT_SUFFIXES:
                items.append("shots/" + name)
    return items


def _analyze(run: Path):
    meta = _load_meta(run)
    events, integ = _load_events(run / "events.sqlite")

    cat_counts = Counter(e.cat or "?" for e in events)
    cat_order = [c for c in CAT_ORDER if cat_counts.get(c)] + \
                [c for c in sorted(cat_counts) if c not in CAT_ORDER]

    started = _parse_iso(meta.get("started_at"))
    ended = _parse_iso(meta.get("ended_at"))
    t_min = min((e.t for e in events), default=None)
    t_max = max((e.t for e in events), default=None)
    if started is None and t_min is not None:
        started = datetime.fromtimestamp(t_min)
    if ended is None and t_max is not None:
        ended = datetime.fromtimestamp(t_max)
    span = {
        "started": _iso_text(started),
        "ended": _iso_text(ended),
        "secs": _seconds_between(started, ended),
        "t_min": _fmt_ts(None, t_min) if t_min is not None else "—",
        "t_max": _fmt_ts(None, t_max) if t_max is not None else "—",
    }

    watch_dirs = meta.get("watch_dirs") or []
    if not isinstance(watch_dirs, (list, tuple)):
        watch_dirs = [watch_dirs]
    watch_dirs = [str(w) for w in watch_dirs if w]
    norm_watch = _norm_watch(watch_dirs)

    proc_nodes, proc_others = _proc_tree(events)
    files = _analyze_files(events, norm_watch)
    reg = _analyze_reg(events)
    net = _analyze_net(events)
    ui = _analyze_ui(events)
    timeline, tl_candidates, tl_truncated = _build_timeline(events)

    stdout_head, stdout_err = _read_lines(run / "stdout.log", STDOUT_LINES)
    stderr_tail, stderr_err = _read_lines(run / "stderr.log", STDERR_LINES, tail=True)

    shots = _shots_list(run)
    shot_events = [e.path for e in events if e.cat == "shot" and e.path]

    db_path = run / "events.sqlite"
    try:
        db_size = db_path.stat().st_size
    except OSError:
        db_size = 0

    return {
        "run": run,
        "meta": meta,
        "events": events,
        "integ": integ,
        "cat_counts": cat_counts,
        "cat_order": cat_order,
        "span": span,
        "watch_dirs": watch_dirs,
        "norm_watch": norm_watch,
        "proc_nodes": proc_nodes,
        "proc_others": proc_others,
        "files": files,
        "reg": reg,
        "net": net,
        "ui": ui,
        "stdout": stdout_head,
        "stdout_err": stdout_err,
        "stderr": stderr_tail,
        "stderr_err": stderr_err,
        "shots": shots,
        "shot_events": shot_events,
        "timeline": timeline,
        "tl_candidates": tl_candidates,
        "tl_truncated": tl_truncated,
        "db_size": db_size,
    }


# --------------------------------------------------------------------------
# Markdown 渲染
# --------------------------------------------------------------------------

def _md_overview(A, out):
    meta, span, integ = A["meta"], A["span"], A["integ"]
    total = len(A["events"])
    exe = meta.get("exe") or ""
    pid = meta.get("pid")
    out.append("## 一、概览\n")
    out.append(_md_table(
        ["项目", "值"],
        [
            ["被测软件", meta.get("name") or "（run_meta 未提供 name）"],
            ["运行标识 run_id", meta.get("run_id") or "—"],
            ["可执行文件", _code_path(exe, 200) if exe else "—"],
            ["目标 PID", pid if pid is not None else "—"],
            ["开始时间", span["started"]],
            ["结束时间", span["ended"]],
            ["总时长", _human_dur(span["secs"])],
            ["事件总数", "%d" % total],
            ["事件时间跨度", "%s → %s" % (span["t_min"], span["t_max"])],
            ["采集器自报事件数", _counts_text(meta.get("counts"))],
            ["备注", _clip(meta.get("notes") or "—", 200)],
        ],
    ))
    out.append("")

    out.append("### 按类别计数\n")
    if A["cat_order"]:
        rows = []
        for c in A["cat_order"]:
            n = A["cat_counts"][c]
            rows.append([CAT_NAMES.get(c, c), "`%s`" % c, n, _pct(n, total)])
        out.append(_md_table(["类别", "代码", "事件数", "占比"], rows))
    else:
        out.append("> 数据库中没有事件。")
    out.append("")

    out.append("### 模块启用情况\n")
    mods = meta.get("modules") or {}
    if isinstance(mods, dict) and mods:
        rows = []
        for name in sorted(mods):
            state, extra = _mod_state(mods[name])
            rows.append([name, "✅ 已启用" if state else "⛔ 未启用", _clip(extra, 120) or "—"])
        out.append(_md_table(["模块", "状态", "附加信息"], rows))
    else:
        out.append("> run_meta.json 未提供 modules 信息。")
    out.append("")

    out.append("### 监视目录\n")
    if A["watch_dirs"]:
        for w in A["watch_dirs"]:
            out.append("- %s" % _code_path(w, 240))
    else:
        out.append("> 未提供 watch_dirs。")
    out.append("")

    out.append("### 数据完整性\n")
    rows = [
        ["events.sqlite 大小", _human_size(A["db_size"])],
        ["detail 非 JSON / 解析失败", "%d 条" % integ["bad_detail"]],
        ["path 为空的事件", "%d 条" % integ["null_path"]],
        ["sqlite 读取异常", integ["db_error"] or "无"],
    ]
    out.append(_md_table(["检查项", "结果"], rows))
    out.append("")


def _counts_text(counts):
    if not isinstance(counts, dict) or not counts:
        return "—"
    return ", ".join("%s=%s" % (k, v) for k, v in sorted(counts.items()))


def _mod_state(v):
    if isinstance(v, dict):
        state = True
        for k in ("enabled", "active", "ok", "available", "loaded"):
            if k in v:
                state = bool(v[k])
                break
        extra = ", ".join("%s=%s" % (k, _clip(v[k], 30)) for k in sorted(v)
                          if k not in ("enabled", "active", "ok", "available", "loaded"))
        return state, extra
    if isinstance(v, str):
        return v.strip().lower() not in ("", "off", "false", "0", "no", "disabled", "none"), v
    return bool(v), ""


def _md_proc(A, out):
    out.append("## 二、进程行为\n")
    nodes = A["proc_nodes"]
    if not nodes:
        out.append("> 未采集到 `proc` 类别事件。\n")
        if A["proc_others"]:
            out.append("其它类别里出现过的进程（按事件数排序，最多 50 条）：\n")
            out.append(_md_table(
                ["PID", "进程", "关联事件数"],
                [[pid, proc, n] for pid, proc, n in A["proc_others"][:50]],
            ))
            out.append("")
        return

    out.append("### 进程树\n")
    out.append("层级用全角空格缩进表示（子进程在父进程下一行）。\n")
    rows = []
    for n in nodes[:300]:
        indent = ("　" * n["depth"]) + ("└ " if n["depth"] else "")
        rows.append([
            indent + (n["proc"] or "?"),
            n["pid"],
            n["ppid"] if n["ppid"] is not None else "—",
            n["first"],
            n["exit"] or n["last"],
            _clip(n["cmdline"] or "—", 160),
        ])
    out.append(_md_table(["进程", "PID", "PPID", "首次出现", "退出 / 末次", "命令行"], rows))
    if len(nodes) > 300:
        out.append("\n> 进程数 %d，表中只显示前 300 个。" % len(nodes))
    out.append("")

    act = Counter()
    for n in nodes:
        act.update(n["acts"])
    if act:
        out.append("### 进程事件动作分布\n")
        tot = sum(act.values())
        out.append(_md_table(["动作", "次数", "占比"],
                             [[a, c, _pct(c, tot)] for a, c in act.most_common()]))
        out.append("")

    if A["proc_others"]:
        out.append("### 其它出现过的 PID（无 proc 事件）\n")
        out.append(_md_table(
            ["PID", "进程", "关联事件数"],
            [[pid, proc, n] for pid, proc, n in A["proc_others"][:50]],
        ))
        out.append("")


def _md_files(A, out):
    F = A["files"]
    out.append("## 三、文件行为\n")
    if not F["total"]:
        out.append("> 未采集到 `file` 类别事件。\n")
        return

    out.append("### 分组统计\n")
    rows = []
    for g in FILE_GROUPS:
        items = F["groups"][g]
        if not items and g == "其他":
            continue
        procs = set()
        for slot in items.values():
            procs |= slot["procs"]
        rows.append([g, sum(s["n"] for s in items.values()), len(items), len(procs)])
    out.append(_md_table(["分组", "事件数", "涉及路径数", "涉及进程数"], rows))
    out.append("")

    out.append("### 目录归属\n")
    if F["bucket"]:
        tot = sum(F["bucket"].values())
        out.append(_md_table(["归属", "事件数", "占比"],
                             [[k, v, _pct(v, tot)] for k, v in F["bucket"].most_common()]))
    else:
        out.append("> 无数据。")
    out.append("")

    if F["watch_hits"]:
        out.append("### 监视目录命中\n")
        out.append(_md_table(["目录", "命中事件数"],
                             [[_code_path(w, 200), n] for w, n in F["watch_hits"].most_common()]))
        out.append("")

    for g in FILE_GROUPS:
        items = F["groups"][g]
        if not items:
            continue
        if g == "其他" and not items:
            continue
        out.append("### %s 明细\n" % g)
        ordered = sorted(items.items(), key=lambda kv: (-kv[1]["n"], kv[0].lower()))
        rows = []
        for path, slot in ordered[:DETAIL_TOP]:
            rows.append([_code_path(path, 200), slot["n"], slot["first"], slot["last"]])
        out.append(_md_table(["路径", "次数", "首次", "末次"], rows))
        if len(ordered) > DETAIL_TOP:
            out.append("\n> 该分组共 %d 个路径，表中只列前 %d 个（按次数降序）。"
                       % (len(ordered), DETAIL_TOP))
        out.append("")

    if F["top_written"]:
        out.append("### 写入文件 Top %d\n" % min(TOP_FILES, len(F["top_written"])))
        rows = []
        for i, (path, n, size) in enumerate(F["top_written"], 1):
            rows.append([i, _code_path(path, 200), n, _human_size(size),
                         _path_bucket(path, A["norm_watch"])])
        out.append(_md_table(["#", "路径", "写入次数", "末次大小", "归属"], rows))
        out.append("")

    if F["renames"]:
        out.append("### 改名映射\n")
        rows = [[_code_path(src, 160), _code_path(dst, 160), n]
                for (src, dst), n in F["renames"].most_common(100)]
        out.append(_md_table(["源路径", "目标路径", "次数"], rows))
        out.append("")


def _md_reg(A, out):
    R = A["reg"]
    out.append("## 四、注册表行为\n")
    if not R["rows"]:
        out.append("> 未采集到 `reg` 类别事件。\n")
        return
    out.append(_md_table(
        ["统计项", "值"],
        [
            ["注册表事件数", R["total"]],
            ["涉及键数", R["keys"]],
            ["涉及键值对", R["names"]],
            ["动作分布", ", ".join(
                "%s=%d" % (REG_ACT_NAMES.get(a, a), c) for a, c in R["acts"].most_common())],
        ],
    ))
    out.append("")
    out.append("### 改动的键值\n")
    rows = []
    for (key, name, act), slot in R["rows"][:300]:
        rows.append([
            _code_path(key, 180),
            name or "(默认值)",
            REG_ACT_NAMES.get(act, act),
            _clip(slot["data"] or "—", 120),
            slot["n"],
            slot["first"],
            slot["last"],
        ])
    out.append(_md_table(["键", "值名", "动作", "值数据", "次数", "首次", "末次"], rows))
    if len(R["rows"]) > 300:
        out.append("\n> 共 %d 组键值记录，表中只列前 300 组。" % len(R["rows"]))
    out.append("")


def _md_net(A, out):
    N = A["net"]
    out.append("## 五、网络行为\n")
    if not N["rows"]:
        out.append("> 未采集到 `net` 类别事件。\n")
        return
    out.append(_md_table(
        ["统计项", "值"],
        [
            ["连接事件数", N["total"]],
            ["唯一远端地址", len(N["remote"])],
            ["发起进程数", N["procs"]],
            ["动作分布", ", ".join("%s=%d" % (a, c) for a, c in N["acts"].most_common())],
            ["远端无法解析的事件", N["bad"]],
        ],
    ))
    out.append("")
    out.append("### 进程 → 远端地址:端口\n")
    rows = []
    for (proc, endpoint, port), slot in N["rows"][:300]:
        rows.append([
            proc,
            _clip(endpoint, 120),
            port or "—",
            slot["n"],
            slot["first"],
            slot["last"],
            ",".join(sorted(slot["acts"])),
        ])
    out.append(_md_table(["进程", "远端地址", "端口", "次数", "首次", "末次", "动作"], rows))
    if len(N["rows"]) > 300:
        out.append("\n> 共 %d 组连接，表中只列前 300 组（按次数降序）。" % len(N["rows"]))
    out.append("")

    out.append("### 远端地址 Top 15\n")
    out.append(_md_table(["远端地址", "连接次数"],
                         [[_clip(k, 120), v] for k, v in N["remote"].most_common(15)]))
    out.append("")


def _md_ui(A, out):
    U = A["ui"]
    out.append("## 六、界面与输入\n")
    has_any = U["focus"] or U["keys"] or U["clicks"] or U["clips"] or U["ui_texts"]
    if not has_any:
        out.append("> 未采集到 `win` / `ui` / `input` / `clip` 类别事件。\n")
        return

    out.append("### 窗口焦点切换序列\n")
    if U["focus"]:
        rows = [[ts, _clip(title, 120), proc, act]
                for ts, title, proc, act in U["focus"][:200]]
        out.append(_md_table(["时间", "窗口标题", "进程", "动作"], rows))
        if len(U["focus"]) > 200:
            out.append("\n> 共 %d 次焦点切换，表中只列前 200 次。" % len(U["focus"]))
    else:
        out.append("> 无窗口事件。")
    out.append("")

    out.append("### 按键统计 Top 25\n")
    if U["keys"]:
        tot = sum(U["keys"].values())
        rows = [[_clip(k, 40), n, _pct(n, tot)] for k, n in U["keys"].most_common(25)]
        out.append(_md_table(["按键 / 字符", "次数", "占比"], rows))
        out.append("\n> 按键事件合计 %d 次，涉及 %d 个不同键。" % (tot, len(U["keys"])))
    else:
        out.append("> 无按键事件。")
    out.append("")

    out.append("### 输入动作分布\n")
    if U["input_acts"]:
        tot = sum(U["input_acts"].values())
        out.append(_md_table(["动作", "次数", "占比"],
                             [[a, c, _pct(c, tot)] for a, c in U["input_acts"].most_common()]))
    else:
        out.append("> 无输入事件。")
    out.append("")

    out.append("### 点击目标 Top 15\n")
    if U["clicks"]:
        out.append(_md_table(["目标 / 坐标", "次数"],
                             [[_clip(k, 100), n] for k, n in U["clicks"].most_common(15)]))
    else:
        out.append("> 无点击事件。")
    out.append("")

    out.append("### 剪贴板内容（单条最长 %d 字符）\n" % CLIP_MAX)
    if U["clips"]:
        rows = []
        for it in U["clips"][:50]:
            text = it["text"].replace("|", "\\|").replace("\n", " ⏎ ")
            rows.append([it["ts"], it["proc"], it["act"], it["len"],
                         text + ("（已截断）" if it["truncated"] else "")])
        out.append(_md_table(["时间", "进程", "动作", "原始长度", "内容"], rows))
        if len(U["clips"]) > 50:
            out.append("\n> 共 %d 条剪贴板事件，表中只列前 50 条。" % len(U["clips"]))
    else:
        out.append("> 无剪贴板事件。")
    out.append("")

    if U["ui_texts"]:
        out.append("### 界面文本变化（cat=ui，最多 40 条）\n")
        out.append("动作分布：%s\n" % ", ".join(
            "%s=%d" % (a, c) for a, c in U["ui_acts"].most_common()))
        rows = [[ts, proc, act, text] for ts, proc, act, text in U["ui_texts"][:40]]
        out.append(_md_table(["时间", "进程", "动作", "文本"], rows))
        if len(U["ui_texts"]) > 40:
            out.append("\n> 共 %d 条界面文本事件，表中只列前 40 条。" % len(U["ui_texts"]))
        out.append("")


def _md_std(A, out):
    out.append("## 七、标准输出摘录\n")
    out.append("### stdout.log（前 %d 行）\n" % STDOUT_LINES)
    if A["stdout_err"]:
        out.append("> `stdout.log`：%s\n" % A["stdout_err"])
    elif not A["stdout"]:
        out.append("> `stdout.log` 为空。\n")
    else:
        out.append("````text")
        for ln in A["stdout"]:
            out.append(_clip(ln.rstrip("\n"), 500))
        out.append("````")
        out.append("")
    out.append("")

    out.append("### stderr.log（末尾 %d 行）\n" % STDERR_LINES)
    if A["stderr_err"]:
        out.append("> `stderr.log` %s\n" % A["stderr_err"])
    elif not A["stderr"]:
        out.append("> `stderr.log` 为空。\n")
    else:
        out.append("````text")
        for ln in A["stderr"]:
            out.append(_clip(ln.rstrip("\n"), 500))
        out.append("````")
        out.append("")


def _md_timeline(A, out):
    out.append("## 八、时间线\n")
    rows = A["timeline"]
    if not rows:
        out.append("> 没有可用于时间线的关键事件。\n")
        return
    note = ("关键事件候选 %d 条，按时间正序展示 %d 条" %
            (A["tl_candidates"], len(rows)))
    if A["tl_truncated"]:
        note += "（**已达 %d 行上限，后续事件被截断**，完整数据见 timeline.html）" % TIMELINE_MAX
    out.append("> %s。\n" % note)
    table = []
    for e in rows:
        obj = e.path or _as_text(_first(e.d, ("target", "title", "cmdline", "name"))) or "—"
        table.append([e.tsd, CAT_NAMES.get(e.cat, e.cat), e.act or "—",
                      e.proc or ("pid %s" % e.pid if e.pid is not None else "—"),
                      _clip(obj, 120)])
    out.append(_md_table(["时间", "类别", "动作", "进程", "对象"], table))
    out.append("")


def _md_appendix(A, out):
    out.append("## 九、附录\n")
    shots = A["shots"]
    out.append("### 截图（%d 张）\n" % len(shots))
    if shots:
        for s in shots[:MAX_SHOT_THUMBS]:
            name = s.split("/")[-1]
            out.append("- [%s](%s)" % (_md_cell(name, 120), s))
        if len(shots) > MAX_SHOT_THUMBS:
            out.append("\n> 共 %d 张，只列出前 %d 张。" % (len(shots), MAX_SHOT_THUMBS))
    elif A["shot_events"]:
        out.append("> `shots/` 目录不存在，但事件里记录了 %d 条截图引用：\n" % len(A["shot_events"]))
        for p in A["shot_events"][:100]:
            out.append("- %s" % _code_path(p, 240))
    else:
        out.append("> 无截图。")
    out.append("")

    out.append("### 数据文件\n")
    run = A["run"]
    rows = []
    for name in ("events.sqlite", "run_meta.json", "stdout.log", "stderr.log", "report.md", "timeline.html"):
        p = run / name
        try:
            rows.append([_code_path(name, 60), "存在" if p.exists() else "缺失",
                         _human_size(p.stat().st_size) if p.exists() else "—"])
        except OSError:
            rows.append([_code_path(name, 60), "不可读", "—"])
    out.append(_md_table(["文件", "状态", "大小"], rows))
    out.append("")


def _render_md(A):
    meta = A["meta"]
    name = meta.get("name") or "（未命名）"
    out = ["# TraceKit 软件行为分析报告 — %s" % _md_cell(name, 160), ""]
    out.append("> 由 TraceKit `report.py` 自动生成（仅标准库），"
               "交互式时间线见同目录 `timeline.html`。")
    out.append("")

    out.append("## 目录\n")
    for i, title in enumerate([
        "概览", "进程行为", "文件行为", "注册表行为", "网络行为",
        "界面与输入", "标准输出摘录", "时间线", "附录",
    ], 1):
        out.append("%d. %s" % (i, title))
    out.append("")

    _md_overview(A, out)
    _md_proc(A, out)
    _md_files(A, out)
    _md_reg(A, out)
    _md_net(A, out)
    _md_ui(A, out)
    _md_std(A, out)
    _md_timeline(A, out)
    _md_appendix(A, out)
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# HTML 渲染
# --------------------------------------------------------------------------

_HTML_TMPL = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
*{box-sizing:border-box}
:root{
  --bg:#0b1220;--panel:#121c30;--panel2:#16223a;--line:#22314f;
  --fg:#e6edf7;--muted:#93a4bf;--acc:#38bdf8;
}
html,body{margin:0;padding:0;background:var(--bg);color:var(--fg);
  font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",system-ui,sans-serif}
.wrap{max-width:1460px;margin:0 auto;padding:0 16px}
.hd{padding-top:22px;padding-bottom:8px}
h1{margin:0 0 6px;font-size:20px;font-weight:650;letter-spacing:.2px}
h2{font-size:15px;margin:22px 0 10px;font-weight:600}
.sub{color:var(--muted);font-size:12.5px;margin:0}
.notes{margin:8px 0 0;padding:8px 12px;border-left:3px solid var(--acc);
  background:rgba(56,189,248,.08);border-radius:6px;color:#cfe3f7;font-size:12.5px;white-space:pre-wrap}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(112px,1fr));gap:8px;margin:14px 0 12px}
.card{background:var(--panel);border:1px solid var(--line);border-top:3px solid var(--line);
  border-radius:9px;padding:8px 9px;cursor:pointer;transition:.14s;user-select:none}
.card:hover{background:var(--panel2);transform:translateY(-1px)}
.card.off{opacity:.32}
.card .n{font-size:18px;font-weight:700;font-variant-numeric:tabular-nums}
.card .t{font-size:11.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.card.total{border-top-color:var(--acc);cursor:default}
.card.total:hover{transform:none;background:var(--panel)}
.toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:8px;
  background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:9px 10px;margin-bottom:8px}
.search{flex:1 1 300px;min-width:180px;background:#0d1626;border:1px solid var(--line);
  color:var(--fg);border-radius:7px;padding:7px 10px;font-size:13px;outline:none}
.search:focus{border-color:var(--acc)}
.switch{display:flex;align-items:center;gap:6px;font-size:12.5px;color:#cbdcf2;
  background:#0d1626;border:1px solid var(--line);border-radius:7px;padding:6px 10px;cursor:pointer;white-space:nowrap}
.switch input{accent-color:var(--acc);margin:0}
.btn{background:#0d1626;border:1px solid var(--line);color:#cbdcf2;border-radius:7px;
  padding:6px 11px;font-size:12.5px;cursor:pointer;transition:.12s;white-space:nowrap}
.btn:hover{border-color:var(--acc);color:#fff}
.btn:disabled{opacity:.35;cursor:not-allowed}
.grow{flex:1 1 auto}
.hint{color:var(--muted);font-size:11.5px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}
.chipbtn{display:inline-flex;align-items:center;gap:6px;background:var(--panel);
  border:1px solid var(--line);border-radius:999px;padding:4px 11px 4px 8px;
  color:#dbe7f6;font-size:12.5px;cursor:pointer;user-select:none;transition:.12s}
.chipbtn:hover{border-color:var(--acc)}
.chipbtn.off{opacity:.32;text-decoration:line-through}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;flex:0 0 auto}
.cnt{color:var(--muted);font-variant-numeric:tabular-nums}
.pager{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:8px 0}
.pginfo{color:var(--muted);font-size:12.5px;font-variant-numeric:tabular-nums}
.pgno{width:74px;background:#0d1626;border:1px solid var(--line);color:var(--fg);
  border-radius:7px;padding:5px 8px;font-size:12.5px}
.tableBox{border:1px solid var(--line);border-radius:9px;overflow:hidden;background:var(--panel)}
table.full{width:100%;border-collapse:collapse;table-layout:fixed}
table.full thead th{position:sticky;top:0;z-index:2;background:#182440;color:#c9dbf2;
  font-size:12px;font-weight:600;text-align:left;padding:8px 9px;border-bottom:1px solid var(--line)}
table.full td{padding:6px 9px;border-bottom:1px solid rgba(34,49,79,.7);vertical-align:top;font-size:12.5px}
.c-ts{width:168px;white-space:nowrap;font-variant-numeric:tabular-nums;color:#b9cbe6}
.c-cat{width:92px}
.c-act{width:110px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.c-proc{width:170px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.c-path{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  font-family:ui-monospace,Consolas,"Cascadia Mono","Microsoft YaHei",monospace;color:#d5e2f4}
tr.ev{cursor:pointer}
tr.ev:hover td{background:rgba(56,189,248,.075)}
tr.ev.open td{background:rgba(56,189,248,.12)}
span.chip{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11.5px;
  color:#fff;white-space:nowrap;font-weight:500}
tr.det td{background:#0b1524;padding:0}
pre.json{margin:0;padding:10px 14px;font-family:ui-monospace,Consolas,"Cascadia Mono",monospace;
  font-size:12px;line-height:1.5;color:#b6e3ff;white-space:pre-wrap;word-break:break-word}
td.empty{padding:22px;text-align:center;color:var(--muted)}
.shots{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px}
figure.shot{margin:0;background:var(--panel);border:1px solid var(--line);border-radius:8px;
  overflow:hidden;cursor:zoom-in}
figure.shot img{display:block;width:100%;height:104px;object-fit:cover;background:#08111d}
figure.shot figcaption{font-size:11px;color:var(--muted);padding:4px 7px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.lb{position:fixed;inset:0;background:rgba(3,7,16,.94);display:flex;flex-direction:column;
  align-items:center;justify-content:center;gap:10px;z-index:99;cursor:zoom-out;padding:20px}
.lb[hidden]{display:none}
.lb img{max-width:94vw;max-height:86vh;border:1px solid #2b3c5c;border-radius:6px;image-rendering:auto}
.lbTip{color:var(--muted);font-size:12px}
footer{color:var(--muted);font-size:11.5px;padding:26px 0 40px;text-align:center}
</style>
</head>
<body>
<header class="wrap hd">
  <h1>__H1__</h1>
  <p class="sub">__SUBLINE__</p>
  __NOTES__
</header>
<main class="wrap">
  <section class="cards" id="cards"></section>
  <section class="toolbar">
    <input id="q" class="search" type="search" placeholder="搜索 时间 / 动作 / 进程 / 路径 / detail …" autocomplete="off">
    <label class="switch" title="按 run_meta 的 pid 前缀或进程名过滤">
      <input type="checkbox" id="target"> 只看目标进程 <span class="hint" id="targetHint"></span>
    </label>
    <button class="btn" id="allCats">全选</button>
    <button class="btn" id="noCats">清空</button>
    <span class="grow"></span>
    <span class="hint" id="catStat"></span>
  </section>
  <section class="chips" id="chips"></section>
  <section class="pager">
    <button class="btn" data-act="first" title="第一页">« 首页</button>
    <button class="btn" data-act="prev" title="上一页">‹ 上一页</button>
    <span class="pginfo" data-info></span>
    <button class="btn" data-act="next" title="下一页">下一页 ›</button>
    <button class="btn" data-act="last" title="最后一页">末页 »</button>
    <input class="pgno" data-pgno type="number" min="1" value="1" title="输入页码后回车">
    <span class="hint">回车跳页</span>
  </section>
  <section class="tableBox">
    <table class="full">
      <thead><tr>
        <th class="c-ts">时间</th><th class="c-cat">类别</th><th class="c-act">动作</th>
        <th class="c-proc">进程</th><th class="c-path">路径 / 标题 / 内容</th>
      </tr></thead>
      <tbody id="tk-rows"></tbody>
    </table>
  </section>
  <section class="pager">
    <button class="btn" data-act="first">« 首页</button>
    <button class="btn" data-act="prev">‹ 上一页</button>
    <span class="pginfo" data-info></span>
    <button class="btn" data-act="next">下一页 ›</button>
    <button class="btn" data-act="last">末页 »</button>
    <input class="pgno" data-pgno type="number" min="1" value="1">
    <span class="hint">每页 __PAGESIZE__ 条 · 点击行展开 detail JSON</span>
  </section>
  <section>
    <h2>截图（__SHOTCOUNT__ 张）</h2>
    <div class="shots" id="shots"></div>
  </section>
</main>
<footer>TraceKit · 单文件自包含报告 · 数据已内联，无外部请求</footer>
<div class="lb" id="lb" hidden>
  <img id="lbimg" alt="">
  <div class="lbTip" id="lbcap"></div>
  <div class="lbTip">点击任意处或按 Esc 关闭</div>
</div>
<script id="tk-data" type="application/json">__PAYLOAD__</script>
<script>
(function () {
  "use strict";
  var dataEl = document.getElementById("tk-data");
  var DATA;
  try {
    DATA = JSON.parse(dataEl.textContent);
  } catch (err) {
    var p = document.createElement("p");
    p.style.cssText = "color:#fca5a5;padding:14px";
    p.textContent = "事件数据解析失败：" + err;
    document.body.appendChild(p);
    return;
  }

  var META = DATA.meta || {};
  var PAGE = DATA.pageSize || 500;
  var CATS = DATA.cats || [];
  var colorOf = {};
  var nameOf = {};
  CATS.forEach(function (c) { colorOf[c[0]] = c[3]; nameOf[c[0]] = c[1]; });

  var EV = [];
  var raw = DATA.events || [];
  for (var i = 0; i < raw.length; i++) {
    var a = raw[i];
    EV.push({ts: a[0], cat: a[1], act: a[2], proc: a[3], path: a[4],
             detail: a[5], pid: a[6], seq: a[7], _h: null});
  }

  var STATE = {q: "", cats: {}, target: false, page: 0, filtered: null};
  CATS.forEach(function (c) { STATE.cats[c[0]] = true; });

  var tpid = (META.pid === null || META.pid === undefined) ? "" : String(META.pid);
  var tproc = String(META.proc || META.name || "").toLowerCase();

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) { n.className = cls; }
    if (text !== undefined && text !== null) { n.textContent = text; }
    return n;
  }

  function isTarget(e) {
    if (!tpid && !tproc) { return false; }
    if (tpid && e.pid !== null && e.pid !== undefined &&
        String(e.pid).indexOf(tpid) === 0) {
      return true;
    }
    if (tproc && e.proc && String(e.proc).toLowerCase().indexOf(tproc) >= 0) {
      return true;
    }
    return false;
  }

  function hay(e) {
    if (e._h === null) {
      e._h = (e.ts + " " + e.cat + " " + e.act + " " + (e.proc || "") + " " +
              (e.path || "") + " " + (e.detail || "")).toLowerCase();
    }
    return e._h;
  }

  function compute() {
    var q = STATE.q.trim().toLowerCase();
    var out = [];
    for (var i = 0; i < EV.length; i++) {
      var e = EV[i];
      if (!STATE.cats[e.cat]) { continue; }
      if (STATE.target && !isTarget(e)) { continue; }
      if (q && hay(e).indexOf(q) < 0) { continue; }
      out.push(e);
    }
    return out;
  }

  function fmtDetail(e) {
    if (!e.detail) { return "（无 detail）"; }
    try { return JSON.stringify(JSON.parse(e.detail), null, 2); }
    catch (err) { return e.detail; }
  }

  function toggleDetail(tr, e) {
    var nx = tr.nextElementSibling;
    if (nx && nx.className === "det") {
      nx.parentNode.removeChild(nx);
      tr.classList.remove("open");
      return;
    }
    var dtr = el("tr", "det");
    var td = el("td");
    td.colSpan = 5;
    var pre = el("pre", "json");
    pre.textContent = "seq=" + (e.seq === null ? "-" : e.seq) +
      "  pid=" + (e.pid === null || e.pid === undefined ? "-" : e.pid) +
      "  cat=" + e.cat + "  act=" + e.act + "\n" + fmtDetail(e);
    td.appendChild(pre);
    dtr.appendChild(td);
    tr.parentNode.insertBefore(dtr, tr.nextElementSibling);
    tr.classList.add("open");
  }

  function makeRow(e) {
    var tr = el("tr", "ev");
    tr.appendChild(el("td", "c-ts", e.ts));
    var tdCat = el("td", "c-cat");
    var chip = el("span", "chip", nameOf[e.cat] || e.cat);
    chip.style.background = colorOf[e.cat] || "#64748b";
    tdCat.appendChild(chip);
    tr.appendChild(tdCat);
    tr.appendChild(el("td", "c-act", e.act || "—"));
    var procText = e.proc || (e.pid === null || e.pid === undefined ? "—" : "pid " + e.pid);
    tr.appendChild(el("td", "c-proc", procText));
    var tdPath = el("td", "c-path", e.path || "—");
    if (e.path) { tdPath.title = e.path; }
    tr.appendChild(tdPath);
    tr.addEventListener("click", function () { toggleDetail(tr, e); });
    return tr;
  }

  var rowsBox = document.getElementById("tk-rows");
  var infoEls = document.querySelectorAll("[data-info]");
  var pgEls = document.querySelectorAll("[data-pgno]");

  function render() {
    var list = STATE.filtered || (STATE.filtered = compute());
    var total = list.length;
    var pages = Math.max(1, Math.ceil(total / PAGE));
    if (STATE.page > pages - 1) { STATE.page = pages - 1; }
    if (STATE.page < 0) { STATE.page = 0; }
    var start = STATE.page * PAGE;
    var end = Math.min(total, start + PAGE);

    rowsBox.textContent = "";
    var frag = document.createDocumentFragment();
    if (total === 0) {
      var tr = el("tr");
      var td = el("td", "empty",
        "没有匹配的事件（试着清空搜索词 / 打开类别过滤 / 关闭「只看目标进程」）");
      td.colSpan = 5;
      tr.appendChild(td);
      frag.appendChild(tr);
    } else {
      for (var i = start; i < end; i++) { frag.appendChild(makeRow(list[i])); }
    }
    rowsBox.appendChild(frag);

    var info = "匹配 " + total.toLocaleString() + " 条 / 共 " + EV.length.toLocaleString() +
      " 条 · 第 " + (total ? (STATE.page + 1) : 0) + "/" + pages +
      " 页 · 显示 " + (total ? (start + 1) : 0) + "-" + end;
    for (var k = 0; k < infoEls.length; k++) { infoEls[k].textContent = info; }
    for (var j = 0; j < pgEls.length; j++) {
      pgEls[j].max = String(pages);
      if (document.activeElement !== pgEls[j]) { pgEls[j].value = String(STATE.page + 1); }
    }
    var prevBtns = document.querySelectorAll('[data-act="prev"],[data-act="first"]');
    var nextBtns = document.querySelectorAll('[data-act="next"],[data-act="last"]');
    for (var b = 0; b < prevBtns.length; b++) { prevBtns[b].disabled = STATE.page <= 0; }
    for (var c2 = 0; c2 < nextBtns.length; c2++) { nextBtns[c2].disabled = STATE.page >= pages - 1; }
  }

  function buildCards() {
    var box = document.getElementById("cards");
    var totalCard = el("div", "card total");
    totalCard.appendChild(el("div", "n", EV.length.toLocaleString()));
    totalCard.appendChild(el("div", "t", "全部事件"));
    box.appendChild(totalCard);
    CATS.forEach(function (c) {
      var card = el("div", "card");
      card.setAttribute("data-cat", c[0]);
      card.title = "点击过滤：" + c[1] + " (" + c[0] + ")";
      card.style.borderTopColor = c[3];
      card.appendChild(el("div", "n", Number(c[2]).toLocaleString()));
      card.appendChild(el("div", "t", c[1] + " · " + c[0]));
      box.appendChild(card);
    });
  }

  function buildChips() {
    var box = document.getElementById("chips");
    CATS.forEach(function (c) {
      var b = el("button", "chipbtn");
      b.setAttribute("data-cat", c[0]);
      var dot = el("span", "dot");
      dot.style.background = c[3];
      b.appendChild(dot);
      b.appendChild(el("span", null, c[1]));
      b.appendChild(el("span", "cnt", Number(c[2]).toLocaleString()));
      box.appendChild(b);
    });
  }

  function syncFilterUI() {
    var on = 0;
    CATS.forEach(function (c) { if (STATE.cats[c[0]]) { on++; } });
    var nodes = document.querySelectorAll("[data-cat]");
    for (var i = 0; i < nodes.length; i++) {
      var c2 = nodes[i].getAttribute("data-cat");
      if (STATE.cats[c2]) { nodes[i].classList.remove("off"); }
      else { nodes[i].classList.add("off"); }
    }
    document.getElementById("catStat").textContent =
      "已选类别 " + on + "/" + CATS.length + (STATE.target ? " · 仅目标进程" : "");
  }

  function resetView() {
    STATE.filtered = null;
    STATE.page = 0;
    syncFilterUI();
    render();
  }

  buildCards();
  buildChips();
  syncFilterUI();

  document.getElementById("targetHint").textContent =
    (tpid || tproc) ? ("pid=" + (tpid || "-") + " / proc=" + (tproc || "-")) : "（run_meta 无 pid）";

  document.addEventListener("click", function (ev) {
    var node = ev.target;
    while (node && node !== document.body && !(node.getAttribute && node.getAttribute("data-cat"))) {
      node = node.parentNode;
    }
    if (!node || node === document.body) { return; }
    var cat = node.getAttribute("data-cat");
    STATE.cats[cat] = !STATE.cats[cat];
    resetView();
  });

  document.getElementById("allCats").addEventListener("click", function () {
    CATS.forEach(function (c) { STATE.cats[c[0]] = true; });
    resetView();
  });
  document.getElementById("noCats").addEventListener("click", function () {
    CATS.forEach(function (c) { STATE.cats[c[0]] = false; });
    resetView();
  });

  var qEl = document.getElementById("q");
  var qTimer = null;
  qEl.addEventListener("input", function () {
    if (qTimer) { clearTimeout(qTimer); }
    qTimer = setTimeout(function () {
      STATE.q = qEl.value || "";
      STATE.filtered = null;
      STATE.page = 0;
      render();
    }, 160);
  });

  var tEl = document.getElementById("target");
  tEl.addEventListener("change", function () {
    STATE.target = tEl.checked;
    resetView();
  });

  var navBtns = document.querySelectorAll("[data-act]");
  for (var n = 0; n < navBtns.length; n++) {
    navBtns[n].addEventListener("click", function () {
      var act = this.getAttribute("data-act");
      if (act === "prev") { STATE.page -= 1; }
      else if (act === "next") { STATE.page += 1; }
      else if (act === "first") { STATE.page = 0; }
      else if (act === "last") { STATE.page = 1e9; }
      render();
      window.scrollTo({top: 0, behavior: "smooth"});
    });
  }

  for (var g = 0; g < pgEls.length; g++) {
    pgEls[g].addEventListener("keydown", function (ev) {
      if (ev.key !== "Enter") { return; }
      var v = parseInt(this.value, 10);
      if (!isNaN(v)) { STATE.page = v - 1; render(); }
    });
  }

  var shots = DATA.shots || [];
  var shotLimit = DATA.shotLimit || 600;
  var shotsBox = document.getElementById("shots");
  var lb = document.getElementById("lb");
  var lbimg = document.getElementById("lbimg");
  var lbcap = document.getElementById("lbcap");

  function openLb(src) {
    lbimg.src = src;
    lbcap.textContent = src;
    lb.hidden = false;
  }
  lb.addEventListener("click", function () { lb.hidden = true; lbimg.src = ""; });
  document.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape") { lb.hidden = true; lbimg.src = ""; }
  });

  for (var s = 0; s < Math.min(shots.length, shotLimit); s++) {
    var fig = el("figure", "shot");
    var img = el("img");
    img.src = shots[s];
    img.loading = "lazy";
    img.alt = shots[s];
    img.addEventListener("click", (function (src) {
      return function () { openLb(src); };
    })(shots[s]));
    var cap = el("figcaption", null, shots[s].replace(/^shots\//, ""));
    fig.appendChild(img);
    fig.appendChild(cap);
    shotsBox.appendChild(fig);
  }
  if (!shots.length) {
    shotsBox.appendChild(el("p", "hint", "未发现截图文件（shots/ 目录为空或不存在）。"));
  } else if (shots.length > shotLimit) {
    shotsBox.appendChild(el("p", "hint",
      "共 " + shots.length + " 张，仅显示前 " + shotLimit + " 张。"));
  }

  render();
})();
</script>
</body>
</html>
"""


def _render_html(A):
    meta = A["meta"]
    name = meta.get("name") or "（未命名）"
    exe = meta.get("exe") or "—"
    span = A["span"]
    total = len(A["events"])

    cats = [[c, CAT_NAMES.get(c, c), A["cat_counts"][c], CAT_COLORS.get(c, "#64748b")]
            for c in A["cat_order"]]

    payload_events = []
    budget = MAX_INLINE_CHARS
    for e in A["events"][:MAX_HTML_EVENTS]:
        det = _detail_for_html(e.detail)
        budget -= len(det) + len(e.path or "") + 64
        if budget <= 0:
            break
        payload_events.append([
            e.tsd, e.cat, e.act, e.proc or "", e.path or "",
            det,
            e.pid if e.pid is not None else None,
            e.seq if isinstance(e.seq, int) else None,
        ])

    proc_name = ""
    if exe and exe != "—":
        proc_name = re.split(r"[\\/]", str(exe))[-1]

    payload = {
        "meta": {
            "run_id": meta.get("run_id"),
            "name": name,
            "exe": exe,
            "proc": proc_name,
            "pid": meta.get("pid"),
            "started": span["started"],
            "ended": span["ended"],
            "duration": _human_dur(span["secs"]),
            "notes": meta.get("notes") or "",
            "total": total,
            "embedded": len(payload_events),
        },
        "cats": cats,
        "events": payload_events,
        "shots": A["shots"],
        "shotLimit": MAX_SHOT_THUMBS,
        "pageSize": HTML_PAGE_SIZE,
    }

    subline = "%s · %s → %s · 时长 %s · 事件 %d 条 · run_id %s" % (
        _html.escape(str(exe)), span["started"], span["ended"],
        _human_dur(span["secs"]), total, _html.escape(str(meta.get("run_id") or "—")))

    notes_html = ""
    note_txt = str(meta.get("notes") or "").strip()
    if note_txt:
        notes_html = '<p class="notes">备注：%s</p>' % _html.escape(note_txt)
    if len(payload_events) < total:
        notes_html += ('<p class="notes">数据量 %d 条，HTML 内联前 %d 条'
                       '（其余请在 report.md 或数据库中查看）。</p>'
                       % (total, len(payload_events)))

    html_text = _HTML_TMPL
    html_text = html_text.replace("__TITLE__",
                                  _html.escape("TraceKit 时间线 — %s" % name))
    html_text = html_text.replace("__H1__", _html.escape("TraceKit 行为时间线 — %s" % name))
    html_text = html_text.replace("__SUBLINE__", subline)
    html_text = html_text.replace("__NOTES__", notes_html)
    html_text = html_text.replace("__SHOTCOUNT__", str(len(A["shots"])))
    html_text = html_text.replace("__PAGESIZE__", str(HTML_PAGE_SIZE))
    # 只替换一次占位符：payload 里即使出现 __PAYLOAD__ 字样也不会被二次替换
    html_text = html_text.replace("__PAYLOAD__", _json_for_script(payload), 1)
    return html_text


# --------------------------------------------------------------------------
# 对外接口
# --------------------------------------------------------------------------

def build_report(run_dir) -> tuple[str, str]:
    """读取 run_dir 下的记录数据，生成 report.md 和 timeline.html。

    参数
    ----
    run_dir : str | os.PathLike
        一次记录运行的目录，内含 events.sqlite / run_meta.json / stdout.log /
        stderr.log / shots/（后四者可选或可能缺失）。

    返回
    ----
    (md_path, html_path) : tuple[str, str]
        生成文件的绝对路径字符串。

    说明
    ----
    * 仅使用标准库；不写除 report.md / timeline.html 之外的文件。
    * 事件只读一遍，Markdown 与 HTML 共用同一份聚合结果。
    """
    run = Path(run_dir).expanduser()
    try:
        run = run.resolve()
    except OSError:
        pass
    if run.is_file():
        run = run.parent

    A = _analyze(run)
    md_path = run / "report.md"
    html_path = run / "timeline.html"

    try:
        run.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    md_path.write_text(_render_md(A), encoding="utf-8")
    html_path.write_text(_render_html(A), encoding="utf-8")
    return str(md_path), str(html_path)
