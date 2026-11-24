"""界面结构录制：把目标的窗口树、控件树、菜单栏文字完整抄下来。

文本变化（`ui/text`）只能说明"日志框里多了几行"。要弄清一个界面程序到底有哪些
功能，需要的是**结构**：有几个窗口、每个窗口里有哪些控件、ID 是多少、菜单栏里
有哪些项（含子菜单）。这些都是标准 Win32 查询接口，跨进程可用、不注入。

变化时才记一条 `ui/tree` 事件；退出时把每个窗口的最新结构写成 `界面结构.txt`。
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time

from . import winapi

MAX_CONTROLS = 300
MAX_MENU_DEPTH = 3


def _menu_tree(hwnd, depth: int = 0, prefix: str = "") -> list[dict]:
    """菜单栏 + 子菜单的文字/id 列表（最多 MAX_MENU_DEPTH 层）。"""
    out: list[dict] = []
    try:
        menu = winapi.user32.GetMenu(hwnd)
        if not menu:
            return out
        count = int(winapi.user32.GetMenuItemCount(menu) or 0)
        for i in range(min(count, 64)):
            text = winapi.menu_item_text(menu, i)
            item_id = int(winapi.user32.GetMenuItemID(menu, i) or 0)
            node = {"level": depth, "path": f"{prefix}{text}" if depth else text,
                    "text": text, "id": item_id}
            sub = winapi.user32.GetSubMenu(menu, i)
            if sub and depth + 1 < MAX_MENU_DEPTH:
                node["children"] = _menu_tree_of(sub, depth + 1, node["path"] + " > ")
            out.append(node)
    except Exception:
        pass
    return out


def _menu_tree_of(menu, depth: int = 1, prefix: str = "") -> list[dict]:
    out: list[dict] = []
    try:
        count = int(winapi.user32.GetMenuItemCount(menu) or 0)
        for i in range(min(count, 64)):
            text = winapi.menu_item_text(menu, i)
            item_id = int(winapi.user32.GetMenuItemID(menu, i) or 0)
            node = {"level": depth, "path": f"{prefix}{text}", "text": text, "id": item_id}
            sub = winapi.user32.GetSubMenu(menu, i)
            if sub and depth + 1 < MAX_MENU_DEPTH:
                node["children"] = _menu_tree_of(sub, depth + 1, node["path"] + " > ")
            out.append(node)
    except Exception:
        pass
    return out


def snapshot_window(hwnd: int) -> dict | None:
    try:
        if not winapi.user32.IsWindow(hwnd):
            return None
    except Exception:
        return None
    title = winapi.window_title(hwnd)
    cls = winapi.window_class(hwnd)
    rect = winapi.window_rect(hwnd)
    controls = []
    for child, ccls, ctext, crect in winapi.enum_children(hwnd)[:MAX_CONTROLS]:
        controls.append({
            "hwnd": child,
            "class": ccls,
            "id": int(winapi.user32.GetDlgCtrlID(child)),
            "text": (ctext or "")[:200],
            "rect": crect,
            "visible": bool(winapi.user32.IsWindowVisible(child)),
            "enabled": bool(winapi.user32.IsWindowEnabled(child)),
        })
    return {
        "hwnd": hwnd,
        "title": title,
        "class": cls,
        "rect": rect,
        "pid": winapi.window_pid(hwnd),
        "menus": _menu_tree(hwnd),
        "controls": controls,
    }


def _hash(struct: dict) -> str:
    blob = json.dumps(
        {k: struct.get(k) for k in ("title", "class", "menus", "controls")},
        ensure_ascii=False, sort_keys=True, default=str,
    )
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:16]


class UiTreeRecorder(threading.Thread):
    def __init__(self, bus, tree, run_dir=None, interval: float = 3.0, logger=print):
        super().__init__(name="uitree", daemon=True)
        self.bus = bus
        self.tree = tree
        self.run_dir = run_dir
        self.interval = max(1.0, interval)
        self.log = logger
        self._stopped = threading.Event()
        self._hashes: dict[int, str] = {}
        self._latest: dict[int, dict] = {}
        self._history: dict[int, dict] = {}   # 关掉的窗口也留着，报告要用
        self._dirty = threading.Event()

    def subscribe(self) -> None:
        """窗口一换焦点就马上重扫一遍，不用等定时器。"""
        def _on_event(ev):
            if ev.get("cat") == "win" and ev.get("act") in ("focus", "window_open", "window_close"):
                self._dirty.set()
        self.bus.subscribe(_on_event)

    def stop(self) -> None:
        self._stopped.set()
        self._dirty.set()   # 唤醒正在 wait 的循环，别让进程先退出把报告带走

    def run(self) -> None:
        while not self._stopped.is_set():
            try:
                self._scan()
            except Exception as exc:
                self.log(f"[uitree] 扫描失败: {exc!r}")
            self._dirty.wait(self.interval)
            self._dirty.clear()
        try:
            self._scan()
        except Exception:
            pass
        self._write_report()

    # ------------------------------------------------------------------ 扫描
    def _scan(self) -> None:
        scope = self.tree.scope()
        if not scope:
            return
        alive = set()
        for hwnd, _title, _cls, pid in winapi.enum_windows():
            if pid not in scope:
                continue
            alive.add(hwnd)
            struct = snapshot_window(hwnd)
            if not struct:
                continue
            digest = _hash(struct)
            if self._hashes.get(hwnd) == digest:
                continue
            first = hwnd not in self._hashes
            self._hashes[hwnd] = digest
            self._latest[hwnd] = struct
            if len(self._history) < 50 or hwnd in self._history:
                self._history[hwnd] = struct
            self.bus.emit(
                "ui", "tree_new" if first else "tree",
                pid=pid, ppid=self.tree.ppid(pid), proc=self.tree.name(pid),
                path=f"{struct['class']}「{struct['title']}」",
                detail={
                    "window": {k: struct[k] for k in ("hwnd", "title", "class", "rect")},
                    "menu_count": len(struct["menus"]),
                    "menus": struct["menus"],
                    "control_count": len(struct["controls"]),
                    "controls": struct["controls"],
                    "digest": digest,
                },
            )
        for hwnd in list(self._hashes):
            if hwnd not in alive:
                self._hashes.pop(hwnd, None)
                st = self._latest.pop(hwnd, None)
                self.bus.emit("ui", "tree_close", detail={"hwnd": hwnd,
                                                          "title": (st or {}).get("title")})

    # ------------------------------------------------------------------ 报告
    def _write_report(self) -> None:
        if not self.run_dir:
            return
        path = os.path.join(self.run_dir, "界面结构.txt")
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as fh:
                fh.write("# 界面结构快照\r\n")
                fh.write(f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\r\n")
                if not self._latest:
                    if not self._history:
                        fh.write("\r\n（未捕获到目标窗口）\r\n")
                        return
                for hwnd, st in (self._history or self._latest).items():
                    closed = "" if hwnd in self._latest else "  [已关闭]"
                    fh.write(f"\r\n===== 窗口 {st['class']}「{st['title']}」 "
                             f"hwnd={hwnd}{closed} =====\r\n")
                    rect = st.get("rect") or {}
                    fh.write(f"位置: {rect.get('left')},{rect.get('top')} "
                             f"尺寸: {rect.get('width')}x{rect.get('height')}\r\n")
                    if st["menus"]:
                        fh.write("\r\n-- 菜单栏 --\r\n")
                        for m in st["menus"]:
                            indent = "  " * int(m.get("level") or 0)
                            fh.write(f"{indent}- {m.get('text')} (id={m.get('id')})\r\n")
                            for c in (m.get("children") or []):
                                fh.write(f"{indent}    - {c.get('text')} (id={c.get('id')})\r\n")
                    fh.write("\r\n-- 控件树 --\r\n")
                    for c in st["controls"]:
                        r = c.get("rect") or {}
                        flag = "" if c.get("visible") else " [隐藏]"
                        flag += "" if c.get("enabled") else " [禁用]"
                        fh.write(f"  [{c.get('class')}] id={c.get('id')} "
                                 f"@{r.get('left')},{r.get('top')} "
                                 f"{r.get('width')}x{r.get('height')}{flag}  "
                                 f"文字={c.get('text')!r}\r\n")
            self.log(f"[uitree] 界面结构: {path}")
        except OSError as exc:
            self.log(f"[uitree] 写报告失败: {exc}")
