"""双击即用的可视化向导：勾选要抓什么 → 开始记录 → 实时看计数 → 中途可停。

    TraceKit.exe                          打开向导
    TraceKit.exe run/attach/probe/...      命令行用法完全保留（原样透传）

向导里的每个勾选都直接对应一个记录器，取消勾选就是省资源；三档预设
（省资源 / 标准 / 全量）一键切换。记录期间有个置顶小窗显示各类事件计数，
随时可以「停止并出报告」。
"""
from __future__ import annotations

import os
import queue
import sqlite3
import subprocess
import sys
import threading
import time
import traceback

APP_TITLE = "TraceKit 软件行为记录器"
SELFTEST_ENV = "TRACEKIT_WIZARD_SELFTEST"


# --------------------------------------------------------------------- helpers
def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _app_dir() -> str:
    if _is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _elevate(args: list[str]) -> bool:
    try:
        import ctypes

        params = subprocess.list2cmdline(args)
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                                 params, _app_dir(), 1)
        return rc > 32
    except Exception:
        return False


def build_argv(target: str, *, name: str = "", out: str = "", watch_dirs=(),
               duration: float = 0.0, shot_interval: float = 0.0,
               keep_files=True, uitree=True, modules=True, sysdiff=True,
               dns=True, ui_text=True, input_hook=True, tail=True,
               etw=True, watch_drive: str = "", quiet: bool = False) -> list[str]:
    """把向导的勾选翻译成命令行参数（单元测试也直接测这个函数）。"""
    argv = ["run", "--name", name or os.path.splitext(os.path.basename(target))[0]]
    if out:
        argv += ["--out", out]
    for d in watch_dirs:
        if d:
            argv += ["--watch-dir", d]
    if duration and duration > 0:
        argv += ["--duration", str(duration)]
    if shot_interval and shot_interval > 0:
        argv += ["--shot-interval", str(shot_interval)]
    else:
        argv += ["--no-shot-on-focus"]
    if not keep_files:
        argv.append("--no-keep-files")
    if not uitree:
        argv.append("--no-uitree")
    if not modules:
        argv.append("--no-modules")
    if not sysdiff:
        argv.append("--no-sys")
    if not dns:
        argv.append("--no-dns")
    if not tail:
        argv.append("--no-tail")
    if not ui_text:
        argv.append("--no-ui")
    if not input_hook:
        argv += ["--no-input", "--no-uiact"]
    if not etw:
        argv.append("--no-etw")
    if watch_drive:
        argv += ["--watch-drive", watch_drive.strip().rstrip(":\\/")]
    if quiet:
        argv.append("--quiet")
    argv += ["--cwd", os.path.dirname(os.path.abspath(target))]
    argv += ["--", target]
    return argv


# ------------------------------------------------------------------- GUI 主体
class Wizard:
    def __init__(self) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.tk = tk
        self.ttk = ttk
        self.root = tk.Tk()
        self.root.title(APP_TITLE)
        self.root.geometry("760x640")
        self.root.minsize(720, 600)
        try:
            self.root.attributes("-topmost", True)
            self.root.iconbitmap(default="")
        except Exception:
            pass

        self.vars = {}
        self.extra_dirs: list[str] = []
        self.target = tk.StringVar()
        self.duration = tk.StringVar(value="0")
        self.shot = tk.StringVar(value="0")
        self.drive = tk.StringVar(value="")
        self.stop_event = threading.Event()
        self.run_dir = ""
        self.worker: threading.Thread | None = None
        self.status_win = None
        self.counts_text = None
        self._build()

    # ------------------------------------------------------------------ 布局
    def _build(self) -> None:
        tk, ttk = self.tk, self.ttk
        pad = {"padx": 8, "pady": 4}

        head = ttk.Frame(self.root)
        head.pack(fill="x", **pad)
        ttk.Label(head, text="1. 选要记录的软件", font=("Microsoft YaHei UI", 11, "bold")).pack(anchor="w")

        row = ttk.Frame(self.root)
        row.pack(fill="x", **pad)
        ttk.Entry(row, textvariable=self.target).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="浏览…", command=self._pick_target).pack(side="left", padx=(6, 0))

        ttk.Label(self.root, text="2. 额外监视的数据目录（它往哪儿写配置/日志/导出）",
                  font=("Microsoft YaHei UI", 11, "bold")).pack(anchor="w", **pad)
        self.dir_label = ttk.Label(self.root, text="（未添加，默认只监视 exe 所在目录和当前目录）",
                                   foreground="#666")
        self.dir_label.pack(anchor="w", padx=8)
        drow = ttk.Frame(self.root)
        drow.pack(fill="x", **pad)
        ttk.Button(drow, text="添加目录…", command=self._add_dir).pack(side="left")
        ttk.Button(drow, text="清空", command=self._clear_dirs).pack(side="left", padx=6)

        ttk.Label(self.root, text="3. 抓什么（取消勾选就省资源）",
                  font=("Microsoft YaHei UI", 11, "bold")).pack(anchor="w", **pad)
        grid = ttk.Frame(self.root)
        grid.pack(fill="x", **pad)
        items = [
            ("keep_files", "文件副本（它写出的文件本体，2MB/个）", True),
            ("uitree", "界面结构（窗口/菜单栏/控件树）", True),
            ("modules", "DLL 模块加载", True),
            ("sysdiff", "系统改动（服务/启动项/计划任务）", True),
            ("dns", "远端 IP 反查主机名", True),
            ("ui_text", "界面文字（日志框/文本框变化）", True),
            ("input_hook", "按键与点击响应", True),
            ("tail", "日志文件内容（.log/.txt/.ini 逐行）", True),
            ("etw", "内核 ETW（需管理员：能记“谁读了文件”）", True),
        ]
        for i, (key, label, default) in enumerate(items):
            var = self.tk.BooleanVar(value=default)
            self.vars[key] = var
            cb = ttk.Checkbutton(grid, text=label, variable=var)
            cb.grid(row=i // 2, column=i % 2, sticky="w", padx=4, pady=2)

        srow = ttk.Frame(self.root)
        srow.pack(fill="x", **pad)
        self.vars["shot"] = self.tk.BooleanVar(value=True)
        ttk.Checkbutton(srow, text="截图", variable=self.vars["shot"]).pack(side="left")
        ttk.Label(srow, text="  间隔(秒,0=只在切窗口时)").pack(side="left")
        ttk.Entry(srow, textvariable=self.shot, width=5).pack(side="left", padx=4)
        ttk.Label(srow, text="   记录时长(秒,0=到目标退出)").pack(side="left")
        ttk.Entry(srow, textvariable=self.duration, width=6).pack(side="left", padx=4)

        drow2 = ttk.Frame(self.root)
        drow2.pack(fill="x", **pad)
        self.vars["whole_drive"] = self.tk.BooleanVar(value=False)
        ttk.Checkbutton(drow2, text="监视整个盘（很重）", variable=self.vars["whole_drive"]).pack(side="left")
        ttk.Entry(drow2, textvariable=self.drive, width=4).pack(side="left", padx=4)

        prow = ttk.Frame(self.root)
        prow.pack(fill="x", **pad)
        ttk.Label(prow, text="预设：").pack(side="left")
        ttk.Button(prow, text="省资源", command=lambda: self._preset("light")).pack(side="left", padx=2)
        ttk.Button(prow, text="标准", command=lambda: self._preset("standard")).pack(side="left", padx=2)
        ttk.Button(prow, text="全量", command=lambda: self._preset("full")).pack(side="left", padx=2)

        brow = ttk.Frame(self.root)
        brow.pack(fill="x", pady=10)
        ttk.Button(brow, text="开始记录", command=self._start).pack(side="right", padx=8)
        ttk.Button(brow, text="退出", command=self.root.destroy).pack(side="right")

        note = ("记录全程只从外部观察：不注入目标进程、不改它的代码、不挂调试器。"
                + ("\n当前已是管理员：可以记录「谁读了哪个文件」。"
                   if _is_admin() else
                   "\n当前不是管理员：记不到「谁读了文件」，也读不到目标命令行；建议以管理员身份运行。"))
        ttk.Label(self.root, text=note, foreground="#555", justify="left").pack(anchor="w", padx=8, pady=(2, 8))

    # ------------------------------------------------------------- 交互动作
    def _pick_target(self) -> None:
        from tkinter import filedialog

        path = filedialog.askopenfilename(
            title="选择要记录的软件",
            filetypes=[("可执行文件", "*.exe"), ("所有文件", "*.*")],
        )
        if path:
            self.target.set(path)

    def _add_dir(self) -> None:
        from tkinter import filedialog

        d = filedialog.askdirectory(title="选择要监视的数据目录")
        if d and d not in self.extra_dirs:
            self.extra_dirs.append(d)
            self._refresh_dirs()

    def _clear_dirs(self) -> None:
        self.extra_dirs.clear()
        self._refresh_dirs()

    def _refresh_dirs(self) -> None:
        if self.extra_dirs:
            self.dir_label.config(text="、".join(self.extra_dirs)[:160])
        else:
            self.dir_label.config(text="（未添加，默认只监视 exe 所在目录和当前目录）")

    def _preset(self, level: str) -> None:
        heavy = level == "full"
        lean = level == "light"
        self.vars["keep_files"].set(not lean)
        self.vars["uitree"].set(not lean)
        self.vars["modules"].set(not lean)
        self.vars["sysdiff"].set(not lean)
        self.vars["dns"].set(not lean)
        self.vars["ui_text"].set(heavy)
        self.vars["input_hook"].set(heavy)
        self.vars["tail"].set(True)
        self.vars["etw"].set(heavy)
        self.vars["shot"].set(not lean)
        self.duration.set("0" if heavy else self.duration.get())
        self.shot.set("20" if heavy else "0")

    # --------------------------------------------------------------- 开始记录
    def _collect(self) -> dict:
        sel = {k: v.get() for k, v in self.vars.items()}

        def num(var, default=0.0):
            try:
                return float(var.get())
            except Exception:
                return default

        return dict(
            target=self.target.get().strip(),
            watch_dirs=list(self.extra_dirs),
            duration=num(self.duration, 0.0),
            shot_interval=num(self.shot, 0.0) if sel.get("shot") else 0.0,
            keep_files=sel["keep_files"], uitree=sel["uitree"], modules=sel["modules"],
            sysdiff=sel["sysdiff"], dns=sel["dns"], ui_text=sel["ui_text"],
            input_hook=sel["input_hook"], tail=sel["tail"], etw=sel["etw"],
            watch_drive=self.drive.get().strip() if sel.get("whole_drive") else "",
            quiet=True,
        )

    def _start(self) -> None:
        from tkinter import messagebox

        cfg = self._collect()
        target = cfg["target"]
        if not target or not os.path.exists(target):
            messagebox.showwarning(APP_TITLE, "先选一个存在的 .exe 再开始。")
            return
        if cfg["etw"] and not _is_admin():
            if messagebox.askyesno(APP_TITLE,
                                   "勾了「内核 ETW」但当前不是管理员。\n\n"
                                   "要以管理员身份重启 TraceKit 吗？\n"
                                   "（否则这一项会被自动跳过）"):
                if _elevate(sys.argv[1:]):
                    self.root.destroy()
                    return
            cfg["etw"] = False

        name = os.path.splitext(os.path.basename(target))[0]
        self.run_dir = os.path.join(_app_dir(), "runs", f"{name}-{time.strftime('%Y%m%d-%H%M%S')}")
        argv = build_argv(out=self.run_dir, name=name, **cfg)
        self.root.withdraw()
        self._open_status(argv, name)

    # ----------------------------------------------------------- 状态小窗口
    def _open_status(self, argv: list[str], name: str) -> None:
        tk, ttk = self.tk, self.ttk
        win = tk.Toplevel(self.root)
        win.title(f"记录中 — {name}")
        win.geometry("560x420")
        win.attributes("-topmost", True)
        self.status_win = win

        ttk.Label(win, text=f"正在记录：{name}", font=("Microsoft YaHei UI", 11, "bold")).pack(anchor="w", padx=10, pady=(10, 2))
        ttk.Label(win, text=self.run_dir, foreground="#666", wraplength=520).pack(anchor="w", padx=10)
        self.counts_text = tk.Text(win, height=14, width=64, font=("Consolas", 10))
        self.counts_text.pack(fill="both", expand=True, padx=10, pady=8)

        btns = ttk.Frame(win)
        btns.pack(fill="x", padx=10, pady=(0, 10))
        self.stop_btn = ttk.Button(btns, text="停止并出报告", command=self._stop)
        self.stop_btn.pack(side="right")

        from tracekit import cli as tkcli

        self.worker = threading.Thread(
            target=self._run_worker, args=(tkcli, argv), daemon=True, name="recorder")
        self.worker.start()
        win.protocol("WM_DELETE_WINDOW", self._stop)
        self.root.after(700, self._tick)

    def _run_worker(self, tkcli, argv: list[str]) -> None:
        try:
            tkcli.main(argv, external_stop=self.stop_event)
        except Exception:
            traceback.print_exc()
        finally:
            self._done = True

    def _tick(self) -> None:
        if not self.status_win or not self.status_win.winfo_exists():
            return
        if getattr(self, "_done", False):
            self._finish()
            return
        rows = self._read_counts()
        elapsed = int(time.time() - self._started) if hasattr(self, "_started") else 0
        if not hasattr(self, "_started"):
            self._started = time.time()
        text = f"已记录 {elapsed} 秒\n\n"
        if rows:
            total = sum(n for _c, n in rows)
            text += f"事件总数 {total}\n" + "-" * 30 + "\n"
            for cat, n in rows:
                text += f"  {cat:<10}{n}\n"
        else:
            text += "（还没有事件，正在启动各记录器 …）\n"
        self.counts_text.delete("1.0", "end")
        self.counts_text.insert("1.0", text)
        self.root.after(800, self._tick)

    def _read_counts(self):
        db = os.path.join(self.run_dir, "events.sqlite")
        if not os.path.exists(db):
            return []
        try:
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1)
            rows = list(conn.execute(
                "select cat, count(*) from events group by cat order by 2 desc"))
            conn.close()
            return rows
        except Exception:
            return []

    def _stop(self) -> None:
        self.stop_event.set()
        try:
            self.stop_btn.config(state="disabled", text="正在收尾…")
        except Exception:
            pass

    def _finish(self) -> None:
        from tkinter import messagebox

        win = self.status_win
        self.status_win = None
        if win is not None:
            try:
                win.destroy()
            except Exception:
                pass
        if os.environ.get(SELFTEST_ENV):
            # 无人值守模式：不弹框、不开浏览器，直接收工
            print(f"[wizard-selftest] run_dir={self.run_dir}")
            try:
                self.root.destroy()
            except Exception:
                pass
            return
        report = os.path.join(self.run_dir, "报告.md")
        timeline = os.path.join(self.run_dir, "时间线.html")
        msg = f"记录结束。\n\n输出目录：\n{self.run_dir}\n\n"
        if os.path.exists(report):
            msg += "报告：报告.md\n"
        if os.path.exists(timeline):
            msg += "时间线：时间线.html\n"
        msg += "\n要现在打开交互式时间线吗？"
        try:
            if messagebox.askyesno(APP_TITLE, msg):
                target = timeline if os.path.exists(timeline) else self.run_dir
                os.startfile(target)
        except Exception:
            pass
        try:
            os.startfile(self.run_dir)
        except Exception:
            pass
        try:
            self.root.destroy()
        except Exception:
            pass

    def run(self) -> int:
        self.root.mainloop()
        return 0


# ---------------------------------------------------------- 无人值守自检（内部）
def _selftest_wizard() -> int:
    """自动填表并开录，用于验证向导本身（不给普通用户用）。"""
    wiz = Wizard()
    demo = os.path.join(os.path.dirname(_app_dir()), "TraceKitDemo.exe")
    if not os.path.exists(demo):
        demo = os.path.join(_app_dir(), "TraceKitDemo.exe")
    wiz.target.set(demo)
    wiz.duration.set("12")
    wiz.shot.set("6")
    wiz.root.after(1200, wiz._start)
    wiz.root.after(26000, wiz._stop)
    return wiz.run()


def main() -> int:
    try:
        import ctypes

        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
        ctypes.windll.kernel32.SetConsoleTitleW(APP_TITLE)
    except Exception:
        pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if os.environ.get(SELFTEST_ENV):
        return _selftest_wizard()

    if len(sys.argv) > 1:
        from tracekit import cli as tkcli

        return tkcli.main(sys.argv[1:])

    try:
        return Wizard().run()
    except KeyboardInterrupt:
        return 130
    except Exception:
        traceback.print_exc()
        try:
            from tkinter import messagebox

            messagebox.showerror(APP_TITLE, "出错了，详情见控制台窗口。")
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
