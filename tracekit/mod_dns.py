"""远端地址反查主机名：把 net/connect 里的 IP 变成主机名。

连接事件里只有 IP，判断"目标把数据发给了谁"时主机名（以及它属于哪个域）比 IP 有用得多。
反查是纯本地动作：只做 PTR 查询，不给目标发包，也不碰它的连接。

实现要点：
  * 订阅 net/connect|listen|bind，从 detail["remote"] / path 里取 IP，丢进有界队列（512 条）
  * 同一个 IP 只查一次（已排队 / 已查过都记在 _seen 里）；队列满了就丢掉并累计计数，
    丢弃的主机名不假装查过 —— 从 _seen 里抹掉，下次再出现还能补上
  * N 个 worker 做 socket.gethostbyaddr。反查可能卡在 DNS 上，而线程杀不掉，
    所以每次查询放进一次性子线程里等 timeout 秒：超时就按"未知"上报并放弃那根线程，
    同时给"烂线程"记数（上限 MAX_ORPHANS），超过就退化成同步查询，绝不无限长线程
  * 127.0.0.0/8 与 ::1 直接给 localhost，0.0.0.0 / :: 直接给"未指定地址"，都不查 DNS
"""
from __future__ import annotations

import ipaddress
import queue
import socket
import threading
import time

INTEREST_ACTS = ("connect", "listen", "bind")
MAX_QUEUE = 512
MAX_ORPHANS = 24
DROP_EMIT_GAP = 1.0          # host_dropped 事件的发出间隔下限，防刷屏
LOCAL_NAMES = ("localhost",)


def _as_port(text) -> int | None:
    try:
        port = int(str(text).strip())
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _clean_ip(text) -> str | None:
    """只接受真正的 IP 字面量（主机名不反查，交给系统自己去解析）。"""
    if not text:
        return None
    raw = str(text).strip().strip("[]")
    if not raw:
        return None
    # Win32 表格里 0.0.0.0 / :: 是"未连接"，保留原样给上层判断
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


def split_hostport(text):
    """'1.2.3.4:80' / '[::1]:80' / '1.2.3.4' / '[fe80::1]' -> (ip|None, port|None)。"""
    if not isinstance(text, str):
        return None, None
    value = text.strip()
    if not value:
        return None, None
    if value.startswith("["):
        end = value.find("]")
        if end <= 0:
            return None, None
        ip = _clean_ip(value[1:end])
        rest = value[end + 1:]
        port = _as_port(rest[1:]) if rest.startswith(":") else None
        return ip, port
    if value.count(":") == 1:
        host, _sep, port_text = value.partition(":")
        return _clean_ip(host), _as_port(port_text)
    if value.count(":") > 1:
        return _clean_ip(value), None      # 裸 IPv6，没有端口
    return _clean_ip(value), None


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _is_unspecified(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_unspecified
    except ValueError:
        return False


class HostResolver(threading.Thread):
    """订阅 net 事件 -> 异步反查远端 IP -> 发 net/host 或 net/host_unknown。

    用法（cli.py 里就是这么接的，subscribe 必须在 start 之前）::

        hr = HostResolver(bus, tree, logger=log)
        hr.subscribe()
        hr.start()
        ...
        hr.stop()
    """

    def __init__(self, bus, tree, logger=print, workers: int = 3, timeout: float = 2.0):
        super().__init__(name="host-resolver", daemon=True)
        self.bus = bus
        self.tree = tree
        self.log = logger or (lambda *_a, **_k: None)
        self.workers = max(1, int(workers))
        self.timeout = max(0.2, float(timeout))

        self.queue: queue.Queue = queue.Queue(maxsize=MAX_QUEUE)
        self._stopped = threading.Event()
        self._lock = threading.Lock()
        self._seen: set[str] = set()      # 已排队或已查过的 IP
        self._threads: list[threading.Thread] = []
        self._orphans = 0                 # 卡死没人收的查询线程
        self._subscribed = False

        self.dropped = 0
        self.resolved = 0
        self.unknown = 0
        self._last_drop_emit = 0.0
        self._last_error = ""

    # ------------------------------------------------------------------ 订阅
    def subscribe(self) -> None:
        if self._subscribed:
            return
        self._subscribed = True
        self.bus.subscribe(self._on_event)

    def _on_event(self, ev) -> None:
        """总线回调：必须极快（它跑在发事件那根线程里，比如网络记录器）。"""
        try:
            if ev.get("cat") != "net":
                return
            if ev.get("act") not in INTEREST_ACTS:
                return
            detail = ev.get("detail") or {}
            target = detail.get("remote") or ev.get("path") or detail.get("local")
            ip, port = split_hostport(target)
            if not ip:
                return
            self._enqueue(ip, port, ev)
        except Exception:
            return

    def _enqueue(self, ip: str, port, ev) -> None:
        with self._lock:
            if ip in self._seen:
                return
            self._seen.add(ip)
        item = {
            "ip": ip,
            "port": port,
            "pid": ev.get("pid"),
            "proc": ev.get("proc"),
        }
        emit_drop = False
        try:
            self.queue.put_nowait(item)
        except queue.Full:
            with self._lock:
                self._seen.discard(ip)        # 丢掉的不算查过，下次出现还能补
                self.dropped += 1
                total = self.dropped
                now = time.time()
                if now - self._last_drop_emit >= DROP_EMIT_GAP:
                    self._last_drop_emit = now
                    emit_drop = True
            if emit_drop:
                try:
                    self.bus.emit("net", "host_dropped",
                                  detail={"dropped": total, "queue_size": MAX_QUEUE})
                except Exception:
                    pass

    # ---------------------------------------------------------------- 线程管理
    def run(self) -> None:
        self._threads = []
        for index in range(self.workers):
            worker = threading.Thread(
                target=self._worker, name="host-resolver-%d" % (index + 1), daemon=True
            )
            worker.start()
            self._threads.append(worker)
        while not self._stopped.is_set():
            self._stopped.wait(0.2)
        deadline = time.time() + 1.5
        for worker in self._threads:
            try:
                worker.join(timeout=max(0.05, deadline - time.time()))
            except Exception:
                pass

    def stop(self) -> None:
        """让 worker 尽快退出（整体不超过约 2 秒），不等卡死的 DNS 查询。"""
        self._stopped.set()
        for _ in range(self.workers * 2):
            try:
                self.queue.put_nowait(None)
            except queue.Full:
                break
        deadline = time.time() + 1.6
        for worker in list(self._threads):
            try:
                worker.join(timeout=max(0.05, deadline - time.time()))
            except Exception:
                pass
        if self.is_alive() and threading.current_thread() is not self:
            self.join(timeout=max(0.05, deadline - time.time() + 0.2))

    def _worker(self) -> None:
        while not self._stopped.is_set():
            try:
                item = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue
            if item is None or self._stopped.is_set():
                break
            try:
                self._resolve(item)
            except Exception as exc:
                self.log(f"[dns] 反查 {item.get('ip')} 出错: {exc!r}")

    # ------------------------------------------------------------------ 反查
    def _resolve(self, item: dict) -> None:
        ip = item["ip"]
        if _is_loopback(ip):
            self._emit_host(item, LOCAL_NAMES[0], [])
            return
        if _is_unspecified(ip):
            self._emit_unknown(item, "未指定地址（0.0.0.0 / :: 的 bind/listen），不做反查")
            return
        result = self._lookup(ip)
        if result is None:
            self._emit_unknown(item, self._last_error or "无 PTR 记录")
            return
        self._emit_host(item, result[0], result[1])

    def _lookup(self, ip: str):
        """-> (hostname, aliases) 或 None；失败原因放 self._last_error。"""
        box: dict = {}
        finished = threading.Event()
        abandoned = threading.Event()

        def _do() -> None:
            try:
                host, aliases, _addrs = socket.gethostbyaddr(ip)
                box["host"] = str(host)
                box["aliases"] = [str(a) for a in (aliases or [])]
            except socket.herror as exc:
                code = exc.args[0] if exc.args else ""
                box["error"] = "herror %s%s" % (code, (": %s" % exc.strerror) if exc.strerror else "")
            except socket.gaierror as exc:
                box["error"] = "gaierror: %s" % (exc.strerror or exc)
            except OSError as exc:
                box["error"] = "%s: %s" % (type(exc).__name__, exc)
            except Exception as exc:  # noqa: BLE001 - 反查不许把 worker 拖死
                box["error"] = repr(exc)
            finally:
                if abandoned.is_set():
                    with self._lock:
                        self._orphans = max(0, self._orphans - 1)
                finished.set()

        with self._lock:
            spawn = self._orphans < MAX_ORPHANS
        if spawn:
            thread = threading.Thread(target=_do, name="host-lookup", daemon=True)
            thread.start()
            if not finished.wait(self.timeout):
                with self._lock:
                    self._orphans += 1
                abandoned.set()
                self._last_error = "反查超时（>%gs 未返回）" % self.timeout
                return None
        else:
            # 卡死的线程太多了：退化成同步查询，宁可慢一点也不再漏线程
            _do()
        if "host" in box:
            return box["host"], box.get("aliases") or []
        self._last_error = (box.get("error") or "无 PTR 记录")[:160]
        return None

    # ------------------------------------------------------------------ 发事件
    def _proc_name(self, pid, fallback=None):
        if pid:
            try:
                name = self.tree.name(pid)
                if name:
                    return name
            except Exception:
                pass
        return fallback

    def _emit_host(self, item: dict, hostname: str, aliases) -> None:
        pid = item.get("pid")
        proc = self._proc_name(pid, item.get("proc"))
        self.resolved += 1
        try:
            self.bus.emit(
                "net", "host",
                pid=pid, proc=proc, path=item["ip"],
                detail={"hostname": hostname, "aliases": list(aliases),
                        "remote_port": item.get("port"), "target_proc": proc},
            )
        except Exception as exc:
            self.log(f"[dns] 发 host 事件失败: {exc!r}")

    def _emit_unknown(self, item: dict, error: str) -> None:
        pid = item.get("pid")
        proc = self._proc_name(pid, item.get("proc"))
        self.unknown += 1
        try:
            self.bus.emit(
                "net", "host_unknown",
                pid=pid, proc=proc, path=item["ip"],
                detail={"error": str(error)[:200], "remote_port": item.get("port"),
                        "target_proc": proc},
            )
        except Exception as exc:
            self.log(f"[dns] 发 host_unknown 事件失败: {exc!r}")
