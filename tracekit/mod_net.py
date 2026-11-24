"""Network recorder: which sockets the target family opens, talks to and closes.

Polls the OS TCP/UDP owner tables (GetExtendedTcpTable / GetExtendedUdpTable),
which is enough to see every connection state transition of a 32-bit target
without touching its process.  Payload bytes are not visible here - use the
ETW module for byte counts, or a local proxy if the traffic itself matters.
"""
from __future__ import annotations

import threading

from . import winapi


def _fmt(addr: str, port: int) -> str:
    return f"{addr}:{port}"


class NetworkRecorder(threading.Thread):
    def __init__(self, bus, tree, interval: float = 1.0, logger=print,
                 include_all: bool = False):
        super().__init__(name="net-recorder", daemon=True)
        self.bus = bus
        self.tree = tree
        self.interval = max(0.3, interval)
        self.log = logger
        self.include_all = include_all
        self._stopped = threading.Event()
        self._seen: dict[tuple, dict] = {}

    def stop(self) -> None:
        self._stopped.set()

    def run(self) -> None:
        while not self._stopped.is_set():
            try:
                self._tick()
            except Exception as exc:
                self.log(f"[net] tick failed: {exc!r}")
            self._stopped.wait(self.interval)

    def _rows(self):
        rows = []
        for proto, laddr, lport, raddr, rport, state, pid in winapi.tcp_table():
            rows.append((proto, laddr, lport, raddr, rport, state, pid))
        for proto, laddr, lport, raddr, rport, state, pid in winapi.udp_table():
            rows.append((proto, laddr, lport, raddr, rport, state, pid))
        return rows

    def _tick(self) -> None:
        scope = self.tree.scope()
        rows = self._rows()
        current = {}
        for proto, laddr, lport, raddr, rport, state, pid in rows:
            in_scope = pid in scope
            if not in_scope and not self.include_all:
                continue
            key = (proto, laddr, lport, raddr, rport, pid)
            current[key] = {"state": state, "in_scope": in_scope}
            if key not in self._seen:
                act = "listen" if state == "LISTEN" else (
                    "bind" if proto == "udp" else "connect"
                )
                remote = _fmt(raddr, rport) if raddr and raddr != "0.0.0.0" else None
                self.bus.emit(
                    "net", act,
                    pid=pid, ppid=self.tree.ppid(pid), proc=self.tree.name(pid),
                    path=remote or _fmt(laddr, lport),
                    detail={
                        "proto": proto, "local": _fmt(laddr, lport),
                        "remote": remote,
                        "state": state, "in_scope": in_scope,
                    },
                )
        for key, info in self._seen.items():
            if key not in current:
                proto, laddr, lport, raddr, rport, pid = key
                self.bus.emit(
                    "net", "close",
                    pid=pid, ppid=self.tree.ppid(pid), proc=self.tree.name(pid),
                    path=_fmt(raddr, rport) if raddr else _fmt(laddr, lport),
                    detail={"proto": proto, "local": _fmt(laddr, lport),
                            "remote": _fmt(raddr, rport) if raddr else None,
                            "last_state": info["state"]},
                )
        # state transitions (LISTEN -> ESTABLISHED etc.)
        for key, info in current.items():
            old = self._seen.get(key)
            if old and old["state"] != info["state"]:
                proto, laddr, lport, raddr, rport, pid = key
                self.bus.emit(
                    "net", "state",
                    pid=pid, ppid=self.tree.ppid(pid), proc=self.tree.name(pid),
                    path=_fmt(raddr, rport) if raddr else _fmt(laddr, lport),
                    detail={"proto": proto, "from": old["state"], "to": info["state"]},
                )
        self._seen = current
