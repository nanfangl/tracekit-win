"""Registry recorder.

Uses RegNotifyChangeKeyValue (a push notification, no polling) so changes show
up within milliseconds, then re-enumerates just that subtree and diffs it
against the previous snapshot to name the exact value that appeared, vanished
or changed.

Scope is deliberately bounded (hive + subkey + depth, default HKCU\\Software)
because enumerating all of HKLM every time a key is touched would cost more
than the program under test.
"""
from __future__ import annotations

import ctypes
import threading
import time
import winreg
from ctypes import wintypes

from . import winapi

HIVES = {
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKCR": winreg.HKEY_CLASSES_ROOT,
    "HKU": winreg.HKEY_USERS,
}
HIVE_NAMES = {v: k for k, v in HIVES.items()}

KEY_READ_NOTIFY = winreg.KEY_READ | 0x0010  # KEY_NOTIFY
REG_NOTIFY_CHANGE_NAME = 0x00000001
REG_NOTIFY_CHANGE_ATTRIBUTES = 0x00000002
REG_NOTIFY_CHANGE_LAST_SET = 0x00000004
REG_NOTIFY_CHANGE_SECURITY = 0x00000008

DEFAULT_SKIP = {
    "\\classes\\clsid", "\\classes\\interface", "\\classes\\typelib",
    "\\classes\\wow6432node", "\\wow6432node\\clsid",
}


def _short(value, limit=300):
    try:
        s = str(value)
    except Exception:
        s = repr(value)
    return s if len(s) <= limit else s[:limit] + "..."


def snapshot(root, depth: int = 4, max_keys: int = 40000, base: str = "") -> dict:
    """{subkey_path (relative to base): {value_name: (type, short_repr)}}."""
    out: dict[str, dict] = {}
    count = 0
    stack = [("", 0)]  # (path relative to base, level)
    while stack and count < max_keys:
        rel, level = stack.pop()
        full_rel = f"{base}\\{rel}" if (base and rel) else (rel or base)
        try:
            with winreg.OpenKey(root, full_rel, 0, winreg.KEY_READ) as key:
                count += 1
                vals = {}
                i = 0
                while True:
                    try:
                        name, data, vtype = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    vals[name] = (vtype, _short(data))
                    i += 1
                if vals:
                    out[rel] = vals
                if level < depth:
                    j = 0
                    while True:
                        try:
                            sub = winreg.EnumKey(key, j)
                        except OSError:
                            break
                        j += 1
                        child = (rel + "\\" + sub) if rel else sub
                        low = "\\" + child.lower()
                        if any(s in low for s in DEFAULT_SKIP):
                            continue
                        stack.append((child, level + 1))
        except OSError:
            continue
    return out


def parse_root(spec: str):
    hive, _, sub = spec.partition("\\")
    hive = hive.upper()
    if hive not in HIVES:
        raise ValueError(f"unknown hive in {spec!r} (use HKCU/HKLM/HKCR/HKU)")
    return HIVES[hive], sub


class _RootWatch(threading.Thread):
    def __init__(self, spec, bus, depth, logger=print):
        super().__init__(name=f"regwatch:{spec}", daemon=True)
        self.spec = spec
        self.bus = bus
        self.depth = depth
        self.log = logger
        self._stopped = threading.Event()
        self._root, self._sub = parse_root(spec)
        self.hive = HIVE_NAMES.get(self._root, "HKCU")

    def stop(self):
        self._stopped.set()

    def run(self):
        try:
            pykey = winreg.OpenKey(self._root, self._sub, 0, KEY_READ_NOTIFY)
        except OSError as exc:
            self.log(f"[reg] cannot open {self.spec}: {exc}")
            return
        raw = pykey.Detach()  # raw HKEY we now own; closed with RegCloseKey
        prev = snapshot(self._root, self.depth, base=self._sub)
        self.log(f"[reg] watching {self.spec} (~{len(prev)} keys with values)")
        event = winapi.kernel32.CreateEventW(None, False, False, None)
        if not event:
            self.log(f"[reg] CreateEvent failed for {self.spec}")
            winapi.advapi32.RegCloseKey(raw)
            return
        try:
            while not self._stopped.is_set():
                winapi.advapi32.RegNotifyChangeKeyValue(
                    raw,
                    True,
                    REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES
                    | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY,
                    event,
                    True,
                )
                rc = winapi.kernel32.WaitForSingleObject(event, 500)
                if self._stopped.is_set():
                    break
                if rc != 0:  # timeout
                    continue
                # give the writer a beat to finish a burst of writes
                time.sleep(0.15)
                cur = snapshot(self._root, self.depth, base=self._sub)
                self._diff(prev, cur)
                prev = cur
        finally:
            winapi.kernel32.CloseHandle(event)
            try:
                winapi.advapi32.RegCloseKey(raw)
            except Exception:
                pass

    def _diff(self, prev: dict, cur: dict) -> None:
        now = time.time()
        for path in cur.keys() - prev.keys():
            self._emit("reg_key_create", path, None, {"values": len(cur[path])})
        for path in prev.keys() - cur.keys():
            self._emit("reg_key_delete", path, None, {"values": len(prev[path])})
        for path in cur.keys() & prev.keys():
            a, b = prev[path], cur[path]
            for name in b.keys() - a.keys():
                self._emit("reg_value_create", path, name, {"type": b[name][0], "data": b[name][1]})
            for name in a.keys() - b.keys():
                self._emit("reg_value_delete", path, name, {"type": a[name][0], "data": a[name][1]})
            for name in a.keys() & b.keys():
                if a[name] != b[name]:
                    self._emit("reg_value_set", path, name,
                               {"type": b[name][0], "old": a[name][1], "new": b[name][1]})

    def _emit(self, act, path, value_name, detail) -> None:
        full = f"{self.spec}\\{path}" if path else self.spec
        d = dict(detail)
        d["value"] = value_name
        self.bus.emit("reg", act, path=full, detail=d)

class RegistryRecorder:
    def __init__(self, bus, roots=None, depth: int = 4, logger=print):
        self.bus = bus
        self.specs = roots or ["HKCU\\Software"]
        self.depth = depth
        self.log = logger
        self._watches: list[_RootWatch] = []

    def start(self) -> bool:
        started = False
        for spec in self.specs:
            try:
                w = _RootWatch(spec, self.bus, self.depth, logger=self.log)
            except ValueError as exc:
                self.log(f"[reg] {exc}")
                continue
            w.start()
            self._watches.append(w)
            started = True
        return started

    def stop(self) -> None:
        for w in self._watches:
            w.stop()
        for w in self._watches:
            w.join(timeout=2)
