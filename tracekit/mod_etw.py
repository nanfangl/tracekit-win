# -*- coding: utf-8 -*-
"""TraceKit ETW kernel trace module (NT Kernel Logger), zero third-party deps.

What it does
------------
Starts a Windows kernel trace session (the "NT Kernel Logger" real-time session)
through ``logman.exe``, consumes the live event stream through ``advapi32``
(OpenTraceW / ProcessTrace with EVENT_RECORD callbacks, ctypes only), decodes the
MOF payloads of FileIo / Registry / TcpIp events and forwards them to the
TraceKit bus::

    bus.emit(cat="file"|"reg"|"net", act=<action>, path=<path or value name>,
             pid=<int|None>, proc=<name|None>, detail=<dict>)

Every emitted event carries ``detail["source"] == "etw"``.

Verified command line (Windows 11 10.0.26300, admin shell, logman 10.0.26100)::

    logman create trace "NT Kernel Logger" -p "Windows Kernel Trace" 0x6030000 ^
           -o <out_dir>\\etk_<ts>_<pid>.etl -rt -bs 128 -max 128 -ets

    # 0x6030000 = FILE_IO (0x04000000) | FILE_IO_INIT (0x02000000)
    #           | NETWORK_TCPIP (0x00010000) | REGISTRY (0x00020000)
    # logman reports the effective mask as 0x26030000; it ORs 0x20000000 in by
    # itself (kernel "fileio"/"fileiocompletion" keywords).  Verified output:
    #   KeywordsAny: 0x26030000 (net,registry,fileiocompletion,fileio,0x20000000)
    # The session name must be exactly "NT Kernel Logger"; any other name is
    # rejected with "The session name provided is invalid".

Stopping (always executed, also on the error path)::

    advapi32.ControlTraceW(0, "NT Kernel Logger", props, EVENT_TRACE_CONTROL_STOP)
    logman stop "NT Kernel Logger" -ets
    wpr -cancel            # last-resort backstop if the session is still alive

If the real-time consumer cannot be opened, the module falls back to stopping
the session and parsing the ETL with::

    tracerpt <etl> -o <csv> -of CSV -y

Usage
-----
    from tracekit.mod_etw import EtwCapture, EtwUnavailable
    cap = EtwCapture(bus, "C:\\logs\\etw", keywords=("file", "registry", "network"))
    cap.start_capture()          # raises EtwUnavailable when not permitted
    ...
    cap.stop_capture()           # stops the trace, flushes decoded events

Self test (works stand-alone, no other TraceKit file needed)::

    python -m tracekit.mod_etw --selftest

Notes on the payload layouts were obtained by controlled calibration runs on the
target machine, see the comments next to each decoder below.

Event sources (all verified on this machine)
--------------------------------------------
    FileIo   {90CBDC39-4A3E-11D1-84F4-0000F80464E3}  create/read/write/setinfo/
                                                      delete/rename (+ paths)
    Registry {AE53722E-C863-11D2-9A82-006008A86939}  create/open/set/delete/
                                                      query key + value name
    TcpIp    {9A280AC0-C8E0-11D1-84E2-00C04FB998A2}  send/recv/connect/accept
    UdpIp    {BF3A50C5-A9C9-4988-A1D3-2A6D1A0E1D1F}  send/recv (same payload as
                                                      TcpIp, PID inside payload)

The registry path is normalised (\\REGISTRY\\MACHINE\\... -> HKLM\\..., see
_friendly_reg) and NT device paths are mapped to drive letters
(\\Device\\HarddiskVolume3\\x -> C:\\x) through QueryDosDeviceW.

Known limits
------------
* registry events whose key handle was opened before the capture started cannot
  be resolved to a key path (path stays None, value name is still reported);
* FileIo Read/Write carry a FileObject, the file name is only known when the
  matching Create event was seen in the same capture;
* the kernel trace is system wide, so a busy machine produces tens of
  thousands of events per second - pass ``pid_filter`` to narrow it down and
  watch ``summary()["dropped"]``;
* the session is a single global resource ("NT Kernel Logger"): one capture at
  a time, and a stale session from a crashed run is reclaimed only when the
  sidecar file .etk_session.json still points into ``out_dir``.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import queue
import string
import struct
import subprocess
import sys
import threading
import time

__all__ = ["EtwUnavailable", "EtwCapture"]


class EtwUnavailable(RuntimeError):
    """Raised when the kernel trace session cannot be started or consumed."""


# ---------------------------------------------------------------------------
# Win32 bindings (ctypes only)
# ---------------------------------------------------------------------------

try:
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _WINDOWS = True
except Exception:                                   # pragma: no cover
    _advapi32 = None
    _kernel32 = None
    _WINDOWS = False

# EVENT_RECORD layout on x64, verified against the live consumer:
#   +0   EVENT_HEADER.Size              (USHORT)
#   +8   ThreadId                       (ULONG)
#   +12  ProcessId                      (ULONG)
#   +16  TimeStamp                      (LONGLONG, 100ns since 1601)
#   +24  ProviderId                     (GUID, 16 bytes)
#   +40  EventDescriptor.Id             (USHORT)
#   +42  Version / +43 Channel / +44 Level / +45 Opcode
#   +46  Task                           (USHORT)
#   +48  Keyword                        (ULONG64)
#   +56  KernelTime, +60 UserTime
#   +80  BufferContext (4) + ExtendedDataCount (2) + UserDataLength (2)
#   +88  ExtendedData ptr, +96 UserData ptr, +104 UserContext ptr
_OFF_REC_THREAD_ID = 8
_OFF_REC_PROCESS_ID = 12
_OFF_REC_TIME = 16
_OFF_REC_PROVIDER = 24
_OFF_REC_OPCODE = 45
_OFF_REC_TASK = 46
_OFF_REC_USER_LEN = 86
_OFF_REC_USER_DATA = 96
_REC_PREFIX = 112

# EVENT_TRACE_LOGFILEW layout on x64 (sizeof 448; TRACE_LOGFILE_HEADER starts at
# 120, i.e. CurrentEvent is 88 bytes).  Verified empirically by dumping the
# structure right after OpenTraceW and locating TRACE_LOGFILE_HEADER.BufferSize.
_LOGFILE_OFF_LOGGER_NAME = 8
_LOGFILE_OFF_MODE = 28
_LOGFILE_OFF_EVENT_RECORD_CALLBACK = 424
_LOGFILE_STRUCT_SIZE = 1024         # >= real sizeof (448), zero-filled

_EVENT_TRACE_REAL_TIME_MODE = 0x00000100
_PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
_EVENT_TRACE_CONTROL_STOP = 1
_INVALID_TRACE_HANDLE = 0xFFFFFFFFFFFFFFFF

# Kernel provider GUID prefixes (first Data1 dword, enough to route events).
_GUID_FILEIO = 0x90CBDC39       # {90CBDC39-4A3E-11D1-84F4-0000F80464E3}
_GUID_REGISTRY = 0xAE53722E     # {AE53722E-C863-11D2-9A82-006008A86939}
_GUID_TCPIP = 0x9A280AC0        # {9A280AC0-C8E0-11D1-84E2-00C04FB998A2}
_GUID_UDPIP = 0xBF3A50C5        # {BF3A50C5-A9C9-4988-A1D3-2A6D1A0E1D1F}
_GUID_EVENTTRACE = 0x68FDD900   # session bookkeeping events, ignored

# logman keyword bits (verified one bit at a time on this machine):
#   0x00000200 file(disk layer)   0x00010000 net     0x00020000 registry
#   0x01000000 profile            0x02000000 fileiocompletion (FILE_IO_INIT)
#   0x04000000 fileio (FILE_IO)   0x00100000 alpc    0x00200000 splitio
_FLAG_FILE = 0x06000000
_FLAG_NET = 0x00010000
_FLAG_REG = 0x00020000

_KEYWORD_FLAGS = {
    "file": _FLAG_FILE, "files": _FLAG_FILE, "fileio": _FLAG_FILE,
    "file_io": _FLAG_FILE,
    "registry": _FLAG_REG, "reg": _FLAG_REG, "regs": _FLAG_REG,
    "network": _FLAG_NET, "net": _FLAG_NET, "tcpip": _FLAG_NET, "tcp": _FLAG_NET,
}

_SESSION_NAME = "NT Kernel Logger"
_LOG_ETL_PREFIX = "etk"
_LOCK = threading.Lock()
_ACTIVE = False


def _init_prototypes():
    """Declare the Win32 prototypes we rely on (needed on 64-bit Python)."""
    if not _WINDOWS:
        return
    try:
        _kernel32.GetCurrentProcess.restype = wt.HANDLE
        _kernel32.GetCurrentProcess.argtypes = []
        _kernel32.CloseHandle.argtypes = [wt.HANDLE]
        _kernel32.CloseHandle.restype = wt.BOOL
        _advapi32.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD,
                                               ctypes.POINTER(wt.HANDLE)]
        _advapi32.OpenProcessToken.restype = wt.BOOL
        _advapi32.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int,
                                                  ctypes.c_void_p, wt.DWORD,
                                                  ctypes.POINTER(wt.DWORD)]
        _advapi32.GetTokenInformation.restype = wt.BOOL
        _kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        _kernel32.OpenProcess.restype = wt.HANDLE
        _kernel32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD,
                                                         wt.LPWSTR,
                                                         ctypes.POINTER(wt.DWORD)]
        _kernel32.QueryFullProcessImageNameW.restype = wt.BOOL
        _kernel32.QueryDosDeviceW.argtypes = [wt.LPCWSTR, wt.LPWSTR, wt.DWORD]
        _kernel32.QueryDosDeviceW.restype = wt.DWORD
        _advapi32.CloseTrace.argtypes = [ctypes.c_ulonglong]
        _advapi32.CloseTrace.restype = wt.ULONG
    except Exception:                                # pragma: no cover
        pass


_init_prototypes()


def _is_admin():
    """Return True when the current process has an elevated token."""
    if not _WINDOWS:
        return False
    try:
        token = wt.HANDLE()
        process = _kernel32.GetCurrentProcess()
        if not _advapi32.OpenProcessToken(process, 0x0008, ctypes.byref(token)):
            raise OSError("OpenProcessToken")
        elevation = ctypes.c_ulong(0)
        size = ctypes.c_ulong(0)
        ok = _advapi32.GetTokenInformation(
            token, 20, ctypes.byref(elevation), ctypes.sizeof(elevation),
            ctypes.byref(size))
        _kernel32.CloseHandle(token)
        return bool(ok) and bool(elevation.value)
    except Exception:
        pass
    try:
        return bool(ctypes.WinDLL("shell32").IsUserAnAdmin())
    except Exception:
        return False


def _run(cmd, timeout=30):
    """Run a console command, return (rc, combined output text)."""
    flags = 0x08000000  # CREATE_NO_WINDOW
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                              creationflags=flags, timeout=timeout)
    except FileNotFoundError:
        return 127, "not found: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "timeout: %s" % " ".join(cmd)
    raw = proc.stdout or b""
    if isinstance(raw, bytes):
        try:
            text = raw.decode("mbcs", "replace")
        except Exception:
            text = raw.decode("utf-8", "replace")
    else:
        text = raw
    return proc.returncode, text


def _which(exe):
    for base in (os.environ.get("SystemRoot", r"C:\Windows"),):
        cand = os.path.join(base, "System32", exe)
        if os.path.isfile(cand):
            return cand
    return exe


def _guid_of(raw):
    try:
        return struct.unpack_from("<I", raw, 0)[0]
    except Exception:
        return 0


def _u16(raw, off):
    """Decode a NUL terminated UTF-16LE string; never raises."""
    try:
        if off < 0 or off >= len(raw):
            return ""
        end = off
        limit = len(raw) - 1
        while end < limit:
            if raw[end] == 0 and raw[end + 1] == 0:
                break
            end += 2
        return raw[off:end].decode("utf-16-le", "replace")
    except Exception:
        return ""


def _u32(raw, off, default=0):
    try:
        return struct.unpack_from("<I", raw, off)[0]
    except Exception:
        return default


def _u64(raw, off, default=0):
    try:
        return struct.unpack_from("<Q", raw, off)[0]
    except Exception:
        return default


def _filetime_to_unix(ts):
    """ETW timestamps are FILETIME (100 ns ticks since 1601-01-01 UTC)."""
    try:
        return ts / 10000000.0 - 11644473600.0
    except Exception:
        return None


def _basename(path):
    if not path:
        return None
    return os.path.basename(path.rstrip("\\/")) or path


_REG_PREFIXES = (
    ("\\registry\\machine\\", "HKLM\\"),
    ("\\registry\\user\\", "HKU\\"),
    ("\\registry\\", ""),
)


def _friendly_reg(path):
    """Turn \\REGISTRY\\MACHINE\\X into HKLM\\X for readability."""
    if not path:
        return path
    low = path.lower()
    for prefix, repl in _REG_PREFIXES:
        if low.startswith(prefix):
            return repl + path[len(prefix):]
    return path


class _ProcCache(object):
    """PID -> process image name, resolved lazily with plain ctypes."""

    def __init__(self):
        self._cache = {}
        self._lock = threading.Lock()
        self._dos_map = None

    # -- process names ----------------------------------------------------
    def name(self, pid):
        if not pid or pid in (0, 4, 0xFFFFFFFF):
            return "System" if pid in (0, 4) else None
        with self._lock:
            if pid in self._cache:
                return self._cache[pid]
        value = None
        h = None
        try:
            _kernel32.OpenProcess.restype = wt.HANDLE
            h = _kernel32.OpenProcess(0x1000, False, pid)   # QUERY_LIMITED
            if h:
                buf = ctypes.create_unicode_buffer(1024)
                size = wt.DWORD(1024)
                if _kernel32.QueryFullProcessImageNameW(h, 0, buf,
                                                        ctypes.byref(size)):
                    value = _basename(buf.value)
        except Exception:
            value = None
        finally:
            if h:
                try:
                    _kernel32.CloseHandle(h)
                except Exception:
                    pass
        with self._lock:
            self._cache[pid] = value
        return value

    # -- NT device path -> DOS path --------------------------------------
    def _load_dos_map(self):
        mapping = {}
        try:
            for letter in string.ascii_uppercase:
                buf = ctypes.create_unicode_buffer(2048)
                if _kernel32.QueryDosDeviceW("%s:" % letter, buf, 2048):
                    mapping[buf.value.lower()] = "%s:" % letter
        except Exception:
            pass
        self._dos_map = sorted(mapping.items(), key=lambda kv: -len(kv[0]))
        return self._dos_map

    def dos_path(self, path):
        if not path:
            return path
        mapped = path
        low = path.lower()
        if low.startswith("\\??\\"):
            mapped = path[4:]
            low = mapped.lower()
        elif low.startswith("\\\\?\\"):
            mapped = path[4:]
            low = mapped.lower()
        if low.startswith("\\systemroot\\"):
            mapped = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                  path[len("\\systemroot\\"):])
            low = mapped.lower()
        if low.startswith("\\device\\") or low.startswith("\\dosdevices\\"):
            table = self._dos_map if self._dos_map is not None else self._load_dos_map()
            for dev, drive in table:
                if low.startswith(dev):
                    rest = mapped[len(dev):]
                    if rest.startswith("\\"):
                        return drive + rest
            return mapped
        return mapped


class _Decoder(object):
    """MOF payload decoders for FileIo / Registry / TcpIp (x64 layouts)."""

    # FileIo opcodes (verified by calibration runs)
    OP_CREATE = 64
    OP_CLEANUP = 65
    OP_CLOSE = 66
    OP_READ = 67
    OP_WRITE = 68
    OP_SETINFO = 69
    OP_DELETE = 70
    OP_RENAME = 71
    OP_QUERYINFO = 72
    OP_DIRENUM = 73
    OP_DIRNOTIFY = 74
    OP_OPEND = 76          # OperationEnd
    OP_DELETE_PATH = 79
    OP_RENAME_PATH = 80

    # Registry opcodes (verified)
    REG_CREATE_KEY = 10
    REG_OPEN_KEY = 11
    REG_DELETE_KEY = 12
    REG_QUERY_KEY = 13
    REG_SET_VALUE = 14
    REG_DELETE_VALUE = 15
    REG_QUERY_VALUE = 16
    REG_ENUM_KEY = 17
    REG_ENUM_VALUE = 18
    REG_SET_INFO = 19
    REG_FLUSH = 20
    REG_KCB = 22           # KCB rundown (carries full key path)
    REG_KCB2 = 23
    REG_CLOSE = 27

    # TcpIp opcodes (verified)
    NET_SEND = 10
    NET_RECV = 11
    NET_CONNECT = 12
    NET_DISCONNECT = 13
    NET_ACCEPT = 15

    def __init__(self, proc_cache, max_map=20000):
        self.proc = proc_cache
        self.max_map = max_map
        # FileObject -> path, filled by FileIo Create (and delete/rename paths)
        self.file_map = {}
        self._file_order = []
        # Registry KeyHandle -> key path, filled by create/open/KCB events
        self.reg_map = {}
        self._reg_order = []

    # -- small helpers ----------------------------------------------------
    def _remember(self, table, order, key, value):
        if not key:
            return
        if key not in table:
            order.append(key)
            if len(order) > self.max_map:
                old = order.pop(0)
                table.pop(old, None)
        table[key] = value

    def _forget(self, table, key):
        table.pop(key, None)

    # -- FileIo ----------------------------------------------------------
    def decode_file(self, opcode, raw, pid):
        """Return dict(cat, act, path, detail) or None."""
        length = len(raw)
        if opcode == self.OP_CREATE:
            # IrpPtr(8) FileObject(8) TTID(4) CreateOptions(4)
            # FileAttributes(4) ShareAccess(4) OpenPath(UTF-16, NUL)
            if length < 33:
                return None
            file_object = _u64(raw, 8)
            path = _u16(raw, 32)
            if path:
                self._remember(self.file_map, self._file_order, file_object, path)
            return {
                "act": "create",
                "path": path or self.file_map.get(file_object),
                "detail": {
                    "file_object": "0x%X" % file_object,
                    "create_options": "0x%X" % _u32(raw, 20),
                    "share_access": _u32(raw, 28),
                },
            }
        if opcode in (self.OP_READ, self.OP_WRITE):
            # Offset(8) IrpPtr(8) FileObject(8) FileKey(8) TTID(4) IOSize(4)
            # (+2 unknown dwords)
            if length < 40:
                return None
            file_object = _u64(raw, 16)
            return {
                "act": "read" if opcode == self.OP_READ else "write",
                "path": self.file_map.get(file_object),
                "detail": {
                    "offset": _u64(raw, 0),
                    "size": _u32(raw, 36),
                    "file_object": "0x%X" % file_object,
                },
            }
        if opcode in (self.OP_DELETE, self.OP_RENAME, self.OP_SETINFO,
                      self.OP_QUERYINFO, self.OP_DIRENUM, self.OP_DIRNOTIFY):
            # IrpPtr(8) FileObject(8) FileKey(8) ExtraInfo(8) TTID(4) InfoClass(4)
            # Delete/Rename are skipped here on purpose: the paired
            # DeletePath (79) / RenamePath (80) events carry the file name and
            # are emitted instead, so every delete/rename is reported once.
            if opcode not in (self.OP_SETINFO,):
                return None
            if length < 40:
                return None
            file_object = _u64(raw, 8)
            return {"act": "setinfo", "path": self.file_map.get(file_object),
                    "detail": {"file_object": "0x%X" % file_object,
                               "info_class": _u32(raw, 36)}}
        if opcode in (self.OP_DELETE_PATH, self.OP_RENAME_PATH):
            # IrpPtr(8) FileObject(8) FileKey(8) ExtraInfo(8) TTID(4)
            # InfoClass(4) FileName(UTF-16, NUL) at +40
            if length < 41:
                return None
            name = _u16(raw, 40)
            file_object = _u64(raw, 8)
            if opcode == self.OP_RENAME_PATH:
                old = self.file_map.get(file_object)
                if name:
                    self._remember(self.file_map, self._file_order, file_object, name)
                return {"act": "rename", "path": name or old,
                        "detail": {"old_path": old, "new_name": name,
                                   "file_object": "0x%X" % file_object}}
            old = self.file_map.get(file_object)
            self._forget(self.file_map, file_object)
            return {"act": "delete", "path": name or old,
                    "detail": {"file_object": "0x%X" % file_object,
                               "old_path": old,
                               "info_class": _u32(raw, 36)}}
        if opcode in (self.OP_CLEANUP, self.OP_CLOSE, self.OP_OPEND):
            # very noisy, and carries no payload worth recording
            return None
        return None

    # -- Registry --------------------------------------------------------
    def decode_reg(self, opcode, raw, pid):
        # Registry MOF layout (verified):
        #   TimeStamp(8) Status(4) pad(4) KeyHandle(8) [KeyName][ValueName]
        if len(raw) < 26:
            return None
        handle = _u64(raw, 16)
        first = _u16(raw, 24)
        if opcode in (self.REG_CREATE_KEY, self.REG_OPEN_KEY,
                      self.REG_KCB, self.REG_KCB2):
            if first:
                self._remember(self.reg_map, self._reg_order, handle, first)
            if opcode == self.REG_CREATE_KEY:
                return {"act": "reg_create_key", "path": first or self.reg_map.get(handle),
                        "detail": {"key_handle": "0x%X" % handle,
                                   "status": _u32(raw, 8)}}
            return None                      # open/KCB only feed the map
        if opcode == self.REG_SET_VALUE:
            return {"act": "reg_set_value", "path": self.reg_map.get(handle),
                    "detail": {"key_handle": "0x%X" % handle,
                               "value_name": first,
                               "status": _u32(raw, 8)}}
        if opcode == self.REG_DELETE_VALUE:
            return {"act": "reg_delete_value", "path": self.reg_map.get(handle),
                    "detail": {"key_handle": "0x%X" % handle,
                               "value_name": first,
                               "status": _u32(raw, 8)}}
        if opcode == self.REG_QUERY_VALUE:
            return {"act": "reg_query", "path": self.reg_map.get(handle),
                    "detail": {"key_handle": "0x%X" % handle,
                               "value_name": first,
                               "status": _u32(raw, 8)}}
        if opcode == self.REG_DELETE_KEY:
            path = self.reg_map.get(handle)
            self._forget(self.reg_map, handle)
            return {"act": "reg_delete_key", "path": path or first,
                    "detail": {"key_handle": "0x%X" % handle,
                               "status": _u32(raw, 8)}}
        if opcode in (self.REG_QUERY_KEY, self.REG_ENUM_KEY, self.REG_ENUM_VALUE):
            # these events carry a handle only; without a resolved key path the
            # event is useless for the recorder, so drop it.
            path = self.reg_map.get(handle)
            if not path:
                return None
            return {"act": "reg_query", "path": path,
                    "detail": {"key_handle": "0x%X" % handle,
                               "status": _u32(raw, 8)}}
        return None

    # -- TcpIp / UdpIp ---------------------------------------------------
    def decode_net(self, opcode, raw, pid, udp=False):
        # TcpIp/UdpIp MOF layout (verified):
        #   PID(4) size(4) daddr(4) saddr(4) dport(BE16) sport(BE16)
        #   Connect/Accept use a 44 byte variant with the same prefix.
        if len(raw) < 20:
            return None
        owner = _u32(raw, 0)
        size = _u32(raw, 4)
        daddr = _u32(raw, 8)
        saddr = _u32(raw, 12)
        dport = struct.unpack_from(">H", raw, 16)[0]
        sport = struct.unpack_from(">H", raw, 18)[0]
        detail = {
            "pid": owner,
            "size": size,
            # 内核 payload 里这两个 32 位值是**小端**存放的网络序地址（内存里就是
            # 7F 00 00 01 = 127.0.0.1），所以按低字节在前拼，别按 >>24 拼，否则
            # 127.0.0.1 会被写成 1.0.0.127。
            "remote_addr": "%d.%d.%d.%d" % (daddr & 0xFF, (daddr >> 8) & 0xFF,
                                            (daddr >> 16) & 0xFF, (daddr >> 24) & 0xFF),
            "local_addr": "%d.%d.%d.%d" % (saddr & 0xFF, (saddr >> 8) & 0xFF,
                                           (saddr >> 16) & 0xFF, (saddr >> 24) & 0xFF),
            "remote_port": dport,
            "local_port": sport,
            "protocol": "udp" if udp else "tcp",
        }
        prefix = "udp" if udp else "tcp"
        if opcode == self.NET_SEND:
            return {"act": prefix + "_send", "path": "%s:%d" % (detail["remote_addr"], dport),
                    "detail": detail, "pid": owner}
        if opcode == self.NET_RECV:
            return {"act": prefix + "_recv", "path": "%s:%d" % (detail["remote_addr"], dport),
                    "detail": detail, "pid": owner}
        if udp:
            return None
        if opcode == self.NET_CONNECT:
            return {"act": "connect", "path": "%s:%d" % (detail["remote_addr"], dport),
                    "detail": detail, "pid": owner}
        if opcode == self.NET_ACCEPT:
            return {"act": "accept", "path": "%s:%d" % (detail["remote_addr"], dport),
                    "detail": detail, "pid": owner}
        return None


# ---------------------------------------------------------------------------
# ETL/CSV fallback parser (used when the real-time consumer cannot attach)
# ---------------------------------------------------------------------------

_CSV_HEADER_ALIASES = {
    "name": ("event name", "eventname", "event", "provider"),
    "sub": ("type", "opcode", "task"),
    "pid": ("pid", "processid", "process id", "process_id", "process id (pid)"),
    "tid": ("tid", "threadid", "thread id", "thread_id"),
    "path": ("filename", "file name", "openpath", "open path", "path",
             "keyname", "key name", "valuename", "value name"),
    "size": ("iosize", "io size", "size", "bytes", "length"),
    "time": ("clock-time", "clock time", "timestamp", "time"),
}

_CSV_ACT_FILE = {
    "create": "create", "read": "read", "write": "write", "delete": "delete",
    "dletepath": "delete", "deletepath": "delete", "rename": "rename",
    "renamepath": "rename", "setinfo": "setinfo", "setinformation": "setinfo",
}
_CSV_ACT_REG = {
    "createkey": "reg_create_key", "setvalue": "reg_set_value",
    "setvaluekey": "reg_set_value", "deletevalue": "reg_delete_value",
    "deletevaluekey": "reg_delete_value", "deletekey": "reg_delete_key",
    "queryvalue": "reg_query", "queryvaluekey": "reg_query",
    "querykey": "reg_query", "query": "reg_query",
    "enumkey": "reg_query", "enumeratekey": "reg_query",
    "enumvaluekey": "reg_query", "enumeratevaluekey": "reg_query",
}
_CSV_ACT_NET = {
    "sendipv4": "tcp_send", "recvipv4": "tcp_recv", "send": "tcp_send",
    "receive": "tcp_recv", "connectipv4": "connect", "connect": "connect",
    "acceptipv4": "accept", "accept": "accept",
}
_CSV_ACT_UDP = {
    "sendipv4": "udp_send", "recvipv4": "udp_recv",
}


def _csv_class(catname):
    """tracerpt 'Event Name' is the MOF class, e.g. FileIo / Registry / TcpIp."""
    key = (catname or "").replace(" ", "").lower()
    if "fileio" in key or key in ("file", "msnt_fileio"):
        return "file"
    if "registry" in key or key.startswith("reg"):
        return "reg"
    if "udpip" in key or key.startswith("udp"):
        return "net-udp"
    if "tcpip" in key or key.startswith("tcp"):
        return "net-tcp"
    return None


def _read_text_rows(path):
    """Yield header + rows from a tracerpt CSV (UTF-8 BOM or UTF-16LE)."""
    with open(path, "rb") as fh:
        head = fh.read(4)
    encoding = "utf-16" if head[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
    import csv
    with open(path, "r", encoding=encoding, errors="replace", newline="") as fh:
        for row in csv.reader(fh):
            yield row


def _map_columns(header):
    """Map logical fields to every candidate column index.

    tracerpt writes a union of all columns and leaves the ones that do not
    apply to an event empty, so each field keeps an ordered candidate list
    (exact header match first, substring match afterwards).
    """
    lowered = [(col or "").strip().lower() for col in header]
    mapping = {}
    for field, aliases in _CSV_HEADER_ALIASES.items():
        exact = [idx for idx, col in enumerate(lowered) if col in aliases]
        fuzzy = [idx for idx, col in enumerate(lowered)
                 if any(alias and alias in col for alias in aliases)
                 and idx not in exact]
        candidates = exact + fuzzy
        if candidates:
            mapping[field] = candidates
    return mapping


def _csv_int(text):
    if text is None:
        return None
    text = str(text).strip()
    if not text or text.lower() in ("-", "n/a"):
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    except ValueError:
        return None


def parse_tracerpt_csv(csv_path, emit, logger=print, limit=200000):
    """Tolerant tracerpt CSV parser; yields nothing, calls emit(event dict).

    Column names differ between kernel MOF events and manifest providers, so
    every lookup is case-insensitive and falls back to substring matching.
    """
    rows = _read_text_rows(csv_path)
    try:
        header = next(rows)
    except StopIteration:
        return 0
    cols = _map_columns(header)
    if "name" not in cols:
        return 0
    emitted = 0
    for row in rows:
        if emitted >= limit:
            break
        if not row:
            continue

        def cell(field):
            for idx in cols.get(field, ()):
                if idx < len(row):
                    value = (row[idx] or "").strip()
                    if value:
                        return value
            return None

        name = cell("name") or cell("sub")
        if not name:
            continue
        sub = cell("sub") or ""
        key = (sub or name).replace(" ", "").replace("_", "").lower()
        cls = _csv_class(name)
        act = None
        if cls == "file":
            act = _CSV_ACT_FILE.get(key)
        elif cls == "reg":
            act = _CSV_ACT_REG.get(key)
        elif cls == "net-tcp":
            act = _CSV_ACT_NET.get(key)
        elif cls == "net-udp":
            act = _CSV_ACT_UDP.get(key)
        if act is None and cls is None:
            # Event Name empty: rely on the sub type alone.
            act = (_CSV_ACT_FILE.get(key) or _CSV_ACT_REG.get(key)
                   or _CSV_ACT_UDP.get(key) or _CSV_ACT_NET.get(key))
        if act is None:
            continue
        if cls in ("file", "reg", "net-tcp", "net-udp"):
            cat = "net" if cls.startswith("net") else cls
        elif act.startswith(("tcp_", "udp_")) or act in ("connect", "accept"):
            cat = "net"
        elif act.startswith("reg_"):
            cat = "reg"
        else:
            cat = "file"
        path = cell("path")
        pid = _csv_int(cell("pid"))
        size = _csv_int(cell("size"))
        detail = {"source": "etw", "via": "tracerpt-csv", "event": name}
        if size is not None:
            detail["size"] = size
        emit({"cat": cat, "act": act, "path": (path or "").strip() or None,
              "pid": pid if pid and pid != 0xFFFFFFFF else None,
              "detail": detail})
        emitted += 1
    return emitted


# ---------------------------------------------------------------------------
# The capture thread
# ---------------------------------------------------------------------------

_SENTINEL = object()


class EtwCapture(threading.Thread):
    """Kernel ETW capture (NT Kernel Logger) that feeds the TraceKit bus.

    Parameters
    ----------
    bus : object
        Anything exposing ``emit(**kwargs)``.
    out_dir : str
        Directory for the ETL / CSV artefacts (created when missing).
    keywords : sequence of str
        Subset of ``("file", "registry", "network")``.
    logger : callable
        Sink for human readable diagnostics (defaults to ``print``).
    pid_filter : iterable of int or None
        When given, only events from those PIDs are emitted.  Network events
        carry the owning PID inside the payload, so they are filtered with the
        same set.
    write_etl : bool
        Keep an ETL copy on disk (also the fallback source for tracerpt).
    etl_max_mb : int
        ``logman -max`` value; the session keeps running after the cap.
    max_queue : int
        Bounded queue between the ETW callback and the bus; overflow is counted.
    """

    def __init__(self, bus, out_dir, keywords=("file", "registry", "network"),
                 logger=print, pid_filter=None, write_etl=True, etl_max_mb=128,
                 buffer_kb=128, max_queue=40000):
        threading.Thread.__init__(self, name="TraceKitEtwCapture", daemon=True)
        self.bus = bus
        self.out_dir = os.path.abspath(out_dir)
        self.keywords = tuple(keywords or ("file", "registry", "network"))
        self.logger = logger or (lambda *a, **k: None)
        self.pid_filter = set(int(p) for p in pid_filter) if pid_filter else None
        self.write_etl = bool(write_etl)
        self.etl_max_mb = max(1, int(etl_max_mb))
        self.buffer_kb = max(16, int(buffer_kb))

        self._queue = queue.Queue(maxsize=max(256, int(max_queue)))
        self._stop = threading.Event()
        self._running = False
        self._handle = 0
        self._handles = None
        self._lo = None              # keeps EVENT_TRACE_LOGFILE buffer alive
        self._buf = None
        self._pump = None
        self._pt_rc = None
        self._callback = None
        self._decoder = _Decoder(_ProcCache())
        self._etl_path = None
        self._csv_path = None
        self._sidecar = os.path.join(self.out_dir, ".etk_session.json")
        self._cmdline = None

        self.counters = {"received": 0, "emitted": 0, "dropped": 0,
                         "decode_errors": 0, "emit_errors": 0, "skipped": 0}
        self.by_kind = {}
        self.first_events = []
        self.session_flags = self._flags()
        self.fallback_used = False
        self.trace_started_at = None
        self.trace_stopped_at = None
        self._lock = threading.Lock()

    # -- public API ------------------------------------------------------
    def start_capture(self):
        """Create the kernel session, attach the consumer and start pumping."""
        global _ACTIVE
        if self._running:
            return True
        if not _WINDOWS:
            raise EtwUnavailable("mod_etw requires Windows (ctypes Win32 API)")
        if not _is_admin():
            raise EtwUnavailable(
                "the kernel trace session needs an elevated (Administrator) token; "
                "start the recorder from an elevated shell")
        if not _which("logman.exe") or not os.path.isfile(_which("logman.exe")):
            raise EtwUnavailable("logman.exe not found under %SystemRoot%\\System32")

        with _LOCK:
            if _ACTIVE:
                raise EtwUnavailable("another EtwCapture instance is already running")
            _ACTIVE = True
        try:
            os.makedirs(self.out_dir, exist_ok=True)
            self.session_flags = self._flags()
            self._create_session()
            self._handle = self._open_realtime()
            self._running = True
            self.trace_started_at = time.time()
            self._pump = threading.Thread(target=self._process_trace,
                                          name="TraceKitEtwPump", daemon=True)
            self._pump.start()
            threading.Thread.start(self)          # our run() drains the queue
            return True
        except Exception:
            self._stop.set()
            self._shutdown_session()
            with _LOCK:
                _ACTIVE = False
            raise

    def stop_capture(self):
        """Stop the kernel session, flush the queue and optionally parse the ETL."""
        if not self._running:
            self._stop.set()
            return
        self._stop.set()
        self.trace_stopped_at = time.time()
        self._shutdown_session()
        if self._pump is not None:
            self._pump.join(timeout=6.0)
        self._close_trace()
        try:
            threading.Thread.join(self, timeout=8.0)
        except Exception:
            pass
        self._drain_queue(final=True)
        self._running = False
        with _LOCK:
            global _ACTIVE
            _ACTIVE = False
        # fallback: if no event made it through the real-time consumer, parse
        # the ETL we kept on disk with tracerpt.
        if self.counters["received"] == 0 and self._etl_path and \
                os.path.isfile(self._etl_path):
            try:
                self._parse_etl_fallback()
            except Exception as exc:                  # pragma: no cover
                self.logger("[etw] ETL fallback failed: %r" % (exc,))

    def summary(self):
        return {
            "received": self.counters["received"],
            "emitted": self.counters["emitted"],
            "dropped": self.counters["dropped"],
            "decode_errors": self.counters["decode_errors"],
            "emit_errors": self.counters["emit_errors"],
            "skipped": self.counters["skipped"],
            "by_kind": dict(sorted(self.by_kind.items())),
            "etl": self._etl_path,
            "csv": self._csv_path,
            "fallback": self.fallback_used,
            "flags": "0x%X" % self.session_flags,
            "command": self._cmdline,
            "started": self.trace_started_at,
            "stopped": self.trace_stopped_at,
        }

    # -- session management ---------------------------------------------
    def _flags(self):
        flags = 0
        for word in self.keywords:
            flags |= _KEYWORD_FLAGS.get(str(word).strip().lower(), 0)
        return flags or (_FLAG_FILE | _FLAG_REG | _FLAG_NET)

    def _unique_etl(self):
        stamp = time.strftime("%Y%m%d_%H%M%S")
        name = "%s_%s_%d.etl" % (_LOG_ETL_PREFIX, stamp, os.getpid())
        return os.path.join(self.out_dir, name)

    def _create_session(self):
        logman = _which("logman.exe")
        etl = self._unique_etl()
        cmd = [logman, "create", "trace", _SESSION_NAME,
               "-p", "Windows Kernel Trace", "0x%X" % self.session_flags,
               "-bs", str(self.buffer_kb), "-max", str(self.etl_max_mb)]
        if self.write_etl:
            cmd += ["-o", etl]
        cmd += ["-rt", "-ets"]
        self._cmdline = subprocess.list2cmdline(cmd)
        rc, out = _run(cmd)
        if rc == 0:
            self._etl_path = etl if self.write_etl else None
            self._write_sidecar()
            self.logger("[etw] trace started: %s" % self._cmdline)
            return
        lowered = out.lower()
        if "already exists" in lowered or "已存在" in out:
            if self._reclaim_session():
                rc, out = _run(cmd)
                if rc == 0:
                    self._etl_path = etl if self.write_etl else None
                    self._write_sidecar()
                    self.logger("[etw] reclaimed stale kernel session: %s"
                                % self._cmdline)
                    return
            raise EtwUnavailable(
                "the kernel trace session '%s' is already in use (WPR/xperf or a "
                "stale TraceKit run). Output: %s" % (_SESSION_NAME, out.strip()))
        raise EtwUnavailable("logman could not start the kernel session: %s"
                             % out.strip())

    def _write_sidecar(self):
        try:
            with open(self._sidecar, "w", encoding="utf-8") as fh:
                json.dump({"pid": os.getpid(), "etl": self._etl_path,
                           "flags": "0x%X" % self.session_flags}, fh)
        except Exception:
            pass

    def _reclaim_session(self):
        """Stop a session previously created by TraceKit in this out_dir."""
        try:
            with open(self._sidecar, "r", encoding="utf-8") as fh:
                state = json.load(fh)
        except Exception:
            return False
        etl = (state or {}).get("etl") or ""
        if not etl or not os.path.abspath(etl).lower().startswith(
                self.out_dir.lower()):
            return False
        return self._stop_session()

    def _open_realtime(self):
        try:
            _advapi32.OpenTraceW.restype = ctypes.c_ulonglong
            _advapi32.OpenTraceW.argtypes = [ctypes.c_void_p]
        except Exception as exc:
            raise EtwUnavailable("advapi32!OpenTraceW unavailable: %r" % (exc,))
        self._buf = ctypes.create_string_buffer(_LOGFILE_STRUCT_SIZE)
        self._lo = ctypes.create_unicode_buffer(_SESSION_NAME)
        struct.pack_into("<I", self._buf, 0, 0)                    # LogFileName
        struct.pack_into("<Q", self._buf, _LOGFILE_OFF_LOGGER_NAME,
                         ctypes.addressof(self._lo))
        struct.pack_into("<I", self._buf, _LOGFILE_OFF_MODE,
                         _PROCESS_TRACE_MODE_EVENT_RECORD | _EVENT_TRACE_REAL_TIME_MODE)
        self._callback = ctypes.WINFUNCTYPE(None, ctypes.c_void_p)(self._on_event)
        struct.pack_into("<Q", self._buf, _LOGFILE_OFF_EVENT_RECORD_CALLBACK,
                         ctypes.cast(self._callback, ctypes.c_void_p).value)
        self._retained_callback = self._callback
        handle = _advapi32.OpenTraceW(ctypes.addressof(self._buf))
        if not handle or handle == _INVALID_TRACE_HANDLE:
            err = ctypes.get_last_error()
            raise EtwUnavailable(
                "OpenTraceW failed on '%s' (Win32 error %d)" % (_SESSION_NAME, err))
        _advapi32.ProcessTrace.argtypes = [ctypes.POINTER(ctypes.c_ulonglong),
                                           wt.ULONG, ctypes.c_void_p, ctypes.c_void_p]
        _advapi32.ProcessTrace.restype = wt.ULONG
        self._handles = (ctypes.c_ulonglong * 1)(handle)
        return handle

    def _process_trace(self):
        try:
            self._pt_rc = _advapi32.ProcessTrace(self._handles, 1, None, None)
        except Exception as exc:                       # pragma: no cover
            self._pt_rc = -1
            self.logger("[etw] ProcessTrace error: %r" % (exc,))

    def _close_trace(self):
        if self._handle:
            try:
                _advapi32.CloseTrace(ctypes.c_ulonglong(self._handle))
            except Exception:
                pass
            self._handle = 0

    def _stop_session(self):
        stopped = False
        try:
            props = ctypes.create_string_buffer(4096)
            struct.pack_into("<I", props, 0, 4096)     # Wnode.BufferSize
            _advapi32.ControlTraceW.argtypes = [ctypes.c_ulonglong, wt.LPCWSTR,
                                                ctypes.c_void_p, wt.ULONG]
            _advapi32.ControlTraceW.restype = wt.ULONG
            rc = _advapi32.ControlTraceW(0, _SESSION_NAME,
                                         ctypes.addressof(props),
                                         _EVENT_TRACE_CONTROL_STOP)
            stopped = rc == 0
        except Exception:
            stopped = False
        rc, out = _run([_which("logman.exe"), "stop", _SESSION_NAME, "-ets"])
        if rc == 0:
            stopped = True
        if not stopped:
            # last resort, as required: wpr -cancel clears a stuck kernel session
            _run([_which("wpr.exe"), "-cancel"], timeout=20)
            rc, out = _run([_which("logman.exe"), "stop", _SESSION_NAME, "-ets"])
            stopped = rc == 0
        return stopped

    def _shutdown_session(self):
        try:
            if not self._stop_session():
                self.logger("[etw] warning: kernel session may still be running")
        except Exception as exc:                       # pragma: no cover
            self.logger("[etw] stop_session error: %r" % (exc,))
        try:
            if self._handle:
                _advapi32.CloseTrace(ctypes.c_ulonglong(self._handle))
                self._handle = 0
        except Exception:
            pass
        try:
            os.remove(self._sidecar)
        except Exception:
            pass

    # -- event path ------------------------------------------------------
    def _on_event(self, record_ptr):
        """ETW callback: decode and enqueue.  Must never raise."""
        try:
            header = ctypes.string_at(record_ptr, _REC_PREFIX)
            pid = struct.unpack_from("<I", header, _OFF_REC_PROCESS_ID)[0]
            tid = struct.unpack_from("<I", header, _OFF_REC_THREAD_ID)[0]
            ts = struct.unpack_from("<q", header, _OFF_REC_TIME)[0]
            provider = _guid_of(header[_OFF_REC_PROVIDER:_OFF_REC_PROVIDER + 4])
            opcode = header[_OFF_REC_OPCODE]
            user_len = struct.unpack_from("<H", header, _OFF_REC_USER_LEN)[0]
            if provider == _GUID_EVENTTRACE or not user_len:
                return None
            data_ptr = struct.unpack_from(
                "<Q", header, _OFF_REC_USER_DATA)[0]
            if not data_ptr:
                return None
            payload = ctypes.string_at(data_ptr, user_len)
            # route
            if provider == _GUID_FILEIO:
                cat = "file"
                if self.pid_filter is not None and pid not in self.pid_filter:
                    return None
                item = self._decoder.decode_file(opcode, payload, pid)
            elif provider == _GUID_REGISTRY:
                cat = "reg"
                if self.pid_filter is not None and pid not in self.pid_filter:
                    return None
                item = self._decoder.decode_reg(opcode, payload, pid)
            elif provider in (_GUID_TCPIP, _GUID_UDPIP):
                cat = "net"
                item = self._decoder.decode_net(opcode, payload, pid,
                                                udp=(provider == _GUID_UDPIP))
                if item is not None:
                    owner = item.get("pid")
                    if owner is not None:
                        pid = owner
                    if self.pid_filter is not None and pid not in self.pid_filter:
                        return None
                else:
                    return None
            else:
                return None
            if item is None:
                with self._lock:
                    self.counters["skipped"] += 1
                return None
            detail = item.get("detail") or {}
            detail.update({"source": "etw", "opcode": opcode,
                           "tid": tid, "provider": "0x%08X" % provider})
            for key in ("old_path", "new_name"):
                if detail.get(key):
                    detail[key] = self._decoder.proc.dos_path(detail[key])
            path = self._decoder.proc.dos_path(item.get("path"))
            if cat == "reg" and path:
                path = _friendly_reg(path)
            stamp = _filetime_to_unix(ts)
            if stamp is not None:
                detail["time"] = round(stamp, 6)
            event = {
                "cat": cat,
                "act": item["act"],
                "path": path,
                "pid": pid if pid not in (0xFFFFFFFF,) else None,
                "proc": self._decoder.proc.name(pid) if pid else None,
                "detail": detail,
            }
            with self._lock:
                self.counters["received"] += 1
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                with self._lock:
                    self.counters["dropped"] += 1
            except Exception:
                pass
        except Exception:
            with self._lock:
                self.counters["decode_errors"] += 1
        return None

    def run(self):
        """Drain thread: forwards queued events to the bus until stopped."""
        while True:
            try:
                item = self._queue.get(timeout=0.2)
            except queue.Empty:
                if self._stop.is_set():
                    break
                continue
            if item is _SENTINEL:
                break
            self._emit(item)
            if self._stop.is_set() and self._queue.empty():
                break
        self._drain_queue(final=True)

    def _drain_queue(self, final=False):
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                return
            if item is _SENTINEL:
                continue
            self._emit(item)

    def _emit(self, event):
        try:
            self.bus.emit(cat=event["cat"], act=event["act"], path=event["path"],
                          pid=event["pid"], proc=event["proc"],
                          detail=event["detail"])
            with self._lock:
                self.counters["emitted"] += 1
                key = "%s/%s" % (event["cat"], event["act"])
                self.by_kind[key] = self.by_kind.get(key, 0) + 1
                if len(self.first_events) < 400:
                    self.first_events.append(event)
        except Exception as exc:                        # pragma: no cover
            with self._lock:
                self.counters["emit_errors"] += 1
            if self.counters["emit_errors"] <= 3:
                self.logger("[etw] bus.emit failed: %r" % (exc,))

    # -- tracerpt fallback ----------------------------------------------
    def _parse_etl_fallback(self):
        tracerpt = _which("tracerpt.exe")
        if not os.path.isfile(tracerpt):
            self.logger("[etw] tracerpt.exe missing, no fallback parse")
            return
        stamp = time.strftime("%Y%m%d_%H%M%S")
        csv_path = os.path.join(self.out_dir,
                                "%s_%s_%d.csv" % (_LOG_ETL_PREFIX, stamp, os.getpid()))
        self.logger("[etw] real-time consumer saw no data, parsing ETL via tracerpt")
        rc, out = _run([tracerpt, self._etl_path, "-o", csv_path,
                        "-of", "CSV", "-y"], timeout=600)
        if rc != 0 or not os.path.isfile(csv_path):
            self.logger("[etw] tracerpt failed: %s" % out.strip()[:300])
            return
        self._csv_path = csv_path
        self.fallback_used = True

        def sink(event):
            event["detail"].setdefault("source", "etw")
            self._emit(event)

        count = parse_tracerpt_csv(csv_path, sink, logger=self.logger)
        self.logger("[etw] tracerpt fallback emitted %d events" % count)


# ---------------------------------------------------------------------------
# Self test
# ---------------------------------------------------------------------------

class _FakeBus(object):
    """Minimal stand-in used by --selftest when tracekit.bus cannot be imported."""

    def __init__(self):
        self.events = []
        self._lock = threading.Lock()

    def emit(self, **kw):
        with self._lock:
            self.events.append(kw)


def _activity(root):
    """Generate file / registry / TCP events for the self test."""
    import socket
    import winreg

    os.makedirs(root, exist_ok=True)
    pid = os.getpid()
    a = os.path.join(root, "selftest_%d_a.bin" % pid)
    b = os.path.join(root, "selftest_%d_b.txt" % pid)
    with open(a, "wb") as fh:
        fh.write(b"S" * 4097)
        fh.flush()
        os.fsync(fh.fileno())
    with open(a, "rb") as fh:
        fh.read(2048)
    os.replace(a, b)
    with open(a, "wb") as fh:
        fh.write(b"D" * 321)
    os.remove(a)

    key = r"Software\TraceKitEtwSelftest_%d" % pid
    handle = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key + r"\Sub")
    winreg.SetValueEx(handle, "Mark", 0, winreg.REG_SZ, "etw-self-test-value")
    winreg.QueryValueEx(handle, "Mark")
    winreg.CloseKey(handle)
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key + r"\Sub")
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    client = socket.create_connection(("127.0.0.1", port), timeout=3)
    client.sendall(b"ping" * 64)          # 256 bytes
    conn, _ = server.accept()
    conn.recv(4096)
    conn.sendall(b"pong" * 16)            # 64 bytes
    client.recv(4096)
    conn.close()
    client.close()
    server.close()

    udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server.bind(("127.0.0.1", 0))
    udp_port = udp_server.getsockname()[1]
    udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_client.sendto(b"u" * 77, ("127.0.0.1", udp_port))
    udp_server.recvfrom(2048)
    udp_client.close()
    udp_server.close()
    return {"file": b, "deleted": a, "reg": key, "tcp_port": port,
            "udp_port": udp_port}


def _selftest(argv=None):
    parser = argparse.ArgumentParser(prog="python -m tracekit.mod_etw --selftest")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--out", default=None,
                        help="output directory for ETL/CSV artefacts")
    parser.add_argument("--settle", type=float, default=1.6,
                        help="seconds to wait before stopping the capture")
    parser.add_argument("--all-pids", action="store_true",
                        help="do not restrict events to this process")
    args = parser.parse_args(argv)

    out_dir = args.out or os.path.join(
        os.environ.get("TEMP", os.getcwd()),
        "tracekit_etw_selftest_%s" % time.strftime("%Y%m%d_%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)

    bus = _FakeBus()
    try:
        from .core import NullBus                # type: ignore
        bus = NullBus()
    except Exception:
        try:
            from tracekit.core import NullBus    # type: ignore
            bus = NullBus()
        except Exception:
            bus = _FakeBus()

    print("[selftest] admin=%s out_dir=%s pid=%d" % (_is_admin(), out_dir, os.getpid()))
    pid_filter = None if args.all_pids else {os.getpid()}
    cap = EtwCapture(bus, out_dir, logger=lambda msg: print(msg), pid_filter=pid_filter)
    try:
        cap.start_capture()
    except EtwUnavailable as exc:
        print("[selftest] FAILED: %s" % exc)
        return 2
    print("[selftest] capture started, flags=%s" % cap.summary()["flags"])
    print("[selftest] command: %s" % cap.summary()["command"])
    try:
        time.sleep(0.4)
        info = _activity(out_dir)
        print("[selftest] activity done: %s" % json.dumps(info, default=str))
        time.sleep(max(0.2, args.settle))
    finally:
        cap.stop_capture()
    summary = cap.summary()
    print("[selftest] summary: %s" % json.dumps(
        {k: v for k, v in summary.items() if k != "command"}, default=str))
    events = getattr(bus, "events", None) or []
    print("[selftest] events captured: %d" % len(events))
    counts = {}
    for ev in events:
        key = "%s/%s" % (ev.get("cat"), ev.get("act"))
        counts[key] = counts.get(key, 0) + 1
    for key in sorted(counts):
        print("[selftest]   %-18s %d" % (key, counts[key]))
    print("[selftest] first 15 events:")
    for ev in events[:15]:
        print(json.dumps(ev, ensure_ascii=False, default=str))
    markers = ("selftest_", "TraceKitEtwSelftest", "127.0.0.1")
    highlights = [ev for ev in events
                  if any(m and m in (ev.get("path") or "") for m in markers)]
    if highlights:
        print("[selftest] activity highlights (%d):" % len(highlights))
        for ev in highlights[:12]:
            print(json.dumps(ev, ensure_ascii=False, default=str))
    ok = len(events) > 0
    print("[selftest] %s" % ("OK" if ok else "FAILED: no events captured"))
    return 0 if ok else 1


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--selftest" in argv:
        return _selftest(argv)
    print("usage: python -m tracekit.mod_etw --selftest [--out DIR] [--all-pids]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
