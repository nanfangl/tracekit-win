"""Minimal zero-dependency ctypes bindings for the Win32 APIs TraceKit needs.

Only the subset used by the recorder: process snapshots, directory change
notifications, low level hooks, window enumeration, TCP/UDP owner tables and
clipboard access.  Nothing here installs a driver or patches any binary.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
from ctypes import POINTER, byref, sizeof, wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
MAX_PATH = 260

# ---------------------------------------------------------------- access rights
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010

# ------------------------------------------------------------ snapshot helpers
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004

# ------------------------------------------------------- ReadDirectoryChangesW
FILE_LIST_DIRECTORY = 0x0001
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OVERLAPPED = 0x40000000
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
FILE_NOTIFY_CHANGE_CREATION = 0x00000040
FILE_NOTIFY_CHANGE_SECURITY = 0x00000100
FILE_NOTIFY_CHANGE_ALL = (
    FILE_NOTIFY_CHANGE_FILE_NAME
    | FILE_NOTIFY_CHANGE_DIR_NAME
    | FILE_NOTIFY_CHANGE_ATTRIBUTES
    | FILE_NOTIFY_CHANGE_SIZE
    | FILE_NOTIFY_CHANGE_LAST_WRITE
    | FILE_NOTIFY_CHANGE_CREATION
    | FILE_NOTIFY_CHANGE_SECURITY
)

FILE_ACTION_ADDED = 1
FILE_ACTION_REMOVED = 2
FILE_ACTION_MODIFIED = 3
FILE_ACTION_RENAMED_OLD_NAME = 4
FILE_ACTION_RENAMED_NEW_NAME = 5

# ------------------------------------------------------------------- win hooks
WH_KEYBOARD_LL = 13
WH_MOUSE_LL = 14
HC_ACTION = 0
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
WM_SYSKEYDOWN = 0x0104
WM_SYSKEYUP = 0x0105
WM_LBUTTONDOWN = 0x0201
WM_LBUTTONUP = 0x0202
WM_RBUTTONDOWN = 0x0204
WM_RBUTTONUP = 0x0205
WM_MBUTTONDOWN = 0x0207
WM_MBUTTONUP = 0x0208
WM_MOUSEWHEEL = 0x020A
WM_MOUSEHWHEEL = 0x020E

EVENT_MIN = 0x00000001
EVENT_MAX = 0x7FFFFFFF
EVENT_SYSTEM_FOREGROUND = 0x0003
EVENT_SYSTEM_DIALOGSTART = 0x0010
EVENT_OBJECT_CREATE = 0x8000
EVENT_OBJECT_DESTROY = 0x8001
EVENT_OBJECT_SHOW = 0x8002
EVENT_OBJECT_HIDE = 0x8003
EVENT_OBJECT_NAMECHANGE = 0x800C
WINEVENT_OUTOFCONTEXT = 0x0000
WINEVENT_SKIPOWNPROCESS = 0x0002

GW_OWNER = 4
GWL_STYLE = -16
WS_VISIBLE = 0x10000000

# ------------------------------------------------------------------ networking
AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1
MIB_TCP_STATE = {
    1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RCVD", 4: "FIN_WAIT1", 5: "FIN_WAIT2",
    6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK", 10: "LISTEN",
    11: "DELETING", 12: "CLOSED",
}

# ---------------------------------------------------------------- clipboard
CF_UNICODETEXT = 13
CF_TEXT = 1


# --------------------------------------------------------------------- structs
class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", wt.LONG),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * MAX_PATH),
    ]


class POINT(ctypes.Structure):
    _fields_ = [("x", wt.LONG), ("y", wt.LONG)]


class MSG(ctypes.Structure):
    _fields_ = [
        ("hwnd", wt.HWND),
        ("message", wt.UINT),
        ("wParam", wt.WPARAM),
        ("lParam", wt.LPARAM),
        ("time", wt.DWORD),
        ("pt", POINT),
    ]


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", wt.DWORD),
        ("scanCode", wt.DWORD),
        ("flags", wt.DWORD),
        ("time", wt.DWORD),
        ("dwExtraInfo", ctypes.c_void_p),
    ]


class MSLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("pt", POINT),
        ("mouseData", wt.DWORD),
        ("flags", wt.DWORD),
        ("time", wt.DWORD),
        ("dwExtraInfo", ctypes.c_void_p),
    ]


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", wt.DWORD),
        ("dwLocalAddr", wt.DWORD),
        ("dwLocalPort", wt.DWORD),
        ("dwRemoteAddr", wt.DWORD),
        ("dwRemotePort", wt.DWORD),
        ("dwOwningPid", wt.DWORD),
    ]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", wt.DWORD),
        ("dwLocalPort", wt.DWORD),
        ("dwOwningPid", wt.DWORD),
    ]


TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE),
        ("szModule", wt.WCHAR * 256),
        ("szExePath", wt.WCHAR * MAX_PATH),
    ]


def module_list(pid: int):
    """Loaded DLL/exe names inside another process (works for 32-bit targets)."""
    kernel32.Module32FirstW.argtypes = [wt.HANDLE, POINTER(MODULEENTRY32W)]
    kernel32.Module32NextW.argtypes = [wt.HANDLE, POINTER(MODULEENTRY32W)]
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == INVALID_HANDLE_VALUE or not snap:
        return []
    out = []
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = sizeof(MODULEENTRY32W)
        ok = kernel32.Module32FirstW(snap, byref(entry))
        while ok:
            out.append({"name": entry.szModule, "path": entry.szExePath,
                        "base": int(entry.modBaseAddr or 0), "size": int(entry.modBaseSize)})
            ok = kernel32.Module32NextW(snap, byref(entry))
    finally:
        kernel32.CloseHandle(snap)
    return out


# ------------------------------------------------------------------ prototypes
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.Process32FirstW.argtypes = [wt.HANDLE, POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.argtypes = [wt.HANDLE, POINTER(PROCESSENTRY32W)]
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]

kernel32.QueryFullProcessImageNameW.argtypes = [
    wt.HANDLE, wt.DWORD, wt.LPWSTR, POINTER(wt.DWORD)
]

kernel32.CreateFileW.restype = wt.HANDLE
kernel32.CreateFileW.argtypes = [
    wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE
]
kernel32.ReadDirectoryChangesW.restype = wt.BOOL
kernel32.ReadDirectoryChangesW.argtypes = [
    wt.HANDLE, ctypes.c_void_p, wt.DWORD, wt.BOOL, wt.DWORD,
    POINTER(wt.DWORD), ctypes.c_void_p, ctypes.c_void_p,
]

kernel32.GetCurrentProcessId.restype = wt.DWORD
kernel32.GetTickCount64.restype = ctypes.c_ulonglong
kernel32.GetModuleHandleW.restype = wt.HMODULE
kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]

user32.SetWindowsHookExW.restype = wt.HHOOK
user32.SetWindowsHookExW.argtypes = [ctypes.c_int, ctypes.c_void_p, wt.HINSTANCE, wt.DWORD]
user32.CallNextHookEx.restype = ctypes.c_ssize_t
user32.CallNextHookEx.argtypes = [wt.HHOOK, ctypes.c_int, wt.WPARAM, wt.LPARAM]
user32.UnhookWindowsHookEx.argtypes = [wt.HHOOK]
user32.GetMessageW.argtypes = [POINTER(MSG), wt.HWND, wt.UINT, wt.UINT]
user32.TranslateMessage.argtypes = [POINTER(MSG)]
user32.DispatchMessageW.argtypes = [POINTER(MSG)]
user32.GetForegroundWindow.restype = wt.HWND
user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
user32.GetWindowTextLengthW.argtypes = [wt.HWND]
user32.GetWindowThreadProcessId.argtypes = [wt.HWND, POINTER(wt.DWORD)]
user32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
user32.IsWindowVisible.argtypes = [wt.HWND]
user32.GetKeyboardLayout.argtypes = [wt.DWORD]
user32.GetKeyboardLayout.restype = wt.HKL
user32.GetKeyState.argtypes = [ctypes.c_int]
user32.GetKeyState.restype = ctypes.c_short
user32.ToUnicodeEx.argtypes = [
    wt.UINT, wt.UINT, ctypes.c_void_p, wt.LPWSTR, ctypes.c_int, wt.UINT, wt.HKL
]
user32.ToUnicodeEx.restype = ctypes.c_int
user32.GetKeyboardLayoutList.argtypes = [ctypes.c_int, POINTER(wt.HKL)]
user32.SetWinEventHook.restype = wt.HANDLE
user32.SetWinEventHook.argtypes = [
    wt.DWORD, wt.DWORD, wt.HMODULE, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.DWORD
]
user32.UnhookWinEvent.argtypes = [wt.HANDLE]
user32.OpenClipboard.argtypes = [wt.HWND]
user32.GetClipboardData.restype = wt.HANDLE
user32.GetClipboardData.argtypes = [wt.UINT]
user32.CloseClipboard.argtypes = []
user32.GetClipboardSequenceNumber.restype = wt.DWORD

iphlpapi.GetExtendedTcpTable.argtypes = [
    ctypes.c_void_p, POINTER(wt.DWORD), wt.BOOL, wt.ULONG, ctypes.c_int, wt.DWORD
]
iphlpapi.GetExtendedUdpTable.argtypes = [
    ctypes.c_void_p, POINTER(wt.DWORD), wt.BOOL, wt.ULONG, ctypes.c_int, wt.DWORD
]

ntdll.NtQueryInformationProcess.argtypes = [
    wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.ULONG, POINTER(wt.ULONG)
]

# registry change notification needs a manual-reset event and a real handle type
kernel32.CreateEventW.restype = wt.HANDLE
kernel32.CreateEventW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR]
kernel32.WaitForSingleObject.restype = wt.DWORD
kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
advapi32.RegNotifyChangeKeyValue.restype = wt.LONG
advapi32.RegNotifyChangeKeyValue.argtypes = [
    wt.HKEY, wt.BOOL, wt.DWORD, wt.HANDLE, wt.BOOL
]
advapi32.RegCloseKey.restype = wt.LONG
advapi32.RegCloseKey.argtypes = [wt.HKEY]


# ------------------------------------------------------------------- helpers
def iter_processes():
    """Yield (pid, ppid, exe_name) for every process visible to us."""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE or not snap:
        return
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snap, byref(entry))
        while ok:
            yield int(entry.th32ProcessID), int(entry.th32ParentProcessID), entry.szExeFile
            ok = kernel32.Process32NextW(snap, byref(entry))
    finally:
        kernel32.CloseHandle(snap)


def process_image_path(pid: int):
    """Full image path for pid, or None when the process is protected/gone."""
    access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
    h = kernel32.OpenProcess(access, False, pid)
    if not h:
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = wt.DWORD(32768)
        if kernel32.QueryFullProcessImageNameW(h, 0, buf, byref(size)):
            return buf.value
        return None
    finally:
        kernel32.CloseHandle(h)


class _PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("AffinityMask", ctypes.c_void_p),
        ("BasePriority", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
    ]


def _read_mem(hproc, address, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(
        hproc, ctypes.c_void_p(address), buf, ctypes.c_size_t(size), byref(read)
    )
    if not ok or read.value == 0:
        return None
    return buf.raw[: read.value]


kernel32.ReadProcessMemory.argtypes = [
    wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, POINTER(ctypes.c_size_t)
]


def _read_ustring(hproc, address, is64=True):
    """Read a UNICODE_STRING located at `address`."""
    hdr = _read_mem(hproc, address, 16 if is64 else 8)
    if not hdr or len(hdr) < (16 if is64 else 8):
        return None
    length = int.from_bytes(hdr[0:2], "little")
    if is64:
        ptr = int.from_bytes(hdr[8:16], "little")
    else:
        ptr = int.from_bytes(hdr[4:8], "little")
    if length <= 0 or length > 0x8000 or not ptr:
        return None
    raw = _read_mem(hproc, ptr, length)
    if not raw:
        return None
    try:
        return raw.decode("utf-16-le", "replace").rstrip("\x00")
    except Exception:
        return None


PROCESS_WOW64_INFORMATION = 26


def is_wow64(pid: int) -> bool | None:
    """True for a 32-bit process running on 64-bit Windows (EasyLanguage exes)."""
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        kernel32.IsWow64Process.argtypes = [wt.HANDLE, POINTER(wt.BOOL)]
        flag = wt.BOOL(False)
        if not kernel32.IsWow64Process(h, byref(flag)):
            return None
        return bool(flag.value)
    finally:
        kernel32.CloseHandle(h)


def process_cmdline(pid: int):
    """Best effort image path / command line / cwd via the PEB.

    Handles both native 64-bit targets and 32-bit (WOW64) targets, which is the
    normal case for EasyLanguage (易语言) programs.  For WOW64 the 64-bit PEB is
    almost empty, so the 32-bit PEB address is fetched through
    ProcessWow64Information and the x86 structure offsets are used.
    Returns dict or None.
    """
    h = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return None
    try:
        wow = is_wow64(pid)
        out = {}
        if wow:
            ret = wt.ULONG(0)
            peb32 = ctypes.c_void_p(0)
            status = ntdll.NtQueryInformationProcess(
                h, PROCESS_WOW64_INFORMATION, byref(peb32), sizeof(peb32), byref(ret)
            )
            if status != 0 or not peb32.value:
                return None
            raw = _read_mem(h, int(peb32.value) + 0x10, 4)
            if not raw:
                return None
            params = int.from_bytes(raw, "little")
            if not params:
                return None
            out["image"] = _read_ustring(h, params + 0x38, False)
            out["cmdline"] = _read_ustring(h, params + 0x40, False)
            out["cwd"] = _read_ustring(h, params + 0x24, False)
        else:
            pbi = _PROCESS_BASIC_INFORMATION()
            ret = wt.ULONG(0)
            status = ntdll.NtQueryInformationProcess(h, 0, byref(pbi), sizeof(pbi), byref(ret))
            if status != 0 or not pbi.PebBaseAddress:
                return None
            peb_addr = int(pbi.PebBaseAddress)
            raw = _read_mem(h, peb_addr + 0x20, 8)
            if not raw:
                return None
            params = int.from_bytes(raw, "little")
            if not params:
                return None
            out["image"] = _read_ustring(h, params + 0x60, True)
            out["cmdline"] = _read_ustring(h, params + 0x70, True)
            out["cwd"] = _read_ustring(h, params + 0x38, True)
        out = {k: v for k, v in out.items() if v}
        if wow:
            out["bits"] = 32
        else:
            out["bits"] = 64
        return out or None
    finally:
        kernel32.CloseHandle(h)


def window_title(hwnd) -> str:
    n = user32.GetWindowTextLengthW(hwnd) + 1
    buf = ctypes.create_unicode_buffer(max(n, 2))
    user32.GetWindowTextW(hwnd, buf, len(buf))
    return buf.value


def window_class(hwnd) -> str:
    buf = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, buf, 256)
    return buf.value


def window_pid(hwnd) -> int:
    pid = wt.DWORD(0)
    user32.GetWindowThreadProcessId(hwnd, byref(pid))
    return int(pid.value)


def foreground_info():
    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return None
    return {
        "hwnd": int(hwnd),
        "title": window_title(hwnd),
        "class": window_class(hwnd),
        "pid": window_pid(hwnd),
    }


def enum_windows():
    """Yield (hwnd, title, class, pid) for visible top level windows."""
    result = []
    CB = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    def _cb(hwnd, lparam):
        if user32.IsWindowVisible(hwnd):
            title = window_title(hwnd)
            if title:
                result.append(
                    (int(hwnd), title, window_class(hwnd), window_pid(hwnd))
                )
        return True

    cb = CB(_cb)
    user32.EnumWindows(ctypes.cast(cb, ctypes.c_void_p), 0)
    return result


user32.EnumWindows.argtypes = [ctypes.c_void_p, wt.LPARAM]


def clipboard_text():
    if not user32.OpenClipboard(None):
        return None
    try:
        handle = user32.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            return None
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalLock.argtypes = [wt.HANDLE]
        kernel32.GlobalUnlock.argtypes = [wt.HANDLE]
        ptr = kernel32.GlobalLock(handle)
        if not ptr:
            return None
        try:
            return ctypes.wstring_at(ptr)
        finally:
            kernel32.GlobalUnlock(handle)
    finally:
        user32.CloseClipboard()


def _port(raw: int) -> int:
    return ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF)


def _ip(raw: int) -> str:
    return ".".join(str((raw >> s) & 0xFF) for s in (0, 8, 16, 24))


def tcp_table():
    """[(proto, laddr, lport, raddr, rport, state, pid)] for IPv4 TCP."""
    size = wt.DWORD(0)
    iphlpapi.GetExtendedTcpTable(None, byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if size.value == 0:
        return []
    buf = ctypes.create_string_buffer(size.value)
    rc = iphlpapi.GetExtendedTcpTable(
        buf, byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0
    )
    if rc != 0:
        return []
    n = wt.DWORD.from_buffer(buf, 0).value
    off = sizeof(wt.DWORD)
    row_size = sizeof(MIB_TCPROW_OWNER_PID)
    out = []
    for i in range(n):
        row = MIB_TCPROW_OWNER_PID.from_buffer_copy(buf.raw[off + i * row_size: off + (i + 1) * row_size])
        out.append(
            (
                "tcp",
                _ip(row.dwLocalAddr),
                _port(row.dwLocalPort),
                _ip(row.dwRemoteAddr),
                _port(row.dwRemotePort),
                MIB_TCP_STATE.get(row.dwState, str(row.dwState)),
                int(row.dwOwningPid),
            )
        )
    return out


def udp_table():
    size = wt.DWORD(0)
    iphlpapi.GetExtendedUdpTable(None, byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0)
    if size.value == 0:
        return []
    buf = ctypes.create_string_buffer(size.value)
    rc = iphlpapi.GetExtendedUdpTable(buf, byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0)
    if rc != 0:
        return []
    n = wt.DWORD.from_buffer(buf, 0).value
    off = sizeof(wt.DWORD)
    row_size = sizeof(MIB_UDPROW_OWNER_PID)
    out = []
    for i in range(n):
        row = MIB_UDPROW_OWNER_PID.from_buffer_copy(buf.raw[off + i * row_size: off + (i + 1) * row_size])
        out.append(("udp", _ip(row.dwLocalAddr), _port(row.dwLocalPort), "", 0, "UDP", int(row.dwOwningPid)))
    return out


def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


# ------------------------------------------------------- window text / controls
# EasyLanguage (易语言) GUI apps put their own log output inside standard Win32
# controls (Edit / ListBox / Static / SysListView32).  WM_GETTEXT is marshalled
# by the OS, so we can read another process's control text without injecting.

class RECT(ctypes.Structure):
    _fields_ = [("left", wt.LONG), ("top", wt.LONG), ("right", wt.LONG), ("bottom", wt.LONG)]


WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E
SMTO_ABORTIFHUNG = 0x0002

user32.SendMessageTimeoutW.restype = wt.LPARAM
user32.SendMessageTimeoutW.argtypes = [
    wt.HWND, wt.UINT, wt.WPARAM, ctypes.c_void_p, wt.UINT, wt.UINT,
    POINTER(ctypes.c_size_t)
]
user32.GetWindowRect.argtypes = [wt.HWND, POINTER(RECT)]
user32.GetParent.restype = wt.HWND
user32.GetParent.argtypes = [wt.HWND]
user32.IsWindow.argtypes = [wt.HWND]
user32.EnumChildWindows.argtypes = [wt.HWND, ctypes.c_void_p, wt.LPARAM]


def control_text(hwnd, limit: int = 65536, timeout: int = 200):
    """Text of a control in any process ("" on failure / non-text control)."""
    buf = ctypes.create_unicode_buffer(limit)
    res = ctypes.c_size_t(0)
    ok = user32.SendMessageTimeoutW(
        hwnd, WM_GETTEXT, limit - 1, ctypes.cast(buf, ctypes.c_void_p),
        SMTO_ABORTIFHUNG, timeout, byref(res),
    )
    if not ok:
        return None
    return buf.value


def window_rect(hwnd):
    rect = RECT()
    if not user32.GetWindowRect(hwnd, byref(rect)):
        return None
    return {
        "left": rect.left, "top": rect.top,
        "width": rect.right - rect.left, "height": rect.bottom - rect.top,
    }


def enum_children(hwnd):
    """All descendant controls of hwnd as [(hwnd, class, text, rect)]."""
    out = []
    box = []
    CB = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    def _cb(child, _l):
        if len(box) < 500:
            box.append(int(child))
        return True

    cb = CB(_cb)
    user32.EnumChildWindows(hwnd, ctypes.cast(cb, ctypes.c_void_p), 0)
    seen = set()
    for child in box:
        if child in seen:
            continue
        seen.add(child)
        out.append((child, window_class(child), control_text(child), window_rect(child)))
    return out


# ------------------------------------------------- control identity and state
# Everything below lets the recorder answer "the user pressed *this* control and
# *that* is how the program answered" - without a single byte inside the target.

user32.WindowFromPoint.restype = wt.HWND
user32.WindowFromPoint.argtypes = [POINT]
user32.GetDlgCtrlID.argtypes = [wt.HWND]
user32.GetDlgCtrlID.restype = ctypes.c_int
user32.GetAncestor.restype = wt.HWND
user32.GetAncestor.argtypes = [wt.HWND, wt.UINT]
user32.IsWindowEnabled.argtypes = [wt.HWND]
user32.GetCursorPos.argtypes = [POINTER(POINT)]
user32.GetMenu.restype = wt.HANDLE
user32.GetMenu.argtypes = [wt.HWND]
user32.MenuItemFromPoint.restype = ctypes.c_int
user32.MenuItemFromPoint.argtypes = [wt.HWND, wt.HANDLE, POINT]
user32.GetMenuStringW.argtypes = [wt.HANDLE, wt.UINT, wt.LPWSTR, ctypes.c_int, wt.UINT]

GA_ROOT = 2
BM_GETCHECK = 0x00F0
BM_GETSTATE = 0x00F2
CB_GETCURSEL = 0x0147
CB_GETCOUNT = 0x0146
LB_GETCURSEL = 0x0188
LB_GETCOUNT = 0x018B
EM_GETSEL = 0x00B0
MF_BYPOSITION = 0x400

CHECK_STATES = {0: "unchecked", 1: "checked", 2: "indeterminate"}


def _msg(hwnd, msg, wparam=0, lparam=0, timeout=150):
    """SendMessageTimeout wrapper: never hangs on a busy target."""
    res = ctypes.c_size_t(0)
    ok = user32.SendMessageTimeoutW(
        hwnd, msg, wparam, ctypes.c_void_p(lparam), SMTO_ABORTIFHUNG, timeout, byref(res)
    )
    if not ok:
        return None
    return res.value


def window_at(x: int, y: int):
    """HWND under a screen point (deepest child), or None."""
    point = POINT(int(x), int(y))
    hwnd = user32.WindowFromPoint(point)
    if not hwnd:
        return None
    # WindowFromPoint already returns the deepest child; climb up if it is a
    # status bar / tooltip like leaf so the caller still sees the real control.
    return int(hwnd)


def root_window(hwnd) -> int:
    root = user32.GetAncestor(hwnd, GA_ROOT)
    return int(root) if root else int(hwnd)


def control_info(hwnd, with_text: bool = True) -> dict | None:
    """Identity of a control: class, caption, id, parent chain, owner window.

    `with_text=False` skips WM_GETTEXT so the call stays cheap (no message sent
    into the target); use it on hot paths such as the mouse hook.
    """
    if not hwnd or not user32.IsWindow(hwnd):
        return None
    cls = window_class(hwnd)
    top = root_window(hwnd)
    info = {
        "hwnd": int(hwnd),
        "class": cls,
        "text": ((control_text(hwnd, 512) or "")[:200] if with_text else ""),
        "ctrl_id": int(user32.GetDlgCtrlID(hwnd)),
        "enabled": bool(user32.IsWindowEnabled(hwnd)),
        "rect": window_rect(hwnd),
        "top_hwnd": top,
        "top_title": window_title(top),
        "top_class": window_class(top),
        "top_pid": window_pid(top),
        "is_top": int(hwnd) == top,
    }
    return info


def control_state(hwnd, cls: str | None = None):
    """Small, comparable state token for a control (None when not applicable)."""
    cls = (cls if cls is not None else window_class(hwnd) or "").lower()
    try:
        if cls == "button":
            check = _msg(hwnd, BM_GETCHECK)
            text = (control_text(hwnd, 256) or "")[:80]
            return {"check": CHECK_STATES.get(check, check), "text": text}
        if cls == "combobox":
            sel = _msg(hwnd, CB_GETCURSEL)
            count = _msg(hwnd, CB_GETCOUNT)
            return {"sel": sel, "count": count,
                    "text": (control_text(hwnd, 256) or "")[:80]}
        if cls == "listbox":
            sel = _msg(hwnd, LB_GETCURSEL)
            count = _msg(hwnd, LB_GETCOUNT)
            return {"sel": sel, "count": count}
        if cls in ("edit", "richedit", "richedit20a", "richedit20w", "richedit50w"):
            text = control_text(hwnd, 4096) or ""
            return {"len": len(text), "tail": text[-120:]}
        if cls in ("static", "syslistview32", "systreeview32"):
            text = control_text(hwnd, 512) or ""
            return {"text": text[:120], "len": len(text)}
    except Exception:
        return None
    return None


def menu_item_at(hwnd_root, x: int, y: int) -> str | None:
    try:
        menu = user32.GetMenu(hwnd_root)
        if not menu:
            return None
        index = user32.MenuItemFromPoint(hwnd_root, menu, POINT(int(x), int(y)))
        if index is None or index < 0:
            return None
        buf = ctypes.create_unicode_buffer(256)
        n = user32.GetMenuStringW(menu, index, buf, 256, MF_BYPOSITION)
        if n <= 0:
            return None
        return buf.value.replace("&", "")
    except Exception:
        return None

# --------------------------------------------------------------- focus lookup
class GUITHREADINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.DWORD), ("flags", wt.DWORD),
        ("hwndActive", wt.HWND), ("hwndFocus", wt.HWND),
        ("hwndCapture", wt.HWND), ("hwndMenuOwner", wt.HWND),
        ("hwndMoveSize", wt.HWND), ("hwndCaret", wt.HWND),
        ("rcCaret", RECT),
    ]


user32.GetGUIThreadInfo.restype = wt.BOOL
user32.GetGUIThreadInfo.argtypes = [wt.DWORD, POINTER(GUITHREADINFO)]


def focused_control():
    """HWND of the control that currently has keyboard focus in the foreground window."""
    try:
        fg = user32.GetForegroundWindow()
        if not fg:
            return None
        tid = user32.GetWindowThreadProcessId(fg, None)
        gti = GUITHREADINFO()
        gti.cbSize = sizeof(GUITHREADINFO)
        if not user32.GetGUIThreadInfo(tid, byref(gti)):
            return None
        return int(gti.hwndFocus or 0) or None
    except Exception:
        return None


# -------------------------------------------------------------- synthetic click
user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
user32.mouse_event.argtypes = [wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, ctypes.c_size_t]

MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP = 0x0010


def click_at(x: int, y: int, right: bool = False, settle: float = 0.25) -> None:
    """Move the cursor and synthesize a real click (for self tests)."""
    import time as _t
    user32.SetCursorPos(int(x), int(y))
    _t.sleep(0.12)
    down = MOUSEEVENTF_RIGHTDOWN if right else MOUSEEVENTF_LEFTDOWN
    up = MOUSEEVENTF_RIGHTUP if right else MOUSEEVENTF_LEFTUP
    user32.mouse_event(down, 0, 0, 0, 0)
    _t.sleep(0.05)
    user32.mouse_event(up, 0, 0, 0, 0)
    _t.sleep(settle)


def find_window(cls: str | None = None, title_contains: str | None = None):
    for hwnd, title, c, pid in enum_windows():
        if cls and c.lower() != cls.lower():
            continue
        if title_contains and title_contains.lower() not in (title or "").lower():
            continue
        return hwnd, title, c, pid
    return None

user32.SetForegroundWindow.restype = wt.BOOL
user32.SetForegroundWindow.argtypes = [wt.HWND]
user32.BringWindowToTop.restype = wt.BOOL
user32.BringWindowToTop.argtypes = [wt.HWND]
user32.SetActiveWindow.restype = wt.HWND
user32.SetActiveWindow.argtypes = [wt.HWND]
user32.SetFocus.argtypes = [wt.HWND]
user32.ShowWindow.argtypes = [wt.HWND, ctypes.c_int]


def activate(hwnd) -> bool:
    """Bring a window to the foreground so a synthetic click lands on it."""
    try:
        user32.ShowWindow(hwnd, 9)          # SW_RESTORE
        user32.BringWindowToTop(hwnd)
        ok = bool(user32.SetForegroundWindow(hwnd))
        user32.SetActiveWindow(hwnd)
        return ok
    except Exception:
        return False

HWND_TOPMOST = -1
HWND_NOTOPMOST = -2
SWP_NOMOVE = 0x0002
SWP_NOSIZE = 0x0001
SWP_SHOWWINDOW = 0x0040

user32.SetWindowPos.restype = wt.BOOL
user32.SetWindowPos.argtypes = [wt.HWND, wt.HWND, ctypes.c_int, ctypes.c_int,
                                ctypes.c_int, ctypes.c_int, ctypes.c_uint]


def set_topmost(hwnd, on: bool = True) -> None:
    """Float the window for a test click, then put it back."""
    try:
        user32.SetWindowPos(hwnd, wt.HWND(HWND_TOPMOST if on else HWND_NOTOPMOST),
                            0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW)
    except Exception:
        pass

# ------------------------------------------------------------- menu bar walking
user32.GetMenuItemCount.restype = ctypes.c_int
user32.GetMenuItemCount.argtypes = [wt.HANDLE]
user32.GetMenuItemID.restype = ctypes.c_uint
user32.GetMenuItemID.argtypes = [wt.HANDLE, ctypes.c_int]
user32.GetSubMenu.restype = wt.HANDLE
user32.GetSubMenu.argtypes = [wt.HANDLE, ctypes.c_int]
user32.GetMenuState.restype = wt.UINT
user32.GetMenuState.argtypes = [wt.HANDLE, wt.UINT, wt.UINT]


def menu_item_text(menu, index: int) -> str:
    """Caption of the menu item at a position (works for another process's menu)."""
    try:
        buf = ctypes.create_unicode_buffer(512)
        n = user32.GetMenuStringW(menu, index, buf, 512, MF_BYPOSITION)
        if n <= 0:
            return ""
        return buf.value.replace("&", "").replace("\t", " ").strip()
    except Exception:
        return ""


# ------------------------------------------------------- clipboard, all formats
CF_BITMAP = 2
CF_DIB = 8
CF_DIBV5 = 17
CF_HDROP = 15
CF_HTML_NAME = "HTML Format"

shell32.DragQueryFileW.restype = wt.UINT
shell32.DragQueryFileW.argtypes = [wt.HANDLE, wt.UINT, wt.LPWSTR, wt.UINT]
user32.EnumClipboardFormats.restype = wt.UINT
user32.EnumClipboardFormats.argtypes = [wt.UINT]
user32.GetClipboardFormatNameW.argtypes = [wt.UINT, wt.LPWSTR, ctypes.c_int]
user32.RegisterClipboardFormatW.restype = wt.UINT
user32.RegisterClipboardFormatW.argtypes = [wt.LPCWSTR]
kernel32.GlobalSize.restype = ctypes.c_size_t
kernel32.GlobalSize.argtypes = [wt.HANDLE]


def clipboard_formats() -> list[dict]:
    """Every format currently on the clipboard, with its registered name."""
    out = []
    if not user32.OpenClipboard(None):
        return out
    try:
        fmt = 0
        while True:
            fmt = int(user32.EnumClipboardFormats(fmt))
            if fmt == 0:
                break
            buf = ctypes.create_unicode_buffer(256)
            n = user32.GetClipboardFormatNameW(fmt, buf, 256)
            name = buf.value if n > 0 else f"CF_{fmt}"
            out.append({"id": fmt, "name": name})
    finally:
        user32.CloseClipboard()
    return out


def _global_bytes(handle):
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [wt.HANDLE]
    kernel32.GlobalUnlock.argtypes = [wt.HANDLE]
    size = int(kernel32.GlobalSize(handle) or 0)
    if not size:
        return b""
    ptr = kernel32.GlobalLock(handle)
    if not ptr:
        return b""
    try:
        return ctypes.string_at(ptr, size)
    finally:
        kernel32.GlobalUnlock(handle)


def clipboard_dropfiles() -> list[str]:
    """Files copied in Explorer (CF_HDROP) as a list of paths."""
    if not user32.OpenClipboard(None):
        return []
    try:
        handle = user32.GetClipboardData(CF_HDROP)
        if not handle:
            return []
        count = int(shell32.DragQueryFileW(handle, 0xFFFFFFFF, None, 0))
        out = []
        for i in range(min(count, 200)):
            buf = ctypes.create_unicode_buffer(1024)
            if shell32.DragQueryFileW(handle, i, buf, 1024):
                out.append(buf.value)
        return out
    finally:
        user32.CloseClipboard()


def clipboard_dib() -> bytes | None:
    """Raw CF_DIB payload (BITMAPINFOHEADER + pixels), ready to wrap in a .bmp."""
    if not user32.OpenClipboard(None):
        return None
    try:
        for fmt in (CF_DIBV5, CF_DIB):
            handle = user32.GetClipboardData(fmt)
            if handle:
                data = _global_bytes(handle)
                return data or None
        return None
    finally:
        user32.CloseClipboard()


def dib_to_bmp(dib: bytes) -> bytes:
    """Wrap a DIB in a minimal BMP file header so any viewer can open it."""
    if len(dib) < 40:
        return dib
    header_size = int.from_bytes(dib[0:4], "little")
    bit_count = int.from_bytes(dib[14:16], "little")
    compression = int.from_bytes(dib[16:20], "little")
    palette = 0
    if bit_count <= 8:
        clr_used = int.from_bytes(dib[32:36], "little")
        palette = (clr_used or (1 << bit_count)) * 4
    offset = 14 + header_size + palette
    file_size = 14 + len(dib)
    file_header = b"BM" + file_size.to_bytes(4, "little") + b"\x00\x00\x00\x00" \
        + offset.to_bytes(4, "little")
    return file_header + dib


def clipboard_html() -> str | None:
    """HTML fragment copied from a browser (CF_HTML), start/end offsets honoured."""
    try:
        fmt = int(user32.RegisterClipboardFormatW(CF_HTML_NAME))
    except Exception:
        return None
    if not fmt or not user32.OpenClipboard(None):
        return None
    try:
        handle = user32.GetClipboardData(fmt)
        if not handle:
            return None
        raw = _global_bytes(handle)
    finally:
        user32.CloseClipboard()
    text = raw.decode("utf-8", "replace")
    try:
        head_end = int(text.split("StartHTML:", 1)[1].split("\r\n")[0]) if "StartHTML:" in text else -1
        frag_start = int(text.split("StartFragment:", 1)[1].split("\r\n")[0])
        frag_end = int(text.split("EndFragment:", 1)[1].split("\r\n")[0])
        return text[frag_start:frag_end]
    except Exception:
        return text[:4000]
