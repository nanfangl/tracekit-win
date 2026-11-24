"""Static triage of the target executable - runs before recording starts.

Answers the questions that decide the recording strategy:

  * 32-bit (EasyLanguage / 易语言) or 64-bit?
  * is it packed, and does it look like VMProtect?  (section names, entropy,
    entry point location, import table size)
  * does it carry EasyLanguage markers (krnln / eAPI / 易语言 in GBK / WTWindow)?
  * what does it import?  (a virtualised binary shows a handful of imports)

Nothing is executed and nothing is modified: this only reads the PE headers,
the section table, the import directory and greps raw bytes.
"""
from __future__ import annotations

import math
import os
import struct

EASY_MARKERS = {
    "krnln": b"krnln",
    "eAPI": b"eAPI",
    "easy_lang_gbk": bytes([0xD2, 0xD7, 0xD3, 0xEF, 0xD1, 0xD4]),  # 易语言
    "WTWindow": b"WTWindow",
    "WindowsUI": b"WindowsUI",
    "e_package": b"Epkg",
    "fnr_support": b".fnr",
    "fne_support": b".fne",
}
PACKER_MARKERS = {
    "VMProtect": b"VMProtect",
    "vmp_section": b".vmp",
    "UPX": b"UPX0",
    "Themida": b"Themida",
    "ASPack": b"ASPack",
}


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def _rva_to_off(rva: int, sections) -> int:
    for s in sections:
        start = s["va"]
        if start <= rva < start + max(s["vsize"], s["rawsize"]):
            return s["raw_ptr"] + (rva - start)
    return -1


def _cstr(data: bytes, off: int, limit: int = 256) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, min(len(data), off + limit))
    if end < 0:
        end = min(len(data), off + limit)
    raw = data[off:end]
    text = "".join(chr(b) for b in raw if 0x20 <= b <= 0x7E)
    return text if text == raw.decode("ascii", "ignore") else text


def analyze(path: str) -> dict:
    info: dict = {"path": os.path.abspath(path) if path else None,
                  "exists": bool(path and os.path.exists(path))}
    if not info["exists"]:
        info["error"] = "file not found"
        return info
    size = os.path.getsize(path)
    info["size"] = size
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:2] != b"MZ":
        info["error"] = "not a PE file (no MZ header)"
        return info
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew: e_lfanew + 4] != b"PE\x00\x00":
        info["error"] = "not a PE file (no PE signature)"
        return info
    coff = e_lfanew + 4
    machine, nsec, timestamp, _symptr, _nsym, optsize, characteristics = struct.unpack_from(
        "<HHIIIHH", data, coff
    )
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = magic == 0x20B
    info.update(
        {
            "machine": {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64"}.get(
                machine, hex(machine)
            ),
            "bits": 64 if is64 else 32,
            "is_dll": bool(characteristics & 0x2000),
            "timestamp": timestamp,
            "sections_count": nsec,
            "subsystem": struct.unpack_from("<H", data, opt + (68 if is64 else 68))[0],
            "entry_point_rva": struct.unpack_from("<I", data, opt + 16)[0],
            "image_base": struct.unpack_from("<Q" if is64 else "<I", data, opt + (24 if is64 else 28))[0],
        }
    )
    # data directories
    dir_off = opt + (112 if is64 else 96)
    dirs = []
    for i in range(16):
        rva, sz = struct.unpack_from("<II", data, dir_off + i * 8)
        dirs.append((rva, sz))
    info["import_dir"] = {"rva": dirs[1][0], "size": dirs[1][1]}
    info["resource_dir"] = {"rva": dirs[2][0], "size": dirs[2][1]}

    # sections
    sec_off = opt + optsize
    sections = []
    for i in range(nsec):
        base = sec_off + i * 40
        name = data[base: base + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
        chars = struct.unpack_from("<I", data, base + 36)[0]
        raw = data[rawptr: rawptr + rawsize] if rawptr and rawsize else b""
        sections.append(
            {
                "name": name, "vsize": vsize, "va": va, "rawsize": rawsize,
                "raw_ptr": rawptr, "chars": hex(chars),
                "entropy": shannon(raw), "writable": bool(chars & 0x80000000),
                "executable": bool(chars & 0x20000000),
                "code": bool(chars & 0x20),
            }
        )
    info["sections"] = sections

    # imports
    imports: dict[str, list[str]] = {}
    imp_rva = dirs[1][0]
    imp_off = _rva_to_off(imp_rva, sections)
    if imp_off > 0:
        thunk_size = 8 if is64 else 4
        for i in range(64):
            base = imp_off + i * 20
            if base + 20 > len(data):
                break
            oft, _ts, _fwd, name_rva, ft = struct.unpack_from("<IIIII", data, base)
            if name_rva == 0:
                break
            dll = _cstr(data, _rva_to_off(name_rva, sections)).lower()
            funcs = []
            thunk_rva = oft or ft
            toff = _rva_to_off(thunk_rva, sections)
            if toff > 0:
                for j in range(512):
                    pos = toff + j * thunk_size
                    if pos + thunk_size > len(data):
                        break
                    val = struct.unpack_from("<Q" if is64 else "<I", data, pos)[0]
                    if val == 0:
                        break
                    if val & (1 << (63 if is64 else 31)):
                        funcs.append(f"ord_{val & 0xFFFF}")
                    else:
                        # IMAGE_IMPORT_BY_NAME: 2 byte hint, then the name
                        fname = _cstr(data, _rva_to_off(val & 0x7FFFFFFF, sections) + 2)
                        funcs.append(fname or f"rva_{val & 0x7FFFFFFF:X}")
            if dll:
                imports.setdefault(dll, []).extend(funcs)
    info["imports"] = imports
    info["import_count"] = sum(len(v) for v in imports.values())

    # markers
    found_easy = [k for k, m in EASY_MARKERS.items() if m in data]
    found_packer = [k for k, m in PACKER_MARKERS.items() if m.lower() in data.lower()]
    info["easy_language_markers"] = found_easy
    info["packer_markers"] = found_packer

    # guesses
    vmp_sections = [s for s in sections if s["name"].lower().startswith(".vmp")]
    entropies = [s["entropy"] for s in sections if s["rawsize"] > 0x400]
    ep_in_packed = any(
        s["va"] <= info["entry_point_rva"] < s["va"] + max(s["vsize"], s["rawsize"])
        and (s["name"].lower().startswith((".vmp", "upx", ".them")))
        for s in sections
    )
    high_entropy = bool(entropies) and (sum(entropies) / len(entropies)) > 7.0
    info["likely_vmprotect"] = bool(vmp_sections) or ep_in_packed or (
        info["import_count"] < 15 and high_entropy
    )
    info["likely_easy_language"] = bool(found_easy) or any(
        "krnln" in dll for dll in imports
    )
    info["notes"] = []
    if info["likely_easy_language"]:
        info["notes"].append(
            "易语言程序：32 位 PE，界面与“运行日志”多在标准 Win32 控件里，"
            "可用控件文本记录器直接读出日志文字。"
        )
    if info["likely_vmprotect"]:
        info["notes"].append(
            "疑似 VMProtect 加壳：静态反编译/调试器不可靠，行为记录应走内核 ETW + "
            "外部钩子，避免注入目标进程（会被 CRC/模块扫描发现）。"
        )
    if info["bits"] == 32:
        info["notes"].append("32 位进程：PEB 读取已走 WOW64 分支，全局钩子不受影响。")
    return info


EASY_MODULE_HINTS = ("krnln", ".fne", ".fnr", "eapi", "elib", "elnk")
EASY_WINDOW_CLASSES = ("wtwindow", "windowsui", "wtlib", "wtedit")


def runtime_triage(pid: int) -> dict:
    """Identify the running process by what it actually loaded.

    Beats static analysis when the binary is VMProtect packed, because the
    loader still has to map the EasyLanguage runtime (krnln) and the window
    class names are created at runtime.
    """
    from . import winapi

    out = {"pid": int(pid), "modules": 0, "easy_language": False,
           "evidence": [], "bits": None}
    if not pid:
        return out
    out["bits"] = 32 if winapi.is_wow64(pid) else 64
    try:
        mods = winapi.module_list(pid)
    except Exception:
        mods = []
    out["modules"] = len(mods)
    for mod in mods:
        name = (mod.get("name") or "").lower()
        if any(h in name for h in EASY_MODULE_HINTS):
            out["easy_language"] = True
            out["evidence"].append(f"module:{mod['name']}")
    try:
        for hwnd, title, cls, wpid in winapi.enum_windows():
            if wpid != int(pid):
                continue
            low = (cls or "").lower()
            if any(low.startswith(c) for c in EASY_WINDOW_CLASSES):
                out["easy_language"] = True
                out["evidence"].append(f"window_class:{cls}")
    except Exception:
        pass
    out["evidence"] = sorted(set(out["evidence"]))[:12]
    return out


def summary(info: dict) -> str:
    if info.get("error"):
        return f"PE 体检失败: {info['error']}"
    lines = [
        f"文件: {info['path']}  ({info['size'] / 1024:.0f} KB)",
        f"架构: {info['machine']} / {info['bits']} 位  子系统: {info['subsystem']}  "
        f"入口: 0x{info['entry_point_rva']:X}",
        f"节区: {len(info['sections'])} 个, 导入: {info['import_count']} 个函数 / "
        f"{len(info['imports'])} 个 DLL",
        "易语言特征: " + (", ".join(info["easy_language_markers"]) or "未发现"),
        "壳特征: " + (", ".join(info["packer_markers"]) or "未发现"),
        f"判定: {'VMProtect 类壳' if info['likely_vmprotect'] else '未见明显壳'} / "
        f"{'易语言程序' if info['likely_easy_language'] else '非易语言或已混淆'}",
    ]
    for note in info.get("notes", []):
        lines.append("  - " + note)
    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else ""
    result = analyze(target)
    print(summary(result))
    for sec in result.get("sections", []):
        print(f"  {sec['name']:<10} vsize={sec['vsize']:<9} raw={sec['rawsize']:<9} "
              f"entropy={sec['entropy']:<6} exec={sec['executable']}")
