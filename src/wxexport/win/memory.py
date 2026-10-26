"""Read-only Windows process memory access used by the key scanner.

The functions here deliberately use only ``ctypes`` so the Windows path has
no dependency on psutil/pymem.  Opening a process for ``PROCESS_VM_READ`` is
sufficient; WeChat does not need to be launched under a debugger and no code
is injected into it.
"""
from __future__ import annotations

import csv
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

IS_WINDOWS = os.name == "nt"

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
MAX_USER_ADDRESS = 0x0000_8000_0000_0000

if IS_WINDOWS:
    _K32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _K32.OpenProcess.argtypes = (wt.DWORD, wt.BOOL, wt.DWORD)
    _K32.OpenProcess.restype = wt.HANDLE
    _K32.CloseHandle.argtypes = (wt.HANDLE,)
    _K32.VirtualQueryEx.argtypes = (
        wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
    _K32.VirtualQueryEx.restype = ctypes.c_size_t
    _K32.ReadProcessMemory.argtypes = (
        wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t))
    _K32.ReadProcessMemory.restype = wt.BOOL
    _K32.QueryFullProcessImageNameW.argtypes = (
        wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD))
    _K32.QueryFullProcessImageNameW.restype = wt.BOOL
else:  # pragma: no cover - imported for test collection on non-Windows
    _K32 = None


class MemoryBasicInformation(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wt.DWORD),
        ("_pad1", wt.DWORD),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
        ("_pad2", wt.DWORD),
    ]


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    memory_kb: int
    path: str = ""

    @property
    def name(self) -> str:
        return Path(self.path).name if self.path else "Weixin.exe"


@dataclass(frozen=True)
class Region:
    base: int
    size: int
    protect: int


def is_admin() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def list_weixin_processes() -> list[ProcessInfo]:
    """List Weixin.exe processes via tasklist, newest/largest first."""
    if not IS_WINDOWS:
        return []
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    result = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
        capture_output=True, text=True, errors="replace",
        encoding="mbcs" if IS_WINDOWS else "utf-8",
        creationflags=creationflags)
    processes: list[ProcessInfo] = []
    for row in csv.reader(result.stdout.splitlines()):
        if len(row) < 5 or not row[0].lower().startswith("weixin"):
            continue
        try:
            pid = int(row[1])
        except ValueError:
            continue
        digits = "".join(ch for ch in row[4] if ch.isdigit())
        memory_kb = int(digits) if digits else 0
        processes.append(ProcessInfo(pid, memory_kb))
    processes.sort(key=lambda item: item.memory_kb, reverse=True)
    return processes


def _visible_window_pids() -> set[int]:
    if not IS_WINDOWS:
        return set()
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    user32.EnumWindows.argtypes = (callback_type, wt.LPARAM)
    user32.EnumWindows.restype = wt.BOOL
    user32.IsWindowVisible.argtypes = (wt.HWND,)
    user32.IsWindowVisible.restype = wt.BOOL
    user32.GetWindowTextLengthW.argtypes = (wt.HWND,)
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowThreadProcessId.argtypes = (wt.HWND, ctypes.POINTER(wt.DWORD))
    user32.GetWindowThreadProcessId.restype = wt.DWORD
    pids: set[int] = set()

    @callback_type
    def callback(hwnd, _lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        pid = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value:
            pids.add(pid.value)
        return True

    user32.EnumWindows(callback, 0)
    return pids


def _process_path(pid: int) -> str:
    if not IS_WINDOWS:
        return ""
    handle = _K32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return ""
    try:
        buffer = ctypes.create_unicode_buffer(32768)
        size = wt.DWORD(len(buffer))
        if _K32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return buffer.value
    finally:
        _K32.CloseHandle(handle)
    return ""


def find_main_weixin_pid() -> ProcessInfo | None:
    """Prefer the process owning a visible window, then the largest one."""
    processes = list_weixin_processes()
    if not processes:
        return None
    visible = _visible_window_pids()
    for item in processes:
        if item.pid in visible:
            return ProcessInfo(item.pid, item.memory_kb, _process_path(item.pid))
    item = processes[0]
    return ProcessInfo(item.pid, item.memory_kb, _process_path(item.pid))


def open_process(pid: int, access: int = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ):
    handle = _K32.OpenProcess(access, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        raise PermissionError(
            f"无法读取微信进程 {pid}（Win32 错误 {error}）。"
            "如遇拒绝访问，请以管理员身份运行本工具。")
    return handle


def close_process(handle) -> None:
    if handle:
        _K32.CloseHandle(handle)


def read_memory(handle, address: int, size: int) -> bytes | None:
    if size <= 0:
        return b""
    buffer = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = _K32.ReadProcessMemory(
        handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(read))
    if not ok or read.value == 0:
        return None
    return buffer.raw[:read.value]


def iter_regions(handle) -> list[Region]:
    regions: list[Region] = []
    address = 0
    info = MemoryBasicInformation()
    while address < MAX_USER_ADDRESS:
        length = _K32.VirtualQueryEx(
            handle, ctypes.c_void_p(address), ctypes.byref(info),
            ctypes.sizeof(info))
        if not length:
            break
        base, size = int(info.BaseAddress), int(info.RegionSize)
        if (info.State == MEM_COMMIT and size > 0
                and not (info.Protect & (PAGE_NOACCESS | PAGE_GUARD))):
            regions.append(Region(base, size, int(info.Protect)))
        next_address = base + size
        if next_address <= address:
            break
        address = next_address
    return regions


def iter_chunks(handle, regions: list[Region], *, chunk_size: int = 2 * 1024 * 1024,
                overlap: int = 0):
    """Yield ``(absolute_base, bytes)`` chunks, optionally with a tail overlap."""
    for region in regions:
        offset = 0
        tail = b""
        while offset < region.size:
            size = min(chunk_size, region.size - offset)
            data = read_memory(handle, region.base + offset, size) or b""
            base = region.base + offset - len(tail)
            combined = tail + data
            if combined:
                yield base, combined
            if overlap and len(combined) >= overlap:
                tail = combined[-overlap:]
            else:
                tail = b""
            offset += size


def find_needle_addresses(handle, regions: list[Region], needle: bytes) -> set[int]:
    addresses: set[int] = set()
    for base, data in iter_chunks(handle, regions, overlap=max(0, len(needle) - 1)):
        position = data.find(needle)
        while position >= 0:
            addresses.add(base + position)
            position = data.find(needle, position + 1)
    return addresses


def read_u64(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 8 > len(data):
        return 0
    return int.from_bytes(data[offset:offset + 8], "little")


def start_weixin(executable: Path, timeout: float = 20.0) -> ProcessInfo | None:
    """Start WeChat if it is not already running and wait for its main process."""
    existing = find_main_weixin_pid()
    if existing:
        return existing
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    subprocess.Popen([str(executable)], cwd=str(executable.parent),
                     creationflags=creationflags)
    deadline = time.time() + timeout
    while time.time() < deadline:
        process = find_main_weixin_pid()
        if process and process.memory_kb > 10_000:
            return process
        time.sleep(0.5)
    return find_main_weixin_pid()
