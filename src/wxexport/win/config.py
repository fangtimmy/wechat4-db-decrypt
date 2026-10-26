"""Windows-specific WeChat discovery helpers.

WeChat 4.x stores its data root in
``%APPDATA%\\Tencent\\xwechat\\config\\<hash>.ini`` (the file content is the
chosen data root, e.g. ``D:\\微信``).  The default ``Documents`` location is
only a fallback: users commonly move the directory and a stale account copy
can remain there, so both places are inspected and the most recently used
account wins.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

IS_WINDOWS = os.name == "nt"
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


@dataclass(frozen=True)
class WeChatInstall:
    executable: Path
    install_dir: Path
    version: str


def _read_text(path: Path) -> str:
    raw = path.read_bytes()
    for encoding in ("utf-8-sig", "gbk", "utf-8"):
        try:
            return raw.decode(encoding).strip()
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace").strip()


def data_roots(appdata: Path | str | None = None,
               home: Path | str | None = None) -> list[Path]:
    """Return candidate WeChat data roots without duplicates."""
    home = Path(home) if home is not None else Path.home()
    if appdata is None:
        appdata = os.environ.get("APPDATA", "")
    roots: list[Path] = []
    seen: set[str] = set()

    def add(root: Path | str | None) -> None:
        if not root:
            return
        candidate = Path(root).expanduser()
        key = os.path.normcase(os.path.abspath(str(candidate)))
        if key in seen:
            return
        seen.add(key)
        roots.append(candidate)

    config_dir = Path(appdata) / "Tencent" / "xwechat" / "config" if appdata else None
    if config_dir and config_dir.is_dir():
        for ini in sorted(config_dir.glob("*.ini")):
            try:
                value = _read_text(ini)
            except OSError:
                continue
            if value:
                add(value)

    add(home / "Documents")
    return roots


def _account_dirs(root: Path) -> list[Path]:
    candidates: list[Path] = []
    if root.name.lower() == "xwechat_files":
        bases = [root]
    else:
        bases = [root / "xwechat_files", root]
    for base in bases:
        if not base.is_dir():
            continue
        try:
            entries = list(base.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not entry.is_dir() or entry.name in {"all_users", "Backup"}:
                continue
            db_dir = entry / "db_storage"
            if db_dir.is_dir():
                candidates.append(db_dir)
    return candidates


def latest_mtime(db_dir: Path) -> float:
    newest = 0.0
    try:
        for path in db_dir.rglob("*.db*"):
            try:
                newest = max(newest, path.stat().st_mtime)
            except OSError:
                continue
    except OSError:
        pass
    return newest


def find_db_dirs(appdata: Path | str | None = None,
                 home: Path | str | None = None) -> list[Path]:
    """All ``db_storage`` directories, most recently used first."""
    found: list[Path] = []
    seen: set[str] = set()
    for root in data_roots(appdata=appdata, home=home):
        for db_dir in _account_dirs(root):
            key = os.path.normcase(os.path.abspath(str(db_dir)))
            if key in seen:
                continue
            seen.add(key)
            found.append(db_dir)
    found.sort(key=latest_mtime, reverse=True)
    return found


def account_label(db_dir: Path) -> str:
    """Best-effort human readable label for a db_storage directory."""
    account = db_dir.parent.name or db_dir.name
    return account


def data_root_label(db_dir: Path) -> str:
    parent = db_dir.parent.parent
    return str(parent if parent.name else parent)


def _known_install_dirs() -> list[Path]:
    dirs: list[Path] = []
    if IS_WINDOWS:
        try:
            import winreg
            for hive, key in (
                (winreg.HKEY_CURRENT_USER, r"Software\Tencent\Weixin"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Tencent\Weixin"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Tencent\Weixin"),
            ):
                try:
                    with winreg.OpenKey(hive, key) as handle:
                        value, _ = winreg.QueryValueEx(handle, "InstallPath")
                    if value:
                        dirs.append(Path(value))
                except OSError:
                    continue
        except ImportError:
            pass
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    dirs.extend([
        Path(program_files) / "Tencent" / "Weixin",
        Path(program_files_x86) / "Tencent" / "Weixin",
    ])
    return dirs


def _version_from_install(install_dir: Path) -> str:
    try:
        versions = [
            child.name for child in install_dir.iterdir()
            if child.is_dir() and _VERSION_RE.match(child.name)
        ]
    except OSError:
        return ""
    if not versions:
        return ""
    versions.sort(key=lambda value: tuple(int(part) for part in value.split(".")),
                  reverse=True)
    return versions[0]


def file_version(path: Path) -> str:
    """Read a Windows PE file version without external dependencies."""
    if not IS_WINDOWS:
        return ""
    try:
        version = ctypes.WinDLL("version", use_last_error=True)
        version.GetFileVersionInfoSizeW.argtypes = [wt.LPCWSTR, ctypes.POINTER(wt.DWORD)]
        version.GetFileVersionInfoSizeW.restype = wt.DWORD
        version.GetFileVersionInfoW.argtypes = [
            wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p]
        version.GetFileVersionInfoW.restype = wt.BOOL
        version.VerQueryValueW.argtypes = [
            ctypes.c_void_p, wt.LPCWSTR, ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wt.UINT)]
        version.VerQueryValueW.restype = wt.BOOL

        size = version.GetFileVersionInfoSizeW(str(path), None)
        if not size:
            return ""
        buffer = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(str(path), 0, size, buffer):
            return ""
        pointer = ctypes.c_void_p()
        length = wt.UINT()
        if not version.VerQueryValueW(buffer, "\\", ctypes.byref(pointer), ctypes.byref(length)):
            return ""
        if not pointer.value or length.value < 52:
            return ""
        # VS_FIXEDFILEINFO: signature at 0, file version MS/LS at 8/12.
        raw = ctypes.string_at(pointer, 52)
        ms = int.from_bytes(raw[8:12], "little")
        ls = int.from_bytes(raw[12:16], "little")
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
    except (OSError, ValueError):
        return ""


def detect_install() -> WeChatInstall | None:
    for install_dir in _known_install_dirs():
        exe = install_dir / "Weixin.exe"
        if not exe.is_file():
            continue
        version = file_version(exe) or _version_from_install(install_dir)
        return WeChatInstall(exe, install_dir, version)
    return None


if __name__ == "__main__":
    if not IS_WINDOWS:
        print("此命令仅适用于 Windows")
        sys.exit(1)
    install = detect_install()
    print(f"安装: {install}")
    for item in find_db_dirs():
        print(f"数据目录: {item}  账号: {account_label(item)}  "
              f"最近使用: {latest_mtime(item):.0f}")
