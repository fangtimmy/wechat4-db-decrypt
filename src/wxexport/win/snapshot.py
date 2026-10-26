"""Windows data snapshot used for consistent mapping/decryption.

Windows has no portable APFS-style copy-on-write clone, so this module copies
``db_storage`` (including ``-wal`` and ``-shm``) with robocopy when available,
falling back to per-file ``shutil.copy2``.  The marker records the source and
WeChat version; ``--refresh-snapshot`` replaces an older copy atomically.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

from wxexport.config import PROJECT_ROOT

DEFAULT_SNAPSHOT_DIR = PROJECT_ROOT / ".runtime" / "win-snapshot"
MARKER_NAME = ".snapshot.json"


def _run_robocopy(source: Path, destination: Path) -> bool:
    executable = shutil.which("robocopy")
    if not executable:
        return False
    command = [
        executable, str(source), str(destination), "/E", "/COPY:DAT",
        "/R:2", "/W:1", "/NFL", "/NDL", "/NJH", "/NJS", "/NP",
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True,
            encoding="mbcs" if os.name == "nt" else "utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        # robocopy uses 0-7 as success codes.
        return result.returncode <= 7
    except (OSError, subprocess.SubprocessError):
        return False


def _copy_tree(source: Path, destination: Path, log) -> int:
    destination.mkdir(parents=True, exist_ok=True)
    copied = 0
    for dirpath, _dirnames, filenames in os.walk(source):
        relative = os.path.relpath(dirpath, source)
        target_dir = destination if relative == "." else destination / relative
        target_dir.mkdir(parents=True, exist_ok=True)
        for name in filenames:
            src = Path(dirpath) / name
            dst = target_dir / name
            try:
                shutil.copy2(src, dst)
                copied += 1
            except OSError as exc:
                log(f"[!] 快照跳过文件 {src}: {exc}")
    return copied


def _marker_matches(destination: Path, source: Path, version: str) -> bool:
    marker = destination / MARKER_NAME
    if not marker.is_file():
        return False
    try:
        recorded = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if os.path.normcase(os.path.abspath(str(recorded.get("source", "")))) != \
            os.path.normcase(os.path.abspath(str(source))):
        return False
    if version and recorded.get("version") and recorded.get("version") != version:
        return False
    return True


def _remove_tree(path: Path) -> None:
    for attempt in range(8):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(0.1 * (attempt + 1))


def _move(source: Path, destination: Path) -> None:
    last_error = None
    for attempt in range(20):
        try:
            os.replace(source, destination)
            return
        except OSError as exc:
            last_error = exc
            time.sleep(0.1 * (attempt + 1))
    raise last_error  # type: ignore[misc]


def prepare_snapshot(source_dir: Path | str,
                     destination: Path | str = DEFAULT_SNAPSHOT_DIR,
                     *, version: str = "", refresh: bool = False,
                     log=print) -> Path:
    source = Path(source_dir).expanduser().resolve()
    destination = Path(destination).expanduser().resolve()
    if not source.is_dir():
        raise RuntimeError(f"数据目录不存在: {source}")
    if destination == source:
        raise RuntimeError("快照目录不能与源目录相同")

    if (destination.is_dir() and not refresh
            and _marker_matches(destination, source, version)):
        print(f"[+] 复用 Windows 数据快照: {destination}")
        return destination

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / (
        f".{destination.name}.tmp-{os.getpid()}-{int(time.time())}")
    _remove_tree(temporary)

    print(f"[*] 正在复制微信数据快照: {source} -> {temporary}")
    copied = 0
    if not _run_robocopy(source, temporary):
        copied = _copy_tree(source, temporary, log)
    else:
        copied = sum(1 for _ in temporary.rglob("*") if _.is_file())
    if not copied:
        _remove_tree(temporary)
        raise RuntimeError("快照复制失败：没有复制到任何文件")

    (temporary / MARKER_NAME).write_text(
        json.dumps({
            "source": str(source),
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "version": version,
            "method": "robocopy" if shutil.which("robocopy") else "copy2",
            "files": copied,
        }, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")

    backup = None
    if destination.exists():
        backup = destination.parent / (
            f".{destination.name}.previous-{os.getpid()}")
        _remove_tree(backup)
        _move(destination, backup)
    try:
        _move(temporary, destination)
    except Exception:
        if backup is not None and not destination.exists():
            _move(backup, destination)
        _remove_tree(temporary)
        raise
    if backup is not None:
        _remove_tree(backup)
    print(f"[+] 已建立 Windows 数据快照: {destination}（{copied} 个文件）")
    return destination
