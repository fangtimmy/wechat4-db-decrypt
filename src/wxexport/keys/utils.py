import os
import posixpath
import subprocess


def normalize_rel(path):
    """Normalize a database-relative path for storage in all_keys.json."""
    return str(path).replace("\\", "/")


def strip_key_metadata(keys):
    """移除 all_keys.json 中以下划线开头的元数据字段，返回新 dict。"""
    return {k: v for k, v in keys.items() if not str(k).startswith("_")}


def _is_safe_rel_path(path):
    """检查路径不包含 ..、绝对路径或盘符。"""
    normalized = posixpath.normpath(normalize_rel(path))
    if normalized in ("", ".", ".."):
        return False
    if normalized.startswith(("/", "//")):
        return False
    parts = normalized.split("/")
    if ".." in parts:
        return False
    if len(parts[0]) == 2 and parts[0][1] == ":":
        return False
    return True


def get_key_info(keys, rel_path):
    """按相对路径查找数据库密钥，兼容 / 与 \\ 分隔符。"""
    if not _is_safe_rel_path(rel_path):
        return None
    normalized = normalize_rel(rel_path)
    info = keys.get(normalized)
    if info is not None:
        return info
    # 兼容旧版 Windows 写入的反斜杠键名。
    for key, value in keys.items():
        if normalize_rel(key) == normalized:
            return value
    return None


def secure_file(path, mode=0o600):
    """Restrict a sensitive file to the current user (best effort)."""
    try:
        os.chmod(path, mode)
    except OSError:
        pass
    if os.name != "nt":
        return
    principal = ""
    try:
        result = subprocess.run(
            ["whoami"], capture_output=True, text=True, timeout=5,
            encoding="mbcs", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        principal = result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        principal = ""
    if not principal or principal.endswith("\\"):
        domain = os.environ.get("USERDOMAIN", "")
        user = os.environ.get("USERNAME", "")
        principal = f"{domain}\\{user}" if domain and user else user
    if not principal:
        return
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        granted = subprocess.run(
            ["icacls", str(path), "/grant:r", f"{principal}:F", "/Q"],
            capture_output=True, text=True, timeout=15,
            encoding="mbcs", errors="replace", creationflags=flags)
        if granted.returncode != 0:
            return
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/Q"],
            capture_output=True, text=True, timeout=15,
            encoding="mbcs", errors="replace", creationflags=flags)
    except (OSError, subprocess.SubprocessError):
        pass
