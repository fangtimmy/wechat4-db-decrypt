"""
配置加载器 - 从项目根目录的 config.json 读取路径配置。

macOS 默认读取微信沙盒容器；Windows 读取
``%APPDATA%\\Tencent\\xwechat\\config\\*.ini`` 中记录的根目录，并枚举
``xwechat_files\\*\\db_storage``。 ``Documents`` 只作为回退位置，因为用户
可能已经迁移数据，而旧账号目录仍留在默认位置。
"""
from __future__ import annotations

import glob
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_FILE = Path(
    os.environ.get("WXEXPORT_CONFIG", str(PROJECT_ROOT / "config.json"))
).expanduser()

IS_WINDOWS = os.name == "nt"

_MAC_DB_TEMPLATE = os.path.expanduser(
    "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/"
    "xwechat_files/your_wxid/db_storage")
_WIN_DB_TEMPLATE = os.path.expanduser(
    r"~\Documents\xwechat_files\your_wxid\db_storage")
_DB_DIR_TEMPLATE = _WIN_DB_TEMPLATE if IS_WINDOWS else _MAC_DB_TEMPLATE

_DEFAULT = {
    "db_dir": _DB_DIR_TEMPLATE,
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "hunted_file": "hunted_keys.txt",
    "snapshot_dir": ".runtime/win-snapshot" if IS_WINDOWS else "",
}

_ENV_OVERRIDES = {
    "db_dir": "WXEXPORT_DB_DIR",
    "keys_file": "WXEXPORT_KEYS_FILE",
    "decrypted_dir": "WXEXPORT_DECRYPTED_DIR",
    "hunted_file": "WXEXPORT_HUNTED_FILE",
}


def _choose_candidate(candidates):
    """在多个候选目录中选择一个。"""
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        if os.environ.get("WXEXPORT_NONINTERACTIVE") == "1":
            return candidates[0]
        if not sys.stdin.isatty():
            return candidates[0]
        print("[!] 检测到多个微信数据目录（请选择当前正在运行的微信账号）:")
        for i, candidate in enumerate(candidates, 1):
            print(f"    {i}. {candidate}")
        print("    0. 跳过，稍后手动配置")
        try:
            while True:
                choice = input("请选择 [0-{}]: ".format(len(candidates))).strip()
                if choice == "0":
                    return None
                if choice.isdigit() and 1 <= int(choice) <= len(candidates):
                    return candidates[int(choice) - 1]
                print("    无效输入，请重新选择")
        except (EOFError, KeyboardInterrupt):
            print()
            print("[*] 无法读取交互输入，自动选择最近使用的目录。")
            return candidates[0]
    return None


def _mac_auto_detect():
    container = os.path.expanduser(
        "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files")
    if not os.path.isdir(container):
        return None
    candidates = [m for m in glob.glob(os.path.join(container, "*", "db_storage"))
                  if os.path.isdir(m)]
    return _choose_candidate(candidates)


def _win_auto_detect():
    try:
        from wxexport.win import config as win_config
    except Exception as exc:  # pragma: no cover - only on broken installs
        print(f"[!] 无法加载 Windows 检测模块: {exc}")
        return None
    candidates = [str(item) for item in win_config.find_db_dirs()]
    if not candidates:
        return None
    for candidate in candidates:
        try:
            account = win_config.account_label(Path(candidate))
        except Exception:
            account = ""
        print(f"[*] 候选数据目录: {candidate}"
              + (f"（账号 {account}）" if account else ""))
    chosen = _choose_candidate(candidates)
    if chosen:
        print(f"[+] 自动检测到微信数据目录: {chosen}")
    return chosen


def auto_detect_db_dir():
    """自动检测微信 db_storage 路径。"""
    if IS_WINDOWS:
        return _win_auto_detect()
    return _mac_auto_detect()


def _snapshot_usable(snapshot_dir: str, db_dir: str) -> bool:
    snapshot = Path(snapshot_dir)
    if not snapshot.is_dir():
        return False
    marker = snapshot / ".snapshot.json"
    if marker.is_file():
        try:
            recorded = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            recorded = {}
        source = recorded.get("source")
        if source and os.path.normcase(os.path.abspath(str(source))) != \
                os.path.normcase(os.path.abspath(str(db_dir))):
            return False
    try:
        return any(snapshot.glob("**/*.db"))
    except OSError:
        return False


def _apply_env_overrides(cfg: dict) -> dict:
    for key, env_name in _ENV_OVERRIDES.items():
        value = os.environ.get(env_name)
        if value:
            cfg[key] = value
    return cfg


def load_config(required: bool = True):
    cfg = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, encoding="utf-8") as stream:
                cfg = json.load(stream)
        except (json.JSONDecodeError, OSError):
            print(f"[!] {CONFIG_FILE} 格式损坏，将使用默认配置")
            cfg = {}

    cfg = {**_DEFAULT, **cfg}
    cfg = _apply_env_overrides(cfg)
    cfg["platform"] = "windows" if IS_WINDOWS else (
        "macos" if sys.platform == "darwin" else "linux")

    db_dir = str(cfg.get("db_dir") or "")
    needs_detection = (
        not db_dir
        or db_dir == _DB_DIR_TEMPLATE
        or "your_wxid" in db_dir
        or not os.path.isdir(db_dir)
    )
    if needs_detection and "WXEXPORT_DB_DIR" not in os.environ:
        detected = auto_detect_db_dir()
        if detected:
            cfg["db_dir"] = detected
            try:
                CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
                with open(CONFIG_FILE, "w", encoding="utf-8") as stream:
                    json.dump(cfg, stream, indent=4, ensure_ascii=False)
                print(f"[+] 已保存到: {CONFIG_FILE}")
            except OSError as exc:
                print(f"[!] 无法写入 {CONFIG_FILE}: {exc}")
        else:
            if required:
                print("[!] 未能自动检测微信数据目录")
                print(f"    请手动编辑 {CONFIG_FILE} 中的 db_dir 字段，"
                      "或使用 --db-dir 指定")
                sys.exit(1)
            cfg["db_dir"] = ""
    elif needs_detection and not os.path.isdir(db_dir):
        print(f"[!] config 中的 db_dir 不存在: {db_dir}")

    # 将相对路径转为绝对路径。
    for key in ("keys_file", "decrypted_dir", "hunted_file", "snapshot_dir"):
        value = cfg.get(key)
        if value and not os.path.isabs(str(value)):
            cfg[key] = os.path.normpath(os.path.join(PROJECT_ROOT, str(value)))

    snapshot = str(cfg.get("snapshot_dir") or "")
    source_dir = str(cfg.get("db_dir") or "")
    decrypt_dir = os.environ.get("WXEXPORT_DECRYPT_DB_DIR", "")
    if not decrypt_dir and snapshot and source_dir and \
            _snapshot_usable(snapshot, source_dir):
        decrypt_dir = snapshot
    cfg["decrypt_db_dir"] = decrypt_dir or source_dir
    cfg["snapshot_active"] = bool(decrypt_dir and decrypt_dir == snapshot)
    return cfg


def update_config(**values):
    """Merge values into config.json without triggering auto-detection."""
    cfg = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, encoding="utf-8") as stream:
                cfg = json.load(stream)
        except (OSError, ValueError):
            cfg = {}
    cfg.update(values)
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as stream:
        json.dump(cfg, stream, indent=4, ensure_ascii=False)
    return cfg
