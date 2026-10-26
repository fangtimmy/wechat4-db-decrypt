#!/usr/bin/env python3
"""导出前检查：macOS 的 TCC/完全磁盘访问；Windows 的数据目录与进程权限。"""

import os
import pathlib
import subprocess
import sys

CONTAINER = pathlib.Path.home() / "Library/Containers/com.tencent.xinWeChat/Data"


def windows_check():
    from wxexport.config import load_config
    from wxexport.win import config as win_config
    from wxexport.win import memory

    cfg = load_config(required=False)
    db_dir = cfg.get("db_dir") or ""
    if not db_dir or not pathlib.Path(db_dir).is_dir():
        print("[!] 未找到微信数据目录。", file=sys.stderr)
        print("    请确认微信已登录，或在 config.json 中填写 db_dir / 使用 --db-dir。",
              file=sys.stderr)
        return 1

    root = pathlib.Path(db_dir)
    try:
        entries = list(root.rglob("*.db"))
    except OSError as exc:
        print(f"[!] 无法读取微信数据目录: {root} ({exc})", file=sys.stderr)
        return 1
    databases = [item for item in entries
                 if not item.name.endswith(("-wal", "-shm"))]
    total = sum(item.stat().st_size for item in databases)
    print(f"[+] 微信数据目录: {root}")
    print(f"[+] 数据库: {len(databases)} 个，{total / 1024 / 1024:.1f}MB")
    if cfg.get("snapshot_active"):
        print(f"[+] 当前解密源: 快照 {cfg.get('decrypt_db_dir')}")
    else:
        print(f"[*] 当前解密源: 实时目录（建议先建立快照）")

    install = win_config.detect_install()
    if install:
        print(f"[+] 微信: {install.version or '未知版本'}  {install.executable}")
    else:
        print("[!] 未能定位 Weixin.exe；手动密钥模式仍可使用。", file=sys.stderr)

    process = memory.find_main_weixin_pid()
    if process:
        print(f"[+] Weixin.exe 主进程: PID={process.pid} "
              f"({process.memory_kb // 1024}MB)")
        try:
            handle = memory.open_process(process.pid)
        except PermissionError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            print("    自动抓取密钥可能失败；可右键“以管理员身份运行”，"
                  "或使用 --key-file / --passphrase。", file=sys.stderr)
        else:
            memory.close_process(handle)
            print("[+] 进程内存读取权限正常（只读）")
    else:
        print("[!] Weixin.exe 未运行；请先登录微信，或使用手动密钥。",
              file=sys.stderr)

    admin = memory.is_admin()
    print(f"[*] 当前权限: {'管理员' if admin else '普通用户'}；"
          "4.1.10+ 的密钥只读扫描通常不需要管理员。")
    print("[*] Windows 密钥策略: Config.Cipher → 旧版 x'...' → 手动 key/passphrase")
    if install and install.version:
        major = install.version.split(".")
        if len(major) >= 3 and (int(major[0]), int(major[1]), int(major[2])) < (4, 1, 10):
            print("[*] 检测到 4.1.10 之前的版本，legacy 内存扫描可能直接命中。")
    return 0


def macos_check():
    try:
        next(os.scandir(CONTAINER), None)
    except PermissionError:
        print("[!] macOS 的 App Data 保护阻止当前进程读取微信容器。", file=sys.stderr)
        print("    请在 系统设置 → 隐私与安全性 → 完全磁盘访问权限 中添加：",
              file=sys.stderr)
        print("      当前运行本项目的 Terminal 或 Codex", file=sys.stderr)
        print("    授权后完全退出并重新打开对应终端/Codex，再运行 ./run.sh。",
              file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"[!] 未发现微信容器: {CONTAINER}", file=sys.stderr)
        return 1
    print(f"[+] 微信容器读取权限正常: {CONTAINER}")
    status = subprocess.run(
        ["csrutil", "status"], capture_output=True, text=True)
    if status.returncode == 0 and "enabled" in status.stdout.lower():
        print("[+] SIP 状态: enabled")
    elif status.stdout.strip():
        print(f"[*] {status.stdout.strip()}")
    return 0


def main():
    if sys.platform == "win32":
        return windows_check()
    if sys.platform == "darwin":
        return macos_check()
    print("[*] 当前平台无需额外权限检查")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
