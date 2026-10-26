#!/usr/bin/env python3
"""抓取微信 4.x 数据库的 SQLCipher 密钥。

macOS：沿用内嵌 Frida Gadget + CommonCrypto 拦截链路，不支持 SIP 关闭时
退回 root 外部附加。
Windows：默认只读扫描 Weixin.exe 的 ``Config.Cipher`` 对象，不注入、不改
微信文件；旧版本回退 ``x'...'`` 内存扫描，并支持手动 key/passphrase。
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time
from datetime import datetime

from wxexport.config import PROJECT_ROOT, load_config, update_config

SCRIPT_JS = pathlib.Path(__file__).resolve().parent / "hook.js"
OUT = PROJECT_ROOT / "hunted_keys.txt"
LOG_PATH = PROJECT_ROOT / "hunt.log"
STOP = PROJECT_ROOT / "hunt.stop"
GADGET_LOAD = "@executable_path/../Frameworks/FridaGadget.dylib"


# ---------------------------------------------------------------------------
# macOS 链路（保持原实现）
# ---------------------------------------------------------------------------

def wechat_pids():
    result = subprocess.run(
        ["pgrep", "-x", "WeChat"], capture_output=True, text=True)
    return [int(item) for item in result.stdout.split() if item.isdigit()]


def process_path(pid):
    import ctypes
    libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
    buffer = ctypes.create_string_buffer(4096)
    length = libproc.proc_pidpath(pid, buffer, len(buffer))
    return pathlib.Path(buffer.value.decode()) if length > 0 else None


def stop_running_wechat(log):
    pids = wechat_pids()
    if not pids:
        return
    print("[*] 正常退出当前微信，准备启动 Gadget 调试副本 ...")
    for pid in pids:
        path = process_path(pid)
        log.write(f"terminate pid={pid} path={path}\n")
        try:
            os.kill(pid, 15)
        except ProcessLookupError:
            pass
    deadline = time.time() + 20
    while time.time() < deadline and wechat_pids():
        time.sleep(0.5)
    remaining = wechat_pids()
    if remaining:
        raise RuntimeError(
            "微信未在 20 秒内退出，请手动退出后重试；未执行强制终止")


def validate_app(app):
    executable = app / "Contents" / "MacOS" / "WeChat"
    gadget = app / "Contents" / "Frameworks" / "FridaGadget.dylib"
    if not executable.is_file() or not gadget.is_file():
        raise RuntimeError(
            f"SIP 调试副本不存在或不完整: {app}\n"
            "请先运行: uv run python -m wxexport.sip.prepare")
    listing = subprocess.run(
        ["otool", "-L", executable], check=True,
        capture_output=True, text=True).stdout
    if GADGET_LOAD not in listing:
        raise RuntimeError("微信调试副本未加载 Frida Gadget")


def launch_app(app, log):
    print(f"[*] 启动 SIP 调试副本: {app}")
    result = subprocess.run(
        ["open", "-n", str(app)], capture_output=True, text=True)
    log.write(f"open rc={result.returncode} stderr={result.stderr}\n")
    if result.returncode != 0:
        raise RuntimeError(f"启动微信调试副本失败: {result.stderr.strip()}")


def prepare_data_snapshot(source, destination, log, refresh=False):
    """在调试副本的容器内建立正式微信数据的 APFS 写时复制。"""
    source = source.expanduser().resolve()
    destination = destination.expanduser()
    marker_name = ".sip-export-source.json"
    replace_snapshot = False
    if not source.is_dir():
        raise RuntimeError(f"正式微信数据目录不存在: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        actual = destination.resolve()
        if actual != source:
            raise RuntimeError(
                f"调试数据链接指向了非预期位置: {destination} -> {actual}")
        destination.unlink()
        log.write(f"removed rejected cross-container symlink {destination}\n")
    if destination.exists():
        marker = destination / marker_name
        if marker.is_file():
            try:
                recorded = json.loads(marker.read_text())
            except (OSError, ValueError):
                recorded = {}
            if recorded.get("source") == str(source):
                if not refresh:
                    print(f"[+] 已存在调试数据快照: {destination}")
                    return False
                replace_snapshot = True
                print("[*] 正在刷新 APFS 数据快照 ...")
        if not replace_snapshot:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup = destination.with_name(
                f"{destination.name}.pre-snapshot-{stamp}")
            counter = 1
            while backup.exists():
                backup = destination.with_name(
                    f"{destination.name}.pre-snapshot-{stamp}-{counter}")
                counter += 1
            destination.rename(backup)
            log.write(f"archived isolated data {destination} -> {backup}\n")
            print(f"[+] 已归档调试副本的独立数据: {backup}")
    temporary = destination.with_name(
        f".{destination.name}.clone-{os.getpid()}-{int(time.time())}")
    try:
        subprocess.run(["cp", "-cR", str(source), str(temporary)], check=True)
        (temporary / marker_name).write_text(json.dumps({
            "source": str(source),
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "method": "APFS clone (cp -cR)",
        }, ensure_ascii=False, indent=2) + "\n")
        if replace_snapshot:
            previous = destination.with_name(
                f".{destination.name}.previous-{os.getpid()}")
            destination.rename(previous)
            try:
                temporary.rename(destination)
            except Exception:
                previous.rename(destination)
                raise
            subprocess.run(["rm", "-rf", str(previous)], check=False)
        else:
            temporary.rename(destination)
    except Exception:
        subprocess.run(["rm", "-rf", str(temporary)], check=False)
        raise
    log.write(f"cloned data snapshot {source} -> {destination}\n")
    print(f"[+] 已建立 APFS 写时复制快照: {destination}")
    return True


def archive_stale_keys():
    if not OUT.exists() or OUT.stat().st_size == 0:
        return
    archive_dir = PROJECT_ROOT / ".runtime" / "key-archives"
    archive_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = archive_dir / f"hunted_keys-{stamp}.txt"
    OUT.rename(target)
    target.chmod(0o600)
    print(f"[+] 数据快照已变化，旧候选密钥已归档: {target}")


def load_existing_keys():
    keys = set()
    try:
        for line in OUT.read_text().splitlines():
            candidate = line.strip().lower()
            if len(candidate) != 64:
                continue
            try:
                bytes.fromhex(candidate)
            except ValueError:
                continue
            keys.add(candidate)
    except FileNotFoundError:
        pass
    return keys


def connect_gadget(frida, address, timeout, log):
    manager = frida.get_device_manager()
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            device = manager.add_remote_device(address)
            processes = device.enumerate_processes()
            gadget = next((item for item in processes if item.name == "Gadget"), None)
            if gadget is None:
                raise RuntimeError("远端已连接，但未发现 Gadget 进程")
            log.write(f"connected gadget pid={gadget.pid} address={address}\n")
            return manager, device, gadget
        except Exception as exc:  # Frida 会抛出多种绑定层异常
            last_error = exc
            time.sleep(0.25)
    raise RuntimeError(f"{timeout}s 内无法连接 Frida Gadget {address}: {last_error}")


def macos_main(args):
    from wxexport.sip.config import (
        DEBUG_XWECHAT_FILES, DEFAULT_TARGET, OFFICIAL_XWECHAT_FILES,
    )
    app = (args.app or DEFAULT_TARGET).resolve()
    official_data = args.official_data or OFFICIAL_XWECHAT_FILES
    debug_data = args.debug_data or DEBUG_XWECHAT_FILES

    if not args.address.startswith(("127.0.0.1:", "localhost:")):
        raise RuntimeError("为避免暴露 Frida 控制面，仅允许 loopback 地址")

    log = open(LOG_PATH, "a", buffering=1)
    manager = session = None
    keys = set()
    state = {"armed": False, "last_new": time.time(), "detached": False}

    try:
        validate_app(app)
        if STOP.exists():
            STOP.unlink()
        if args.restart:
            stop_running_wechat(log)
            redirected = prepare_data_snapshot(
                official_data, debug_data, log,
                refresh=args.refresh_snapshot)
            if redirected:
                archive_stale_keys()
            launch_app(app, log)

        keys = load_existing_keys()
        if keys:
            print(f"[*] 已载入 {len(keys)} 个现有候选密钥，后续捕获自动去重")

        import frida

        print(f"[*] 等待 Frida Gadget {args.address} ...")
        manager, device, gadget = connect_gadget(
            frida, args.address, args.connect_timeout, log)

        def on_message(message, data):
            if message["type"] == "send":
                payload = message["payload"]
                if not isinstance(payload, str):
                    return
                if payload.startswith("KEY32 "):
                    hexkey = payload.split()[-1]
                    if hexkey not in keys:
                        keys.add(hexkey)
                        state["last_new"] = time.time()
                        with open(OUT, "a") as stream:
                            stream.write(hexkey + "\n")
                        log.write(payload + "\n")
                        print(f"[+] 密钥 #{len(keys)}: {hexkey[:16]}...")
                elif payload.startswith(("ARMED", "MISS", "PBKDF")):
                    log.write(payload + "\n")
                    if payload.startswith("ARMED"):
                        state["armed"] = True
                        print(f"[*] {payload}")
            elif message["type"] == "error":
                log.write("script error: %s\n" % message.get("stack", message))

        def on_detached(reason, crash):
            state["detached"] = True
            log.write(f"detached reason={reason} crash={crash}\n")

        session = device.attach(gadget.pid)
        session.on("detached", on_detached)
        script = session.create_script(SCRIPT_JS.read_text())
        script.on("message", on_message)
        script.load()
        state["last_new"] = time.time()

        deadline = time.time() + args.timeout
        print(f"[*] 抓取中（超时 {args.timeout}s，静默 {args.quiet}s 自动停止），"
              "touch hunt.stop 可提前停止")
        while time.time() < deadline and not STOP.exists():
            if state["detached"]:
                if not keys:
                    raise RuntimeError(
                        "Gadget 会话在微信初始化阶段断开。请确认当前终端/Codex"
                        "具有完全磁盘访问权限，并运行 ./run.sh "
                        "--refresh-snapshot 重建调试数据快照。详情见 hunt.log")
                raise RuntimeError("Gadget 会话意外断开，详情见 hunt.log")
            if (args.quiet > 0 and keys
                    and time.time() - state["last_new"] >= args.quiet):
                print(f"[*] 已 {args.quiet}s 无新密钥，自动停止")
                break
            time.sleep(0.5)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        log.write(f"fatal: {exc!r}\n")
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception as exc:
                log.write(f"detach error: {exc!r}\n")
        if manager is not None:
            try:
                manager.remove_remote_device(args.address)
            except Exception:
                pass
        log.close()
        for path in (OUT, LOG_PATH):
            try:
                path.chmod(0o600)
            except OSError:
                pass
    print(f"[+] 完成，共捕获 {len(keys)} 个唯一密钥 → {OUT}")
    return 0 if keys else 2


# ---------------------------------------------------------------------------
# Windows 链路
# ---------------------------------------------------------------------------

def _existing_hunted(path: pathlib.Path) -> list[str]:
    keys = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            pieces = value.split()
            candidate = pieces[-1].lstrip("xX'").rstrip("'")
            if len(candidate) in (64, 96):
                try:
                    bytes.fromhex(candidate)
                except ValueError:
                    continue
                keys.append(candidate)
    except FileNotFoundError:
        pass
    return keys


def windows_main(args):
    from wxexport.win import config as win_config
    from wxexport.win import keyscan, memory, snapshot

    cfg = load_config(required=bool(not args.db_dir))
    raw_db_dir = args.db_dir or cfg.get("db_dir")
    if not raw_db_dir:
        print("[!] 未指定微信数据库目录；请使用 --db-dir 或完成 config.json 配置",
              file=sys.stderr)
        return 1
    db_dir = pathlib.Path(raw_db_dir).expanduser()
    if not db_dir.is_dir():
        print(f"[!] 微信数据库目录不存在: {db_dir}", file=sys.stderr)
        return 1
    db_dir = db_dir.resolve()
    install = win_config.detect_install()
    version = install.version if install else ""

    keys_file = pathlib.Path(cfg["keys_file"])
    hunted_file = pathlib.Path(cfg.get("hunted_file") or OUT)
    log_path = pathlib.Path(cfg.get("hunt_log") or LOG_PATH)
    log_stream = open(log_path, "a", encoding="utf-8", buffering=1)

    def log(message: str) -> None:
        print(message, flush=True)
        log_stream.write(message + "\n")

    log(f"[*] 数据目录: {db_dir}")
    log(f"[*] 微信版本: {version or '未知'}；进程: "
        f"{'运行中' if memory.find_main_weixin_pid() else '未运行'}")

    if args.restart:
        if memory.find_main_weixin_pid() is None:
            if install is not None:
                log("[*] 启动微信并等待主进程 ...")
                started = memory.start_weixin(install.executable)
                if started is None:
                    raise RuntimeError("启动微信失败，请手动登录后重试")
                log(f"[*] 微信已启动: PID={started.pid}")
        else:
            log("[*] 微信已在运行；只读扫描不需要重启")

    manual_keys = list(args.key)
    manual_keys.extend(_existing_hunted(hunted_file))
    strategy = args.strategy
    if args.inject:
        strategy = "inject"

    try:
        if strategy == "inject":
            from wxexport.win import inject
            if install is None:
                raise RuntimeError("未找到 Weixin.exe，无法使用 --inject")
            mapping, inject_stats, missing = inject.hunt_with_frida(
                install.executable, db_dir, timeout=args.timeout,
                version=version, log=log)
            inventory = keyscan.collect_inventory(db_dir)
            result = keyscan.HuntResult(
                inventory, mapping, {"inject": inject_stats}, missing)
        else:
            result = keyscan.hunt(
                db_dir, version=version,
                strategies=strategy,
                deep=args.deep,
                key_file=args.key_file,
                keys=manual_keys,
                passphrase=args.passphrase,
                pid=args.pid,
                log=log)
        for name, stats in result.stats.items():
            log(f"[*] {name}: {stats.summary()}")
        if result.mapping:
            keyscan.write_outputs(
                result, keys_file=keys_file, hunted_file=hunted_file,
                metadata={"version": version, "strategy": strategy})
            log(f"[+] 已验证密钥: {len(result.mapping)}/{len(result.inventory.databases)} "
                f"→ {keys_file}")
        if result.missing:
            log(f"[!] 未覆盖 {len(result.missing)} 个数据库:")
            for rel in result.missing:
                log(f"    {rel}")
        if not result.mapping:
            log("[!] 未获得任何可通过 HMAC 校验的密钥。"
                "可尝试 --deep、手动 --key/--passphrase，或确认微信已登录。")
            return 2

        if not args.no_snapshot:
            destination = pathlib.Path(
                cfg.get("snapshot_dir") or snapshot.DEFAULT_SNAPSHOT_DIR)
            if destination.resolve() != db_dir:
                created = snapshot.prepare_snapshot(
                    db_dir, destination, version=version,
                    refresh=args.refresh_snapshot, log=log)
                update_config(snapshot_dir=str(created))
                log(f"[+] 后续 map/decrypt 将默认使用快照: {created}")
        return 0 if result.complete else 3
    except (OSError, RuntimeError, PermissionError) as exc:
        log(f"[!] {exc}")
        return 1
    except Exception as exc:  # 防止单个版本解析异常中断整条链路
        log(f"[!] {type(exc).__name__}: {exc}")
        return 1
    finally:
        log_stream.close()


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="微信 4.x 数据库密钥抓取")
    # macOS
    parser.add_argument("--restart", action="store_true",
                        help="退出当前微信并启动 Gadget 调试副本（macOS）")
    parser.add_argument("--app", type=pathlib.Path, default=None,
                        help="Gadget 微信副本路径（macOS）")
    parser.add_argument("--address", default="127.0.0.1:27042",
                        help="Gadget 地址（仅 loopback）")
    parser.add_argument("--official-data", type=pathlib.Path, default=None,
                        help="正式微信 xwechat_files 目录（macOS）")
    parser.add_argument("--debug-data", type=pathlib.Path, default=None,
                        help="调试副本 xwechat_files 入口（macOS）")
    parser.add_argument("--refresh-snapshot", action="store_true",
                        help="重建数据快照")
    parser.add_argument("--connect-timeout", type=int, default=30)
    parser.add_argument("--timeout", type=int, default=420,
                        help="最长抓取秒数（macOS）/ hook 等待秒数（Windows）")
    parser.add_argument("--quiet", type=int, default=45,
                        help="连续 N 秒无新密钥即停止（macOS，0=禁用）")
    # Windows
    parser.add_argument("--db-dir", type=pathlib.Path, default=None,
                        help="指定 Windows db_storage 目录")
    parser.add_argument("--pid", type=int, default=None,
                        help="指定 Weixin.exe PID（Windows）")
    parser.add_argument("--strategy", default="auto",
                        choices=["auto", "config", "legacy", "passphrase", "manual"],
                        help="Windows 密钥策略（默认 auto）")
    parser.add_argument("--key-file", type=pathlib.Path, default=None,
                        help="手动 key 文件（JSON/每行 hex）")
    parser.add_argument("--key", action="append", default=[],
                        help="手动 key：64hex 或 相对路径=64hex，可重复")
    parser.add_argument("--passphrase", default=None,
                        help="手动 32 字节 passphrase（64hex）")
    parser.add_argument("--deep", action="store_true",
                        help="Windows: 额外尝试 passphrase/PBKDF2 扫描（较慢）")
    parser.add_argument("--no-snapshot", action="store_true",
                        help="Windows: 抓取后不复制数据快照")
    parser.add_argument("--inject", action="store_true",
                        help="Windows: 实验性 Frida spawn hook（需先退出微信）")
    parser.add_argument("--no-restart", action="store_true",
                        help="兼容参数；Windows 默认不重启微信")
    args = parser.parse_args()

    if sys.platform == "darwin":
        if args.no_restart:
            parser.error("--no-restart 仅用于 Windows")
        if not args.address.startswith(("127.0.0.1:", "localhost:")):
            parser.error("为避免暴露 Frida 控制面，仅允许 loopback 地址")
        return macos_main(args)
    if sys.platform == "win32":
        return windows_main(args)
    parser.error("仅支持 macOS 和 Windows")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
