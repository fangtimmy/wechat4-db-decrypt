"""Experimental Frida spawn hook for Windows WeChat.

The verified Windows path in :mod:`wxexport.win.keyscan` is read-only and
does not inject anything.  This module is an explicit opt-in fallback for
future versions where the Config.Cipher shape changes: it spawns Weixin.exe
under Frida and hooks the system crypto entry points that WeChat might use.
Every captured value is still validated against the database HMAC.
"""
from __future__ import annotations

import pathlib
import time
from typing import Callable

from wxexport.win import keyscan
from wxexport.win import memory

HOOK_JS = pathlib.Path(__file__).resolve().parent / "hook.js"


def hunt_with_frida(executable: pathlib.Path, db_dir: pathlib.Path,
                    *, timeout: int = 120, version: str = "",
                    log: Callable[[str], None] = print):
    try:
        import frida
    except ImportError as exc:
        raise RuntimeError(
            "未安装 frida，无法使用 --inject；可改用默认的只读扫描或手动密钥"
        ) from exc

    inventory = keyscan.collect_inventory(db_dir)
    if memory.find_main_weixin_pid() is not None:
        raise RuntimeError(
            "微信已在运行。--inject 需要先退出微信，再以 spawn 方式启动；"
            "日常场景请直接使用默认的只读扫描。")

    device = frida.get_local_device()
    log(f"[*] spawn: {executable}")
    pid = device.spawn([str(executable)])
    session = device.attach(pid)
    candidates: list[keyscan.Candidate] = []
    stats = keyscan.ScanStats()
    state = {"armed": False}

    def on_message(message, data):
        if message.get("type") != "send":
            if message.get("type") == "error":
                log(f"[!] hook 错误: {message.get('description', message)}")
            return
        payload = message.get("payload")
        if not isinstance(payload, str):
            return
        if payload.startswith("KEY32 "):
            pieces = payload.split()
            if len(pieces) >= 3:
                try:
                    key = bytes.fromhex(pieces[-1])
                except ValueError:
                    return
                candidates.append(keyscan.Candidate(key, None, "frida-hook", 40))
                log(f"[+] hook 捕获候选 #{len(candidates)} ({pieces[1]})")
        elif payload.startswith("ARMED"):
            state["armed"] = True
            log(f"[*] {payload}")
        elif payload.startswith("MISS"):
            log(f"[*] {payload}")

    script = session.create_script(HOOK_JS.read_text(encoding="utf-8"))
    script.on("message", on_message)
    script.load()
    device.resume(pid)
    log(f"[*] 等待密钥（最多 {timeout}s）...")
    deadline = time.time() + timeout
    mapping: dict[str, dict] = {}
    try:
        while time.time() < deadline:
            if candidates:
                mapping = keyscan.verify_candidates(candidates, inventory, log=log)
                if mapping:
                    break
            time.sleep(0.5)
    finally:
        try:
            session.detach()
        except Exception:
            pass
    stats.candidates = len(candidates)
    stats.verified = len(mapping)
    missing = [db.rel for db in inventory.databases if db.rel not in mapping]
    return mapping, stats, missing
