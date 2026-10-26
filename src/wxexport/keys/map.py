#!/usr/bin/env python3
"""密钥映射 — 校验候选密钥并生成 decrypt 使用的 all_keys.json。

候选来源：hunted_keys.txt（Config.Cipher / legacy / 手动）、hunt.log 的
PBKDF 字段、已有 all_keys.json、--key-file 与 --passphrase。所有候选都必须
通过数据库第 1 页的 HMAC-SHA512 校验，未验证的 key 不会写入。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from wxexport.config import PROJECT_ROOT, load_config
from wxexport.keys.utils import secure_file, strip_key_metadata
from wxexport.sqlcipher import PAGE_SZ, SALT_SZ, derive_enc_key, page1_hmac_ok

PBKDF_RE = re.compile(r"PBKDF pw=([0-9a-fA-F]{64})\b")


def _normalize(path: str) -> str:
    return str(path).replace("\\", "/")


def collect_databases(db_dir: Path):
    databases = []
    for dirpath, _dirnames, filenames in os.walk(db_dir):
        for name in filenames:
            if not name.endswith(".db") or name.endswith(("-wal", "-shm")):
                continue
            path = Path(dirpath) / name
            try:
                if path.stat().st_size < PAGE_SZ:
                    continue
                with open(path, "rb") as stream:
                    page1 = stream.read(PAGE_SZ)
            except OSError:
                continue
            if len(page1) < PAGE_SZ:
                continue
            rel = _normalize(os.path.relpath(path, db_dir))
            databases.append((rel, path, page1))
    databases.sort(key=lambda item: item[0])
    return databases


def _hex_candidates(value: str):
    """Yield (key, salt) from a 64/96/192-character hex candidate."""
    value = value.strip().lower().lstrip("x").strip("'")
    if len(value) < 64:
        return
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return
    for offset in range(0, max(1, len(raw) - 31), 32):
        key = raw[offset:offset + 32]
        if len(key) != 32:
            continue
        salt = raw[offset + 32:offset + 48]
        yield key, salt if len(salt) == SALT_SZ else None


def _load_file_candidates(path: Path):
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    candidates = []
    if isinstance(payload, dict):
        for rel, value in payload.items():
            if str(rel).startswith("_"):
                continue
            if isinstance(value, dict):
                value = value.get("enc_key") or value.get("key")
            if isinstance(value, str):
                for key, salt in _hex_candidates(value):
                    candidates.append((key, salt, f"key-file:{rel}"))
    elif isinstance(payload, list):
        for item in payload:
            if isinstance(item, str):
                for key, salt in _hex_candidates(item):
                    candidates.append((key, salt, "key-file"))
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            pieces = line.split()
            for key, salt in _hex_candidates(pieces[-1]):
                rel = pieces[0] if len(pieces) > 1 else ""
                candidates.append((key, salt, f"key-file:{rel}" if rel else "key-file"))
    return candidates


def _load_settings_candidates(hunted_file: Path, log_file: Path,
                              keys_file: Path):
    candidates = []
    if hunted_file.is_file():
        for line in hunted_file.read_text(encoding="utf-8", errors="replace").splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            for key, salt in _hex_candidates(value.split()[-1]):
                candidates.append((key, salt, "hunted_keys"))
    if log_file.is_file():
        try:
            text = log_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        for match in PBKDF_RE.finditer(text):
            for key, salt in _hex_candidates(match.group(1)):
                candidates.append((key, salt, "hunt.log"))
    if keys_file.is_file():
        try:
            payload = json.loads(keys_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = {}
        for rel, value in strip_key_metadata(payload).items():
            if isinstance(value, dict):
                value = value.get("enc_key") or value.get("key")
            if isinstance(value, str):
                for key, salt in _hex_candidates(value):
                    candidates.append((key, salt, f"existing:{rel}"))
    return candidates


def _verify(candidates, databases, mapping, log):
    for key, salt, source in candidates:
        salt_hex = salt.hex() if salt else None
        for rel, _path, page1 in databases:
            if rel in mapping:
                continue
            if salt_hex and page1[:SALT_SZ].hex() != salt_hex:
                continue
            if page1_hmac_ok(key, page1):
                mapping[rel] = {
                    "enc_key": key.hex(),
                    "salt": page1[:SALT_SZ].hex(),
                    "source": source,
                }
                if log:
                    log(f"  [KEY] {rel} ← {source}")


def main():
    cfg = load_config()
    parser = argparse.ArgumentParser(description="验证并映射微信数据库密钥")
    parser.add_argument("--db-dir", default=None,
                        help="覆盖 config 中的数据库目录（如 Windows 快照）")
    parser.add_argument("--key-file", type=Path, default=None,
                        help="额外候选密钥文件（JSON 或每行 hex）")
    parser.add_argument("--passphrase", default=None,
                        help="32 字节 passphrase（64hex），用于 PBKDF2 派生")
    args = parser.parse_args()

    db_dir = Path(args.db_dir or cfg.get("decrypt_db_dir") or cfg["db_dir"]).expanduser()
    if not db_dir.is_dir():
        print(f"[ERROR] 数据库目录不存在: {db_dir}")
        return 1
    hunted_file = Path(cfg.get("hunted_file") or "hunted_keys.txt").expanduser()
    log_file = Path(cfg.get("hunt_log") or (PROJECT_ROOT / "hunt.log")).expanduser()
    keys_file = Path(cfg["keys_file"]).expanduser()
    databases = collect_databases(db_dir)
    if not databases:
        print(f"[ERROR] 在 {db_dir} 未找到可解密的 .db 文件")
        return 1

    candidates = _load_settings_candidates(hunted_file, log_file, keys_file)
    if args.key_file:
        candidates.extend(_load_file_candidates(args.key_file))

    print(f"[+] {len(databases)} 个数据库，{len(candidates)} 个候选密钥")
    mapping = {}
    _verify(candidates, databases, mapping, print)

    if args.passphrase:
        try:
            passphrase = bytes.fromhex(args.passphrase.strip())
        except ValueError:
            print("[ERROR] passphrase 必须是 64 位十六进制字符串")
            return 1
        for rel, _path, page1 in databases:
            if rel in mapping:
                continue
            key = derive_enc_key(passphrase, page1[:SALT_SZ])
            if page1_hmac_ok(key, page1):
                mapping[rel] = {
                    "enc_key": key.hex(),
                    "salt": page1[:SALT_SZ].hex(),
                    "source": "passphrase",
                }
                print(f"  [KEY] {rel} ← passphrase")

    # Preserve verified metadata from an older file, but only for databases
    # that still validate against the current data.
    payload = dict(mapping)
    payload["_meta"] = {
        "platform": cfg.get("platform"),
        "db_dir": str(db_dir),
        "databases": len(databases),
        "matched": len(mapping),
        "keys_file": str(keys_file),
    }
    keys_file.parent.mkdir(parents=True, exist_ok=True)
    keys_file.write_text(
        json.dumps(payload, indent=4, ensure_ascii=False) + "\n",
        encoding="utf-8")
    secure_file(keys_file)

    print(f"[+] 匹配 {len(mapping)}/{len(databases)} 个数据库，已写入 {keys_file}")
    missing = [rel for rel, _path, _page1 in databases if rel not in mapping]
    if missing:
        print(f"[!] 未覆盖 {len(missing)} 个（可在微信中打开对应功能后重跑，"
              "或使用 --key/--passphrase）:")
        for rel in missing:
            print(f"    {rel}")
    return 0 if mapping else 2


if __name__ == "__main__":
    raise SystemExit(main())
