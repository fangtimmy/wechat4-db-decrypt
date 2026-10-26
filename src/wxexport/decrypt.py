"""
WeChat 4.x 数据库解密器

使用抓取到的 per-DB enc_key 解密 SQLCipher 4 加密的数据库
参数: SQLCipher 4, AES-256-CBC, HMAC-SHA512, reserve=80, page_size=4096
密钥来源: all_keys.json (由 wxexport.keys.hunt/map 生成)
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from pathlib import Path

import functools
print = functools.partial(print, flush=True)

from wxexport.config import load_config
from wxexport.keys.utils import get_key_info, strip_key_metadata
from wxexport.sqlcipher import (
    PAGE_SZ, SALT_SZ, SQLITE_HDR, decrypt_page, page1_hmac_ok,
)

__all__ = ["decrypt_database", "merge_wal", "decrypt_page", "main"]


def _wal_cksum(s1, s2, data, big_endian):
    fmt = ">%dI" if big_endian else "<%dI"
    words = struct.unpack(fmt % (len(data) // 4), data)
    for i in range(0, len(words), 2):
        s1 = (s1 + words[i] + s2) & 0xFFFFFFFF
        s2 = (s2 + words[i + 1] + s1) & 0xFFFFFFFF
    return s1, s2


def merge_wal(db_path, out_path, enc_key):
    """把 -wal 中未合并进主文件的页解密后写入已解密库，否则最新消息会缺失。

    按 SQLite 读端语义取舍帧：仅接受与 WAL 头同代 salt 且校验和连续成立的
    帧，止于最后一个提交帧（帧头 dbsize>0）。
    """
    wal_path = db_path + "-wal"
    if not os.path.exists(wal_path):
        return
    wal = open(wal_path, "rb").read()
    if len(wal) < 32 + 24 + PAGE_SZ:
        return
    magic, _ver, page_sz, _ckpt, salt1, salt2, hc1, hc2 = struct.unpack(">8I", wal[:32])
    if page_sz != PAGE_SZ:
        print(f"  [WARN] WAL 页大小 {page_sz} != {PAGE_SZ}，跳过 WAL 合并")
        return
    if _wal_cksum(0, 0, wal[:24], magic & 1) != (hc1, hc2):
        print("  [WARN] WAL 头校验和不符，跳过 WAL 合并")
        return

    frames, pending, commit_size = {}, [], 0
    s1, s2 = hc1, hc2  # 帧校验和从 WAL 头校验和起链
    off = 32
    while off + 24 + PAGE_SZ <= len(wal):
        pgno, dbsz, fs1, fs2, fc1, fc2 = struct.unpack(">6I", wal[off:off + 24])
        if (fs1, fs2) != (salt1, salt2):
            break  # 上一代残留帧
        page = wal[off + 24: off + 24 + PAGE_SZ]
        s1, s2 = _wal_cksum(s1, s2, wal[off:off + 8], magic & 1)
        s1, s2 = _wal_cksum(s1, s2, page, magic & 1)
        if (s1, s2) != (fc1, fc2):
            break  # 撕裂/损坏的尾部
        pending.append((pgno, page))
        if dbsz > 0:
            for p, pg in pending:
                frames[p] = pg
            commit_size = dbsz
            pending = []
        off += 24 + PAGE_SZ

    if not frames:
        return
    with open(out_path, "r+b") as f:
        for pgno, page in frames.items():
            f.seek((pgno - 1) * PAGE_SZ)
            f.write(decrypt_page(enc_key, page, pgno))
        if commit_size:
            f.truncate(commit_size * PAGE_SZ)
    print(f"  WAL 合并: {len(frames)} 页")


def decrypt_database(db_path, out_path, enc_key):
    """解密整个数据库文件"""
    file_size = os.path.getsize(db_path)
    total_pages = file_size // PAGE_SZ
    if file_size % PAGE_SZ != 0:
        print(f"  [WARN] 文件大小 {file_size} 不是 {PAGE_SZ} 的倍数")
        total_pages += 1

    with open(db_path, "rb") as fin:
        page1 = fin.read(PAGE_SZ)
    if len(page1) < PAGE_SZ:
        print("  [ERROR] 文件太小")
        return False

    if not page1_hmac_ok(enc_key, page1):
        print(f"  [ERROR] Page 1 HMAC验证失败! salt: {page1[:SALT_SZ].hex()}")
        return False

    print(f"  HMAC OK, {total_pages} pages")
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(db_path, "rb") as fin, open(out_path, "wb") as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                if len(page) > 0:
                    page = page + b"\x00" * (PAGE_SZ - len(page))
                else:
                    break
            decrypted = decrypt_page(enc_key, page, pgno)
            fout.write(decrypted)
            if pgno == 1 and decrypted[:16] != SQLITE_HDR:
                print("  [WARN] 解密后header不匹配!")
            if pgno % 10000 == 0:
                print(f"  进度: {pgno}/{total_pages} ({100 * pgno / total_pages:.1f}%)")
    return True


def main():
    print("=" * 60)
    print("  WeChat 4.x 数据库解密器")
    print("=" * 60)

    cfg = load_config()
    parser = argparse.ArgumentParser(description="解密 SQLCipher 4 数据库")
    parser.add_argument("--db-dir", default=None,
                        help="覆盖 config 中的数据库源目录（如离线快照目录）")
    parser.add_argument("--out-dir", default=None,
                        help="覆盖 config 中的解密输出目录")
    parser.add_argument("--keys", default=None,
                        help="覆盖 all_keys.json 路径")
    args = parser.parse_args()

    db_dir = Path(args.db_dir or cfg.get("decrypt_db_dir") or cfg["db_dir"]).expanduser()
    out_dir = Path(args.out_dir or cfg["decrypted_dir"]).expanduser()
    keys_file = Path(args.keys or cfg["keys_file"]).expanduser()

    if not keys_file.exists():
        print(f"[ERROR] 密钥文件不存在: {keys_file}")
        print("请先运行 wxexport.keys.hunt 和 wxexport.keys.map（或直接运行 run.ps1/run.sh）")
        return 1

    with open(keys_file, encoding="utf-8") as stream:
        keys = strip_key_metadata(json.load(stream))
    print(f"\n加载 {len(keys)} 个数据库密钥")
    print(f"输出目录: {out_dir}")
    print(f"源目录: {db_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)

    db_files = []
    for dirpath, _dirnames, filenames in os.walk(db_dir):
        for name in filenames:
            if not name.endswith(".db") or name.endswith(("-wal", "-shm")):
                continue
            path = Path(dirpath) / name
            try:
                size = path.stat().st_size
            except OSError:
                continue
            rel = os.path.relpath(path, db_dir).replace(os.sep, "/")
            db_files.append((rel, path, size))
    db_files.sort(key=lambda item: item[2])

    print(f"找到 {len(db_files)} 个数据库文件\n")
    success = failed = 0
    total_bytes = 0
    for rel, path, size in db_files:
        key_info = get_key_info(keys, rel)
        if not key_info:
            print(f"SKIP: {rel} (无密钥)")
            failed += 1
            continue
        enc_key = bytes.fromhex(key_info["enc_key"])
        out_path = out_dir.joinpath(*rel.split("/"))
        print(f"解密: {rel} ({size / 1024 / 1024:.1f}MB) ...", end=" ")
        if not decrypt_database(str(path), str(out_path), enc_key):
            failed += 1
            continue
        merge_wal(str(path), str(out_path), enc_key)
        try:
            import sqlite3
            conn = sqlite3.connect(str(out_path), timeout=30)
            try:
                tables = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            finally:
                conn.close()
            table_names = [row[0] for row in tables]
            print(f"  OK! 表: {', '.join(table_names[:5])}", end="")
            if len(table_names) > 5:
                print(f" ...共{len(table_names)}个", end="")
            print()
            success += 1
            total_bytes += size
        except Exception as exc:
            print(f"  [WARN] SQLite验证失败: {exc}")
            failed += 1

    print(f"\n{'=' * 60}")
    print(f"结果: {success} 成功, {failed} 失败, 共 {len(db_files)} 个")
    print(f"解密数据量: {total_bytes / 1024 / 1024 / 1024:.1f}GB")
    print(f"解密文件在: {out_dir}")
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
