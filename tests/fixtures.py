"""Synthetic WeChat 4.x database fixture encrypted as SQLCipher 4.

The generated files use exactly the layout consumed by wxexport:
AES-256-CBC, reserve=80, page=4096, HMAC-SHA512 over the ciphertext page.
No real user data is involved.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import os
import shutil
import sqlite3
import struct
import sys
from pathlib import Path

import zstandard
from Crypto.Cipher import AES

from wxexport.sqlcipher import (
    HMAC_SZ, PAGE_SZ, RESERVE_SZ, SALT_SZ, compute_page_hmac,
    derive_mac_key,
)

MY_WXID = "wxid_me"
FRIEND1 = "wxid_friend1"
FRIEND2 = "wxid_friend2"
GROUP = "123456@chatroom"

FIXTURE_KEY = bytes.fromhex(
    "0123456789abcdeffedcba9876543210"
    "00112233445566778899aabbccddeeff")
FIXTURE_SALT_MESSAGE = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
FIXTURE_SALT_CONTACT = bytes.fromhex("1112131415161718191a1b1c1d1e1f20")


def msg_table(username: str) -> str:
    return "Msg_" + hashlib.md5(username.encode()).hexdigest()


def _create_schema(path: Path, is_contact: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA page_size=4096")
    conn.execute("PRAGMA journal_mode=DELETE")
    if is_contact:
        conn.execute(
            "CREATE TABLE contact (id INTEGER PRIMARY KEY, username TEXT, "
            "nick_name TEXT, remark TEXT, alias TEXT)")
        conn.executemany(
            "INSERT INTO contact(username, nick_name, remark, alias) VALUES (?,?,?,?)",
            [
                (MY_WXID, "Me", "", "me"),
                (FRIEND1, "Friend1", "Friend One", "friend1"),
                (FRIEND2, "Friend2", "Friend Two", "friend2"),
                (GROUP, "Test Group", "", ""),
            ])
    else:
        conn.execute("CREATE TABLE Name2Id (user_name TEXT, is_group INTEGER)")
        conn.executemany(
            "INSERT INTO Name2Id(rowid, user_name, is_group) VALUES (?,?,?)",
            [(1, MY_WXID, 0), (2, FRIEND1, 0), (3, FRIEND2, 0)])
        for username, rows in _conversations().items():
            table = msg_table(username)
            conn.execute(
                f"CREATE TABLE {table} ("
                "local_id INTEGER PRIMARY KEY, server_id INTEGER, "
                "local_type INTEGER, sort_seq INTEGER, create_time INTEGER, "
                "real_sender_id INTEGER, message_content BLOB, "
                "WCDB_CT_message_content INTEGER)")
            conn.executemany(
                f"INSERT INTO {table}(local_id, server_id, local_type, sort_seq, "
                "create_time, real_sender_id, message_content, "
                "WCDB_CT_message_content) VALUES (?,?,?,?,?,?,?,?)",
                rows)
    conn.commit()
    conn.close()


def _conversations():
    plain = "hello from me".encode("utf-8")
    friend = "hi there".encode("utf-8")
    group_friend = f"{FRIEND1}:\nhello group".encode("utf-8")
    group_me = f"{MY_WXID}:\nmy group message".encode("utf-8")
    revoke = ('<?xml version="1.0"?><sysmsg type="revokemsg"><revokemsg>'
              '<content>"Friend Two" 撤回了一条消息</content>'
              '</revokemsg></sysmsg>').encode("utf-8")
    link = ('<msg><appmsg><title>Example Link</title><type>1</type>'
            '<url>https://example.com/a</url></appmsg></msg>').encode("utf-8")
    compressed = zstandard.ZstdCompressor().compress(link)
    image = ('<msg><img md5="m1" length="1024" cdnthumbwidth="100" '
             'cdnthumbheight="50"/></msg>').encode("utf-8")
    base = 1_700_000_000

    return {
        FRIEND1: [
            (1, 1001, 1, 1, base + 1, 1, plain, 0),
            (2, 1002, 1, 2, base + 2, 2, friend, 0),
            (3, 1003, (1 << 32) | 49, 3, base + 3, 2, compressed, 4),
        ],
        FRIEND2: [
            (1, 2001, 1, 1, base + 4, 1, plain, 0),
            (2, 2002, 1, 2, base + 5, 3, friend, 0),
            (3, 2003, 10000, 3, base + 6, 3, revoke, 0),
        ],
        GROUP: [
            (1, 3001, 1, 1, base + 7, 2, group_friend, 0),
            (2, 3002, 1, 2, base + 8, 1, group_me, 0),
            (3, 3003, 3, 3, base + 9, 3, image, 0),
        ],
    }


def build_plain_fixture(root: Path) -> dict[str, Path]:
    root = Path(root)
    contact = root / "contact" / "contact.db"
    message = root / "message" / "message_0.db"
    _create_schema(contact, is_contact=True)
    _create_schema(message, is_contact=False)
    return {"contact/contact.db": contact, "message/message_0.db": message}


def _encrypt_file(plain: Path, encrypted: Path, key: bytes, salt: bytes) -> None:
    data = plain.read_bytes()
    if len(data) % PAGE_SZ:
        data += b"\x00" * (PAGE_SZ - len(data) % PAGE_SZ)
    encrypted.parent.mkdir(parents=True, exist_ok=True)
    mac_key = derive_mac_key(key, salt)
    with open(encrypted, "wb") as out:
        for offset in range(0, len(data), PAGE_SZ):
            pgno = offset // PAGE_SZ + 1
            page = bytearray(data[offset:offset + PAGE_SZ])
            page[PAGE_SZ - RESERVE_SZ:] = b"\x00" * RESERVE_SZ
            iv = hashlib.sha256(salt + struct.pack("<I", pgno)).digest()[:16]
            if pgno == 1:
                ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(
                    bytes(page[SALT_SZ:PAGE_SZ - RESERVE_SZ]))
                encrypted_page = salt + ciphertext + iv + b"\x00" * HMAC_SZ
            else:
                ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(
                    bytes(page[:PAGE_SZ - RESERVE_SZ]))
                encrypted_page = ciphertext + iv + b"\x00" * HMAC_SZ
            digest = compute_page_hmac(mac_key, encrypted_page, pgno)
            out.write(encrypted_page[:-HMAC_SZ] + digest)


def _sqlite_library():
    candidates = []
    if os.name == "nt":
        for base in (sys.base_prefix, sys.prefix):
            candidates.append(os.path.join(base, "Library", "bin", "sqlite3.dll"))
        candidates.extend([
            r"C:\Windows\System32\winsqlite3.dll",
            "sqlite3.dll",
        ])
    else:
        candidates.append(ctypes.util.find_library("sqlite3"))
    for candidate in candidates:
        if not candidate:
            continue
        try:
            lib = ctypes.CDLL(candidate)
        except OSError:
            continue
        if hasattr(lib, "sqlite3_file_control"):
            return lib
    return None


_SQLITE = _sqlite_library()
RESERVE_SUPPORTED = (_SQLITE is not None
                     and tuple(int(part) for part in sqlite3.sqlite_version.split(".")[:2])
                     >= (3, 45))


def _create_reserved_copy(plain: Path, target: Path) -> Path:
    """Recreate a plain SQLite DB with 80 reserved bytes per page.

    Standard SQLite writes cells at the end of a page; SQLCipher reserves the
    last 80 bytes.  SQLITE_FCNTL_RESERVE_BYTES (38) must be set before the
    first page is allocated.  If the local SQLite is too old, the plain file
    is returned and tests that need a real SQLite open can skip.
    """
    if _SQLITE is None:
        shutil.copy2(plain, target)
        return target
    try:
        conn = sqlite3.connect(plain)
        try:
            statements = list(conn.iterdump())
        finally:
            conn.close()
    except sqlite3.Error:
        shutil.copy2(plain, target)
        return target

    lib = _SQLITE
    lib.sqlite3_open.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    lib.sqlite3_open.restype = ctypes.c_int
    lib.sqlite3_exec.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p]
    lib.sqlite3_exec.restype = ctypes.c_int
    lib.sqlite3_file_control.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
    lib.sqlite3_file_control.restype = ctypes.c_int
    lib.sqlite3_close.argtypes = [ctypes.c_void_p]

    db = ctypes.c_void_p()
    if lib.sqlite3_open(str(target).encode(), ctypes.byref(db)) != 0:
        shutil.copy2(plain, target)
        return target
    ok = True
    if lib.sqlite3_exec(db, b"PRAGMA page_size=4096;", None, None, None) != 0:
        ok = False
    reserve = ctypes.c_int(RESERVE_SZ)
    if ok and lib.sqlite3_file_control(
            db, b"main", 38, ctypes.byref(reserve)) != 0:
        ok = False
    if ok:
        for statement in statements:
            if lib.sqlite3_exec(db, statement.encode("utf-8"),
                                None, None, None) != 0:
                ok = False
                break
    lib.sqlite3_close(db)
    try:
        header = target.read_bytes()[:100]
        if not ok or len(header) < 100 or header[20] != RESERVE_SZ:
            shutil.copy2(plain, target)
    except OSError:
        shutil.copy2(plain, target)
    return target


def build_encrypted_fixture(root: Path) -> dict[str, str]:
    """Return {relative_db_path: hex_key} for the encrypted fixture."""
    root = Path(root)
    plain_root = root / "plain"
    encrypted_root = root / "db_storage"
    plain = build_plain_fixture(plain_root)
    keys = {}
    for rel, path in plain.items():
        salt = (FIXTURE_SALT_MESSAGE if "message/" in rel
                else FIXTURE_SALT_CONTACT)
        key = FIXTURE_KEY
        reserved = path.with_name(path.stem + ".reserved.db")
        _create_reserved_copy(path, reserved)
        target = encrypted_root / rel
        _encrypt_file(reserved, target, key, salt)
        keys[rel] = key.hex()
    return keys


def write_config(path: Path, db_dir: Path, keys_file: Path,
                 decrypted_dir: Path, hunted_file: Path) -> None:
    import json
    path.write_text(json.dumps({
        "db_dir": str(db_dir),
        "keys_file": str(keys_file),
        "decrypted_dir": str(decrypted_dir),
        "hunted_file": str(hunted_file),
        "snapshot_dir": "",
    }, indent=2), encoding="utf-8")
