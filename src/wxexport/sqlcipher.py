"""SQLCipher 4 primitives shared by the macOS and Windows pipelines.

WeChat 4.x uses WCDB with SQLCipher 4: AES-256-CBC, HMAC-SHA512,
page size 4096 and 80 reserved bytes (16 IV + 64 HMAC).  Each database has
its own 32-byte raw key and 16-byte salt.  A passphrase, when only that is
available, is expanded with PBKDF2-HMAC-SHA512 and 256,000 rounds.
"""
from __future__ import annotations

import hashlib
import hmac
import struct

from Crypto.Cipher import AES

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = 80  # IV(16) + HMAC(64)
SQLITE_HDR = b"SQLite format 3\x00"
PASSPHRASE_ITERATIONS = 256_000


def derive_mac_key(enc_key: bytes, salt: bytes) -> bytes:
    """Derive the SQLCipher 4 HMAC key from a raw enc_key and a DB salt."""
    mac_salt = bytes(b ^ 0x3A for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)


def derive_enc_key(passphrase: bytes, salt: bytes,
                   iterations: int = PASSPHRASE_ITERATIONS) -> bytes:
    """Derive a per-database raw enc_key from an account passphrase."""
    return hashlib.pbkdf2_hmac(
        "sha512", passphrase, salt, iterations, dklen=KEY_SZ)


def page1_hmac_data(page1: bytes) -> bytes:
    return page1[SALT_SZ:PAGE_SZ - RESERVE_SZ + IV_SZ]


def page1_stored_hmac(page1: bytes) -> bytes:
    return page1[PAGE_SZ - HMAC_SZ:PAGE_SZ]


def page1_hmac_ok(enc_key: bytes, page1: bytes) -> bool:
    """Verify a raw key against page 1 of an encrypted SQLCipher database."""
    if len(page1) < PAGE_SZ or len(enc_key) != KEY_SZ:
        return False
    mac_key = derive_mac_key(enc_key, page1[:SALT_SZ])
    digest = hmac.new(mac_key, page1_hmac_data(page1), hashlib.sha512)
    digest.update(struct.pack("<I", 1))
    return hmac.compare_digest(digest.digest(), page1_stored_hmac(page1))


def compute_page_hmac(mac_key: bytes, encrypted_page: bytes, pgno: int) -> bytes:
    """Compute the SQLCipher HMAC for an encrypted page (used by tests)."""
    if pgno == 1:
        data = encrypted_page[SALT_SZ:PAGE_SZ - RESERVE_SZ + IV_SZ]
    else:
        data = encrypted_page[:PAGE_SZ - RESERVE_SZ + IV_SZ]
    digest = hmac.new(mac_key, data, hashlib.sha512)
    digest.update(struct.pack("<I", pgno))
    return digest.digest()


def decrypt_page(enc_key: bytes, page_data: bytes, pgno: int) -> bytes:
    """Decrypt one SQLCipher page into a 4096-byte standard SQLite page."""
    iv = page_data[PAGE_SZ - RESERVE_SZ:PAGE_SZ - RESERVE_SZ + IV_SZ]
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    if pgno == 1:
        encrypted = page_data[SALT_SZ:PAGE_SZ - RESERVE_SZ]
        decrypted = cipher.decrypt(encrypted)
        return bytes(SQLITE_HDR + decrypted + b"\x00" * RESERVE_SZ)
    encrypted = page_data[:PAGE_SZ - RESERVE_SZ]
    decrypted = cipher.decrypt(encrypted)
    return decrypted + b"\x00" * RESERVE_SZ
