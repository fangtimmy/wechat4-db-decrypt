"""Windows WeChat 4.x key acquisition.

Primary path (verified on 4.1.13.12 and 4.1.15.13): read-only scan of the
``com.Tencent.WCDB.Config.Cipher`` object.  The object exposes a small XOR
obfuscated blob containing ``x'<64hex key><32hex salt>'`` pairs; every
candidate is accepted only after a SQLCipher page-1 HMAC verification.

Fallbacks: legacy ``x'<hex>'`` scans (WeChat 4.0.x-4.1.9), passphrase
candidates expanded with PBKDF2-HMAC-SHA512 (256k rounds), and manually
supplied keys/passphrases.  The scanner never writes unverified keys.
"""
from __future__ import annotations

import json
import os
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from wxexport.keys.utils import secure_file
from wxexport.sqlcipher import (
    KEY_SZ, PAGE_SZ, SALT_SZ, derive_enc_key, page1_hmac_ok,
)
from wxexport.win import memory, profiles

Log = Callable[[str], None]

MAX_CONFIG_NODE = 0x50
MAX_BLOB_DEPTH = 0x28


@dataclass(frozen=True)
class Database:
    rel: str
    path: Path
    size: int
    page1: bytes

    @property
    def salt(self) -> bytes:
        return self.page1[:SALT_SZ]

    @property
    def salt_hex(self) -> str:
        return self.salt.hex()


@dataclass
class Inventory:
    db_dir: Path
    databases: list[Database] = field(default_factory=list)
    salt_to_dbs: dict[str, list[Database]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.databases:
            return
        for db in self.databases:
            self.salt_to_dbs.setdefault(db.salt_hex, []).append(db)

    def match(self, enc_key: bytes, salt_hex: str | None = None) -> list[Database]:
        if len(enc_key) != KEY_SZ:
            return []
        if salt_hex:
            targets = self.salt_to_dbs.get(salt_hex, [])
        else:
            targets = self.databases
        return [db for db in targets if page1_hmac_ok(enc_key, db.page1)]

    def reference_db(self) -> Database | None:
        for db in self.databases:
            if db.rel.endswith("message/message_0.db"):
                return db
        if not self.databases:
            return None
        return max(self.databases, key=lambda db: db.size)


@dataclass(frozen=True)
class Candidate:
    enc_key: bytes
    salt: bytes | None = None
    source: str = "unknown"
    priority: int = 50


@dataclass
class ScanStats:
    regions: int = 0
    bytes_scanned: int = 0
    needles: int = 0
    nodes: int = 0
    blobs: int = 0
    candidates: int = 0
    verified: int = 0
    elapsed: float = 0.0

    def summary(self) -> str:
        return (f"区域 {self.regions}，{self.bytes_scanned / 1024 / 1024:.0f}MB；"
                f"锚点 {self.needles}，节点 {self.nodes}，blob {self.blobs}，"
                f"候选 {self.candidates}，验证 {self.verified}；"
                f"{self.elapsed:.1f}s")


@dataclass
class HuntResult:
    inventory: Inventory
    mapping: dict[str, dict]
    stats: dict[str, ScanStats]
    missing: list[str]

    @property
    def complete(self) -> bool:
        return not self.missing


def collect_inventory(db_dir: Path | str) -> Inventory:
    root = Path(db_dir).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"数据库目录不存在: {root}")
    databases: list[Database] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if not name.endswith(".db") or name.endswith(("-wal", "-shm")):
                continue
            path = Path(dirpath) / name
            try:
                size = path.stat().st_size
                if size < PAGE_SZ:
                    continue
                with open(path, "rb") as stream:
                    page1 = stream.read(PAGE_SZ)
            except OSError:
                continue
            if len(page1) < PAGE_SZ:
                continue
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            databases.append(Database(rel, path, size, page1))
    databases.sort(key=lambda db: db.rel)
    return Inventory(root, databases)


def _probable_key(value: bytes) -> bool:
    return (len(value) == KEY_SZ
            and len(set(value)) >= 15
            and value != b"\x00" * KEY_SZ
            and value != b"\xff" * KEY_SZ)


def _xor_repeat(data: bytes, mask: bytes) -> bytes:
    if not mask:
        return data
    return bytes(value ^ mask[index % len(mask)]
                 for index, value in enumerate(data))


def _empty_mapping() -> dict[str, dict]:
    return {}


def _merge_mapping(target: dict[str, dict], source: dict[str, dict]) -> None:
    for rel, info in source.items():
        if rel not in target:
            target[rel] = info


def verify_candidates(candidates: Iterable[Candidate], inventory: Inventory,
                      existing: dict[str, dict] | None = None,
                      log: Log | None = None) -> dict[str, dict]:
    """Validate candidates and return ``{db_rel: key_info}``."""
    mapping = dict(existing or {})
    ordered = sorted(candidates, key=lambda item: item.priority)
    seen: set[tuple[bytes, bytes | None]] = set()
    for candidate in ordered:
        identity = (candidate.enc_key, candidate.salt)
        if identity in seen:
            continue
        seen.add(identity)
        salt_hex = candidate.salt.hex() if candidate.salt else None
        if salt_hex and salt_hex not in inventory.salt_to_dbs:
            continue
        targets = [db for db in inventory.databases
                   if db.rel not in mapping and (not salt_hex or db.salt_hex == salt_hex)]
        if not targets:
            continue
        for db in targets:
            if page1_hmac_ok(candidate.enc_key, db.page1):
                mapping[db.rel] = {
                    "enc_key": candidate.enc_key.hex(),
                    "salt": db.salt_hex,
                    "source": candidate.source,
                    "size_mb": round(db.size / 1024 / 1024, 1),
                }
                if log:
                    log(f"  [KEY] {db.rel} ← {candidate.source}")
    return mapping


def _candidates_from_blob(blob: bytes, source: str,
                          priority: int = 10) -> list[Candidate]:
    found: list[Candidate] = []
    seen: set[tuple[bytes, bytes | None]] = set()
    for match in profiles.CONFIG_KEY_RE.finditer(blob):
        run = match.group(1).decode("ascii", errors="ignore").lower()
        for start in profiles.candidate_hex_starts(len(run)):
            key_hex = run[start:start + 64]
            if len(key_hex) != 64:
                continue
            try:
                key = bytes.fromhex(key_hex)
            except ValueError:
                continue
            if not _probable_key(key):
                continue
            salt = None
            if len(run) >= start + 96:
                try:
                    salt = bytes.fromhex(run[start + 64:start + 96])
                except ValueError:
                    salt = None
            identity = (key, salt)
            if identity in seen:
                continue
            seen.add(identity)
            found.append(Candidate(key, salt, source, priority))
    return found


def _walk_config_objects(handle, regions: list[memory.Region],
                         profile: profiles.ConfigCipherProfile,
                         needle_addresses: set[int] | None = None):
    """Yield (node_address, config_ptr, blob) for Config.Cipher objects."""
    if needle_addresses is None:
        needle_addresses = memory.find_needle_addresses(
            handle, regions, profile.needle)
    if not needle_addresses:
        return
    pair_patterns = []
    seen_patterns = set()
    for address in needle_addresses:
        pattern = struct.pack("<QQ", address, len(profile.needle))
        if pattern not in seen_patterns:
            seen_patterns.add(pattern)
            pair_patterns.append(pattern)

    seen_blobs: set[tuple[int, int]] = set()
    for base, data in memory.iter_chunks(handle, regions, overlap=0x80):
        for pattern in pair_patterns:
            position = data.find(pattern)
            while position >= 0:
                qaddr = base + position
                node = memory.read_memory(
                    handle, qaddr - profile.node_back, MAX_CONFIG_NODE)
                if node and len(node) >= 0x40:
                    if (memory.read_u64(node, 0x10) in needle_addresses
                            and memory.read_u64(node, 0x18) == len(profile.needle)):
                        config_ptr = memory.read_u64(node, profile.config_ptr_offset)
                        if 0x10000 <= config_ptr < memory.MAX_USER_ADDRESS:
                            obj = memory.read_memory(
                                handle,
                                config_ptr + profile.blob_object_offset,
                                MAX_BLOB_DEPTH)
                            if obj and len(obj) >= 0x18:
                                data_ptr = memory.read_u64(
                                    obj, profile.blob_ptr_offset)
                                data_len = memory.read_u64(
                                    obj, profile.blob_len_offset)
                                if (0 < data_len <= profile.blob_max
                                        and 0x10000 <= data_ptr < memory.MAX_USER_ADDRESS):
                                    identity = (data_ptr, int(data_len))
                                    if identity not in seen_blobs:
                                        seen_blobs.add(identity)
                                        blob = memory.read_memory(
                                            handle, data_ptr, int(data_len))
                                        if blob and len(blob) == data_len:
                                            yield qaddr, config_ptr, blob
                position = data.find(pattern, position + 1)


def scan_config_cipher(handle, inventory: Inventory, version: str = "",
                       log: Log | None = None) -> tuple[dict[str, dict], ScanStats]:
    started = time.time()
    regions = memory.iter_regions(handle)
    stats = ScanStats(regions=len(regions),
                      bytes_scanned=sum(region.size for region in regions))
    candidates: list[Candidate] = []
    for profile in profiles.profiles_for(version):
        needles = memory.find_needle_addresses(handle, regions, profile.needle)
        stats.needles += len(needles)
        if log:
            log(f"[*] Config.Cipher: {profile.name}，锚点 {len(needles)}")
        for _node_addr, _config_ptr, blob in _walk_config_objects(
                handle, regions, profile, needles):
            stats.nodes += 1
            stats.blobs += 1
            for mask in profile.masks:
                decoded = _xor_repeat(blob, mask)
                candidates.extend(_candidates_from_blob(
                    decoded, f"config-cipher/{profile.name}"))
    stats.candidates = len(candidates)
    mapping = verify_candidates(candidates, inventory, log=log)
    stats.verified = len(mapping)
    stats.elapsed = time.time() - started
    return mapping, stats


def scan_legacy(handle, inventory: Inventory,
                log: Log | None = None) -> tuple[dict[str, dict], ScanStats]:
    started = time.time()
    regions = memory.iter_regions(handle)
    stats = ScanStats(regions=len(regions),
                      bytes_scanned=sum(region.size for region in regions))
    candidates: list[Candidate] = []
    seen: set[tuple[bytes, bytes | None]] = set()
    for _base, data in memory.iter_chunks(handle, regions, overlap=256):
        for match in profiles.LEGACY_HEX_RE.finditer(data):
            run = match.group(1).decode("ascii", errors="ignore").lower()
            for start in profiles.candidate_hex_starts(len(run)):
                key_hex = run[start:start + 64]
                if len(key_hex) != 64:
                    continue
                try:
                    key = bytes.fromhex(key_hex)
                except ValueError:
                    continue
                if not _probable_key(key):
                    continue
                salt = None
                if len(run) >= start + 96:
                    try:
                        salt = bytes.fromhex(run[start + 64:start + 96])
                    except ValueError:
                        salt = None
                identity = (key, salt)
                if identity in seen:
                    continue
                seen.add(identity)
                candidates.append(Candidate(key, salt, "legacy-memory", priority=20))
    stats.candidates = len(candidates)
    mapping = verify_candidates(candidates, inventory, log=log)
    stats.verified = len(mapping)
    stats.elapsed = time.time() - started
    return mapping, stats


def _passphrase_candidates(handle, regions: list[memory.Region],
                           profile: profiles.ConfigCipherProfile,
                           limit: int = 128) -> list[bytes]:
    """Collect plausible 32-byte passphrase candidates around Config.Cipher."""
    seen: set[bytes] = set()
    result: list[bytes] = []
    for address in memory.find_needle_addresses(handle, regions, profile.needle):
        window = memory.read_memory(handle, max(0, address - 128), 384)
        if not window:
            continue
        for start in range(0, len(window) - 31, 4):
            value = window[start:start + 32]
            if _probable_key(value) and value not in seen:
                seen.add(value)
                result.append(value)
                if len(result) >= limit:
                    return result
    return result


def scan_passphrases(handle, inventory: Inventory, version: str = "",
                     limit: int = 128,
                     log: Log | None = None) -> tuple[dict[str, dict], ScanStats]:
    """Best-effort passphrase fallback (slow: 256k PBKDF2 rounds per candidate)."""
    started = time.time()
    regions = memory.iter_regions(handle)
    stats = ScanStats(regions=len(regions),
                      bytes_scanned=sum(region.size for region in regions))
    reference = inventory.reference_db()
    if reference is None:
        return {}, stats
    candidates: list[bytes] = []
    for profile in profiles.profiles_for(version):
        candidates.extend(_passphrase_candidates(
            handle, regions, profile, limit=limit))
    candidates = list(dict.fromkeys(candidates))
    if log:
        log(f"[*] passphrase 候选: {len(candidates)}（PBKDF2 256k，可能较慢）")
    mapping: dict[str, dict] = {}
    for passphrase in candidates:
        enc_key = derive_enc_key(passphrase, reference.salt)
        if not page1_hmac_ok(enc_key, reference.page1):
            continue
        if log:
            log("[KEY] passphrase 已验证，开始派生全部数据库")
        derived = [Candidate(derive_enc_key(passphrase, db.salt), db.salt,
                             "passphrase", priority=30)
                   for db in inventory.databases]
        mapping = verify_candidates(derived, inventory, log=log)
        break
    stats.candidates = len(candidates)
    stats.verified = len(mapping)
    stats.elapsed = time.time() - started
    return mapping, stats


def _manual_candidate(value: str) -> Candidate | None:
    hex_value = str(value).strip().lower().lstrip("x").strip("'")
    if len(hex_value) < 64:
        return None
    try:
        raw = bytes.fromhex(hex_value)
    except ValueError:
        return None
    key = raw[:32]
    if not _probable_key(key):
        return None
    salt = raw[32:48] if len(raw) >= 48 else None
    return Candidate(key, salt, "manual", priority=0)


def _manual_entries(key_file: str | Path | None,
                    keys: Iterable[str] | None,
                    passphrase: str | None) -> tuple[list[Candidate], list[bytes]]:
    candidates: list[Candidate] = []
    passphrases: list[bytes] = []
    if key_file:
        path = Path(key_file).expanduser()
        text = path.read_text(encoding="utf-8")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            for rel, value in payload.items():
                if str(rel).startswith("_"):
                    continue
                if isinstance(value, dict):
                    value = value.get("enc_key") or value.get("key")
                if isinstance(value, str):
                    candidate = _manual_candidate(value)
                    if candidate:
                        candidates.append(candidate)
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, str):
                    candidate = _manual_candidate(item)
                    if candidate:
                        candidates.append(candidate)
        else:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                candidate = _manual_candidate(line.split()[-1])
                if candidate:
                    candidates.append(candidate)
    for value in keys or []:
        hex_value = value.strip()
        if "=" in hex_value:
            _rel, hex_value = hex_value.split("=", 1)
        candidate = _manual_candidate(hex_value)
        if candidate:
            candidates.append(candidate)
    if passphrase:
        try:
            passphrases.append(bytes.fromhex(passphrase.strip()))
        except ValueError:
            pass
    return candidates, passphrases


def _apply_manual(inventory: Inventory, key_file, keys, passphrase,
                  log: Log) -> dict[str, dict]:
    candidates, passphrases = _manual_entries(key_file, keys, passphrase)
    mapping = verify_candidates(candidates, inventory, log=log)
    for value in passphrases:
        derived = [Candidate(derive_enc_key(value, db.salt), db.salt,
                             "passphrase", priority=0)
                   for db in inventory.databases]
        mapping = verify_candidates(derived, inventory, mapping, log=log)
    return mapping


def hunt(db_dir: Path | str, *, version: str = "",
         strategies: str = "auto", deep: bool = False,
         key_file: str | Path | None = None,
         keys: Iterable[str] | None = None,
         passphrase: str | None = None,
         pid: int | None = None,
         log: Log | None = None) -> HuntResult:
    """Run the Windows key hunt and return verified per-DB keys."""
    log = log or (lambda _message: None)
    inventory = collect_inventory(db_dir)
    if not inventory.databases:
        raise RuntimeError(f"在 {db_dir} 未找到可解密的 .db 文件")
    log(f"[+] 数据库: {len(inventory.databases)} 个，"
        f"{len(inventory.salt_to_dbs)} 个不同 salt")

    mapping: dict[str, dict] = {}
    stats: dict[str, ScanStats] = {}
    if key_file or keys or passphrase:
        mapping = _apply_manual(inventory, key_file, keys, passphrase, log)
        if mapping:
            log(f"[+] 手动密钥验证通过: {len(mapping)} 个数据库")

    wanted = strategies
    if wanted == "auto":
        wanted = "config,legacy"
        if deep:
            wanted += ",passphrase"
    if "config" in wanted or "legacy" in wanted or "passphrase" in wanted:
        processes = memory.list_weixin_processes()
        if pid is not None:
            processes = [memory.ProcessInfo(pid, 0)] + [
                item for item in processes if item.pid != pid]
        if not processes:
            log("[!] Weixin.exe 未运行；只能使用手动密钥")
        handles = []
        try:
            for process in processes:
                try:
                    handle = memory.open_process(process.pid)
                except PermissionError as exc:
                    log(f"[!] {exc}")
                    continue
                handles.append(handle)
                log(f"[*] 扫描进程 PID={process.pid} "
                    f"({process.memory_kb // 1024}MB)")
                if "config" in wanted and len(mapping) < len(inventory.databases):
                    found, config_stats = scan_config_cipher(
                        handle, inventory, version, log=log)
                    _merge_mapping(mapping, found)
                    stats["config"] = config_stats
                    log(f"[+] Config.Cipher: {len(found)} 个，"
                        f"{config_stats.summary()}")
                if "legacy" in wanted and len(mapping) < len(inventory.databases):
                    found, legacy_stats = scan_legacy(handle, inventory, log=log)
                    _merge_mapping(mapping, found)
                    stats["legacy"] = legacy_stats
                    log(f"[+] legacy: {len(found)} 个，{legacy_stats.summary()}")
                if ("passphrase" in wanted
                        and len(mapping) < len(inventory.databases)):
                    found, pass_stats = scan_passphrases(
                        handle, inventory, version, log=log)
                    _merge_mapping(mapping, found)
                    stats["passphrase"] = pass_stats
                    log(f"[+] passphrase: {len(found)} 个，{pass_stats.summary()}")
                if len(mapping) >= len(inventory.databases):
                    break
        finally:
            for handle in handles:
                memory.close_process(handle)
    missing = [db.rel for db in inventory.databases if db.rel not in mapping]
    return HuntResult(inventory, mapping, stats, missing)


def write_outputs(result: HuntResult, *, keys_file: str | Path,
                  hunted_file: str | Path, metadata: dict | None = None) -> None:
    """Write ``all_keys.json`` and ``hunted_keys.txt``; no unverified keys."""
    payload: dict = dict(result.mapping)
    meta = {
        "platform": "windows",
        "db_dir": str(result.inventory.db_dir),
        "databases": len(result.inventory.databases),
        "matched": len(result.mapping),
        **(metadata or {}),
    }
    payload["_meta"] = meta
    keys_path = Path(keys_file).expanduser()
    keys_path.parent.mkdir(parents=True, exist_ok=True)
    keys_path.write_text(
        json.dumps(payload, indent=4, ensure_ascii=False) + "\n",
        encoding="utf-8")
    secure_file(keys_path)

    hunted_path = Path(hunted_file).expanduser()
    unique = sorted({info["enc_key"] for info in result.mapping.values()})
    hunted_path.write_text("\n".join(unique) + ("\n" if unique else ""),
                           encoding="utf-8")
    secure_file(hunted_path)
