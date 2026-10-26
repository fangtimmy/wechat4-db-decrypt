"""Version profiles for the read-only WCDB ``Config.Cipher`` key scan.

The layout below was verified against WeChat 4.1.13.12 and 4.1.15.13 on
Windows.  Tencent changes these offsets between releases, so every value is
kept in a profile and unknown versions fall back to trying all profiles plus
the legacy/raw scans.  All candidates are finally validated with the database
HMAC; no candidate is trusted merely because it was found at an offset.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

CONFIG_CIPHER_NEEDLE = b"com.Tencent.WCDB.Config.Cipher"
LEGACY_HEX_RE = re.compile(rb"[xX]'([0-9a-fA-F]{64,192})'")
CONFIG_KEY_RE = re.compile(rb"[xX]'([0-9a-fA-F]{64,192})'")

# The blob in current WCDB builds is XOR-obfuscated with this repeating mask.
CONFIG_CIPHER_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b"
    "450048844c2448488944254048584c24"
)


@dataclass(frozen=True)
class ConfigCipherProfile:
    name: str
    min_version: tuple[int, ...]
    max_version: tuple[int, ...]
    needle: bytes = CONFIG_CIPHER_NEEDLE
    node_back: int = 0x10
    config_ptr_offset: int = 0x28
    blob_object_offset: int = 0x88
    blob_ptr_offset: int = 0x08
    blob_len_offset: int = 0x10
    blob_max: int = 1024
    masks: tuple[bytes, ...] = (CONFIG_CIPHER_MASK, b"")

    def supports(self, version: tuple[int, ...]) -> bool:
        if not version:
            return True
        width = max(len(version), len(self.min_version), len(self.max_version))
        value = version + (0,) * (width - len(version))
        low = self.min_version + (0,) * (width - len(self.min_version))
        high = self.max_version + (0,) * (width - len(self.max_version))
        return low <= value <= high


# 4.1.13.12 and 4.1.15.13 are confirmed on real installations.  The range is
# intentionally conservative: the profile is tried for unknown versions too.
PROFILES: tuple[ConfigCipherProfile, ...] = (
    ConfigCipherProfile(
        name="wcdb-config-cipher-4.1.11+",
        min_version=(4, 1, 11, 0),
        max_version=(4, 1, 15, 99),
    ),
)


def parse_version(value: str) -> tuple[int, ...]:
    parts = []
    for piece in (value or "").strip().split("."):
        try:
            parts.append(int(piece))
        except ValueError:
            break
    return tuple(parts)


def profiles_for(version: str) -> tuple[ConfigCipherProfile, ...]:
    parsed = parse_version(version)
    matched = tuple(profile for profile in PROFILES if profile.supports(parsed))
    return matched or PROFILES


def candidate_hex_starts(length: int) -> Iterable[int]:
    yield 0
    if length > 96:
        for start in range(0, length - 63, 32):
            yield start
        yield length - 64
