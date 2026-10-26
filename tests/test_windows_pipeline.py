"""Cross-platform pipeline tests using a synthetic SQLCipher fixture."""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests import fixtures
from wxexport.sqlcipher import PAGE_SZ, decrypt_page, page1_hmac_ok
from wxexport.win import keyscan, profiles
from wxexport.win import config as win_config

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "src"


class SqlCipherPrimitiveTest(unittest.TestCase):
    @unittest.skipUnless(fixtures.RESERVE_SUPPORTED,
                         "local SQLite lacks SQLITE_FCNTL_RESERVE_BYTES")
    def test_fixture_page_hmac_and_decrypt(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            keys = fixtures.build_encrypted_fixture(root)
            db_dir = root / "db_storage"
            page1 = (db_dir / "contact/contact.db").read_bytes()[:PAGE_SZ]
            key = bytes.fromhex(keys["contact/contact.db"])
            self.assertTrue(page1_hmac_ok(key, page1))
            self.assertFalse(page1_hmac_ok(b"\x00" * 32, page1))

            decrypted = decrypt_page(key, page1, 1)
            self.assertEqual(decrypted[:16], b"SQLite format 3\x00")
            self.assertEqual(len(decrypted), PAGE_SZ)

            # Page 2 decrypts into a normal SQLite page and the fixture is openable.
            decrypted_root = root / "decrypted"
            rel = "contact/contact.db"
            target = decrypted_root / rel
            target.parent.mkdir(parents=True)
            source = (db_dir / rel).read_bytes()
            target.write_bytes(b"".join(
                decrypt_page(key, source[i:i + PAGE_SZ], i // PAGE_SZ + 1)
                for i in range(0, len(source), PAGE_SZ)))
            conn = sqlite3.connect(target)
            try:
                self.assertIn("contact", [r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")])
            finally:
                conn.close()


class WindowsConfigTest(unittest.TestCase):
    def test_data_root_ini_and_documents_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            appdata = root / "appdata"
            home = root / "home"
            data_root = root / "wechat-data"
            config_dir = appdata / "Tencent" / "xwechat" / "config"
            config_dir.mkdir(parents=True)
            (config_dir / "abc.ini").write_text(str(data_root), encoding="utf-8")
            first = data_root / "xwechat_files" / "acc1" / "db_storage"
            second = home / "Documents" / "xwechat_files" / "acc2" / "db_storage"
            first.mkdir(parents=True)
            second.mkdir(parents=True)
            (second / "dummy.db").write_bytes(b"x")

            found = win_config.find_db_dirs(appdata=appdata, home=home)
            self.assertEqual(len(found), 2)
            self.assertEqual(found[0], second)
            self.assertEqual(win_config.account_label(second), "acc2")
            self.assertGreater(win_config.latest_mtime(second), 0)

    def test_env_config_override(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_path = root / "config.json"
            db_dir = root / "db_storage"
            db_dir.mkdir()
            config_path.write_text(json.dumps({
                "db_dir": str(db_dir),
                "keys_file": str(root / "keys.json"),
                "decrypted_dir": str(root / "decrypted"),
                "hunted_file": str(root / "hunted_keys.txt"),
                "snapshot_dir": "",
            }), encoding="utf-8")
            env = os.environ.copy()
            env["WXEXPORT_CONFIG"] = str(config_path)
            env["PYTHONPATH"] = str(SRC)
            code = (
                "from wxexport.config import load_config;"
                "c=load_config(required=False);"
                "print(c['db_dir']);print(c['decrypt_db_dir'])"
            )
            result = subprocess.run(
                [sys.executable, "-c", code], cwd=PROJECT_ROOT, env=env,
                capture_output=True, text=True, encoding="utf-8",
                errors="replace")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(Path(result.stdout.splitlines()[0]), db_dir)


class WindowsKeyCandidateTest(unittest.TestCase):
    def test_config_blob_candidate_and_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            keys = fixtures.build_encrypted_fixture(root)
            inventory = keyscan.collect_inventory(root / "db_storage")
            rel = "message/message_0.db"
            key_hex = keys[rel]
            db = next(item for item in inventory.databases if item.rel == rel)
            salt_hex = db.salt_hex
            raw = f"x'{key_hex}{salt_hex}'".encode()
            blob = bytes(
                value ^ profiles.CONFIG_CIPHER_MASK[index % len(profiles.CONFIG_CIPHER_MASK)]
                for index, value in enumerate(raw))
            decoded = bytes(
                value ^ profiles.CONFIG_CIPHER_MASK[index % len(profiles.CONFIG_CIPHER_MASK)]
                for index, value in enumerate(blob))
            self.assertEqual(decoded, raw)
            candidates = keyscan._candidates_from_blob(decoded, "test")
            self.assertTrue(candidates)
            mapping = keyscan.verify_candidates(candidates, inventory)
            self.assertIn(rel, mapping)
            self.assertEqual(mapping[rel]["enc_key"], key_hex)

    def test_manual_96_hex_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            keys = fixtures.build_encrypted_fixture(root)
            inventory = keyscan.collect_inventory(root / "db_storage")
            db = next(item for item in inventory.databases
                      if item.rel == "message/message_0.db")
            value = f"{keys[db.rel]}{db.salt_hex}"
            mapping = keyscan._apply_manual(inventory, None, [value], None, lambda _m: None)
            self.assertIn(db.rel, mapping)


@unittest.skipUnless(fixtures.RESERVE_SUPPORTED,
                     "local SQLite lacks SQLITE_FCNTL_RESERVE_BYTES")
class WindowsPipelineTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.keys = fixtures.build_encrypted_fixture(self.root)
        self.db_dir = self.root / "db_storage"
        self.hunted = self.root / "hunted_keys.txt"
        self.hunted.write_text("\n".join(self.keys.values()) + "\n", encoding="utf-8")
        self.config = self.root / "config.json"
        self.keys_file = self.root / "all_keys.json"
        self.decrypted = self.root / "decrypted"
        fixtures.write_config(self.config, self.db_dir, self.keys_file,
                              self.decrypted, self.hunted)
        self.env = os.environ.copy()
        self.env.update({
            "PYTHONPATH": str(SRC),
            "WXEXPORT_CONFIG": str(self.config),
            "PYTHONIOENCODING": "utf-8",
        })

    def tearDown(self):
        self.temp.cleanup()

    def run_module(self, *args):
        result = subprocess.run(
            [sys.executable, "-m", *args],
            cwd=PROJECT_ROOT, env=self.env, capture_output=True,
            text=True, encoding="utf-8", errors="replace")
        self.assertEqual(result.returncode, 0,
                         f"{args}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
        return result

    def test_full_pipeline(self):
        self.run_module("wxexport.keys.map")
        payload = json.loads(self.keys_file.read_text(encoding="utf-8"))
        self.assertEqual(payload["_meta"]["matched"], 2)
        self.assertIn("message/message_0.db", payload)
        self.assertIn("contact/contact.db", payload)

        self.run_module("wxexport.decrypt")
        conn = sqlite3.connect(self.decrypted / "contact" / "contact.db")
        try:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM contact").fetchone()[0], 4)
        finally:
            conn.close()

        output = self.root / "exported"
        self.run_module("wxexport.export.all", "--output", str(output))
        friend = output / "chats" / "Friend One" / "chat.txt"
        group = output / "chats" / "Test Group" / "chat.txt"
        self.assertTrue(friend.is_file())
        self.assertTrue(group.is_file())
        friend_text = friend.read_text(encoding="utf-8")
        group_text = group.read_text(encoding="utf-8")
        self.assertIn("hello from me", friend_text)
        self.assertIn("我: hello from me", friend_text)
        self.assertIn("hi there", friend_text)
        self.assertIn("[链接] Example Link", friend_text)
        self.assertIn("hello group", group_text)
        self.assertIn("Friend One: hello group", group_text)
        self.assertIn("我: my group message", group_text)
        self.assertIn("[图片]", group_text)
        self.assertTrue((output / "index.csv").is_file())
        detail_rows = list((output / "chats" / "Friend One" / "chat.csv")
                           .read_text(encoding="utf-8-sig").splitlines())
        self.assertGreater(len(detail_rows), 3)


class SnapshotTest(unittest.TestCase):
    def test_snapshot_copy_and_refresh(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "a.db").write_bytes(b"a" * 16)
            (source / "a.db-wal").write_bytes(b"w" * 16)
            destination = root / "snapshot"
            from wxexport.win.snapshot import prepare_snapshot
            created = prepare_snapshot(source, destination, version="4.1.15.13",
                                       log=lambda _m: None)
            self.assertTrue((created / "a.db").is_file())
            self.assertTrue((created / ".snapshot.json").is_file())
            (source / "b.db").write_bytes(b"b" * 16)
            prepare_snapshot(source, destination, version="4.1.15.13",
                             log=lambda _m: None)
            self.assertFalse((created / "b.db").exists())
            prepare_snapshot(source, destination, version="4.1.15.13",
                             refresh=True, log=lambda _m: None)
            self.assertTrue((created / "b.db").is_file())


if __name__ == "__main__":
    unittest.main()
