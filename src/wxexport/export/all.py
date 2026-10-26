#!/usr/bin/env python3
"""批量导出全部会话 — TXT/CSV/JSON 三种格式。

特性：
  - 消息解析为结构化模型（wxexport.msgparse）：content 可读文本 + detail
    无损字段（聊天记录子项时间、引用原文、转账留言等），JSON/CSV 完整保留
  - 群聊发言人解析为昵称（通过联系人库）
  - 账号主人自动识别（跨会话出现频率最高的发送者）
  - 按 (create_time, sort_seq) 稳定排序
  - 输出 index.csv 总索引
"""
import argparse
import csv
import hashlib
import json
import os
import pathlib
import re
import shutil
import sqlite3
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone, timedelta

from wxexport.config import PROJECT_ROOT, load_config
from wxexport.msgparse import SYSTEM_TYPES, parse_message

DEFAULT_OUT_ROOT = os.path.join(PROJECT_ROOT, "exported_all")
CST = timezone(timedelta(hours=8))
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def get_decrypted_dir():
    return load_config()["decrypted_dir"]


def get_contact_db():
    return os.path.join(get_decrypted_dir(), "contact", "contact.db")


def _connect(path):
    conn = sqlite3.connect(path, timeout=30)
    try:
        conn.execute("PRAGMA busy_timeout=30000")
    except sqlite3.Error:
        pass
    return conn


def _md5(value):
    try:
        return hashlib.md5(value, usedforsecurity=False).hexdigest()
    except TypeError:  # pragma: no cover - Python < 3.9
        return hashlib.md5(value).hexdigest()


def get_message_dbs():
    msg_dir = os.path.join(get_decrypted_dir(), "message")
    dbs = []
    try:
        names = sorted(os.listdir(msg_dir))
    except OSError:
        return []
    for f in names:
        if re.fullmatch(r"message_\d+\.db", f):
            dbs.append(os.path.join(msg_dir, f))
    return dbs


def load_contact_map():
    conn = _connect(get_contact_db())
    m = {}
    for username, nick, remark in conn.execute(
            "SELECT username, nick_name, remark FROM contact"):
        m[username] = (remark or nick or username).strip() or username
    conn.close()
    return m


def detect_my_wxid():
    """账号主人 = 在最多不同会话中作为发送者出现的 wxid。"""
    table_senders = []
    for db_path in get_message_dbs():
        conn = _connect(db_path)
        try:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'")]
            name2id = {}
            try:
                name2id = dict(conn.execute("SELECT rowid, user_name FROM Name2Id"))
            except sqlite3.Error:
                pass
            for t in tables:
                try:
                    senders = conn.execute(
                        f"SELECT DISTINCT real_sender_id FROM {t}").fetchall()
                    wxids = {name2id.get(r[0], "") for r in senders} - {""}
                    if wxids:
                        table_senders.append(wxids)
                except sqlite3.Error:
                    continue
        finally:
            conn.close()
    counter = Counter()
    for senders in table_senders:
        for w in senders:
            counter[w] += 1
    if not counter:
        return None, 0
    wxid, n = counter.most_common(1)[0]
    return wxid, n


def sanitize(name, fallback):
    name = re.sub(r'[\\/:*?"<>|\r\n\t]', "_", name).strip(" .")[:80].rstrip(" .")
    if not name:
        return fallback
    if os.name == "nt" and name.split(".")[0].upper() in _WINDOWS_RESERVED:
        name = "_" + name
    return name


def export_one(username, display, contact_map, my_wxid, seen_dirs, chats_dir=None):
    table = "Msg_" + _md5(username.encode())
    out_name = sanitize(display, username)
    if out_name in seen_dirs:
        out_name = sanitize(f"{out_name}_{username}", username)
    seen_dirs.add(out_name)
    if chats_dir is None:
        raise ValueError("chats_dir is required")
    out_dir = os.path.join(chats_dir, out_name)
    os.makedirs(out_dir, exist_ok=True)

    messages = []
    for db_path in get_message_dbs():
        conn = _connect(db_path)
        try:
            name2id = {}
            try:
                name2id = dict(conn.execute("SELECT rowid, user_name FROM Name2Id"))
            except sqlite3.Error:
                pass
            try:
                rows = conn.execute(f"""
                    SELECT local_id, server_id, local_type, sort_seq,
                           create_time, real_sender_id,
                           message_content, WCDB_CT_message_content
                    FROM {table} ORDER BY create_time ASC, sort_seq ASC
                """).fetchall()
            except sqlite3.Error:
                rows = []
        finally:
            conn.close()
        is_chatroom = username.endswith("@chatroom")
        for local_id, server_id, type_id, sort_seq, ts, sender_id, content, ct in rows:
            sender_wxid = name2id.get(sender_id, "")
            if my_wxid and sender_wxid == my_wxid:
                sender = "我"
            elif type_id & 0xFFFFFFFF in SYSTEM_TYPES:
                sender = "系统"
            elif sender_wxid and sender_wxid in contact_map:
                sender = contact_map[sender_wxid]
            elif sender_wxid:
                sender = sender_wxid
            else:
                sender = display
            parsed = parse_message(type_id, content, ct, is_chatroom)
            messages.append({
                "time": datetime.fromtimestamp(ts, tz=CST).strftime(
                    "%Y-%m-%d %H:%M:%S") if ts else "",
                "timestamp": ts,
                "sort_seq": sort_seq,
                "local_id": local_id,
                "server_id": server_id,
                "sender": sender,
                "sender_wxid": sender_wxid or None,
                "is_self": bool(my_wxid and sender_wxid == my_wxid),
                "type": type_id,
                "subtype": parsed["sub"],
                "type_name": parsed["type_name"],
                "content": parsed["content"],
                "detail": parsed["detail"],
            })

    messages.sort(key=lambda x: (x["timestamp"] or 0, x["sort_seq"] or 0))
    if not messages:
        return None

    with open(os.path.join(out_dir, "chat.txt"), "w", encoding="utf-8") as f:
        f.write(f"微信聊天记录: {display} ({username})\n")
        f.write(f"总消息数: {len(messages)}\n")
        f.write(f"时间范围: {messages[0]['time']} ~ {messages[-1]['time']}\n")
        f.write("=" * 60 + "\n\n")
        for m in messages:
            f.write(f"[{m['time']}] {m['sender']}: {m['content']}\n")

    with open(os.path.join(out_dir, "chat.csv"), "w", encoding="utf-8-sig",
              newline="") as f:
        w = csv.writer(f)
        w.writerow(["时间", "发送者", "发送者wxid", "类型", "子类型", "内容", "详情"])
        for m in messages:
            detail = json.dumps(m["detail"], ensure_ascii=False,
                                separators=(",", ":")) if m["detail"] else ""
            w.writerow([m["time"], m["sender"], m["sender_wxid"] or "",
                        m["type_name"], m["subtype"], m["content"], detail])

    with open(os.path.join(out_dir, "chat.json"), "w", encoding="utf-8") as f:
        json.dump(messages, f, ensure_ascii=False)

    return {"目录": out_name, "消息数": len(messages),
            "开始": messages[0]["time"], "结束": messages[-1]["time"]}


def _path_key(path):
    return os.path.normcase(os.path.abspath(str(pathlib.Path(path).resolve(strict=False))))


def _move(source, destination):
    last_error = None
    for attempt in range(20):
        try:
            os.replace(source, destination)
            return
        except OSError as exc:
            last_error = exc
            time.sleep(0.1 * (attempt + 1))
    raise last_error


def _rmtree(path):
    for attempt in range(8):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(0.1 * (attempt + 1))


def main():
    parser = argparse.ArgumentParser(description="批量导出全部微信会话")
    parser.add_argument(
        "--output", default=DEFAULT_OUT_ROOT,
        help="导出目录（默认: 项目目录/exported_all）")
    args = parser.parse_args()

    # 聊天记录包含敏感数据；新建目录/文件仅允许当前用户访问。
    if hasattr(os, "umask"):
        os.umask(0o077)
    final_root = pathlib.Path(args.output).expanduser().absolute()
    protected = {_path_key(path) for path in (
        pathlib.Path("/"), pathlib.Path.home(),
        pathlib.Path.home() / "Desktop", pathlib.Path(PROJECT_ROOT),
    )}
    if _path_key(final_root) in protected:
        parser.error(f"拒绝使用受保护目录作为导出目标: {final_root}")
    if final_root.is_symlink():
        parser.error(f"导出目标不能是符号链接: {final_root}")
    if final_root.exists() and not final_root.is_dir():
        parser.error(f"导出目标已存在且不是目录: {final_root}")

    final_root.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    staging = pathlib.Path(tempfile.mkdtemp(
        prefix=f".{final_root.name}.tmp-", dir=final_root.parent))
    out_root = str(staging)
    chats_dir = str(staging / "chats")
    os.makedirs(chats_dir, mode=0o700, exist_ok=True)

    try:
        export_all(out_root, chats_dir)
        previous = None
        if final_root.exists():
            previous = final_root.with_name(
                f".{final_root.name}.previous-{os.getpid()}")
            if previous.exists():
                raise RuntimeError(f"临时备份路径已存在: {previous}")
            _move(final_root, previous)
        try:
            _move(staging, final_root)
        except Exception:
            if previous is not None:
                _move(previous, final_root)
            raise
        if previous is not None:
            _rmtree(previous)
    finally:
        if staging.exists():
            _rmtree(staging)

    print(f"[+] 输出目录: {final_root}")


def export_all(out_root, chats_dir):
    contact_map = load_contact_map()
    print(f"[+] 联系人表: {len(contact_map)} 条")

    my_wxid, n_tables = detect_my_wxid()
    if my_wxid:
        print(f"[+] 自动识别账号主人: {contact_map.get(my_wxid, my_wxid)} "
              f"({my_wxid})，出现于 {n_tables} 个会话")
    else:
        print("[!] 未能识别账号主人，群发送者标注可能不完全")
        my_wxid = ""

    md5_to_username = {}
    for username in contact_map:
        md5_to_username[_md5(username.encode())] = username

    conv_tables = set()
    for db_path in get_message_dbs():
        conn = _connect(db_path)
        for (t,) in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"):
            conv_tables.add(t)
        conn.close()

    usernames = [md5_to_username.get(t[4:], t[4:]) for t in conv_tables]
    print(f"[+] 待导出会话: {len(usernames)} 个")

    index_rows = []
    seen_dirs = set()
    done = 0
    for username in usernames:
        display = contact_map.get(username, username)
        try:
            info = export_one(
                username, display, contact_map, my_wxid, seen_dirs, chats_dir)
        except Exception as e:
            print(f"[!] {username} 导出失败: {e}")
            continue
        done += 1
        if info:
            index_rows.append({
                "显示名": display, "用户名": username,
                "消息数": info["消息数"], "开始": info["开始"],
                "结束": info["结束"], "目录": info["目录"],
            })
        if done % 40 == 0:
            print(f"  已导出 {done}/{len(usernames)}")

    index_rows.sort(key=lambda r: -r["消息数"])
    with open(os.path.join(out_root, "index.csv"), "w",
              encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(
            f, fieldnames=["显示名", "用户名", "消息数", "开始", "结束", "目录"])
        w.writeheader()
        w.writerows(index_rows)

    total = sum(r["消息数"] for r in index_rows)
    print(f"\n[+] 导出完成: {len(index_rows)} 个会话, 共 {total} 条消息")


if __name__ == "__main__":
    main()
