#!/usr/bin/env python3
"""导出指定会话或列出会话 — 消息解析与批量导出共用 wxexport.export.all。

用法：
    uv run python -m wxexport.export.chats --list
    uv run python -m wxexport.export.chats --username wxid_xxx --out ./out
    uv run python -m wxexport.export.chats --name "昵称或备注" --out ./out
"""
import argparse
import os
import sqlite3

from wxexport.export.all import (_connect, _md5, detect_my_wxid, export_one,
                                 get_decrypted_dir, get_message_dbs,
                                 load_contact_map)


def find_contacts(query):
    conn = _connect(os.path.join(get_decrypted_dir(), "contact", "contact.db"))
    rows = conn.execute("""
        SELECT username, nick_name, remark, alias FROM contact
        WHERE username = ? OR nick_name LIKE ? OR remark LIKE ? OR alias LIKE ?
    """, (query, f"%{query}%", f"%{query}%", f"%{query}%")).fetchall()
    conn.close()
    return rows


def list_conversations(top_n=20):
    """列出所有会话（按消息数排序），并映射出联系人显示名。"""
    contact_map = load_contact_map()
    table_to_username = {
        "Msg_" + _md5(u.encode()): u for u in contact_map}

    conversations = {}
    for db_path in get_message_dbs():
        conn = _connect(db_path)
        try:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
            ).fetchall()
            for (table_name,) in tables:
                try:
                    count, earliest, latest = conn.execute(f"""
                        SELECT COUNT(*),
                               datetime(MIN(create_time), 'unixepoch', 'localtime'),
                               datetime(MAX(create_time), 'unixepoch', 'localtime')
                        FROM {table_name} WHERE create_time > 0
                    """).fetchone()
                except sqlite3.Error:
                    continue
                if count == 0:
                    continue
                info = conversations.setdefault(
                    table_name, {"count": 0, "earliest": None, "latest": None})
                info["count"] += count
                if earliest and (not info["earliest"] or earliest < info["earliest"]):
                    info["earliest"] = earliest
                if latest and (not info["latest"] or latest > info["latest"]):
                    info["latest"] = latest
        finally:
            conn.close()

    print(f"\n{'排名':<4} {'消息数':<8} {'时间范围':<45} {'显示名':<20} {'用户名'}")
    print("-" * 120)
    for i, (table, info) in enumerate(
            sorted(conversations.items(), key=lambda x: -x[1]["count"])[:top_n], 1):
        username = table_to_username.get(table, table)
        display = contact_map.get(username, "(?)")
        time_range = f"{info['earliest']} ~ {info['latest']}"
        print(f"{i:<4} {info['count']:<8} {time_range:<45} {display:<20} {username}")

    print(f"\n共 {len(conversations)} 个会话")


def main():
    parser = argparse.ArgumentParser(description="导出/列出指定微信会话")
    parser.add_argument("--username", "-u", action="append", default=[],
                        help="精确用户名（wxid / xxx@chatroom），可多次指定")
    parser.add_argument("--name", "-n", action="append", default=[],
                        help="昵称/备注/微信号模糊查找，可多次指定")
    parser.add_argument("--out", "-o", help="输出根目录")
    parser.add_argument("--list", "-l", action="store_true",
                        help="列出所有会话（按消息数排序）")
    parser.add_argument("--top", type=int, default=20, help="列出前N个会话（默认20）")
    args = parser.parse_args()

    if args.list:
        list_conversations(args.top)
        return

    usernames = list(dict.fromkeys(args.username))
    for query in args.name:
        rows = find_contacts(query)
        if not rows:
            raise SystemExit(f'[!] 未找到匹配 "{query}" 的联系人')
        if len(rows) > 1:
            print(f'[!] "{query}" 匹配到 {len(rows)} 个联系人，请用 --username 精确指定:')
            for username, nick, remark, alias in rows:
                print(f"    {username}  (昵称: {nick}, 备注: {remark}, 微信号: {alias})")
            raise SystemExit(1)
        usernames.append(rows[0][0])

    if not usernames:
        parser.print_help()
        raise SystemExit(1)
    if not args.out:
        parser.error("--out 必填（或使用 --list）")

    contact_map = load_contact_map()
    my_wxid, _ = detect_my_wxid()

    # 目标会话的消息表所在的库
    tables = {"Msg_" + _md5(u.encode()) for u in usernames}
    found = set()
    for db_path in get_message_dbs():
        conn = _connect(db_path)
        found |= {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'")
        } & tables
        conn.close()

    seen_dirs = set()
    for username in usernames:
        table = "Msg_" + _md5(username.encode())
        if table not in found:
            print(f"[!] {username}: 本地消息库中无此会话"
                  + ("（数据可能只在手机上，需先迁移到电脑微信）" if table in tables else ""))
            continue
        display = contact_map.get(username, username)
        info = export_one(username, display, contact_map, my_wxid, seen_dirs,
                          chats_dir=args.out)
        if info:
            print(f"[+] {display}: {info['消息数']} 条, "
                  f"{info['开始']} ~ {info['结束']} -> {args.out}/{info['目录']}")
        else:
            print(f"[!] {display}: 无消息")


if __name__ == "__main__":
    main()
