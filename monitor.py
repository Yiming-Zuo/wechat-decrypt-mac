"""
微信实时消息监听器 (macOS)

原理: 定期解密 session_new.db (< 1秒), 检测新消息
session_new.db 包含每个聊天的最新消息摘要、发送者、时间戳
"""
import os, sys, json, time, sqlite3, io
from datetime import datetime

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import functools
print = functools.partial(print, flush=True)

from crypto_params import PAGE_SZ, decrypt_page
from config import load_config
from session_parser import parse_session_info
from msg_format import format_msg_type, format_summary, resolve_sender_display

_cfg = load_config()
DB_DIR = _cfg["db_dir"]
KEYS_FILE = _cfg["keys_file"]
CONTACT_CACHE = os.path.join(_cfg["decrypted_dir"], "Contact", "wccontact_new2.db")
GROUP_CACHE = os.path.join(_cfg["decrypted_dir"], "Group", "group_new.db")

POLL_INTERVAL = 3  # 秒

SESSION_KEY = "Session/session_new.db"
SESSION_REL = "Session/session_new.db"


def decrypt_db_to_memory(db_path, enc_key):
    file_size = os.path.getsize(db_path)
    total_pages = file_size // PAGE_SZ
    if file_size % PAGE_SZ != 0:
        total_pages += 1

    chunks = []
    with open(db_path, 'rb') as fin:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                if len(page) > 0:
                    page = page + b'\x00' * (PAGE_SZ - len(page))
                else:
                    break
            chunks.append(decrypt_page(enc_key, page, pgno))

    return b''.join(chunks)


def decrypt_db_to_sqlite(db_path, enc_key):
    data = decrypt_db_to_memory(db_path, enc_key)
    tmp_path = db_path + ".tmp_monitor"
    with open(tmp_path, 'wb') as f:
        f.write(data)
    conn = sqlite3.connect(tmp_path)
    conn.row_factory = sqlite3.Row
    return conn, tmp_path


def load_contact_names():
    names = {}
    if not os.path.exists(CONTACT_CACHE):
        return names
    try:
        conn = sqlite3.connect(CONTACT_CACHE)
        # macOS 微信联系人表可能是 WCContact，fallback contact
        rows = conn.execute(
            "SELECT m_nsUsrName, nickname, m_nsRemark FROM WCContact"
        ).fetchall()
        for uname, nick, remark in rows:
            names[uname] = remark if remark else nick if nick else uname
        conn.close()
    except Exception as e:
        print(f"[WARN] 加载联系人失败: {e}")
    try:
        conn = sqlite3.connect(GROUP_CACHE)
        for uname, nick in conn.execute("SELECT m_nsUsrName, nickname FROM GroupMember").fetchall():
            if uname not in names and nick:
                names[uname] = nick
        conn.close()
    except Exception:
        pass
    return names


def get_session_state(conn):
    state = {}
    try:
        rows = conn.execute("""
            SELECT m_nsUserName, m_uUnReadCount, m_uLastTime, _packed_MMSessionInfo
            FROM SessionAbstract
            WHERE m_uLastTime > 0
        """).fetchall()
        for r in rows:
            info = parse_session_info(r[3])
            state[r[0]] = {
                'unread': r[1] or 0,
                'summary': info['summary'],
                'timestamp': r[2],
                'msg_type': info['msg_type'],
                'sender': info['sender'],
                'mes_des': info.get('mes_des', -1),
                'display_name': info.get('display_name', ''),
            }
    except Exception as e:
        print(f"[ERROR] 读取 session 失败: {e}")
    return state


def main():
    print("=" * 60)
    print("  微信实时消息监听器 (macOS)")
    print("=" * 60)

    with open(KEYS_FILE) as f:
        keys = json.load(f)

    session_key_info = keys.get(SESSION_KEY)
    if not session_key_info:
        print(f"[ERROR] 找不到 {SESSION_KEY} 的密钥")
        sys.exit(1)

    enc_key = bytes.fromhex(session_key_info["enc_key"])
    session_db = os.path.join(DB_DIR, SESSION_REL)

    print("加载联系人...")
    contact_names = load_contact_names()
    print(f"已加载 {len(contact_names)} 个联系人")

    print("读取初始状态...")
    conn, tmp_path = decrypt_db_to_sqlite(session_db, enc_key)
    prev_state = get_session_state(conn)
    conn.close()
    os.remove(tmp_path)

    print(f"跟踪 {len(prev_state)} 个会话")
    print(f"轮询间隔: {POLL_INTERVAL}秒")
    print(f"\n{'='*60}")
    print("开始监听... (Ctrl+C 停止)\n")

    poll_count = 0
    try:
        while True:
            time.sleep(POLL_INTERVAL)
            poll_count += 1

            try:
                conn, tmp_path = decrypt_db_to_sqlite(session_db, enc_key)
                curr_state = get_session_state(conn)
                conn.close()
                os.remove(tmp_path)
            except Exception as e:
                if poll_count % 10 == 0:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] 读取失败: {e}")
                continue

            for username, curr in curr_state.items():
                prev = prev_state.get(username)

                if prev is None:
                    display = contact_names.get(username) or curr.get('display_name') or username
                    ts = datetime.fromtimestamp(curr['timestamp']).strftime('%H:%M:%S')
                    summary = format_summary(curr['msg_type'], curr['summary'])
                    print(f"[{ts}] 新会话 [{display}]")
                    print(f"  {summary}")
                    print()
                    continue

                if curr['timestamp'] > prev['timestamp']:
                    display = contact_names.get(username) or curr.get('display_name') or username
                    ts = datetime.fromtimestamp(curr['timestamp']).strftime('%H:%M:%S')
                    msg_type_label = format_msg_type(curr['msg_type'])
                    sender = resolve_sender_display(
                        curr.get('mes_des', -1), username, curr['sender'], contact_names
                    )

                    if sender:
                        print(f"[{ts}] [{display}] {sender}:")
                    else:
                        print(f"[{ts}] [{display}]")

                    summary = format_summary(curr['msg_type'], curr['summary'])
                    print(f"  [{msg_type_label}] {summary}")

                    if curr['unread'] > 0:
                        print(f"  (未读: {curr['unread']})")
                    print()

            prev_state = curr_state

            if poll_count % 20 == 0:
                now = datetime.now().strftime('%H:%M:%S')
                print(f"--- {now} 运行中 (第{poll_count}次轮询) ---")

    except KeyboardInterrupt:
        print(f"\n监听结束, 共 {poll_count} 次轮询")

    tmp = session_db + ".tmp_monitor"
    if os.path.exists(tmp):
        os.remove(tmp)


if __name__ == '__main__':
    main()
