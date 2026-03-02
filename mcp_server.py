r"""
WeChat MCP Server - query WeChat messages, contacts via Claude

Based on FastMCP (stdio transport), reuses existing decryption.
Runs on Windows Python (needs access to D:\ WeChat databases).
"""

import os, sys, json, re, time, sqlite3, tempfile, hashlib, atexit
from datetime import datetime
from mcp.server.fastmcp import FastMCP

from crypto_params import PAGE_SZ, full_decrypt, decrypt_wal, SQLITE_HDR, WAL_HEADER_SZ, WAL_FRAME_HEADER_SZ
from session_parser import parse_session_info
from msg_format import format_msg_type, format_summary, resolve_sender_display

# ============ 配置加载 ============
from config import load_config
_cfg = load_config()
DB_DIR = _cfg["db_dir"]
KEYS_FILE = _cfg["keys_file"]
DECRYPTED_DIR = _cfg["decrypted_dir"]

with open(KEYS_FILE) as f:
    ALL_KEYS = json.load(f)

# ============ DB 缓存 ============

class DBCache:
    """缓存解密后的 DB，通过 mtime 检测变化"""

    def __init__(self):
        self._cache = {}  # rel_key -> (db_mtime, wal_mtime, tmp_path)

    def get(self, rel_key):
        if rel_key not in ALL_KEYS:
            return None
        db_path = os.path.join(DB_DIR, rel_key)
        wal_path = db_path + "-wal"
        if not os.path.exists(db_path):
            return None

        try:
            db_mtime = os.path.getmtime(db_path)
            wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
        except OSError:
            return None

        if rel_key in self._cache:
            c_db_mt, c_wal_mt, c_path = self._cache[rel_key]
            if c_db_mt == db_mtime and c_wal_mt == wal_mtime and os.path.exists(c_path):
                return c_path
            try:
                os.unlink(c_path)
            except OSError:
                pass

        enc_key = bytes.fromhex(ALL_KEYS[rel_key]["enc_key"])
        fd, tmp_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        full_decrypt(db_path, tmp_path, enc_key)
        if os.path.exists(wal_path):
            decrypt_wal(wal_path, tmp_path, enc_key)
        self._cache[rel_key] = (db_mtime, wal_mtime, tmp_path)
        return tmp_path

    def cleanup(self):
        for _, _, path in self._cache.values():
            try:
                os.unlink(path)
            except OSError:
                pass
        self._cache.clear()


_cache = DBCache()
atexit.register(_cache.cleanup)


# ============ 联系人缓存 ============

_contact_names = None  # {username: display_name}
_contact_full = None   # [{username, nick_name, remark}]
_session_names = None  # {username: display_name} from Session protobuf


def _load_contacts_from(db_path):
    names = {}
    full = []
    conn = sqlite3.connect(db_path)
    try:
        for r in conn.execute("SELECT m_nsUsrName, nickname, m_nsRemark FROM WCContact").fetchall():
            uname, nick, remark = r
            display = remark if remark else nick if nick else uname
            names[uname] = display
            full.append({'username': uname, 'nick_name': nick or '', 'remark': remark or ''})
    finally:
        conn.close()
    return names, full


def _merge_group_members(names):
    """將 GroupMember 暱稱合併進 names（WCContact 優先，不覆蓋）"""
    pre_decrypted = os.path.join(DECRYPTED_DIR, "Group", "group_new.db")
    group_db = pre_decrypted if os.path.exists(pre_decrypted) else _cache.get("Group/group_new.db")
    if not group_db:
        return
    try:
        conn = sqlite3.connect(group_db)
        for uname, nick in conn.execute("SELECT m_nsUsrName, nickname FROM GroupMember").fetchall():
            if uname not in names and nick:
                names[uname] = nick
        conn.close()
    except Exception:
        pass


def get_contact_names():
    global _contact_names, _contact_full
    if _contact_names is not None:
        return _contact_names

    # 優先用已解密的 wccontact_new2.db
    pre_decrypted = os.path.join(DECRYPTED_DIR, "Contact", "wccontact_new2.db")
    if os.path.exists(pre_decrypted):
        try:
            _contact_names, _contact_full = _load_contacts_from(pre_decrypted)
            _merge_group_members(_contact_names)
            return _contact_names
        except Exception:
            pass

    # 實時解密
    path = _cache.get("Contact/wccontact_new2.db")
    if path:
        try:
            _contact_names, _contact_full = _load_contacts_from(path)
            _merge_group_members(_contact_names)
            return _contact_names
        except Exception:
            pass

    return {}


def get_contact_full():
    global _contact_full
    if _contact_full is None:
        get_contact_names()
    return _contact_full or []


# ============ 辅助函数 ============

def _get_session_names():
    global _session_names
    if _session_names is not None:
        return _session_names
    _session_names = {}
    path = _cache.get("Session/session_new.db")
    if not path:
        return _session_names
    conn = sqlite3.connect(path)
    try:
        for username, blob in conn.execute(
            "SELECT m_nsUserName, _packed_MMSessionInfo FROM SessionAbstract WHERE m_uLastTime > 0"
        ).fetchall():
            name = parse_session_info(blob).get('display_name', '')
            if name:
                _session_names[username] = name
    except Exception:
        pass
    finally:
        conn.close()
    return _session_names


def resolve_username(chat_name):
    """将聊天名/备注名/wxid 解析为 username"""
    names = get_contact_names()

    if chat_name in names or chat_name.startswith('wxid_') or '@chatroom' in chat_name:
        return chat_name

    chat_lower = chat_name.lower()
    for uname, display in names.items():
        if chat_lower == display.lower():
            return uname
    for uname, display in names.items():
        if chat_lower in display.lower():
            return uname

    session_names = _get_session_names()
    for uname, display in session_names.items():
        if chat_lower == display.lower():
            return uname
    for uname, display in session_names.items():
        if chat_lower in display.lower():
            return uname

    return None


def _parse_message_content(content, local_type, is_group):
    """解析消息内容，返回 (sender_id, text)"""
    if content is None:
        return '', ''
    if isinstance(content, bytes):
        return '', '(压缩内容)'

    sender = ''
    text = content
    if is_group and ':\n' in content:
        sender, text = content.split(':\n', 1)

    return sender, text


# 消息 DB 的 rel_keys（排除 fts/resource/media/biz）
MSG_DB_KEYS = sorted([
    k for k in ALL_KEYS
    if k.startswith("Message/msg_") and k.endswith(".db")
    and "fts" not in k and "resource" not in k
])


def _find_msg_table_for_user(username):
    """在所有 message_N.db 中查找用户的消息表，返回 (db_path, table_name)"""
    table_hash = hashlib.md5(username.encode()).hexdigest()
    table_name = f"Chat_{table_hash}"

    for rel_key in MSG_DB_KEYS:
        path = _cache.get(rel_key)
        if not path:
            continue
        conn = sqlite3.connect(path)
        try:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,)
            ).fetchone()
            if exists:
                conn.close()
                return path, table_name
        except Exception:
            pass
        finally:
            conn.close()

    return None, None


# ============ MCP Server ============

mcp = FastMCP("wechat", instructions="查询微信消息、联系人等数据")

# 新消息追踪
_last_check_state = {}  # {username: last_timestamp}


@mcp.tool()
def get_recent_sessions(limit: int = 20) -> str:
    """获取微信最近会话列表，包含最新消息摘要、未读数、时间等。
    用于了解最近有哪些人/群在聊天。

    Args:
        limit: 返回的会话数量，默认20
    """
    path = _cache.get("Session/session_new.db")
    if not path:
        return json.dumps({"error": "无法解密 session_new.db"}, ensure_ascii=False)

    names = get_contact_names()
    conn = sqlite3.connect(path)
    rows = conn.execute("""
        SELECT m_nsUserName, m_uUnReadCount, m_uLastTime, _packed_MMSessionInfo
        FROM SessionAbstract
        WHERE m_uLastTime > 0
        ORDER BY m_uLastTime DESC
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()

    sessions = []
    for r in rows:
        username, unread, ts, blob = r
        info = parse_session_info(blob)
        display = names.get(username) or info.get('display_name') or username
        is_group = '@chatroom' in username
        sender_display = resolve_sender_display(info.get('mes_des', -1), username, info['sender'], names)
        sessions.append({
            "username": username, "display": display, "is_group": is_group,
            "unread": unread or 0,
            "time": datetime.fromtimestamp(ts).strftime('%m-%d %H:%M'),
            "timestamp": ts,
            "type": format_msg_type(info['msg_type']),
            "sender": sender_display,
            "content": format_summary(info['msg_type'], info['summary']) or "",
        })
    return json.dumps({"count": len(sessions), "sessions": sessions}, ensure_ascii=False)


@mcp.tool()
def get_chat_history(chat_name: str, limit: int = 50) -> str:
    """获取指定聊天的消息记录。

    Args:
        chat_name: 聊天对象的名字、备注名或wxid，自动模糊匹配
        limit: 返回的消息数量，默认50
    """
    username = resolve_username(chat_name)
    if not username:
        return json.dumps({"error": f"找不到聊天对象: {chat_name}"}, ensure_ascii=False)

    names = get_contact_names()
    display_name = names.get(username, username)
    is_group = '@chatroom' in username

    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return json.dumps({"username": username, "display": display_name, "count": 0, "messages": [], "error": "找不到消息记录"}, ensure_ascii=False)

    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(f"""
            SELECT messageType, msgCreateTime, msgContent, mesDes
            FROM [{table_name}]
            ORDER BY msgCreateTime DESC
            LIMIT ?
        """, (limit,)).fetchall()
    except Exception as e:
        conn.close()
        return json.dumps({"error": f"查询失败: {e}"}, ensure_ascii=False)
    conn.close()

    if not rows:
        return json.dumps({"username": username, "display": display_name, "count": 0, "messages": []}, ensure_ascii=False)

    messages = []
    for local_type, create_time, content, mes_des in reversed(rows):
        time_str = datetime.fromtimestamp(create_time).strftime('%m-%d %H:%M')
        sender, text = _parse_message_content(content, local_type, is_group)

        if local_type != 1:
            text = format_summary(local_type, text)

        if text and len(text) > 500:
            text = text[:500] + "..."

        sender_label = resolve_sender_display(mes_des, username, sender, names)
        messages.append({
            "time": time_str, "sender": sender_label,
            "type": format_msg_type(local_type), "content": text,
        })

    return json.dumps({
        "username": username, "display": display_name, "is_group": is_group,
        "count": len(messages), "limit": limit, "has_more": len(rows) == limit,
        "messages": messages,
    }, ensure_ascii=False)


@mcp.tool()
def search_messages(keyword: str, limit: int = 20) -> str:
    """在所有聊天记录中搜索包含关键词的消息。

    Args:
        keyword: 搜索关键词
        limit: 返回的结果数量，默认20
    """
    if not keyword or len(keyword) < 1:
        return json.dumps({"error": "请提供搜索关键词"}, ensure_ascii=False)

    names = get_contact_names()
    results = []

    for rel_key in MSG_DB_KEYS:
        if len(results) >= limit:
            break

        path = _cache.get(rel_key)
        if not path:
            continue

        conn = sqlite3.connect(path)
        try:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Chat_%'"
            ).fetchall()

            name2id = {}
            try:
                for r in conn.execute("SELECT user_name FROM Name2Id").fetchall():
                    h = hashlib.md5(r[0].encode()).hexdigest()
                    name2id[f"Chat_{h}"] = r[0]
            except Exception:
                pass

            for (tname,) in tables:
                if len(results) >= limit:
                    break
                username = name2id.get(tname, '')
                is_group = '@chatroom' in username
                display = names.get(username, username) if username else tname

                try:
                    rows = conn.execute(f"""
                        SELECT messageType, msgCreateTime, msgContent, mesDes
                        FROM [{tname}]
                        WHERE msgContent LIKE ?
                        ORDER BY msgCreateTime DESC
                        LIMIT ?
                    """, (f'%{keyword}%', limit - len(results))).fetchall()
                except Exception:
                    continue

                for local_type, ts, content, mes_des in rows:
                    sender, text = _parse_message_content(content, local_type, is_group)
                    if local_type != 1:
                        text = format_summary(local_type, text)
                    if text and len(text) > 300:
                        text = text[:300] + "..."
                    time_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')
                    sender_label = resolve_sender_display(mes_des, username, sender, names)
                    results.append((ts, {
                        "time": time_str, "chat": display, "username": username,
                        "sender": sender_label, "content": text,
                    }))
        finally:
            conn.close()

    results.sort(key=lambda x: x[0], reverse=True)
    entries = [r[1] for r in results[:limit]]

    return json.dumps({
        "keyword": keyword, "count": len(entries), "limit": limit,
        "has_more": len(entries) == limit, "results": entries,
    }, ensure_ascii=False)


@mcp.tool()
def get_contacts(query: str = "", limit: int = 50) -> str:
    """搜索或列出微信联系人。

    Args:
        query: 搜索关键词（匹配昵称、备注名、wxid），留空列出所有
        limit: 返回数量，默认50
    """
    contacts = get_contact_full()
    if not contacts:
        return json.dumps({"error": "无法加载联系人数据"}, ensure_ascii=False)

    if query:
        q = query.lower()
        filtered = [
            c for c in contacts
            if q in c['nick_name'].lower()
            or q in c['remark'].lower()
            or q in c['username'].lower()
        ]
    else:
        filtered = contacts

    filtered = filtered[:limit]

    return json.dumps({
        "query": query, "count": len(filtered),
        "contacts": [{"username": c["username"], "nick_name": c["nick_name"], "remark": c["remark"]} for c in filtered],
    }, ensure_ascii=False)


@mcp.tool()
def get_new_messages() -> str:
    """获取自上次调用以来的新消息。首次调用返回最近的会话状态。"""
    global _last_check_state

    path = _cache.get("Session/session_new.db")
    if not path:
        return json.dumps({"error": "无法解密 session_new.db"}, ensure_ascii=False)

    names = get_contact_names()
    conn = sqlite3.connect(path)
    rows = conn.execute("""
        SELECT m_nsUserName, m_uUnReadCount, m_uLastTime, _packed_MMSessionInfo
        FROM SessionAbstract
        WHERE m_uLastTime > 0
        ORDER BY m_uLastTime DESC
    """).fetchall()
    conn.close()

    curr_state = {}
    for r in rows:
        username, unread, ts, blob = r
        info = parse_session_info(blob)
        curr_state[username] = {
            'unread': unread or 0, 'summary': info['summary'], 'timestamp': ts,
            'msg_type': info['msg_type'], 'sender': info['sender'],
            'mes_des': info.get('mes_des', -1),
            'display_name': info.get('display_name', ''),
        }

    if not _last_check_state:
        _last_check_state = {u: s['timestamp'] for u, s in curr_state.items()}
        unread_list = []
        for username, s in curr_state.items():
            if s['unread'] and s['unread'] > 0:
                display = names.get(username) or s.get('display_name') or username
                unread_list.append({
                    "username": username, "display": display,
                    "is_group": '@chatroom' in username,
                    "unread": s['unread'],
                    "time": datetime.fromtimestamp(s['timestamp']).strftime('%H:%M'),
                    "type": format_msg_type(s['msg_type']),
                    "content": format_summary(s['msg_type'], s['summary']),
                })
        return json.dumps({"first_call": True, "count": len(unread_list), "unread": unread_list}, ensure_ascii=False)

    new_msgs = []
    for username, s in curr_state.items():
        prev_ts = _last_check_state.get(username, 0)
        if s['timestamp'] > prev_ts:
            display = names.get(username) or s.get('display_name') or username
            sender_display = resolve_sender_display(s.get('mes_des', -1), username, s['sender'], names)
            new_msgs.append((s['timestamp'], {
                "username": username, "display": display,
                "is_group": '@chatroom' in username,
                "time": datetime.fromtimestamp(s['timestamp']).strftime('%H:%M:%S'),
                "timestamp": s['timestamp'],
                "type": format_msg_type(s['msg_type']),
                "sender": sender_display,
                "content": format_summary(s['msg_type'], s['summary']),
            }))

    _last_check_state = {u: s['timestamp'] for u, s in curr_state.items()}

    new_msgs.sort(key=lambda x: x[0])
    entries = [m[1] for m in new_msgs]
    return json.dumps({"first_call": False, "count": len(entries), "messages": entries}, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run()
