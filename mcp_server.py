import contextlib, hashlib, json, logging, os, re, sqlite3, sys, tempfile, atexit
from datetime import datetime
from mcp.server.fastmcp import FastMCP

from crypto_params import full_decrypt, decrypt_wal
from session_parser import parse_session_info
from msg_format import format_msg_type, format_summary, resolve_sender_display
from config import load_config

logging.basicConfig(stream=sys.stderr, level=logging.WARNING,
                    format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

# ============ 配置加载 ============

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
        try:
            full_decrypt(db_path, tmp_path, enc_key)
            if os.path.exists(wal_path):
                decrypt_wal(wal_path, tmp_path, enc_key)
        except Exception:
            logger.error("解密失败: %s", rel_key, exc_info=True)
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return None
        self._cache[rel_key] = (db_mtime, wal_mtime, tmp_path)
        return tmp_path

    def mtime_of(self, rel_key):
        """返回 DB 当前的 (db_mtime, wal_mtime)，用于外部缓存失效判断"""
        db_path = os.path.join(DB_DIR, rel_key)
        wal_path = db_path + "-wal"
        try:
            db_mt = os.path.getmtime(db_path) if os.path.exists(db_path) else 0
            wal_mt = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
            return db_mt, wal_mt
        except OSError:
            return 0, 0

    def cleanup(self):
        for _, _, path in self._cache.values():
            try:
                os.unlink(path)
            except OSError:
                pass
        self._cache.clear()


_cache = DBCache()
atexit.register(_cache.cleanup)


# ============ 联系人缓存（带 mtime 失效） ============

_contact_names = None       # {username: display_name}
_contact_full = None        # [{username, nick_name, remark}]
_contact_mtime = (0, 0)    # (db_mtime, wal_mtime) of wccontact_new2.db

_session_names = None       # {username: display_name}
_session_mtime = (0, 0)    # (db_mtime, wal_mtime) of session_new.db

_hash2username = None       # {Chat_<md5>: username}
_hash2_sources_mtime = {}  # {rel_key: (db_mtime, wal_mtime)}

_CONTACT_REL = "Contact/wccontact_new2.db"
_SESSION_REL = "Session/session_new.db"
_HASH2U_SOURCES = [
    (_CONTACT_REL, "SELECT m_nsUsrName FROM WCContact"),
    ("Group/group_new.db", "SELECT m_nsUsrName FROM GroupMember"),
    ("Group/group_new.db", "SELECT m_nsUsrName FROM GroupContact"),
    (_SESSION_REL, "SELECT m_nsUserName FROM SessionAbstract"),
    (_SESSION_REL, "SELECT m_nsUserName FROM SessionAbstractBrand"),
]


def _db_path_for(rel_key):
    pre = os.path.join(DECRYPTED_DIR, rel_key)
    return pre if os.path.exists(pre) else _cache.get(rel_key)


def _db_mtime_for(rel_key):
    pre = os.path.join(DECRYPTED_DIR, rel_key)
    if os.path.exists(pre):
        wal = pre + "-wal"
        try:
            return os.path.getmtime(pre), os.path.getmtime(wal) if os.path.exists(wal) else 0
        except OSError:
            return 0, 0
    return _cache.mtime_of(rel_key)


def _load_contacts_from(db_path):
    names = {}
    full = []
    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        for uname, nick, remark in conn.execute(
            "SELECT m_nsUsrName, nickname, m_nsRemark FROM WCContact"
        ).fetchall():
            display = remark if remark else nick if nick else uname
            names[uname] = display
            full.append({'username': uname, 'nick_name': nick or '', 'remark': remark or ''})
    return names, full


def _merge_group_members(names):
    """将 GroupMember 昵称合并进 names（WCContact 优先，不覆盖）"""
    db = _db_path_for("Group/group_new.db")
    if not db:
        return
    try:
        with contextlib.closing(sqlite3.connect(db)) as conn:
            for uname, nick in conn.execute(
                "SELECT m_nsUsrName, nickname FROM GroupMember"
            ).fetchall():
                if uname not in names and nick:
                    names[uname] = nick
    except Exception:
        logger.warning("读取 GroupMember 失败", exc_info=True)


def get_contact_names():
    global _contact_names, _contact_full, _contact_mtime

    curr_mtime = _db_mtime_for(_CONTACT_REL)
    if _contact_names is not None and curr_mtime == _contact_mtime:
        return _contact_names

    db = _db_path_for(_CONTACT_REL)
    if db:
        try:
            _contact_names, _contact_full = _load_contacts_from(db)
            _merge_group_members(_contact_names)
            _contact_mtime = curr_mtime
            return _contact_names
        except Exception:
            logger.warning("加载联系人失败", exc_info=True)

    if _contact_names is None:
        _contact_names, _contact_full = {}, []
    return _contact_names


def get_contact_full():
    global _contact_full
    if _contact_full is None:
        get_contact_names()
    return _contact_full or []


# ============ 辅助函数 ============

def _get_session_names():
    global _session_names, _session_mtime

    curr_mtime = _db_mtime_for(_SESSION_REL)
    if _session_names is not None and curr_mtime == _session_mtime:
        return _session_names

    _session_names = {}
    path = _db_path_for(_SESSION_REL) or _cache.get(_SESSION_REL)
    if not path:
        return _session_names
    try:
        with contextlib.closing(sqlite3.connect(path)) as conn:
            for username, blob in conn.execute(
                "SELECT m_nsUserName, _packed_MMSessionInfo FROM SessionAbstract WHERE m_uLastTime > 0"
            ).fetchall():
                name = parse_session_info(blob).get('display_name', '')
                if name:
                    _session_names[username] = name
        _session_mtime = curr_mtime
    except Exception:
        logger.warning("读取 session 名称失败", exc_info=True)
    return _session_names


def _build_hash2username():
    global _hash2username, _hash2_sources_mtime

    curr_mtimes = {rel: _db_mtime_for(rel) for rel, _ in _HASH2U_SOURCES}
    if _hash2username is not None and curr_mtimes == _hash2_sources_mtime:
        return _hash2username

    usernames = set()
    for rel, sql in _HASH2U_SOURCES:
        db = _db_path_for(rel)
        if not db:
            continue
        try:
            with contextlib.closing(sqlite3.connect(db)) as conn:
                usernames |= {r[0] for r in conn.execute(sql).fetchall() if r[0]}
        except Exception:
            logger.warning("读取 username 失败: %s", rel, exc_info=True)

    _hash2username = {f"Chat_{hashlib.md5(u.encode()).hexdigest()}": u for u in usernames}
    _hash2_sources_mtime = curr_mtimes
    return _hash2username


# ============ 消息表索引（带 mtime 失效） ============

_msg_table_index = None   # {table_name: rel_key}
_msg_index_mtime = {}     # {rel_key: (db_mtime, wal_mtime)}

_TABLE_NAME_RE = re.compile(r'^Chat_[0-9a-f]{32}$')

MSG_DB_KEYS = sorted([
    k for k in ALL_KEYS
    if k.startswith("Message/msg_") and k.endswith(".db")
    and "fts" not in k and "resource" not in k
])


def _get_msg_table_index():
    global _msg_table_index, _msg_index_mtime

    curr_mtimes = {k: _cache.mtime_of(k) for k in MSG_DB_KEYS}
    if _msg_table_index is not None and curr_mtimes == _msg_index_mtime:
        return _msg_table_index

    index = {}
    for rel_key in MSG_DB_KEYS:
        path = _cache.get(rel_key)
        if not path:
            continue
        try:
            with contextlib.closing(sqlite3.connect(path)) as conn:
                for (tname,) in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Chat_%' AND name NOT LIKE '%_dels'"
                ).fetchall():
                    if _TABLE_NAME_RE.match(tname):
                        index[tname] = rel_key
        except Exception:
            logger.warning("索引消息表失败: %s", rel_key, exc_info=True)

    _msg_table_index = index
    _msg_index_mtime = curr_mtimes
    return _msg_table_index


def _find_msg_table_for_user(username):
    """在消息表索引中查找用户的消息表，返回 (db_path, table_name)"""
    table_name = f"Chat_{hashlib.md5(username.encode()).hexdigest()}"
    index = _get_msg_table_index()
    rel_key = index.get(table_name)
    if rel_key:
        path = _cache.get(rel_key)
        if path:
            return path, table_name
    return None, None


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


_TIME_FORMATS = [
    ('%Y-%m-%d %H:%M:%S', False),
    ('%Y-%m-%d %H:%M', False),
    ('%Y-%m-%d', True),
]


def _parse_time_arg(value, is_end):
    """解析时间参数，返回 (timestamp, normalized_string)。空字符串返回 (None, None)。"""
    if not value:
        return None, None

    for fmt, date_only in _TIME_FORMATS:
        try:
            dt = datetime.strptime(value, fmt)
            if date_only:
                dt = dt.replace(hour=23, minute=59, second=59) if is_end else dt.replace(
                    hour=0, minute=0, second=0
                )
            return int(dt.timestamp()), dt.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            continue

    raise ValueError


def _resolve_time_range(start_time, end_time):
    start_ts = end_ts = None
    normalized_start = normalized_end = None

    if start_time:
        try:
            start_ts, normalized_start = _parse_time_arg(start_time, is_end=False)
        except ValueError:
            return None, None, None, json.dumps({"error": "时间格式错误: start_time"}, ensure_ascii=False)

    if end_time:
        try:
            end_ts, normalized_end = _parse_time_arg(end_time, is_end=True)
        except ValueError:
            return None, None, None, json.dumps({"error": "时间格式错误: end_time"}, ensure_ascii=False)

    if start_ts is not None and end_ts is not None and start_ts > end_ts:
        return None, None, None, json.dumps({"error": "start_time 不能晚于 end_time"}, ensure_ascii=False)

    if start_ts is None and end_ts is None:
        return None, None, None, None

    return start_ts, end_ts, {
        "start_time": normalized_start,
        "end_time": normalized_end,
    }, None


# ============ MCP Server ============

mcp = FastMCP("wechat", instructions="查询微信消息、联系人等数据")

_last_check_state = {}  # {username: last_timestamp}


@mcp.tool()
def get_recent_sessions(limit: int = 20) -> str:
    """获取微信最近会话列表，包含最新消息摘要、未读数、时间等。
    用于了解最近有哪些人/群在聊天。

    Args:
        limit: 返回的会话数量，默认20
    """
    path = _cache.get(_SESSION_REL)
    if not path:
        return json.dumps({"error": "无法解密 session_new.db"}, ensure_ascii=False)

    names = get_contact_names()
    try:
        with contextlib.closing(sqlite3.connect(path)) as conn:
            rows = conn.execute("""
                SELECT m_nsUserName, m_uUnReadCount, m_uLastTime, _packed_MMSessionInfo
                FROM SessionAbstract
                WHERE m_uLastTime > 0
                ORDER BY m_uLastTime DESC
                LIMIT ?
            """, (limit,)).fetchall()
    except Exception:
        logger.error("查询 SessionAbstract 失败", exc_info=True)
        return json.dumps({"error": "查询会话失败"}, ensure_ascii=False)

    sessions = []
    for username, unread, ts, blob in rows:
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
def get_chat_history(chat_name: str, limit: int = 50, start_time: str = "", end_time: str = "") -> str:
    """获取指定聊天的消息记录。

    Args:
        chat_name: 聊天对象的名字、备注名或wxid，自动模糊匹配
        limit: 返回的消息数量，默认50
        start_time: 起始时间，支持 YYYY-MM-DD / YYYY-MM-DD HH:MM / YYYY-MM-DD HH:MM:SS
        end_time: 结束时间，支持 YYYY-MM-DD / YYYY-MM-DD HH:MM / YYYY-MM-DD HH:MM:SS
    """
    if limit <= 0:
        return json.dumps({"error": "limit 必须大于 0"}, ensure_ascii=False)

    start_ts, end_ts, time_filter, error = _resolve_time_range(start_time, end_time)
    if error:
        return error

    username = resolve_username(chat_name)
    if not username:
        return json.dumps({"error": f"找不到聊天对象: {chat_name}"}, ensure_ascii=False)

    names = get_contact_names()
    display_name = names.get(username, username)
    is_group = '@chatroom' in username

    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return json.dumps({
            "username": username, "display": display_name, "count": 0,
            "messages": [], "time_filter": time_filter, "error": "找不到消息记录"
        }, ensure_ascii=False)

    try:
        where_clauses = ["1=1"]
        params = []
        if start_ts is not None:
            where_clauses.append("msgCreateTime >= ?")
            params.append(start_ts)
        if end_ts is not None:
            where_clauses.append("msgCreateTime <= ?")
            params.append(end_ts)
        params.append(limit + 1)

        with contextlib.closing(sqlite3.connect(db_path)) as conn:
            rows = conn.execute(f"""
                SELECT messageType, msgCreateTime, msgContent, mesDes
                FROM [{table_name}]
                WHERE {' AND '.join(where_clauses)}
                ORDER BY msgCreateTime DESC
                LIMIT ?
            """, params).fetchall()
    except Exception as e:
        logger.error("查询消息失败: %s", table_name, exc_info=True)
        return json.dumps({"error": f"查询失败: {e}"}, ensure_ascii=False)

    has_more = len(rows) > limit
    if has_more:
        rows = rows[:limit]

    if not rows:
        return json.dumps({
            "username": username, "display": display_name, "count": 0,
            "messages": [], "time_filter": time_filter,
        }, ensure_ascii=False)

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
        "count": len(messages), "limit": limit, "has_more": has_more,
        "time_filter": time_filter,
        "messages": messages,
    }, ensure_ascii=False)


@mcp.tool()
def search_messages(keyword: str, limit: int = 20, start_time: str = "", end_time: str = "") -> str:
    """在所有聊天记录中搜索包含关键词的消息。

    Args:
        keyword: 搜索关键词
        limit: 返回的结果数量，默认20
        start_time: 起始时间，支持 YYYY-MM-DD / YYYY-MM-DD HH:MM / YYYY-MM-DD HH:MM:SS
        end_time: 结束时间，支持 YYYY-MM-DD / YYYY-MM-DD HH:MM / YYYY-MM-DD HH:MM:SS
    """
    if not keyword:
        return json.dumps({"error": "请提供搜索关键词"}, ensure_ascii=False)
    if limit <= 0:
        return json.dumps({"error": "limit 必须大于 0"}, ensure_ascii=False)

    start_ts, end_ts, time_filter, error = _resolve_time_range(start_time, end_time)
    if error:
        return error

    names = get_contact_names()
    hash2u = _build_hash2username()
    index = _get_msg_table_index()
    results = []

    # 按 rel_key 分组，避免重复打开同一 DB
    rel_to_tables: dict[str, list[str]] = {}
    for tname, rel_key in index.items():
        rel_to_tables.setdefault(rel_key, []).append(tname)

    per_table_limit = max(20, limit + 1)

    for rel_key, tables in rel_to_tables.items():
        path = _cache.get(rel_key)
        if not path:
            continue
        try:
            with contextlib.closing(sqlite3.connect(path)) as conn:
                for tname in tables:
                    username = hash2u.get(tname, '')
                    is_group = '@chatroom' in username
                    display = names.get(username) or _get_session_names().get(username) or username if username else tname
                    try:
                        where_clauses = ["typeof(msgContent) = 'text'", "msgContent LIKE ?"]
                        params = [f'%{keyword}%']
                        if start_ts is not None:
                            where_clauses.append("msgCreateTime >= ?")
                            params.append(start_ts)
                        if end_ts is not None:
                            where_clauses.append("msgCreateTime <= ?")
                            params.append(end_ts)
                        params.append(per_table_limit)

                        rows = conn.execute(f"""
                            SELECT messageType, msgCreateTime, msgContent, mesDes
                            FROM [{tname}]
                            WHERE {' AND '.join(where_clauses)}
                            ORDER BY msgCreateTime DESC
                            LIMIT ?
                        """, params).fetchall()
                    except Exception:
                        logger.warning("搜索表失败: %s", tname, exc_info=True)
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
                            "is_group": is_group,
                            "sender": sender_label, "content": text,
                        }))
        except Exception:
            logger.warning("打开消息 DB 失败: %s", rel_key, exc_info=True)

    results.sort(key=lambda x: x[0], reverse=True)
    has_more = len(results) > limit
    entries = [r[1] for r in results[:limit]]

    return json.dumps({
        "keyword": keyword, "count": len(entries), "limit": limit,
        "has_more": has_more, "time_filter": time_filter, "results": entries,
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

    path = _cache.get(_SESSION_REL)
    if not path:
        return json.dumps({"error": "无法解密 session_new.db"}, ensure_ascii=False)

    names = get_contact_names()
    try:
        with contextlib.closing(sqlite3.connect(path)) as conn:
            rows = conn.execute("""
                SELECT m_nsUserName, m_uUnReadCount, m_uLastTime, _packed_MMSessionInfo
                FROM SessionAbstract
                WHERE m_uLastTime > 0
                ORDER BY m_uLastTime DESC
            """).fetchall()
    except Exception:
        logger.error("查询新消息失败", exc_info=True)
        return json.dumps({"error": "查询失败"}, ensure_ascii=False)

    curr_state = {}
    for username, unread, ts, blob in rows:
        info = parse_session_info(blob)
        curr_state[username] = {
            'unread': unread or 0, 'summary': info['summary'], 'timestamp': ts,
            'msg_type': info['msg_type'], 'sender': info['sender'],
            'mes_des': info.get('mes_des', -1),
            'display_name': info.get('display_name', ''),
        }

    if not _last_check_state:
        _last_check_state = {u: s['timestamp'] for u, s in curr_state.items()}
        unread_list = [
            {
                "username": u, "display": names.get(u) or s.get('display_name') or u,
                "is_group": '@chatroom' in u,
                "unread": s['unread'],
                "time": datetime.fromtimestamp(s['timestamp']).strftime('%H:%M'),
                "type": format_msg_type(s['msg_type']),
                "content": format_summary(s['msg_type'], s['summary']),
            }
            for u, s in curr_state.items() if s['unread'] > 0
        ]
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
