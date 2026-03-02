"""测量消息延迟 - 用mtime检测WAL变化（WAL文件是预分配固定大小的）(macOS)"""
import time, os, sys, io, sqlite3, json
from datetime import datetime

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from crypto_params import PAGE_SZ, full_decrypt, decrypt_wal
from config import load_config
from session_parser import parse_session_info

_cfg = load_config()
DB_DIR = _cfg["db_dir"]
KEYS_FILE = _cfg["keys_file"]
DECRYPTED = os.path.join(_cfg["decrypted_dir"], "Session", "session_new.db")

SESSION_KEY = "Session/session_new.db"
SESSION_REL = "Session/session_new.db"

with open(KEYS_FILE) as f:
    keys = json.load(f)
enc_key = bytes.fromhex(keys[SESSION_KEY]["enc_key"])

session_db = os.path.join(DB_DIR, SESSION_REL)
wal_path = session_db + "-wal"


def timed_full_decrypt(src, dst):
    t0 = time.perf_counter()
    total = full_decrypt(src, dst, enc_key)
    return total, (time.perf_counter() - t0) * 1000


def timed_decrypt_wal(wal, dst):
    t0 = time.perf_counter()
    patched = decrypt_wal(wal, dst, enc_key)
    return patched, (time.perf_counter() - t0) * 1000


# 初始化: 全量解密
print("初始全量解密...", flush=True)
pages, ms = timed_full_decrypt(session_db, DECRYPTED)
print(f"  DB: {pages}页 {ms:.0f}ms", flush=True)
if os.path.exists(wal_path):
    patched, ms2 = timed_decrypt_wal(wal_path, DECRYPTED)
    print(f"  WAL: {patched}页 {ms2:.0f}ms", flush=True)

# 获取初始状态
conn = sqlite3.connect(DECRYPTED)
prev_sessions = {}
try:
    for r in conn.execute("SELECT m_nsUserName, m_uLastTime FROM SessionAbstract WHERE m_uLastTime>0"):
        prev_sessions[r[0]] = r[1]
except Exception as e:
    print(f"[WARN] 读取 session 失败: {e}")
conn.close()

# 记录初始mtime
prev_wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
prev_db_mtime = os.path.getmtime(session_db)
wal_sz = os.path.getsize(wal_path) if os.path.exists(wal_path) else 0

print(f"\nWAL大小: {wal_sz} bytes (固定预分配)", flush=True)
print(f"跟踪 {len(prev_sessions)} 个会话", flush=True)
print(f"\n等待微信新消息... (60秒超时, 30ms轮询)\n", flush=True)

start = time.time()

while time.time() - start < 60:
    time.sleep(0.03)

    try:
        wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
        db_mtime = os.path.getmtime(session_db)
    except Exception:
        continue

    if wal_mtime == prev_wal_mtime and db_mtime == prev_db_mtime:
        continue

    t_detect = time.perf_counter()
    detect_str = datetime.now().strftime('%H:%M:%S.%f')[:-3]

    wal_changed = wal_mtime != prev_wal_mtime
    db_changed = db_mtime != prev_db_mtime
    print(f"[{detect_str}] 变化检测: WAL={'变' if wal_changed else '不变'} DB={'变' if db_changed else '不变'}", flush=True)

    pages, ms = timed_full_decrypt(session_db, DECRYPTED)
    if os.path.exists(wal_path):
        patched, ms2 = timed_decrypt_wal(wal_path, DECRYPTED)
        print(f"  DB {pages}页/{ms:.0f}ms + WAL {patched}页/{ms2:.0f}ms", flush=True)
    else:
        print(f"  DB {pages}页/{ms:.0f}ms", flush=True)

    t_decrypt = time.perf_counter()

    conn = sqlite3.connect(DECRYPTED)
    new_msgs = []
    try:
        for r in conn.execute("""
            SELECT m_nsUserName, m_uLastTime, _packed_MMSessionInfo
            FROM SessionAbstract WHERE m_uLastTime > 0
        """):
            uname, ts, blob = r
            info = parse_session_info(blob)
            sender = info['sender']
            if ts > prev_sessions.get(uname, 0):
                delay = time.time() - ts
                new_msgs.append((uname, ts, info['summary'], sender, delay))
                prev_sessions[uname] = ts
    except Exception:
        pass
    conn.close()

    t_query = time.perf_counter()

    decrypt_ms = (t_decrypt - t_detect) * 1000
    query_ms = (t_query - t_decrypt) * 1000
    total_ms = (t_query - t_detect) * 1000

    print(f"  处理总耗时: {total_ms:.1f}ms (解密{decrypt_ms:.1f}ms + 查询{query_ms:.1f}ms)", flush=True)

    for uname, ts, summary, sender, delay in sorted(new_msgs, key=lambda x: x[1]):
        msg_time = datetime.fromtimestamp(ts).strftime('%H:%M:%S')
        print(f"  >>> 消息时间={msg_time} | 微信→DB延迟={delay:.1f}s | {sender}: {summary}", flush=True)

    if not new_msgs:
        print(f"  (无新消息变化)", flush=True)

    prev_wal_mtime = wal_mtime
    prev_db_mtime = db_mtime
    print(flush=True)

print("超时退出", flush=True)
