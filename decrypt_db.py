"""
WeChat 3.8.x (macOS) 数据库解密器

使用从进程内存提取的 per-DB enc_key 解密 SQLCipher 3 加密数据库
参数: SQLCipher 3, AES-256-CBC, HMAC-SHA1, reserve=48, page_size=1024
密钥来源: all_keys.json (由 find_all_keys.py 从内存提取)
"""
import os, sys, json, shutil
import sqlite3

import functools
print = functools.partial(print, flush=True)

from crypto_params import (
    PAGE_SZ, SALT_SZ, IV_SZ, HMAC_SZ, RESERVE_SZ, KEY_SZ,
    SQLITE_HDR, decrypt_page, derive_mac_key,
)
import hmac as hmac_mod
import hashlib, struct

from config import load_config
_cfg = load_config()
DB_DIR = _cfg["db_dir"]
OUT_DIR = _cfg["decrypted_dir"]
KEYS_FILE = _cfg["keys_file"]


def decrypt_database(db_path, out_path, enc_key):
    file_size = os.path.getsize(db_path)
    total_pages = file_size // PAGE_SZ

    if file_size % PAGE_SZ != 0:
        print(f"  [WARN] 文件大小 {file_size} 不是 {PAGE_SZ} 的倍数")
        total_pages += 1

    with open(db_path, 'rb') as fin:
        page1 = fin.read(PAGE_SZ)

    if len(page1) < PAGE_SZ:
        print(f"  [ERROR] 文件太小")
        return False

    salt = page1[:SALT_SZ]
    mac_key = derive_mac_key(enc_key, salt)
    hmac_data = page1[SALT_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ]
    stored_hmac = page1[PAGE_SZ - RESERVE_SZ + IV_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ + HMAC_SZ]
    h = hmac_mod.new(mac_key, hmac_data, hashlib.sha1)
    h.update(struct.pack('<I', 1))
    if h.digest() != stored_hmac:
        print(f"  [ERROR] Page 1 HMAC 验证失败! salt: {salt.hex()}")
        return False

    print(f"  HMAC OK, {total_pages} pages")

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(db_path, 'rb') as fin, open(out_path, 'wb') as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                if len(page) > 0:
                    page = page + b'\x00' * (PAGE_SZ - len(page))
                else:
                    break

            decrypted = decrypt_page(enc_key, page, pgno)
            fout.write(decrypted)

            if pgno == 1 and decrypted[:16] != SQLITE_HDR:
                print(f"  [WARN] 解密后 header 不匹配!")

            if pgno % 10000 == 0:
                print(f"  进度: {pgno}/{total_pages} ({100*pgno/total_pages:.1f}%)")

    return True


def main():
    print("=" * 60)
    print("  WeChat 3.8.x (macOS) 数据库解密器")
    print("=" * 60)

    if not os.path.exists(KEYS_FILE):
        print(f"[ERROR] 密钥文件不存在: {KEYS_FILE}")
        print("请先运行 find_all_keys.py")
        sys.exit(1)

    with open(KEYS_FILE) as f:
        keys = json.load(f)

    print(f"\n加载 {len(keys)} 个数据库密钥")
    print(f"输出目录: {OUT_DIR}")
    os.makedirs(OUT_DIR, exist_ok=True)

    db_files = []
    for root, dirs, files in os.walk(DB_DIR):
        for f in files:
            if f.endswith('.db') and not f.endswith('-wal') and not f.endswith('-shm'):
                path = os.path.join(root, f)
                rel = os.path.relpath(path, DB_DIR)
                sz = os.path.getsize(path)
                db_files.append((rel, path, sz))

    db_files.sort(key=lambda x: x[2])
    print(f"找到 {len(db_files)} 个数据库文件\n")

    success = 0
    failed = 0
    total_bytes = 0

    for rel, path, sz in db_files:
        out_path = os.path.join(OUT_DIR, rel)

        if rel not in keys:
            # 检查是否明文 SQLite
            with open(path, 'rb') as f:
                hdr = f.read(16)
            if hdr == SQLITE_HDR:
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                shutil.copy2(path, out_path)
                print(f"COPY: {rel} (明文SQLite)")
                success += 1
                total_bytes += sz
            else:
                print(f"SKIP: {rel} (无密钥)")
                failed += 1
            continue

        enc_key = bytes.fromhex(keys[rel]["enc_key"])
        out_path = os.path.join(OUT_DIR, rel)

        print(f"解密: {rel} ({sz/1024/1024:.1f}MB) ...", end=" ")

        ok = decrypt_database(path, out_path, enc_key)
        if ok:
            try:
                conn = sqlite3.connect(out_path)
                tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                conn.close()
                table_names = [t[0] for t in tables]
                print(f"  OK! 表: {', '.join(table_names[:5])}", end="")
                if len(table_names) > 5:
                    print(f" ...共{len(table_names)}个", end="")
                print()
                success += 1
                total_bytes += sz
            except Exception as e:
                print(f"  [WARN] SQLite 验证失败: {e}")
                failed += 1
        else:
            failed += 1

    print(f"\n{'='*60}")
    print(f"结果: {success} 成功, {failed} 失败, 共 {len(db_files)} 个")
    print(f"解密数据量: {total_bytes/1024/1024/1024:.1f}GB")
    print(f"解密文件在: {OUT_DIR}")


if __name__ == '__main__':
    main()
