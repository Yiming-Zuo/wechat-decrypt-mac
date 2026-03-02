"""
从微信进程内存中提取所有数据库的缓存 raw key (macOS)

WCDB 为每个 DB 缓存: x'<64hex_enc_key><32hex_salt>'
使用 macOS Mach API (task_for_pid + mach_vm_region + mach_vm_read_overwrite)
需要: sudo 权限 + SIP 关闭
"""
import ctypes, ctypes.util
import struct, os, sys, hashlib, time, re, json, subprocess
import hmac as hmac_mod

import functools
print = functools.partial(print, flush=True)

from crypto_params import PAGE_SZ, KEY_SZ, SALT_SZ, verify_key_for_db
from config import load_config

_cfg = load_config()
DB_DIR = _cfg["db_dir"]
OUT_FILE = _cfg["keys_file"]

# ============ Mach API 绑定 ============

libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
_kern = ctypes.CDLL('/usr/lib/system/libsystem_kernel.dylib', use_errno=True)

# mach_task_self_ 是全局变量（mach_port_t），不是函数，必须用 in_dll 读取
MACH_TASK_SELF = ctypes.c_uint.in_dll(_kern, 'mach_task_self_').value

KERN_SUCCESS = 0
VM_REGION_BASIC_INFO_64 = 9
VM_REGION_BASIC_INFO_COUNT_64 = 9


class vm_region_basic_info_64(ctypes.Structure):
    _pack_ = 4
    _fields_ = [
        ("protection",       ctypes.c_int),
        ("max_protection",   ctypes.c_int),
        ("inheritance",      ctypes.c_uint32),
        ("shared",           ctypes.c_uint32),
        ("reserved",         ctypes.c_uint32),
        ("offset",           ctypes.c_uint64),
        ("behavior",         ctypes.c_int),
        ("user_wired_count", ctypes.c_ushort),
    ]


task_for_pid = _kern.task_for_pid
task_for_pid.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.POINTER(ctypes.c_uint)]
task_for_pid.restype = ctypes.c_int

mach_vm_region = _kern.mach_vm_region
mach_vm_region.argtypes = [
    ctypes.c_uint,                          # task
    ctypes.POINTER(ctypes.c_uint64),        # address
    ctypes.POINTER(ctypes.c_uint64),        # size
    ctypes.c_int,                           # flavor
    ctypes.POINTER(vm_region_basic_info_64),# info
    ctypes.POINTER(ctypes.c_uint),          # infoCnt
    ctypes.POINTER(ctypes.c_uint),          # object_name
]
mach_vm_region.restype = ctypes.c_int

mach_vm_read_overwrite = _kern.mach_vm_read_overwrite
mach_vm_read_overwrite.argtypes = [
    ctypes.c_uint,                 # task
    ctypes.c_uint64,               # address
    ctypes.c_uint64,               # size
    ctypes.c_uint64,               # data (ptr as int)
    ctypes.POINTER(ctypes.c_uint64), # outsize
]
mach_vm_read_overwrite.restype = ctypes.c_int

mach_port_deallocate = _kern.mach_port_deallocate
mach_port_deallocate.argtypes = [ctypes.c_uint, ctypes.c_uint]
mach_port_deallocate.restype = ctypes.c_int

VM_PROT_READ = 0x01
READABLE_MASK = VM_PROT_READ


def get_pid():
    proc = _cfg.get("wechat_process", "WeChat")
    r = subprocess.run(["pgrep", "-x", proc], capture_output=True, text=True)
    pids = [int(p) for p in r.stdout.strip().split() if p.strip().isdigit()]
    if not pids:
        print(f"[ERROR] {proc} 未运行"); sys.exit(1)

    # 选内存最大的
    best = (0, 0)
    for pid in pids:
        r2 = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True)
        rss = int(r2.stdout.strip() or "0")
        if rss > best[1]:
            best = (pid, rss)

    print(f"[+] {proc} PID={best[0]} ({best[1]//1024}MB)")
    return best[0]


def open_task(pid):
    task = ctypes.c_uint(0)
    kr = task_for_pid(MACH_TASK_SELF, pid, ctypes.byref(task))
    if kr != KERN_SUCCESS:
        print(f"[ERROR] task_for_pid 失败: {kr} (需要 sudo + SIP 关闭)")
        sys.exit(1)
    return task.value


def enum_regions(task):
    regs = []
    addr = ctypes.c_uint64(0)
    size = ctypes.c_uint64(0)
    info = vm_region_basic_info_64()
    cnt = ctypes.c_uint(VM_REGION_BASIC_INFO_COUNT_64)
    obj = ctypes.c_uint(0)

    while True:
        cnt.value = VM_REGION_BASIC_INFO_COUNT_64
        kr = mach_vm_region(
            task, ctypes.byref(addr), ctypes.byref(size),
            VM_REGION_BASIC_INFO_64,
            ctypes.byref(info), ctypes.byref(cnt), ctypes.byref(obj),
        )
        if kr != KERN_SUCCESS:
            break
        if (info.protection & VM_PROT_READ) and 0 < size.value < 500 * 1024 * 1024:
            regs.append((addr.value, size.value))
        addr.value = addr.value + size.value

    return regs


def read_mem(task, address, size):
    buf = ctypes.create_string_buffer(size)
    outsize = ctypes.c_uint64(0)
    kr = mach_vm_read_overwrite(
        task, address, size,
        ctypes.cast(buf, ctypes.c_void_p).value,
        ctypes.byref(outsize),
    )
    if kr == KERN_SUCCESS and outsize.value > 0:
        return buf.raw[:outsize.value]
    return None


def main():
    print("=" * 60)
    print("  提取所有微信数据库密钥 (macOS)")
    print("=" * 60)

    # 1. 收集所有 DB 文件及 salt
    db_files = []
    salt_to_dbs = {}

    for root, dirs, files in os.walk(DB_DIR):
        for f in files:
            if f.endswith('.db') and not f.endswith('-wal') and not f.endswith('-shm'):
                path = os.path.join(root, f)
                rel = os.path.relpath(path, DB_DIR)
                sz = os.path.getsize(path)
                if sz < PAGE_SZ:
                    continue
                with open(path, 'rb') as fh:
                    page1 = fh.read(PAGE_SZ)
                salt = page1[:SALT_SZ].hex()
                db_files.append((rel, path, sz, salt, page1))
                salt_to_dbs.setdefault(salt, []).append(rel)

    print(f"\n找到 {len(db_files)} 个数据库, {len(salt_to_dbs)} 个不同的 salt")
    for salt_hex, dbs in sorted(salt_to_dbs.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  salt {salt_hex}: {', '.join(dbs)}")

    # 2. 获取进程 task
    pid = get_pid()
    task = open_task(pid)

    regions = enum_regions(task)
    total_mb = sum(s for _, s in regions) / 1024 / 1024
    print(f"[+] 可读内存: {len(regions)} 区域, {total_mb:.0f}MB")

    # 3. 搜索 x'<hex>' 模式
    print(f"\n搜索 x'<hex>' 缓存密钥...")
    hex_re = re.compile(b"x'([0-9a-fA-F]{64,192})'")

    key_map = {}
    all_hex_matches = 0
    t0 = time.time()

    for reg_idx, (base, size) in enumerate(regions):
        data = read_mem(task, base, size)
        if not data:
            continue

        for m in hex_re.finditer(data):
            hex_str = m.group(1).decode()
            addr = base + m.start()
            all_hex_matches += 1
            hex_len = len(hex_str)

            if hex_len == 96:
                enc_key_hex = hex_str[:64]
                salt_hex = hex_str[64:]
                if salt_hex in salt_to_dbs and salt_hex not in key_map:
                    enc_key = bytes.fromhex(enc_key_hex)
                    for rel, path, sz, s, page1 in db_files:
                        if s == salt_hex:
                            if verify_key_for_db(enc_key, page1):
                                key_map[salt_hex] = enc_key_hex
                                print(f"\n  [FOUND] salt={salt_hex}")
                                print(f"    enc_key={enc_key_hex}")
                                print(f"    地址: 0x{addr:016X}")
                                print(f"    数据库: {', '.join(salt_to_dbs[salt_hex])}")
                            break

            elif hex_len == 64:
                enc_key_hex = hex_str
                enc_key = bytes.fromhex(enc_key_hex)
                for rel, path, sz, salt_hex_db, page1 in db_files:
                    if salt_hex_db not in key_map:
                        if verify_key_for_db(enc_key, page1):
                            key_map[salt_hex_db] = enc_key_hex
                            print(f"\n  [FOUND] salt={salt_hex_db}")
                            print(f"    enc_key={enc_key_hex}")
                            print(f"    地址: 0x{addr:016X}")
                            print(f"    数据库: {', '.join(salt_to_dbs[salt_hex_db])}")
                            break

            elif hex_len > 96 and hex_len % 2 == 0:
                enc_key_hex = hex_str[:64]
                salt_hex = hex_str[-32:]
                if salt_hex in salt_to_dbs and salt_hex not in key_map:
                    enc_key = bytes.fromhex(enc_key_hex)
                    for rel, path, sz, s, page1 in db_files:
                        if s == salt_hex:
                            if verify_key_for_db(enc_key, page1):
                                key_map[salt_hex] = enc_key_hex
                                print(f"\n  [FOUND] salt={salt_hex} (long hex {hex_len})")
                                print(f"    enc_key={enc_key_hex}")
                                print(f"    地址: 0x{addr:016X}")
                                print(f"    数据库: {', '.join(salt_to_dbs[salt_hex])}")
                            break

        if (reg_idx + 1) % 200 == 0:
            elapsed = time.time() - t0
            progress = sum(s for b, s in regions[:reg_idx + 1]) / sum(s for _, s in regions) * 100
            print(f"  [{progress:.1f}%] {len(key_map)}/{len(salt_to_dbs)} salts matched, "
                  f"{all_hex_matches} hex patterns, {elapsed:.1f}s")

    elapsed = time.time() - t0
    print(f"\n扫描完成: {elapsed:.1f}s, {all_hex_matches} hex 模式")

    # 4. 交叉验证 — 用已找到的 key 尝试未匹配的 salt（所有DB共用一个 enc_key 时有效）
    missing_salts = set(salt_to_dbs.keys()) - set(key_map.keys())
    if missing_salts and key_map:
        print(f"\n还有 {len(missing_salts)} 个 salt 未匹配，尝试交叉验证...")
        known_keys = list(set(key_map.values()))  # 快照，避免迭代时修改
        for salt_hex in list(missing_salts):
            for rel, path, sz, s, page1 in db_files:
                if s == salt_hex:
                    for known_key_hex in known_keys:
                        enc_key = bytes.fromhex(known_key_hex)
                        if verify_key_for_db(enc_key, page1):
                            key_map[salt_hex] = known_key_hex
                            print(f"  [CROSS] salt={salt_hex}")
                            missing_salts.discard(salt_hex)
                            break
                    break

    # 5. Fallback: raw salt 搜索（交叉验证仍有剩余时才启动，通常不需要）
    if missing_salts:
        plain_salt = bytes.fromhex('53514c69746520666f726d6174203300')  # SQLite 明文 header，跳过
        real_missing = {s for s in missing_salts if bytes.fromhex(s) != plain_salt}
        if real_missing:
            print(f"\n{len(real_missing)} 个 salt 仍未找到，尝试 raw salt 搜索...")
            for rel, path, sz, salt_hex, page1 in db_files:
                if salt_hex not in real_missing:
                    continue
                salt_bytes = bytes.fromhex(salt_hex)
                for base, size in regions:
                    data = read_mem(task, base, size)
                    if not data:
                        continue
                    idx = 0
                    while True:
                        pos = data.find(salt_bytes, idx)
                        if pos == -1:
                            break
                        if pos >= KEY_SZ:
                            enc_key = bytes(data[pos - KEY_SZ:pos])
                            if verify_key_for_db(enc_key, page1):
                                key_map[salt_hex] = enc_key.hex()
                                print(f"  [FALLBACK] salt={salt_hex} enc_key={enc_key.hex()}")
                                break
                        idx = pos + 1
                    if salt_hex in key_map:
                        break

    # 5. 输出结果
    print(f"\n{'='*60}")
    encrypted_found = len(key_map)
    encrypted_total = len(salt_to_dbs) - (1 if bytes.fromhex('53514c69746520666f726d6174203300') in [bytes.fromhex(s) for s in salt_to_dbs] else 0)
    print(f"结果: {encrypted_found}/{len(salt_to_dbs)} salts 找到密钥")

    SQLITE_MAGIC = b'SQLite format 3\x00'
    result = {}
    for rel, path, sz, salt_hex, page1 in db_files:
        if salt_hex in key_map:
            result[rel] = {
                "enc_key": key_map[salt_hex],
                "salt": salt_hex,
                "size_mb": round(sz / 1024 / 1024, 1),
            }
            print(f"  OK: {rel} ({sz/1024/1024:.1f}MB)")
        elif page1[:16] == SQLITE_MAGIC:
            print(f"  PLAIN: {rel} (明文SQLite，无需解密)")
        else:
            print(f"  MISSING: {rel} (salt={salt_hex})")

    with open(OUT_FILE, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"\n密钥保存到: {OUT_FILE}")

    mach_port_deallocate(MACH_TASK_SELF, task)


if __name__ == '__main__':
    main()
