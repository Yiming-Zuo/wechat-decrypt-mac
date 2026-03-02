"""
SQLCipher 3 解密原语 (macOS 微信 3.8.x)

参数: AES-256-CBC, HMAC-SHA1, page_size=1024, reserve=48
KDF: PBKDF2-HMAC-SHA1, 64000 iter (fast KDF: 2 iter)
"""
import hashlib, struct, os
import hmac as hmac_mod
from Crypto.Cipher import AES

PAGE_SZ = 1024
KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 20       # SHA1
RESERVE_SZ = 48    # IV(16) + HMAC(20) + pad(12)
SQLITE_HDR = b'SQLite format 3\x00'

WAL_HEADER_SZ = 32
WAL_FRAME_HEADER_SZ = 24


def derive_mac_key(enc_key, salt):
    mac_salt = bytes(b ^ 0x3a for b in salt)
    return hashlib.pbkdf2_hmac("sha1", enc_key, mac_salt, 2, dklen=KEY_SZ)


def verify_key_for_db(enc_key, db_page1):
    salt = db_page1[:SALT_SZ]
    mac_key = derive_mac_key(enc_key, salt)
    # SQLCipher 3 layout: [salt(16)] [payload] [IV(16)] [HMAC(20)] [pad(12)]
    # HMAC covers: payload + IV, page number appended
    hmac_data = db_page1[SALT_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ]
    stored_hmac = db_page1[PAGE_SZ - RESERVE_SZ + IV_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ + HMAC_SZ]
    h = hmac_mod.new(mac_key, hmac_data, hashlib.sha1)
    h.update(struct.pack('<I', 1))
    return h.digest() == stored_hmac


def decrypt_page(enc_key, page_data, pgno):
    iv = page_data[PAGE_SZ - RESERVE_SZ : PAGE_SZ - RESERVE_SZ + IV_SZ]
    if pgno == 1:
        encrypted = page_data[SALT_SZ : PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return bytes(bytearray(SQLITE_HDR + decrypted + b'\x00' * RESERVE_SZ))
    else:
        encrypted = page_data[:PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return decrypted + b'\x00' * RESERVE_SZ


def full_decrypt(db_path, out_path, enc_key):
    file_size = os.path.getsize(db_path)
    total_pages = file_size // PAGE_SZ
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(db_path, 'rb') as fin, open(out_path, 'wb') as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                if len(page) > 0:
                    page = page + b'\x00' * (PAGE_SZ - len(page))
                else:
                    break
            fout.write(decrypt_page(enc_key, page, pgno))
    return total_pages


def decrypt_wal(wal_path, out_path, enc_key):
    if not os.path.exists(wal_path):
        return 0
    wal_size = os.path.getsize(wal_path)
    if wal_size <= WAL_HEADER_SZ:
        return 0
    frame_size = WAL_FRAME_HEADER_SZ + PAGE_SZ
    patched = 0
    with open(wal_path, 'rb') as wf, open(out_path, 'r+b') as df:
        wal_hdr = wf.read(WAL_HEADER_SZ)
        wal_salt1 = struct.unpack('>I', wal_hdr[16:20])[0]
        wal_salt2 = struct.unpack('>I', wal_hdr[20:24])[0]
        while wf.tell() + frame_size <= wal_size:
            fh = wf.read(WAL_FRAME_HEADER_SZ)
            if len(fh) < WAL_FRAME_HEADER_SZ:
                break
            pgno = struct.unpack('>I', fh[0:4])[0]
            frame_salt1 = struct.unpack('>I', fh[8:12])[0]
            frame_salt2 = struct.unpack('>I', fh[12:16])[0]
            ep = wf.read(PAGE_SZ)
            if len(ep) < PAGE_SZ:
                break
            if pgno == 0 or pgno > 1000000:
                continue
            if frame_salt1 != wal_salt1 or frame_salt2 != wal_salt2:
                continue
            dec = decrypt_page(enc_key, ep, pgno)
            df.seek((pgno - 1) * PAGE_SZ)
            df.write(dec)
            patched += 1
    return patched
