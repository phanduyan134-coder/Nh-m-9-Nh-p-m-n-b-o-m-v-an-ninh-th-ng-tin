"""
rainbow.py
Module minh họa Hash, Rainbow Table và ảnh hưởng của Salt.

Chức năng:
- Sinh hash MD5 / SHA-1 / SHA-256 cho mật khẩu
- Sinh hash có salt + bcrypt
- Xây dựng Rainbow Table từ wordlist (bảng tra cứu hash -> plaintext)
- Lookup hash trong Rainbow Table để minh họa việc "crack" khi không có salt
- Minh họa vì sao salt làm Rainbow Table truyền thống mất tác dụng
"""

import hashlib
import secrets

try:
    import bcrypt
    _HAS_BCRYPT = True
except ImportError:
    _HAS_BCRYPT = False


# ---------------------------------------------------------------------------
# 1. HASH GENERATION
# ---------------------------------------------------------------------------

def generate_hash(password: str, algo: str = "sha256") -> str:
    """Sinh hash không salt cho mật khẩu theo thuật toán chỉ định."""
    data = password.encode("utf-8")
    if algo == "md5":
        return hashlib.md5(data).hexdigest()
    if algo == "sha1":
        return hashlib.sha1(data).hexdigest()
    if algo == "sha256":
        return hashlib.sha256(data).hexdigest()
    raise ValueError(f"Thuật toán không hỗ trợ: {algo}")


def generate_salt(length: int = 16) -> str:
    """Sinh salt ngẫu nhiên an toàn bằng module secrets."""
    return secrets.token_hex(length // 2)


def generate_salted_hash(password: str, salt: str = None, algo: str = "sha256") -> dict:
    """Sinh hash có salt: hash(salt + password)."""
    if salt is None:
        salt = generate_salt()
    combined = (salt + password).encode("utf-8")
    if algo == "md5":
        digest = hashlib.md5(combined).hexdigest()
    elif algo == "sha1":
        digest = hashlib.sha1(combined).hexdigest()
    else:
        digest = hashlib.sha256(combined).hexdigest()
    return {"salt": salt, "hash": digest, "algo": algo}


def generate_bcrypt_hash(password: str) -> str:
    """Sinh hash bcrypt (đã tự động kèm salt, chuẩn lưu mật khẩu hiện đại)."""
    if not _HAS_BCRYPT:
        return "bcrypt chưa được cài đặt (pip install bcrypt)"
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_bcrypt(password: str, hashed: str) -> bool:
    if not _HAS_BCRYPT:
        return False
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


# ---------------------------------------------------------------------------
# 2. RAINBOW TABLE (bảng tra cứu hash -> plaintext, không salt)
# ---------------------------------------------------------------------------

def build_rainbow_table(wordlist: list, algo: str = "sha256") -> dict:
    """
    Xây dựng "rainbow table" đơn giản hóa: tiền tính hash cho toàn bộ wordlist.
    (Đây là dạng lookup-table minh họa nguyên lý; rainbow table thật dùng
    reduction function theo chuỗi để tiết kiệm bộ nhớ, được giải thích trong báo cáo.)
    """
    table = {}
    for word in wordlist:
        word = word.strip()
        if not word:
            continue
        table[generate_hash(word, algo)] = word
    return table


def lookup_hash(hash_value: str, table: dict) -> str:
    """Tra cứu hash trong rainbow table. Trả về plaintext nếu tìm thấy, None nếu không."""
    return table.get(hash_value)


def demonstrate_salt_effect(password: str, wordlist_sample: list, algo: str = "sha256") -> dict:
    """
    Minh họa: cùng 1 mật khẩu, hash không salt sẽ luôn giống nhau (dễ bị rainbow
    table tấn công), trong khi hash có salt (mỗi lần random salt khác nhau) sẽ
    cho ra kết quả khác nhau -> rainbow table truyền thống KHÔNG lookup được nữa.
    """
    unsalted_1 = generate_hash(password, algo)
    unsalted_2 = generate_hash(password, algo)  # luôn giống nhau

    salted_1 = generate_salted_hash(password, algo=algo)
    salted_2 = generate_salted_hash(password, algo=algo)  # salt khác -> hash khác

    table = build_rainbow_table(wordlist_sample, algo)

    return {
        "unsalted_hash_1": unsalted_1,
        "unsalted_hash_2": unsalted_2,
        "unsalted_identical": unsalted_1 == unsalted_2,
        "salted_hash_1": salted_1,
        "salted_hash_2": salted_2,
        "salted_identical": salted_1["hash"] == salted_2["hash"],
        "found_in_rainbow_table": lookup_hash(unsalted_1, table),
        "salted_found_in_rainbow_table": lookup_hash(salted_1["hash"], table),
    }
