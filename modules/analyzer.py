"""
analyzer.py
Module phân tích độ mạnh mật khẩu (Password Strength Analyzer).

Chức năng:
- Character Analysis: kiểm tra độ dài, chữ hoa, chữ thường, số, ký tự đặc biệt
- Entropy Calculation: tính entropy (bits) dựa trên charset và độ dài
- Pattern Detection: phát hiện chuỗi lặp, chuỗi tuần tự, bàn phím, năm sinh...
- Dictionary Check: so khớp với danh sách mật khẩu phổ biến
- Security Score: tổng hợp điểm 0-100 và phân loại mức độ an toàn
"""

import re
import math
import os

# ---------------------------------------------------------------------------
# 1. CHARACTER ANALYSIS
# ---------------------------------------------------------------------------

def analyze_character_sets(password: str) -> dict:
    """Trả về các tiêu chí ký tự cơ bản của mật khẩu."""
    return {
        "length_ok": len(password) >= 8,
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"\d", password)),
        "has_symbol": bool(re.search(r"[^A-Za-z0-9]", password)),
        "length": len(password),
    }


def charset_size(password: str) -> int:
    """Ước lượng kích thước bảng ký tự (charset) mà mật khẩu đang sử dụng."""
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"\d", password):
        size += 10
    if re.search(r"[^A-Za-z0-9]", password):
        size += 32  # ước lượng số ký tự đặc biệt thường dùng trên bàn phím
    return size or 1


# ---------------------------------------------------------------------------
# 2. ENTROPY CALCULATION
# ---------------------------------------------------------------------------

def calculate_entropy(password: str) -> float:
    """
    Entropy (bits) = length * log2(charset_size)
    Đây là công thức entropy lý thuyết (Shannon) áp dụng phổ biến trong
    các công cụ kiểm tra độ mạnh mật khẩu.
    """
    if not password:
        return 0.0
    size = charset_size(password)
    return len(password) * math.log2(size)


def estimate_crack_time(entropy_bits: float, guesses_per_second: float = 1e10) -> str:
    """
    Ước lượng thời gian brute-force trung bình dựa trên entropy.
    guesses_per_second mặc định = 10 tỷ lượt/giây (tấn công offline bằng GPU hiện đại)
    """
    if entropy_bits <= 0:
        return "Ngay lập tức"

    total_combinations = 2 ** entropy_bits
    seconds = (total_combinations / 2) / guesses_per_second  # trung bình dò được ở giữa không gian

    if seconds < 1:
        return "Ngay lập tức (dưới 1 giây)"

    units = [
        ("thế kỷ", 60 * 60 * 24 * 365 * 100),
        ("năm", 60 * 60 * 24 * 365),
        ("tháng", 60 * 60 * 24 * 30),
        ("ngày", 60 * 60 * 24),
        ("giờ", 60 * 60),
        ("phút", 60),
        ("giây", 1),
    ]

    if seconds > units[0][1] * 1000:
        return "Hàng nghìn thế kỷ (Centuries+)"

    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            return f"~{value:,.1f} {name}"

    return "Ngay lập tức"


# ---------------------------------------------------------------------------
# 3. PATTERN DETECTION
# ---------------------------------------------------------------------------

_KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

_SEQUENTIAL_ALPHA = "abcdefghijklmnopqrstuvwxyz"
_SEQUENTIAL_DIGIT = "0123456789"


def _has_repeated_chars(password: str, run_length: int = 3) -> bool:
    """Phát hiện ký tự lặp liên tiếp, ví dụ 'aaa', '111'."""
    for i in range(len(password) - run_length + 1):
        chunk = password[i : i + run_length]
        if len(set(chunk)) == 1:
            return True
    return False


def _has_sequential_chars(password: str, run_length: int = 3) -> bool:
    """Phát hiện chuỗi tuần tự tăng/giảm, ví dụ 'abc', '321'."""
    lowered = password.lower()
    sequences = [_SEQUENTIAL_ALPHA, _SEQUENTIAL_DIGIT, _SEQUENTIAL_ALPHA[::-1], _SEQUENTIAL_DIGIT[::-1]]
    for seq in sequences:
        for i in range(len(seq) - run_length + 1):
            if seq[i : i + run_length] in lowered:
                return True
    return False


def _has_keyboard_pattern(password: str, run_length: int = 3) -> bool:
    """Phát hiện các cụm phím liền kề trên bàn phím, ví dụ 'qwerty', 'asdf'."""
    lowered = password.lower()
    for row in _KEYBOARD_ROWS:
        for i in range(len(row) - run_length + 1):
            chunk = row[i : i + run_length]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def _has_year_pattern(password: str) -> bool:
    """Phát hiện năm (1950-2029) thường bị dùng làm hậu tố mật khẩu."""
    return bool(re.search(r"(19[5-9]\d|20[0-2]\d)", password))


def detect_patterns(password: str) -> list:
    """Trả về danh sách các pattern yếu được phát hiện."""
    findings = []
    if _has_repeated_chars(password):
        findings.append("Ký tự lặp liên tiếp (vd: aaa, 111)")
    if _has_sequential_chars(password):
        findings.append("Chuỗi tuần tự (vd: abc, 123, cba, 321)")
    if _has_keyboard_pattern(password):
        findings.append("Cụm phím liền kề trên bàn phím (vd: qwerty, asdf)")
    if _has_year_pattern(password):
        findings.append("Chứa năm sinh/năm phổ biến (vd: 1990, 2024)")
    return findings


# ---------------------------------------------------------------------------
# 4. DICTIONARY CHECK
# ---------------------------------------------------------------------------

_DEFAULT_WORDLIST_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "common_passwords.txt"
)


def load_wordlist(path: str = _DEFAULT_WORDLIST_PATH) -> list:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip().lower() for line in f if line.strip()]


def dictionary_check(password: str, wordlist: list = None) -> dict:
    """
    Kiểm tra mật khẩu có trùng hoặc chứa từ trong danh sách mật khẩu phổ biến.
    Trả về {"is_common": bool, "matched_word": str|None}
    """
    if wordlist is None:
        wordlist = load_wordlist()

    lowered = password.lower()

    if lowered in wordlist:
        return {"is_common": True, "matched_word": lowered, "match_type": "exact"}

    for word in wordlist:
        if len(word) >= 4 and word in lowered:
            return {"is_common": True, "matched_word": word, "match_type": "substring"}

    return {"is_common": False, "matched_word": None, "match_type": None}


# ---------------------------------------------------------------------------
# 5. SECURITY SCORE
# ---------------------------------------------------------------------------

def calculate_score(password: str, wordlist: list = None) -> dict:
    """
    Tổng hợp toàn bộ phân tích thành điểm số 0-100 và nhãn phân loại.
    Trọng số:
        - Character variety & length: 40 điểm
        - Entropy: 30 điểm
        - Không có pattern yếu: 15 điểm
        - Không nằm trong dictionary: 15 điểm
    """
    if not password:
        return {
            "score": 0,
            "label": "Không có mật khẩu",
            "entropy": 0,
            "crack_time": "N/A",
            "char_analysis": analyze_character_sets(""),
            "patterns": [],
            "dictionary": {"is_common": False, "matched_word": None},
        }

    char_analysis = analyze_character_sets(password)
    entropy = calculate_entropy(password)
    patterns = detect_patterns(password)
    dict_result = dictionary_check(password, wordlist)

    # --- Điểm ký tự & độ dài (40đ) ---
    char_score = 0
    char_score += 10 if char_analysis["length_ok"] else max(0, char_analysis["length"] * 1.2)
    if char_analysis["length"] >= 12:
        char_score += 5
    char_score += 7.5 if char_analysis["has_upper"] else 0
    char_score += 7.5 if char_analysis["has_lower"] else 0
    char_score += 7.5 if char_analysis["has_digit"] else 0
    char_score += 7.5 if char_analysis["has_symbol"] else 0
    char_score = min(char_score, 40)

    # --- Điểm entropy (30đ), quy đổi 0-80 bits -> 0-30 điểm ---
    entropy_score = min(entropy / 80 * 30, 30)

    # --- Điểm pattern (15đ) ---
    pattern_score = 15 if not patterns else max(0, 15 - 5 * len(patterns))

    # --- Điểm dictionary (15đ) ---
    dict_score = 0 if dict_result["is_common"] else 15

    total = round(char_score + entropy_score + pattern_score + dict_score)
    total = max(0, min(total, 100))

    if total < 30:
        label = "Rất yếu"
    elif total < 50:
        label = "Yếu"
    elif total < 70:
        label = "Trung bình"
    elif total < 90:
        label = "Mạnh"
    else:
        label = "Xuất sắc"

    return {
        "score": total,
        "label": label,
        "entropy": round(entropy, 2),
        "crack_time": estimate_crack_time(entropy),
        "char_analysis": char_analysis,
        "patterns": patterns,
        "dictionary": dict_result,
    }
