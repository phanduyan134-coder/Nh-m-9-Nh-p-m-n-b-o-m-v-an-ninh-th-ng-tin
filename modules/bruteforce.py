"""
bruteforce.py
Module mô phỏng tấn công mật khẩu (Password Cracking Simulation).

LƯU Ý PHẠM VI (Scope):
- Chỉ mô phỏng trên mật khẩu do CHÍNH người dùng nhập để phục vụ học tập/kiểm thử.
- Brute-force thật sự chỉ chạy cục bộ, giới hạn độ dài <= 6 ký tự để đảm bảo
  demo chạy trong thời gian hợp lý (phục vụ minh họa thuật toán, không nhằm
  bẻ khóa hệ thống thực tế).
- Với mật khẩu dài hơn, hệ thống chỉ TÍNH TOÁN/ƯỚC LƯỢNG (không brute-force thật)
  dựa trên số tổ hợp và tốc độ dò giả định.
"""

import itertools
import string
import time


def get_charset(password: str) -> str:
    """Xác định bảng ký tự cần dùng để brute-force dựa trên các loại ký tự có trong mật khẩu."""
    charset = ""
    if any(c.islower() for c in password):
        charset += string.ascii_lowercase
    if any(c.isupper() for c in password):
        charset += string.ascii_uppercase
    if any(c.isdigit() for c in password):
        charset += string.digits
    if any(c in string.punctuation for c in password):
        charset += string.punctuation
    return charset or string.ascii_lowercase


def calculate_combinations(charset_size: int, length: int) -> int:
    """Tổng số tổ hợp có thể có = charset_size ^ length."""
    return charset_size ** length


def estimate_time_seconds(total_combinations: int, guesses_per_second: float = 1e7) -> float:
    """Ước lượng thời gian trung bình (giây) để brute-force hết không gian mật khẩu."""
    return (total_combinations / 2) / guesses_per_second


def format_seconds(seconds: float) -> str:
    if seconds < 1:
        return "< 1 giây"
    units = [
        ("năm", 60 * 60 * 24 * 365),
        ("ngày", 60 * 60 * 24),
        ("giờ", 60 * 60),
        ("phút", 60),
        ("giây", 1),
    ]
    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            return f"{seconds / unit_seconds:,.2f} {name}"
    return f"{seconds:.2f} giây"


def simulate_bruteforce_live(password: str, max_length: int = 6, max_attempts: int = 2_000_000):
    """
    Generator brute-force THẬT trên máy cục bộ, chỉ dùng cho demo với mật khẩu
    ngắn (<= max_length) do chính người dùng cung cấp.

    Yield mỗi lần thử: (attempt_number, current_guess, found: bool, elapsed_seconds)
    """
    if len(password) > max_length:
        # Không brute-force thật với mật khẩu dài -> tránh treo ứng dụng
        yield (0, None, False, 0.0)
        return

    charset = get_charset(password)
    start = time.time()
    attempt = 0

    for length in range(1, len(password) + 1):
        for combo in itertools.product(charset, repeat=length):
            attempt += 1
            guess = "".join(combo)
            elapsed = time.time() - start
            found = guess == password
            if attempt % 500 == 0 or found:
                yield (attempt, guess, found, elapsed)
            if found:
                return
            if attempt >= max_attempts:
                yield (attempt, guess, False, elapsed)
                return


def dictionary_attack(password: str, wordlist: list) -> dict:
    """
    Mô phỏng dictionary attack: thử lần lượt từng từ trong wordlist.
    Trả về kết quả có tìm thấy không, số lượt thử, thời gian.
    """
    start = time.time()
    for i, word in enumerate(wordlist, start=1):
        if word.strip().lower() == password.lower():
            return {
                "cracked": True,
                "attempts": i,
                "elapsed": time.time() - start,
                "matched_word": word.strip(),
            }
    return {
        "cracked": False,
        "attempts": len(wordlist),
        "elapsed": time.time() - start,
        "matched_word": None,
    }


def full_bruteforce_analysis(password: str, guesses_per_second: float = 1e7) -> dict:
    """Bảng phân tích brute-force đầy đủ theo từng loại tấn công (offline/online, GPU...)."""
    charset = get_charset(password)
    combos = calculate_combinations(len(charset), len(password))

    scenarios = {
        "Online (100 lượt/giây - có giới hạn thử)": 100,
        "Offline chậm (10 nghìn lượt/giây - CPU thường)": 1e4,
        "Offline nhanh (10 tỷ lượt/giây - GPU hiện đại)": 1e10,
        "Offline siêu tốc (100 tỷ lượt/giây - Cluster GPU)": 1e11,
    }

    results = {}
    for name, speed in scenarios.items():
        seconds = estimate_time_seconds(combos, speed)
        results[name] = format_seconds(seconds)

    return {
        "charset_size": len(charset),
        "length": len(password),
        "total_combinations": combos,
        "scenarios": results,
    }
