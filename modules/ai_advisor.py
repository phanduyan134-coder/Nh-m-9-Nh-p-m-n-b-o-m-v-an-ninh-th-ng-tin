"""
ai_advisor.py
Module tích hợp AI (Gemini API) để giải thích rủi ro và đưa ra khuyến nghị.

NGUYÊN TẮC BẢO MẬT / QUYỀN RIÊNG TƯ (Privacy by Design):
- KHÔNG BAO GIỜ gửi mật khẩu gốc (plaintext) của người dùng lên AI API.
- Chỉ gửi METADATA đã được trích xuất: độ dài, có chữ hoa/thường/số/ký tự đặc
  biệt hay không, entropy, điểm số, danh sách pattern yếu phát hiện được,
  có trùng dictionary hay không (boolean).
- API key do người dùng tự nhập tại runtime (session_state), KHÔNG hard-code
  trong source code, KHÔNG ghi log ra file.
- Việc sinh mật khẩu mạnh mới dùng module `secrets` (CSPRNG) để đảm bảo tính
  ngẫu nhiên thật sự, AI chỉ được dùng để gợi ý PHONG CÁCH (passphrase, cấu trúc)
  chứ không tự bịa ra mật khẩu cuối cùng.
"""

import json
import secrets
import string

import requests

GEMINI_MODEL = "gemini-1.5-flash"
GEMINI_ENDPOINT = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"


def build_privacy_safe_metadata(score_result: dict) -> dict:
    """Trích xuất metadata an toàn (không chứa mật khẩu gốc) để gửi cho AI."""
    char = score_result.get("char_analysis", {})
    return {
        "length": char.get("length"),
        "has_upper": char.get("has_upper"),
        "has_lower": char.get("has_lower"),
        "has_digit": char.get("has_digit"),
        "has_symbol": char.get("has_symbol"),
        "entropy_bits": score_result.get("entropy"),
        "score": score_result.get("score"),
        "label": score_result.get("label"),
        "estimated_crack_time": score_result.get("crack_time"),
        "weak_patterns_found": score_result.get("patterns", []),
        "is_common_password": score_result.get("dictionary", {}).get("is_common", False),
    }


def _build_prompt(metadata: dict) -> str:
    return (
        "Bạn là một chuyên gia an ninh thông tin (security advisor). "
        "Dưới đây là kết quả phân tích độ mạnh của một mật khẩu (KHÔNG chứa mật khẩu gốc, "
        "chỉ chứa các đặc điểm đã được trích xuất):\n\n"
        f"{json.dumps(metadata, ensure_ascii=False, indent=2)}\n\n"
        "Hãy trả lời bằng tiếng Việt, ngắn gọn, gồm 3 phần:\n"
        "1) Nhận xét rủi ro (2-3 câu, giải thích vì sao mật khẩu này an toàn/không an toàn).\n"
        "2) Khuyến nghị cải thiện cụ thể (gạch đầu dòng, tối đa 4 ý).\n"
        "3) Một gợi ý CẤU TRÚC passphrase mạnh (ví dụ dạng 'TinhTu-DanhTu-So-KyTuDacBiet'), "
        "không tự tạo ra một mật khẩu cụ thể nào.\n"
    )


def get_available_models(api_key: str) -> list:
    """Lấy danh sách các model đang hoạt động thực tế trên tài khoản này từ Google."""
    headers = {"Content-Type": "application/json", "x-goog-api-key": api_key}
    params = {"key": api_key} if api_key.startswith("AIza") else None

    EXCLUDED_KEYWORDS = ["tts", "embed", "imagen", "audio", "realtime", "robotics", "vision-preview"]

    def _is_valid_text_model(name: str, methods: list = None, output_modalities: list = None) -> bool:
        n = name.lower()
        if any(bad in n for bad in EXCLUDED_KEYWORDS):
            return False
        if "gemini" not in n:
            return False
        if methods and "generateContent" not in methods:
            return False
        if output_modalities and "TEXT" not in output_modalities:
            return False
        return True

    def _sort_key(name: str):
        n = name.lower()
        is_flash = 0 if "flash" in n else 1
        is_preview = 1 if ("preview" in n or "exp" in n) else 0
        if "2.0" in n:
            ver = 0
        elif "1.5" in n:
            ver = 1
        elif "2.5" in n:
            ver = 2
        else:
            ver = 3
        return (is_flash, is_preview, ver)

    # 1. Thử lấy qua official SDK client.models.list()
    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        sdk_models = []
        for m in client.models.list():
            name = getattr(m, "name", "")
            clean_name = name.replace("models/", "")
            actions = getattr(m, "supported_actions", []) or getattr(m, "supported_generation_methods", [])
            output_mods = getattr(m, "output_modalities", None) or getattr(m, "supported_output_modalities", None)
            if _is_valid_text_model(clean_name, actions, output_mods):
                sdk_models.append(clean_name)
        if sdk_models:
            return sorted(list(set(sdk_models)), key=_sort_key)
    except Exception:
        pass

    # 2. Fallback qua HTTP GET ListModels
    for ver in ["v1beta", "v1"]:
        try:
            url = f"https://generativelanguage.googleapis.com/{ver}/models"
            res = requests.get(url, headers=headers, params=params, timeout=10)
            if res.status_code == 200:
                data = res.json()
                models = []
                for m in data.get("models", []):
                    clean_name = m.get("name", "").replace("models/", "")
                    methods = m.get("supportedGenerationMethods", [])
                    output_mods = m.get("supportedOutputModalities", [])
                    if _is_valid_text_model(clean_name, methods, output_mods):
                        models.append(clean_name)
                if models:
                    return sorted(list(set(models)), key=_sort_key)
        except Exception:
            pass

    return ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-2.5-flash", "gemini-1.5-pro"]


def call_gemini_advisor(score_result: dict, api_key: str, timeout: int = 20) -> dict:
    """
    Gọi Gemini API để lấy phân tích rủi ro + khuyến nghị.
    Tự động dò tìm danh sách các model khả dụng cho tài khoản và gọi model tối ưu nhất.
    """
    if not api_key or not api_key.strip():
        return {"success": False, "text": None, "error": "Chưa nhập API key."}

    clean_key = api_key.strip()
    metadata = build_privacy_safe_metadata(score_result)
    prompt = _build_prompt(metadata)

    # 1. Tự động lấy danh sách model văn bản khả dụng mà Google cấp cho tài khoản này
    models_to_try = get_available_models(clean_key)

    # Luôn bảo đảm có danh sách dự phòng các model text phổ biến nhất
    for fallback_m in ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-2.5-flash", "gemini-1.5-pro"]:
        if fallback_m not in models_to_try:
            models_to_try.append(fallback_m)

    # 2. Thử gọi qua official google-genai SDK nếu có
    try:
        from google import genai
        client = genai.Client(api_key=clean_key)
        for m in models_to_try:
            try:
                resp = client.models.generate_content(model=m, contents=prompt)
                if resp and resp.text:
                    return {"success": True, "text": resp.text, "error": None}
            except Exception as e_sdk:
                err_str = str(e_sdk)
                if "401" in err_str or "UNAUTHENTICATED" in err_str:
                    return {"success": False, "text": None, "error": "Lỗi xác thực (401): API key không hợp lệ hoặc tài khoản chưa kích hoạt Generative Language API."}
                if "403" in err_str or "PERMISSION_DENIED" in err_str:
                    return {"success": False, "text": None, "error": "Lỗi quyền truy cập (403): Key bị giới hạn hoặc chưa bật Generative Language API trong Project."}
                # Nếu gặp lỗi 400 (model không hỗ trợ) hoặc lỗi khác -> tiếp tục thử model tiếp theo
                continue
    except Exception:
        pass

    # 3. Fallback sang HTTP requests trực tiếp
    payload = {
        "contents": [{"parts": [{"text": prompt}]}]
    }

    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": clean_key,
    }

    last_error = None
    for model in models_to_try:
        for api_ver in ["v1beta", "v1"]:
            url = f"https://generativelanguage.googleapis.com/{api_ver}/models/{model}:generateContent"
            try:
                params = {"key": clean_key} if clean_key.startswith("AIza") else None
                response = requests.post(
                    url,
                    headers=headers,
                    params=params,
                    json=payload,
                    timeout=timeout,
                )
                if response.status_code == 200:
                    data = response.json()
                    candidates = data.get("candidates", [])
                    if candidates and "content" in candidates[0]:
                        parts = candidates[0]["content"].get("parts", [])
                        if parts and "text" in parts[0]:
                            return {"success": True, "text": parts[0]["text"], "error": None}
                elif response.status_code in (401, 403):
                    err_data = response.json().get("error", {})
                    msg = err_data.get("message", "API key không hợp lệ hoặc chưa được cấp quyền.")
                    return {"success": False, "text": None, "error": f"Lỗi xác thực ({response.status_code}): {msg}"}
                elif response.status_code == 404:
                    continue
                elif response.status_code == 400:
                    err_data = response.json().get("error", {})
                    msg = err_data.get("message", "")
                    last_error = f"Model {model} ({api_ver}) không tương thích (400: {msg})"
                    continue
                elif response.status_code == 429:
                    last_error = f"Model {model} ({api_ver}) bị giới hạn quota (429)."
                    continue
                else:
                    last_error = f"Lỗi máy chủ Google ({response.status_code}): {response.text[:120]}"
            except requests.exceptions.RequestException as e:
                last_error = f"Lỗi kết nối mạng: {e}"
            except (KeyError, IndexError, json.JSONDecodeError) as e:
                last_error = f"Không đọc được phản hồi từ AI: {e}"

    return {"success": False, "text": None, "error": last_error or "Không thể kết nối với mô hình AI."}


def rule_based_fallback_advice(score_result: dict) -> str:
    """Khuyến nghị dự phòng (rule-based) khi không có API key hoặc API lỗi."""
    metadata = build_privacy_safe_metadata(score_result)
    lines = ["**Nhận xét (rule-based, không dùng AI):**"]

    if metadata["is_common_password"]:
        lines.append("- Mật khẩu trùng/chứa từ trong danh sách mật khẩu phổ biến -> rất dễ bị dò bằng dictionary attack.")
    if metadata["weak_patterns_found"]:
        lines.append(f"- Phát hiện pattern yếu: {', '.join(metadata['weak_patterns_found'])}.")
    if not metadata["has_symbol"]:
        lines.append("- Thiếu ký tự đặc biệt, nên bổ sung để tăng entropy.")
    if metadata["length"] and metadata["length"] < 12:
        lines.append("- Độ dài dưới 12 ký tự, nên tăng lên >= 12-16 ký tự.")
    if metadata["score"] >= 80:
        lines.append("- Mật khẩu đã khá tốt, có thể giữ nguyên cấu trúc hiện tại.")

    lines.append("\n**Gợi ý cấu trúc passphrase:** `TinhTu-DanhTu-Nam-KyTuDacBiet` (ví dụ ý tưởng: `NangDong-BienXanh-92!`).")
    return "\n".join(lines)


def generate_strong_password(length: int = 16, use_symbols: bool = True) -> str:
    """
    Sinh mật khẩu mạnh bằng CSPRNG (module secrets), KHÔNG dùng AI để tạo
    trực tiếp chuỗi mật khẩu cuối cùng nhằm đảm bảo tính ngẫu nhiên thật sự.
    """
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+"

    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and (not use_symbols or any(c in "!@#$%^&*()-_=+" for c in pwd))
        ):
            return pwd


def generate_passphrase(num_words: int = 4) -> str:
    """Sinh passphrase kiểu Diceware đơn giản từ danh sách từ tiếng Việt không dấu ngắn."""
    words = [
        "song", "nui", "bien", "hoa", "may", "gio", "sao", "trang", "nang",
        "cay", "la", "chim", "ca", "voi", "ho", "cop", "rong", "phuong",
        "kim", "moc", "thuy", "tho", "hoc", "vui", "an", "yen", "manh", "nhanh",
    ]
    parts = [secrets.choice(words).capitalize() for _ in range(num_words)]
    parts.append(str(secrets.randbelow(90) + 10))
    parts.append(secrets.choice("!@#$%*"))
    return "-".join(parts[:-2]) + "-" + parts[-2] + parts[-1]
