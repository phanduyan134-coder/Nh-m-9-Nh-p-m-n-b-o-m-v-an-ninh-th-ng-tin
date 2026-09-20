"""
app.py
AI Password Auditing Tool
Đồ án môn: Nhập môn Bảo đảm và An ninh Thông tin
Đề tài: AI phát hiện mật khẩu yếu trong quá trình Password Auditing

Chạy ứng dụng:
    streamlit run app.py
"""

import time

import pandas as pd
import streamlit as st

import importlib
from modules import analyzer, bruteforce, rainbow, ai_advisor
importlib.reload(ai_advisor)

# ---------------------------------------------------------------------------
# PAGE CONFIG & CUSTOM CSS (dark navy theme, giống bản thiết kế tham khảo)
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Password Strength Analyzer",
    page_icon="🔐",
    layout="centered",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    .stApp {
        background: radial-gradient(circle at top, #101a33 0%, #0a1224 60%, #060b17 100%);
        color: #e5eaf5;
    }
    .block-container { padding-top: 2rem; max-width: 760px; }

    .main-title {
        text-align: center;
        font-size: 2.3rem;
        font-weight: 800;
        background: linear-gradient(90deg, #4f8bff, #7ce0ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.1rem;
    }
    .sub-title { text-align: center; color: #9fb0d0; margin-bottom: 1.5rem; }

    .card {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 16px;
        padding: 1.3rem 1.4rem;
        margin-bottom: 1rem;
    }

    .checklist-item { display:flex; align-items:center; gap:0.5rem; margin-bottom:0.4rem; font-size:0.95rem;}
    .check-ok { color:#33d17a; }
    .check-no { color:#5c6a8a; }

    .crack-time-value { color:#39d6f0; font-weight:700; }

    .verdict-box {
        text-align:center; padding:0.8rem; border-radius:12px; font-weight:700; margin-top:0.6rem;
    }
    .verdict-excellent { background: rgba(51,209,122,0.12); color:#33d17a; }
    .verdict-strong { background: rgba(57,214,240,0.12); color:#39d6f0; }
    .verdict-medium { background: rgba(255,193,7,0.12); color:#ffc107; }
    .verdict-weak { background: rgba(255,99,99,0.12); color:#ff6363; }

    div.stButton > button {
        background: linear-gradient(90deg, #2f80ff, #39d6f0);
        color: white; border: none; border-radius: 10px; font-weight:700; padding: 0.55rem 1rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown('<div class="main-title">🔐 Password Strength Analyzer</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Secure Your Digital Life — AI Password Auditing Tool</div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# SIDEBAR: API KEY (không hard-code, không log lại)
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("⚙️ Cấu hình AI")
    api_key = st.text_input(
        "Gemini API Key",
        type="password",
        help="API key chỉ lưu tạm trong phiên làm việc (session), không được ghi log hay lưu file.",
    )
    st.session_state["gemini_api_key"] = api_key
    st.caption("🔒 Mật khẩu gốc của bạn KHÔNG BAO GIỜ được gửi lên AI API — chỉ gửi thông số phân tích (độ dài, entropy, điểm số...).")
    st.divider()
    st.caption("Đồ án: Nhập môn Bảo đảm và An ninh Thông tin — Nhóm 9")

wordlist = analyzer.load_wordlist()

# ---------------------------------------------------------------------------
# TABS
# ---------------------------------------------------------------------------

tab1, tab2, tab3, tab4 = st.tabs(
    ["🔍 Phân tích mật khẩu", "⚔️ Mô phỏng tấn công", "🌈 Rainbow Table", "🤖 AI Security Advisor"]
)

# ===========================================================================
# TAB 1 — PASSWORD ANALYZER
# ===========================================================================
with tab1:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    col_input, col_check = st.columns([1.3, 1])

    with col_input:
        password = st.text_input("Nhập mật khẩu cần kiểm tra", type="password", key="pwd_input")
        result = analyzer.calculate_score(password, wordlist)

        st.progress(result["score"] / 100)
        st.markdown(f"**Điểm số: {result['score']}%**  —  Mức độ: **{result['label']}**")

        if st.button("📋 Copy mật khẩu (giả lập)"):
            st.toast("Đã copy mật khẩu vào clipboard (giả lập demo).")

    with col_check:
        char = result["char_analysis"]
        checklist = [
            ("8+ ký tự", char["length_ok"]),
            ("Chữ hoa", char["has_upper"]),
            ("Chữ thường", char["has_lower"]),
            ("Số", char["has_digit"]),
            ("Ký tự đặc biệt", char["has_symbol"]),
        ]
        for label, ok in checklist:
            icon = "✅" if ok else "⬜"
            cls = "check-ok" if ok else "check-no"
            st.markdown(f'<div class="checklist-item {cls}">{icon} {label}</div>', unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

    if password:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"**Entropy:** {result['entropy']} bits")
        with c2:
            st.markdown(f'**Crack Time:** <span class="crack-time-value">{result["crack_time"]}</span>', unsafe_allow_html=True)

        if result["patterns"]:
            st.markdown("**⚠️ Pattern yếu phát hiện:**")
            for p in result["patterns"]:
                st.markdown(f"- {p}")

        if result["dictionary"]["is_common"]:
            st.error(f"❌ Mật khẩu trùng/chứa từ phổ biến: `{result['dictionary']['matched_word']}` — rất dễ bị dò!")

        verdict_class = {
            "Rất yếu": "verdict-weak",
            "Yếu": "verdict-weak",
            "Trung bình": "verdict-medium",
            "Mạnh": "verdict-strong",
            "Xuất sắc": "verdict-excellent",
        }.get(result["label"], "verdict-medium")

        verdict_text = {
            "Rất yếu": "Rất yếu: Đổi mật khẩu ngay lập tức!",
            "Yếu": "Yếu: Nên cải thiện thêm.",
            "Trung bình": "Trung bình: Có thể cải thiện.",
            "Mạnh": "Mạnh: Khá an toàn.",
            "Xuất sắc": "Xuất sắc: Rất an toàn!",
        }.get(result["label"], "")

        st.markdown(f'<div class="verdict-box {verdict_class}">{verdict_text}</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("Nhập mật khẩu ở trên để xem phân tích chi tiết.")

# ===========================================================================
# TAB 2 — ATTACK SIMULATION (Dictionary + Brute-force)
# ===========================================================================
with tab2:
    st.subheader("⚔️ Mô phỏng tấn công mật khẩu")
    st.caption("Chỉ mô phỏng trên mật khẩu bạn tự nhập, phục vụ mục đích học tập.")

    atk_password = st.text_input("Mật khẩu để mô phỏng tấn công", type="password", key="atk_pwd")

    if atk_password:
        st.markdown("### 📖 Dictionary Attack")
        with st.spinner("Đang thử các mật khẩu phổ biến..."):
            dict_result = bruteforce.dictionary_attack(atk_password, wordlist)
        if dict_result["cracked"]:
            st.error(f"❌ Bị dò ra sau {dict_result['attempts']} lượt thử ({dict_result['elapsed']:.4f}s) — khớp từ điển: `{dict_result['matched_word']}`")
        else:
            st.success(f"✅ Không tìm thấy trong wordlist ({dict_result['attempts']} từ, {dict_result['elapsed']:.4f}s)")

        st.markdown("### 💥 Brute-force Analysis")
        bf_info = bruteforce.full_bruteforce_analysis(atk_password)
        st.write(f"Charset size: **{bf_info['charset_size']}**, Độ dài: **{bf_info['length']}**")
        st.write(f"Tổng số tổ hợp có thể: **{bf_info['total_combinations']:,}**")

        df = pd.DataFrame(
            [{"Kịch bản tấn công": k, "Thời gian ước lượng": v} for k, v in bf_info["scenarios"].items()]
        )
        st.table(df)

        if len(atk_password) <= 6:
            st.markdown("### 🎬 Mô phỏng Brute-force trực tiếp (thật, độ dài ≤ 6)")
            if st.button("▶️ Chạy mô phỏng"):
                placeholder = st.empty()
                progress = st.progress(0)
                found_result = None
                for attempt, guess, found, elapsed in bruteforce.simulate_bruteforce_live(atk_password):
                    placeholder.write(f"Lượt thử #{attempt}: `{guess}`  —  {elapsed:.3f}s")
                    progress.progress(min(attempt / 500000, 1.0))
                    if found:
                        found_result = (attempt, elapsed)
                        break
                if found_result:
                    st.success(f"🎯 Bẻ khóa thành công sau {found_result[0]} lượt thử, {found_result[1]:.3f} giây!")
                else:
                    st.warning("Không tìm thấy trong giới hạn số lượt thử demo.")
        else:
            st.caption("Mật khẩu dài hơn 6 ký tự → chỉ hiển thị ước lượng lý thuyết ở trên (brute-force thật sẽ mất quá nhiều thời gian để demo).")
    else:
        st.info("Nhập mật khẩu ở trên để bắt đầu mô phỏng.")

# ===========================================================================
# TAB 3 — RAINBOW TABLE
# ===========================================================================
with tab3:
    st.subheader("🌈 Rainbow Table & Hashing")

    algo = st.selectbox("Thuật toán băm", ["md5", "sha1", "sha256"], index=0)
    rt_password = st.text_input("Mật khẩu để minh họa", type="password", key="rt_pwd")

    if rt_password:
        st.markdown("### 🔑 Hash không salt")
        h = rainbow.generate_hash(rt_password, algo)
        st.code(h, language="text")

        st.markdown("### 🔎 Tra cứu trong Rainbow Table (từ danh sách mật khẩu phổ biến)")
        table = rainbow.build_rainbow_table(wordlist, algo)
        found = rainbow.lookup_hash(h, table)
        if found:
            st.error(f"❌ Cracked! Hash khớp với plaintext trong bảng: `{found}`")
        else:
            st.success("✅ Không tìm thấy trong rainbow table demo (mật khẩu không nằm trong wordlist mẫu).")

        st.markdown("### 🧂 Minh họa hiệu ứng của Salt")
        demo = rainbow.demonstrate_salt_effect(rt_password, wordlist, algo)
        colA, colB = st.columns(2)
        with colA:
            st.markdown("**Không salt (2 lần hash):**")
            st.code(demo["unsalted_hash_1"], language="text")
            st.code(demo["unsalted_hash_2"], language="text")
            st.write("Giống nhau:", "✅ Có" if demo["unsalted_identical"] else "❌ Không")
        with colB:
            st.markdown("**Có salt (2 lần hash, salt random):**")
            st.code(demo["salted_hash_1"]["hash"], language="text")
            st.code(demo["salted_hash_2"]["hash"], language="text")
            st.write("Giống nhau:", "✅ Có" if demo["salted_identical"] else "❌ Không")

        st.info(
            "➡️ Vì salt ngẫu nhiên mỗi lần khác nhau nên hai lần hash cùng một mật khẩu cho ra "
            "kết quả khác nhau. Rainbow table (được tính sẵn không kèm salt) sẽ **không** lookup được "
            "hash có salt — đây là lý do salt là biện pháp phòng chống rainbow table hiệu quả."
        )

        st.markdown("### 🔒 So sánh với bcrypt (chuẩn lưu mật khẩu hiện đại)")
        bc_hash = rainbow.generate_bcrypt_hash(rt_password)
        st.code(bc_hash, language="text")
        st.caption("bcrypt tự động sinh salt và có 'work factor' để làm chậm brute-force — an toàn hơn MD5/SHA thuần rất nhiều.")
    else:
        st.info("Nhập mật khẩu ở trên để xem minh họa hashing & rainbow table.")

# ===========================================================================
# TAB 4 — AI SECURITY ADVISOR
# ===========================================================================
with tab4:
    st.subheader("🤖 AI Security Advisor")
    st.caption("Mật khẩu gốc KHÔNG được gửi lên AI — chỉ gửi metadata (độ dài, entropy, điểm số, pattern...).")

    ai_password = st.text_input("Mật khẩu cần AI tư vấn", type="password", key="ai_pwd")

    if ai_password:
        score_result = analyzer.calculate_score(ai_password, wordlist)
        metadata_preview = ai_advisor.build_privacy_safe_metadata(score_result)

        with st.expander("📦 Xem metadata sẽ gửi lên AI (không chứa mật khẩu gốc)"):
            st.json(metadata_preview)

        if st.button("🧠 Nhận phân tích từ AI"):
            key = st.session_state.get("gemini_api_key", "")
            with st.spinner("Đang gọi Gemini API..."):
                st.session_state["ai_result"] = ai_advisor.call_gemini_advisor(score_result, key)

        if "ai_result" in st.session_state and st.session_state["ai_result"]:
            ai_res = st.session_state["ai_result"]
            if ai_res["success"]:
                st.markdown(ai_res["text"])
            else:
                st.warning(f"⚠️ Không gọi được AI ({ai_res['error']}). Hiển thị khuyến nghị dự phòng (rule-based):")
                st.markdown(ai_advisor.rule_based_fallback_advice(score_result))

        st.divider()
        st.markdown("### 🔑 Sinh mật khẩu mạnh mới (CSPRNG — không dùng AI để tạo trực tiếp)")
        col1, col2 = st.columns(2)
        with col1:
            length = st.slider("Độ dài", 8, 32, 16)
        with col2:
            use_symbols = st.checkbox("Bao gồm ký tự đặc biệt", value=True)

        if st.button("🎲 Tạo mật khẩu mạnh"):
            new_pwd = ai_advisor.generate_strong_password(length, use_symbols)
            st.code(new_pwd, language="text")

        if st.button("📝 Tạo Passphrase gợi ý"):
            phrase = ai_advisor.generate_passphrase()
            st.code(phrase, language="text")
    else:
        st.info("Nhập mật khẩu ở trên để nhận tư vấn từ AI.")

st.markdown("---")
st.caption("⚠️ Công cụ phục vụ mục đích học tập/kiểm thử trên dữ liệu do người dùng cung cấp — không dùng để tấn công hệ thống hoặc tài khoản thực tế.")
