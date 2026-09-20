# AI Password Auditing Tool

Đồ án môn **Nhập môn Bảo đảm và An ninh Thông tin**
Đề tài: *AI phát hiện mật khẩu yếu trong quá trình Password Auditing*

## 1. Cài đặt

```bash
cd password_auditing_tool
pip install -r requirements.txt
```

## 2. Chạy ứng dụng

```bash
streamlit run app.py
```

Ứng dụng sẽ mở tại `http://localhost:8501`.

## 3. Cấu hình AI (Gemini API)

1. Lấy API key miễn phí tại: https://aistudio.google.com/app/apikey
2. Mở ứng dụng → nhập key vào ô **"Gemini API Key"** ở thanh bên trái (sidebar).
3. Key chỉ được lưu tạm trong phiên làm việc (session), **không** được ghi vào file hay hard-code trong source code.
4. Nếu không nhập key hoặc gọi API lỗi, hệ thống tự động dùng **khuyến nghị dự phòng rule-based**.

> ⚠️ Mật khẩu gốc của người dùng **không bao giờ** được gửi lên AI API — chỉ gửi
> các thông số đã trích xuất (độ dài, entropy, điểm số, pattern phát hiện được...).

## 4. Cấu trúc project

```
password_auditing_tool/
├── app.py                     # Giao diện Streamlit chính (4 tab chức năng)
├── modules/
│   ├── analyzer.py            # Character analysis, entropy, pattern, dictionary, score
│   ├── bruteforce.py          # Mô phỏng dictionary attack & brute-force
│   ├── rainbow.py             # Hashing, rainbow table, minh họa salt, bcrypt
│   └── ai_advisor.py          # Tích hợp Gemini API (privacy-safe) + sinh mật khẩu mạnh
├── data/
│   └── common_passwords.txt   # Wordlist mật khẩu phổ biến (dùng cho demo)
├── requirements.txt
└── README.md
```

## 5. Các chức năng chính (map với sườn báo cáo)

| Tab | Chức năng | Tương ứng đề mục báo cáo |
|---|---|---|
| Phân tích mật khẩu | Character Analysis, Entropy, Pattern Detection, Dictionary Check, Security Score | Password Strength, Password Analyzer |
| Mô phỏng tấn công | Dictionary Attack, Brute-force (mô phỏng thật với mật khẩu ≤ 6 ký tự + ước lượng lý thuyết) | Password Cracking, Brute-force Attack |
| Rainbow Table | Sinh hash MD5/SHA-1/SHA-256, xây rainbow table, lookup, minh họa salt, so sánh bcrypt | Hash và Password Hashing, Rainbow Table |
| AI Security Advisor | Gửi metadata (không gửi password gốc) cho Gemini API để giải thích rủi ro & khuyến nghị; sinh mật khẩu mạnh bằng CSPRNG | AI trong Password Security |

## 6. Phạm vi & giới hạn (Scope)

- Hệ thống phục vụ mục đích **học tập và kiểm thử** trên mật khẩu do chính người dùng nhập.
- **Không** thực hiện tấn công vào tài khoản hoặc hệ thống thực tế.
- Brute-force thật sự chỉ chạy cục bộ và giới hạn ở mật khẩu ngắn (≤ 6 ký tự) để đảm bảo demo chạy trong thời gian hợp lý; với mật khẩu dài hơn, hệ thống chỉ tính toán ước lượng lý thuyết.
- Rainbow table trong demo là bảng tra cứu (lookup table) đơn giản hóa để minh họa nguyên lý; rainbow table thực tế dùng reduction function theo chuỗi để tối ưu bộ nhớ (được trình bày ở phần lý thuyết trong báo cáo).
