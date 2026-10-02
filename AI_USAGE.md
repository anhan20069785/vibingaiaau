# Ghi chú về việc dùng trợ lý AI

Trang này được viết với sự hỗ trợ của một trợ lý lập trình AI, dưới sự chỉ đạo và kiểm chứng
của người yêu cầu. Ghi chú này nói rõ phần nào do AI làm và cách người dùng kiểm chứng lại.

## Hướng và phạm vi

Ý tưởng, phạm vi và các quyết định kỹ thuật đều do người yêu cầu chốt: dùng P-256, ký và xác
minh theo FIPS 186-5, sinh `k` theo RFC 6979, có bảng tham số miền và các ca kiểm thử phá hoại.
Trợ lý AI chọn hướng trình bày (bàn thí nghiệm kiểu tài liệu chuẩn) và màu sắc, như đã ghi ở
đầu `DESIGN.md`.

## Phần AI soạn

- Mã nguồn trong `src/`: số học đường cong, codec DER/PEM, sinh `k` theo RFC 6979, hàm ký và
  xác minh, minh họa dùng lại `k`.
- Giao diện `index.html`, `styles.css`, và phần nối sự kiện `src/lab.js`.
- Bộ kiểm thử trong `tests/`.
- Các tài liệu: `BAO_CAO.md`, `README.md`, `AI_USAGE.md`, `DESIGN.md`.

## Cách kiểm chứng

- Hằng số P-256 trong `src/p256.js` được so với bản in trong SP 800-186 và khóa lại bằng test.
- Vector RFC 6979 A.2.5 được so từng byte cho `Q`, `k`, `r`, `s`.
- Bốn chiều đối chiếu với OpenSSL CLI trong `tests/interop.test.mjs`.
- Trang chạy bảy ca phá hoại ngay trên trình duyệt; bảng kết quả là bằng chứng của phiên đang mở,
  không phải số liệu mẫu.

Người yêu cầu chịu trách nhiệm về nội dung cuối cùng; mọi con số hiển thị trên trang đều do
chính trang tính ra trong phiên chạy đó.
