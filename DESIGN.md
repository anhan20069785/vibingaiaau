# DESIGN.md

> Cảnh báo trung thực: hướng này do trợ lý AI chọn, không phải do người dùng cung cấp.
> Theo antislop (First-Run Install Wizard, đường 2), hướng do AI chọn có xu hướng rơi về
> gu mặc định của mô hình nên dễ đơn điệu. Bản dựng vẫn là deliverable thật (không phải
> draft without direction), nhưng thay bằng hướng của bạn thì kết quả sẽ có dấu ấn riêng hơn.

## Sản phẩm

Công cụ web một trang để thực hành đúng một việc: sinh khóa P-256, ký một thông điệp bằng
khóa bí mật, và xác minh chữ ký bằng khóa công khai. Kèm bảng tham số miền, bảng đối chiếu
FIPS 186-5, và các ca kiểm thử phá hoại chạy được ngay trên trang.

## Đối tượng

Sinh viên môn mật mã đang làm bài theo FIPS 186-5, và giảng viên chấm demo 8 đến 10 phút.
Người dùng đọc được hex, biết ECDSA là gì, cần đối chiếu từng bước với chuẩn.

## Danh tính

Bàn thí nghiệm của một tài liệu chuẩn: giấy ngà, mực xanh đen, mực son đỏ dùng rất tiết chế.
Số thứ tự bước và đường kẻ mảnh thay cho khung trang trí. Không logo, không slogan, không
biểu tượng trang trí.

## Bảng màu

| Vai trò | Mã | Dùng ở đâu |
|---|---|---|
| Giấy | `#f4f1e8` | nền trang |
| Mặt giấy | `#fbf9f3` | vùng nhập liệu, bảng |
| Mực | `#171b21` | chữ chính |
| Mực nhạt | `#5c6470` | chú thích, nhãn |
| Đường kẻ | `#d5cec0` | đường phân cách, viền 1px |
| Son | `#9d3323` | số bước đang làm, nút chính, viền tiêu điểm, trạng thái sai |
| Lục | `#1c5c3c` | trạng thái hợp lệ |

Ba màu lõi (giấy, mực, đường kẻ) cộng một màu nhấn là son. Lục chỉ mang nghĩa "hợp lệ",
đỏ son mang nghĩa "cần chú ý hoặc sai", nên hai màu này là ngữ nghĩa chứ không phải trang trí.

## Kiểu chữ

| Vai trò | Stack | Lý do |
|---|---|---|
| Tiêu đề | Georgia, "Iowan Old Style", "Palatino Linotype", serif | đọc như tiêu đề một tài liệu chuẩn, không phải như landing page |
| Nội dung | system-ui, "Segoe UI", sans-serif | đọc nhanh trên màn hình |
| Hex, số, PEM | ui-monospace, Consolas, "Courier New", monospace | cột hex thẳng hàng, so sánh từng byte bằng mắt được |

Không tải font từ mạng. Trang chạy offline.

## Dials

- ENERGY 2: nền tĩnh, một màu nhấn, không glow, không gradient.
- RHYTHM 3: nhịp khác nhau giữa các phần. Bảng tham số, khối lệnh, cặp đôi ký và xác minh, và
  danh sách ca kiểm thử có bố cục khác nhau, không lặp một khuôn.
- MOTION 1: chỉ trạng thái hover và focus. Không hoạt ảnh chạy vòng.

## Điều không làm

Không emoji, không gạch dài trong câu chữ, không số liệu bịa, không logo, không ảnh minh họa
chung chung. Số hiển thị trên trang đều là số thật do chính trang tính ra trong phiên chạy đó.