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

Studio sáng, hiện đại, kiểu công cụ kỹ thuật: nền trắng xám rất nhạt, thẻ trắng bo góc nhẹ có
bóng mờ, một màu nhấn xanh dương, thanh neo dính trên đầu trang. Số thứ tự bước là chip nhỏ màu
nhấn, không phải khung trang trí. Không logo, không slogan, không biểu tượng trang trí. Đọc rõ
khi chiếu máy chiếu trong phòng sáng.

## Bảng màu

| Vai trò | Mã | Dùng ở đâu |
|---|---|---|
| Nền | `#f6f7f9` | nền trang |
| Thẻ | `#ffffff` | thẻ bước, mặt bảng, vùng nhập được |
| Thẻ chìm | `#f1f3f7` | ô chỉ đọc, hàng xen kẽ, nền phụ |
| Mực | `#0f172a` | chữ chính |
| Mực nhạt | `#5b6572` | chú thích, nhãn |
| Mực mờ | `#8a93a3` | nhãn phụ, chữ khóa |
| Đường kẻ | `#e3e7ee` | viền 1px, đường phân cách |
| Đường kẻ đậm | `#cdd4e0` | viền ô nhập |
| Xanh | `#1d4ed8` | chip số bước, nút chính, viền tiêu điểm |
| Xanh nhạt | `#e8eeff` | nền chip, nền trạng thái trung tính |
| Teal | `#0f766e` | trạng thái hợp lệ |
| Đỏ | `#b42318` | trạng thái sai, cảnh báo |

Xanh là màu nhấn duy nhất, dùng cho hành động và số bước. Teal chỉ mang nghĩa "hợp lệ", đỏ chỉ
mang nghĩa "sai", nên hai màu này là ngữ nghĩa chứ không phải trang trí.

## Kiểu chữ

| Vai trò | Stack | Lý do |
|---|---|---|
| Tiêu đề và nội dung | system-ui, -apple-system, "Segoe UI", Roboto, sans-serif | giao diện hiện đại, đọc nhanh; bỏ serif để không ra dáng tài liệu cũ |
| Hex, số, PEM, nhãn | ui-monospace, Consolas, "Courier New", monospace | cột hex thẳng hàng, so sánh từng byte bằng mắt được |

Không tải font từ mạng. Trang chạy offline.

## Dials

- ENERGY 2: nền tĩnh, một màu nhấn, bóng mờ rất nhẹ, không glow, không gradient.
- RHYTHM 3: nhịp khác nhau giữa các phần. Thẻ bước, bảng tham số, cặp đôi ký và xác minh, và
  bảng ca kiểm thử có bố cục khác nhau, không lặp một khuôn.
- MOTION 1: chỉ trạng thái hover và focus. Không hoạt ảnh chạy vòng.

## Điều không làm

Không emoji, không gạch dài trong câu chữ, không số liệu bịa, không logo, không ảnh minh họa
chung chung. Số hiển thị trên trang đều là số thật do chính trang tính ra trong phiên chạy đó.