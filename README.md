# Bàn thực hành ECDSA P-256

Công cụ web một trang để sinh khóa P-256, ký một thông điệp, và xác minh chữ ký, đối chiếu
từng bước với NIST FIPS 186-5 và NIST SP 800-186. Số bí mật `k` sinh theo IETF RFC 6979.

Trang tĩnh, không gọi mạng. Mọi phép tính chạy trong trình duyệt. Không tải font, không có
phụ thuộc ngoài, chạy được khi ngắt mạng.

- Bản chạy thử: <https://anhan20069785.github.io/vibingaiaau/>
- Kịch bản demo trước giảng viên: [`DEMO.md`](DEMO.md)
- Báo cáo đối chiếu chuẩn: [`BAO_CAO.md`](BAO_CAO.md)
- Ghi chú dùng trợ lý AI: [`AI_USAGE.md`](AI_USAGE.md)

## Chạy tại máy

Chrome không nạp được module ES qua `file://`, nên cần một máy chủ tĩnh.

```bash
npm run serve          # mở http://localhost:8080/
npm test               # 18 test đơn vị + 1 test đối chiếu OpenSSL
```

`npm test` cần Node 18 trở lên. Test đối chiếu OpenSSL tự bỏ qua nếu `openssl` không có trong
`PATH`.

## Kịch bản demo 8 đến 10 phút

1. **Bước 1, sinh khóa (1 phút).** Bấm *Sinh khóa*. Chỉ vào khóa bí mật `d`, khóa công khai
   `Q`, và dòng cho biết trang đã tính lại `Q = [d]G` và kiểm điểm nằm trên đường cong. Đây là
   Phụ lục A.2.1 của FIPS 186-5.
2. **Bước 2, ký (2 phút).** Gõ một thông điệp, bấm *Ký*. Chỉ vào `H = SHA-256(M)`, `k`, `r`, `s`.
   Nhấn mạnh `k` tất định theo RFC 6979: bấm *Ký* lần nữa với cùng nội dung, chữ ký ra y hệt
   từng byte. Đối chiếu `r`, `s` với WebCrypto: cùng xác minh được, nhưng khác byte vì WebCrypto
   dùng `k` ngẫu nhiên.
3. **Bước 3, xác minh (1 phút).** Bấm *Xác minh nội dung hiện tại*. Trang chạy song song số học
   đường cong tự viết và WebCrypto, và cho biết hai đường đồng ý. Mở khối *Chi tiết phép xác minh
   theo §6.4.2* để chỉ bảy bước.
4. **Bước 4, phá hoại (3 phút).** Bấm lần lượt:
   - *Sửa 1 bit của bản đã ký*: bị từ chối.
   - *Dùng khóa công khai khác*: bị từ chối.
   - *Dùng lại k cho thông điệp thứ hai*: khóa bí mật bị suy ra, đây là lý do §6.3 buộc `k` mới
     cho mỗi chữ ký.
5. **Đối chiếu (1 phút).** Cuộn xuống bảng *Yêu cầu chuẩn, nơi thực hiện trong mã, và bằng chứng*,
   rồi mở `BAO_CAO.md` nếu giảng viên muốn bảng đầy đủ mười hai dòng.

Nếu giảng viên muốn tự kiểm: dán PEM khóa công khai vào khối *Nhập khóa công khai từ PEM hoặc
hex*, hoặc dán một chữ ký DER sinh bởi OpenSSL vào khối *Xác minh chữ ký dán từ ngoài*.

## Triển khai lên GitHub Pages

Kho này xuất bản trực tiếp từ nhánh `main`, thư mục gốc, nên không cần bước dựng.

```bash
git init
git add .
git commit -m "Ban thuc hanh ECDSA P-256"
git branch -M main
git remote add origin https://github.com/anhan20069785/vibingaiaau.git
git push -u origin main
gh api repos/anhan20069785/vibingaiaau/pages -X POST -f 'source[branch]=main' -f 'source[path]=/'
```

Trang chạy ở `https://anhan20069785.github.io/vibingaiaau/`. Đường dẫn trong trang đều là tương
đối, nên chạy đúng ở thư mục con của trang.

## Nguồn

- NIST FIPS 186-5, Digital Signature Standard, 2/2023.
- NIST SP 800-186, Recommendations for Discrete Logarithm-based Cryptography, 2/2023.
- IETF RFC 6979, Deterministic Usage of DSA and ECDSA.
- NIST FIPS 180-4, Secure Hash Standard.