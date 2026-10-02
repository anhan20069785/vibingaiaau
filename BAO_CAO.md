# Báo cáo đối chiếu

Trang ECDSA P-256 trong kho này hiện thực quy trình ký và xác minh của NIST FIPS 186-5,
dùng tham số miền P-256 in trong NIST SP 800-186, và sinh số bí mật `k` theo IETF RFC 6979.
Báo cáo này đối chiếu từng điều khoản với vị trí trong mã nguồn và cách kiểm chứng.

Mọi phép tính chạy trong trình duyệt hoặc trong Node; không có mạng tham gia trong lúc ký,
xác minh, hay kiểm thử.

## Bảng đối chiếu

| # | Điều khoản | Yêu cầu | Nơi thực hiện | Cách kiểm chứng |
|---|---|---|---|---|
| 1 | FIPS 186-5 §6.2.1 và Phụ lục A.2.1 bước 5 | `d` là số nguyên trong `[1, n-1]`, khóa công khai `Q = [d]G` | `generateKeyPair` trong `src/ecdsa.js` | Trang tính lại `Q` bằng số học đường cong và so với khóa công khai WebCrypto sinh ra; sai thì ném lỗi. Test `sinh khóa...` trong `tests/ecdsa.test.mjs` |
| 2 | FIPS 186-5 §6.3 | Mỗi chữ ký dùng một `k` mới, `0 < k < n`; dùng lại `k` làm lộ khóa bí mật | `generateK` trong `src/rfc6979.js`, minh họa ở `src/reused-k.js` | Test `dùng lại k làm lộ khóa bí mật`; nút *Dùng lại k cho thông điệp thứ hai* trên trang suy ra `d` từ hai chữ ký cùng `k` |
| 3 | FIPS 186-5 §6.3.2 và Phụ lục A.3.3 | `k` tất định theo RFC 6979 khi muốn ký tất định | `generateK` trong `src/rfc6979.js` | Vector RFC 6979 A.2.5 với P-256 và SHA-256 trùng từng byte cho `k`, `r`, `s`, ở test `vector RFC 6979 A.2.5...` |
| 4 | FIPS 186-5 §6.4.1 | `r = x_R mod n`, `s = k^-1 (e + r d) mod n`, `r` và `s` khác 0 | `signMessage` trong `src/ecdsa.js` | Đối chứng hai chiều với WebCrypto trong test `ký và xác minh...`; trang hiển thị `k`, `r`, `s`, chữ ký raw và DER |
| 5 | FIPS 186-5 §6.4.2 | Kiểm tra `r`, `s` trong `[1, n-1]`; `u = e s^-1`, `v = r s^-1`, `R1 = [u]G + [v]Q`; chấp nhận khi `r = x_R1 mod n` | `verifyWithMath` trong `src/ecdsa.js` | Bảy bước in ở Bước 3 của trang; test `thông điệp bị sửa...`, `chữ ký bị sửa một bit...`, `giá trị biên của r và s...` |
| 6 | FIPS 186-5 §6.4 | Khi độ dài đầu ra băm lớn hơn `len(n)` thì lấy `len(n)` bit trái nhất | `bits2int` trong `src/rfc6979.js` | Dùng chung cho cả đường ký và đường xác minh; đối chiếu vector RFC 6979 |
| 7 | FIPS 186-5 Bảng 1 trong §6.1.1 | Với `len(n)` từ 256 đến 383, độ mạnh bảo mật ít nhất 128 bit | Bảng *Tham số chuẩn* ở `src/nist.js`, hiển thị ở Bước 1 | Trang in bảng nguyên văn; P-256 được đối chiếu với dòng 256 đến 383 |
| 8 | SP 800-186 §3.2.1.3 | Tham số miền P-256: `p`, `a`, `b`, `Gx`, `Gy`, `n`, `h`, Seed | Hằng số trong `src/p256.js`, in ở `src/nist.js` | Test `hằng số P-256 khớp bản in của SP 800-186` kiểm `A = p-3`, `n*G` là điểm vô cực, `G` nằm trên đường cong |
| 9 | SP 800-186 Bảng 1 và Bảng 2 trong §3.1.2 | P-256 được phép cho ECDSA và thiết lập khóa; các đường cong nhị phân K-/B- đã deprecated | `CURVE_USAGE`, `CURVE_STATUS` trong `src/nist.js` | Trang in nguyên văn hai bảng và tô trạng thái theo mã màu lục son |
| 10 | SP 800-186 Phụ lục D.1.1.1 | Kiểm tra điểm công khai: loại điểm vô cực, tọa độ trong `[0, p-1]`, điểm phải nằm trên đường cong | `validatePublicPoint` trong `src/ecdsa.js` | Test `điểm công khai không nằm trên đường cong hoặc là điểm vô cực đều bị loại`; khối *Nhập khóa công khai* trên trang chạy đúng phép kiểm tra này |
| 11 | FIPS 180-4 | Hàm băm SHA-256 cho thông điệp | `sha256` trong `src/ecdsa.js` (gọi WebCrypto) | Test so `signature.hashHex` với `sha256` độc lập; trang in `H = SHA-256(M)` ở Bước 2 |
| 12 | RFC 5480 và ANSI X9.62 | Định danh OID cho khóa EC công khai và đường cong P-256 | `OID_EC_PUBLIC_KEY`, `OID_PRIME256V1` trong `src/der.js` | Test dựng và đọc SPKI/PKCS#8, so OID `1.2.840.10045.2.1` và `1.2.840.10045.3.1.7` |

## Kiểm chứng độc lập với OpenSSL

Ngoài bộ kiểm thử nội bộ, `tests/interop.test.mjs` chạy bốn chiều đối chiếu với OpenSSL CLI:

1. Ta sinh khóa và ký; OpenSSL xác minh chữ ký và trả `Verified OK`.
2. OpenSSL sinh khóa và ký; ta nhập khóa công khai từ SPKI, xác minh bằng cả số học đường cong và WebCrypto.
3. Nhập khóa bí mật SEC1 của OpenSSL, ký lại, OpenSSL xác minh lại.
4. Chữ ký của ta trên thông điệp khác thì OpenSSL từ chối.

Nếu `openssl` không có trong `PATH`, test này tự bỏ qua và ghi rõ lý do.

## Vector RFC 6979 dùng làm mốc

Khóa bí mật của vector A.2.5 (đường cong P-256, hàm băm SHA-256):

```
d  = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
Qx = 60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
Qy = 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
```

Hai thông điệp `sample` và `test` cho ra `k`, `r`, `s` trùng bản in trong Phụ lục A.2.5.
Test trong `tests/ecdsa.test.mjs` so từng byte, kể cả khi đọc lại chữ ký từ DER.

## Giới hạn

- Bảng trên đối chiếu các điều khoản liên quan trực tiếp tới luồng ký và xác minh; không bao
  gồm toàn bộ văn bản FIPS 186-5.
- Số bí mật `k` ở luồng ký của trang là tất định (RFC 6979) để tái lập được. FIPS 186-5 §6.3.1
  cũng cho phép `k` ngẫu nhiên; đường WebCrypto dùng cách ngẫu nhiên đó, nên hai đường cho ra
  chữ ký khác byte nhưng đều xác minh được.
- Trang là công cụ học tập, không phải thư viện mật mã để dùng trong sản phẩm.
