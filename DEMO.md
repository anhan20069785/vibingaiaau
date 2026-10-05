# Kịch bản demo trước giảng viên

Trang đã xuất bản: <https://anhan20069785.github.io/> (dự phòng: <https://anhan20069785.github.io/vibingaiaau/>)

Mở sẵn tab này trước giờ demo, và tắt thông báo để không bị chen ngang. Trang chạy offline sau
lần nạp đầu, nên mạng yếu cũng không sao. Nếu mạng hỏng hẳn, chạy `npm run serve` rồi mở
`http://localhost:8080/`; nội dung y hệt.

Cần hai việc để demo trôi: biết **bấm nút nào**, và biết **nói gì khi giảng viên hỏi khó**. Dưới
đây là cả hai. Tổng thời lượng khoảng 8 đến 10 phút.

## Chuẩn bị trước khi vào (2 phút, không tính vào bài)

- Mở trang, bấm thử *Sinh cặp khóa P-256* một lần cho nóng máy, rồi tải lại trang cho sạch trạng thái.
- Kéo cửa sổ rộng ra; bảng tham số và bảng đối chiếu cần chỗ. Điện thoại không hợp để chiếu.
- Mở sẵn `BAO_CAO.md` trên GitHub trong tab thứ hai để lôi ra khi bị hỏi sâu.

## Phân vai

Hai người thì chia: một người bấm và nói phần cơ chế, một người giữ phần "đối chiếu chuẩn"
(Bước 4 và phần bằng chứng). Một người thì tự nói hết, chỉ cần đừng bấm nút nào khi chưa nói
xong ý của nút trước.

---

## Kịch bản 10 phút

### 0:00 – 0:45, mở màn

Chưa bấm gì. Chỉ vào tiêu đề và nói:

> "Bọn em làm một bàn thực hành ECDSA trên đường cong P-256. Trang chạy hoàn toàn trong trình
> duyệt, không gọi mạng. Mọi con số trên trang đều do trang tự tính trong phiên này, không có
> số mẫu chép sẵn. Bài đối chiếu với NIST FIPS 186-5 và SP 800-186, và sinh số bí mật k theo
> RFC 6979."

Chỉ vào thanh trạng thái đang ghi "Sẵn sàng. Bắt đầu bằng nút sinh khóa."

### 0:45 – 2:00, Bước 1: sinh khóa

Bấm **Sinh cặp khóa P-256**.

> "Khóa bí mật d là một số trong khoảng [1, n-1]. Khóa công khai Q bằng [d]G. Điểm đáng nói:
> trình duyệt sinh khóa, nhưng bọn em **tính lại Q bằng số học đường cong tự viết** rồi so với
> khóa của trình duyệt."

Chỉ vào dòng chú thích ngay dưới nút, nó ghi: *"Q tính lại bằng số học đường cong trùng với khóa
công khai: trùng. Điểm nằm trên đường cong: đúng."*

> "Hai kết quả trùng nhau, nên code tự viết của bọn em và WebCrypto của Chrome cho ra cùng một
> khóa. Bên phải là PKCS#8 và SPKI dạng PEM, bọn em tự dựng bằng bộ mã hóa DER tự viết và so
> lại từng byte với bản của trình duyệt."

Nếu bị hỏi vì sao có cả PEM: "để chứng minh mã DER/PEM tự viết đúng, và để lấy khóa đem sang
OpenSSL đối chiếu."

### 2:00 – 4:00, Bước 2: ký, và điểm ăn tiền là tính tất định

Sửa thông điệp thành một câu bất kỳ, ví dụ "Xin chao giang vien". Bấm **Ký thông điệp**.

> "Đường đi đúng theo FIPS 186-5 mục 6.4.1: băm SHA-256 ra H, rút gọn thành e, sinh k theo
> RFC 6979, tính R = [k]G, r là hoành độ của R rút gọn theo n, rồi s = k^-1 (e + r d) mod n.
> Trang in từng giá trị trung gian, nên giảng viên soi được từng bước."

Rồi **bấm Ký thông điệp lần thứ hai** với nguyên nội dung đó.

> "Chữ ký ra **y hệt từng byte**. Vì k là hàm tất định của khóa và thông điệp theo RFC 6979,
> không dùng nguồn ngẫu nhiên. Đây là mục 6.3.2 của FIPS 186-5."

Chỉ vào hai ô chữ ký DER: "giống nhau hoàn toàn."

> "Ngược lại, nút WebCrypto bên trong dùng k ngẫu nhiên, nên hai đường cho ra chữ ký khác byte
> nhưng **cùng xác minh được**. Bọn em đối chứng hai chiều: chữ ký của WebCrypto thì số học của
> bọn em nhận, và ngược lại."

Nếu bị hỏi vì sao chọn tất định: "vì tái lập được, đối chiếu được từng byte, và loại bỏ rủi ro
nguồn ngẫu nhiên yếu. RFC 6979 được chuẩn dẫn chiếu, không phải bọn em tự chế."

### 4:00 – 5:30, Bước 3: xác minh

Bấm **Xác minh nội dung hiện tại**.

> "Kiểm r và s trong [1, n-1], tính u = e s^-1 và v = r s^-1, dựng R1 = [u]G + [v]Q, chấp nhận
> khi r bằng x của R1 rút gọn theo n. Đây là mục 6.4.2."

Kết quả hiện: *"Chấp nhận. r bằng x của R1 rút gọn theo n."*

> "Trang chạy **song song hai đường**: số học đường cong tự viết và WebCrypto. Bước này ghi rõ
> hai đường đồng ý."

Mở khối **Chi tiết phép xác minh theo §6.4.2** để chỉ bảy bước in sẵn nếu giảng viên muốn thấy
đối chiếu từng bước một.

### 5:30 – 8:30, Bước 4: ba ca phá hoại, đây là phần chứng minh hiểu bài

Bấm lần lượt ba nút, mỗi nút nói một câu:

1. **Sửa 1 bit của bản đã ký** → "Đổi đúng một bit ở byte cuối, chữ ký **bị từ chối**. Sai một
   bit cũng đủ hỏng."
2. **Dùng khóa công khai khác** → "Lấy khóa công khai của cặp khác, cũng bị từ chối."
3. **Dùng lại k cho thông điệp thứ hai** → đây là ca quan trọng nhất.

> "Ca thứ ba: bọn em cố tình dùng lại **cùng một k** cho hai thông điệp khác nhau. Từ hai chữ ký
> cùng k, khóa bí mật **suy ra được** bằng công thức d = (k·s - e)·r^-1 mod n. Trang in ra khóa
> bí mật vừa suy được và so với khóa gốc."

Chỉ xuống bảng kết quả kiểm thử, nó ghi *"7 ca đã chạy, 0 ca lệch kỳ vọng."*

> "Bảng này là bằng chứng của phiên đang mở, không phải số liệu mẫu. Đây cũng là lý do FIPS 186-5
> mục 6.3 buộc mỗi chữ ký phải có một k mới."

### 8:30 – 10:00, đối chiếu và kết

Cuộn xuống bảng **Yêu cầu chuẩn, nơi thực hiện trong mã, và bằng chứng**.

> "Mỗi dòng nối một điều khoản với đúng hàm trong mã nguồn và cách kiểm chứng. Bảng đầy đủ mười
> hai dòng nằm trong BAO_CAO.md."

Mở BAO_CAO.md nếu cần, chỉ vào dòng OpenSSL:

> "Ngoài ra bộ kiểm thử có bốn chiều đối chiếu với OpenSSL CLI: OpenSSL xác minh chữ ký của
> bọn em, bọn em xác minh chữ ký của OpenSSL, nhập khóa bí mật OpenSSL để ký lại, và OpenSSL
> từ chối khi thông điệp bị đổi. Tổng cộng 19 test, chạy bằng `npm test`."

Câu kết:

> "Mã nguồn, bộ kiểm thử và báo cáo đều công khai trên GitHub. Giảng viên tự mở lại chạy được."

---

## Bản 3 phút (nếu bị giới hạn thời gian)

Bấm **Sinh khóa** → nói một câu về "tính lại Q = [d]G, trùng". Bấm **Ký** hai lần → chỉ chữ ký
giống nhau từng byte, nói "k tất định theo RFC 6979". Bấm **Xác minh** → "hai đường đồng ý".
Bấm **Dùng lại k** → "dùng lại k là lộ khóa bí mật". Chỉ bảng đối chiếu. Hết.

## Nếu giảng viên hỏi, trả lời gọn

| Câu hỏi | Trả lời |
|---|---|
| Sao k lại tất định, ngẫu nhiên chẳng an toàn hơn? | Cả hai đều được chuẩn cho phép. Tất định (§6.3.2 + RFC 6979) loại bỏ rủi ro RNG yếu và tái lập được. Trang vẫn chạy k ngẫu nhiên ở đường WebCrypto và kiểm chứng chéo hai đường. |
| Sao lại phơi khóa bí mật ra màn hình? | Đây là công cụ học tập. Khóa sinh mới mỗi phiên, không phải khóa thật. Phải hiện thì mới đối chiếu được. |
| Sao biết code tự viết đúng? | Ba lớp: vector RFC 6979 A.2.5 khớp từng byte, bốn chiều đối chiếu OpenSSL, và đối chứng hai chiều với WebCrypto. |
| Nếu điểm công khai nằm ngoài đường cong thì sao? | Bị loại trước khi tính, theo SP 800-186 Phụ lục D.1.1.1: loại điểm vô cực, kiểm tọa độ trong [0, p-1], kiểm nằm trên đường cong. Có nút nhập khóa để tự thử. |
| Dùng được trong sản phẩm thật không? | Không. Đây là bàn thực hành, không phải thư viện mật mã. Code tự viết để đối chiếu, không để chạy production. |
| Vector chuẩn lấy ở đâu? | RFC 6979 Phụ lục A.2.5 cho P-256 và SHA-256; tham số miền in trong SP 800-186 mục 3.2.1.3. |
| Số trên trang có chép sẵn không? | Không. Toàn bộ tính trong phiên đang mở. Chỉ tham số miền và các dòng vector là hằng số in theo chuẩn. |

## Ba lỗi hay gặp khi demo, và cách tránh

1. **Bấm nút khi chưa nói xong.** Người xem nhìn kết quả trước khi nghe giải thích thì hết hấp
   dẫn. Nói ý trước, bấm sau.
2. **Quên bấm Ký lần hai.** Mất luôn điểm mạnh nhất là tính tất định. Phải bấm hai lần với
   nguyên một nội dung.
3. **Chỉ đọc kết quả mà không nói ý nghĩa.** "Chấp nhận" không có gì đặc biệt; "hai đường độc
   lập cùng chấp nhận, nên code tự viết khớp với OpenSSL và WebCrypto" mới là ý.