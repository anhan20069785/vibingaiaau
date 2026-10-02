import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

// Node 22 đã có globalThis.crypto; gán tường minh để test không phụ thuộc cờ khởi động.
globalThis.crypto ??= webcrypto;

const {
  generateKeyPair,
  signMessage,
  verifyWithMath,
  verifyMessage,
  verifyViaWebCrypto,
  validatePublicPoint,
  sha256,
  importPublicKeyFromSpki,
} = await import('../src/ecdsa.js');
const {
  pemDecode,
  pemEncode,
  parseSpki,
  parsePkcs8,
  parseSignatureDer,
  buildPkcs8,
  buildSpki,
  signatureRawToDer,
} = await import('../src/der.js');
const { bytesToHex, hexToBytes, utf8Bytes, bytesEqual, base64UrlToBytes } = await import('../src/codec.js');
const {
  bigIntToBytesBE,
  bytesToBigIntBE,
  mod,
  modInv,
  scalarMul,
  isOnCurve,
  rawToPoint,
  G,
  N,
  A,
  P,
  FIELD_BYTES,
} = await import('../src/p256.js');
const { generateK } = await import('../src/rfc6979.js');
const { demonstrateReusedK, recoverPrivateKey } = await import('../src/reused-k.js');

// Vector nguyên văn của IETF RFC 6979 Phụ lục A.2.5: đường cong NIST P-256, hàm băm SHA-256.
const RFC6979 = {
  d: 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
  ux: '60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6',
  uy: '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299',
  sample: {
    message: 'sample',
    hash: 'af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf',
    k: 'a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60',
    r: 'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716',
    s: 'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8',
  },
  test: {
    message: 'test',
    hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    k: 'd16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0',
    r: 'f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367',
    s: '019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083',
  },
};

test('hằng số P-256 khớp bản in của SP 800-186', () => {
  assert.equal(A, P - 3n);
  assert.equal(P.toString(16), 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
  assert.equal(N.toString(16), 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
  assert.ok(isOnCurve(G.x, G.y), 'điểm sinh G phải nằm trên đường cong');
  assert.equal(scalarMul(N, G), null, 'n*G phải là điểm vô cực');
  assert.equal(scalarMul(1n, G).x, G.x);
});

test('vector RFC 6979 A.2.5: khóa bí mật tạo ra đúng điểm công khai', () => {
  const derived = scalarMul(bytesToBigIntBE(hexToBytes(RFC6979.d)), G);
  assert.equal(bytesToHex(bigIntToBytesBE(derived.x, FIELD_BYTES)), RFC6979.ux);
  assert.equal(bytesToHex(bigIntToBytesBE(derived.y, FIELD_BYTES)), RFC6979.uy);
});

test('vector RFC 6979 A.2.5: k, r, s của hai thông điệp trùng bản in', async () => {
  const d = hexToBytes(RFC6979.d);
  for (const vector of [RFC6979.sample, RFC6979.test]) {
    const hash = await sha256(utf8Bytes(vector.message));
    assert.equal(bytesToHex(hash), vector.hash, `SHA-256("${vector.message}")`);

    const k = await generateK(d, hash);
    assert.equal(bytesToHex(bigIntToBytesBE(k, FIELD_BYTES)), vector.k, `k cho "${vector.message}"`);

    const r = mod(scalarMul(k, G).x, N);
    const s = mod(modInv(k, N) * (bytesToBigIntBE(hash) + r * bytesToBigIntBE(d)), N);
    assert.equal(bytesToHex(bigIntToBytesBE(r, FIELD_BYTES)), vector.r, `r cho "${vector.message}"`);
    assert.equal(bytesToHex(bigIntToBytesBE(s, FIELD_BYTES)), vector.s, `s cho "${vector.message}"`);

    const der = signatureRawToDer(new Uint8Array([...bigIntToBytesBE(r, 32), ...bigIntToBytesBE(s, 32)]));
    const parsed = parseSignatureDer(der);
    assert.equal(bytesToHex(parsed.r).padStart(64, '0'), vector.r, 'DER đọc lại phải ra đúng r');
  }
});

test('generateK tất định: cùng đầu vào cho cùng k, khác thông điệp cho khác k', async () => {
  const d = hexToBytes(RFC6979.d);
  const sampleHash = hexToBytes(RFC6979.sample.hash);
  assert.equal(await generateK(d, sampleHash), await generateK(d, sampleHash));
  assert.notEqual(await generateK(d, sampleHash), await generateK(d, hexToBytes(RFC6979.test.hash)));
});

test('sinh khóa: d trong [1, n-1], điểm công khai nằm trên đường cong, PEM dựng lại đúng DER', async () => {
  const key = await generateKeyPair();
  const d = bytesToBigIntBE(key.d);
  assert.ok(d >= 1n && d < N, 'd nằm trong [1, n-1]');
  assert.equal(key.d.length, 32);
  assert.ok(key.pointOnCurve);
  assert.equal(key.rawPublic.length, 64);

  const point = rawToPoint(key.rawPublic);
  assert.equal(bytesToHex(bigIntToBytesBE(point.x, 32)), bytesToHex(key.x));
  assert.equal(bytesToHex(bigIntToBytesBE(point.y, 32)), bytesToHex(key.y));
  assert.equal(scalarMul(d, G).x, point.x, 'Q phải bằng [d]G');

  const parsedPublic = parseSpki(key.spki);
  assert.equal(parsedPublic.algorithm, '1.2.840.10045.2.1');
  assert.equal(parsedPublic.curve, '1.2.840.10045.3.1.7');
  assert.equal(bytesToHex(parsedPublic.point), bytesToHex(key.rawPublic));

  const parsedPrivate = parsePkcs8(key.pkcs8);
  assert.equal(parsedPrivate.curve, '1.2.840.10045.3.1.7');
  assert.equal(bytesToHex(parsedPrivate.d), bytesToHex(key.d));
  assert.ok(parsedPrivate.point === null || bytesToHex(parsedPrivate.point) === bytesToHex(key.rawPublic));

  assert.ok(bytesEqual(buildPkcs8(key.d, key.x, key.y), key.pkcs8), 'PKCS#8 tự dựng phải trùng bản WebCrypto');
  assert.ok(bytesEqual(buildSpki(key.x, key.y), key.spki), 'SPKI tự dựng phải trùng bản WebCrypto');
  assert.ok(bytesEqual(pemDecode(pemEncode('PRIVATE KEY', key.pkcs8)).der, key.pkcs8));
  assert.ok(bytesEqual(pemDecode(pemEncode('PUBLIC KEY', key.spki)).der, key.spki));
});

test('ký và xác minh: raw, DER, số học đường cong và WebCrypto đều chấp nhận', async () => {
  const key = await generateKeyPair();
  const message = utf8Bytes('Ký bằng khóa elliptic curve');
  const signature = await signMessage(key, message);

  assert.equal(signature.hashHex, bytesToHex(await sha256(message)));
  assert.ok(bytesEqual(signature.derSignature, signatureRawToDer(signature.rawSignature)));
  assert.equal(signature.rawSignature.length, 64);
  assert.ok(signature.r >= 1n && signature.r < N);
  assert.ok(signature.s >= 1n && signature.s < N);

  const parsed = parseSignatureDer(signature.derSignature);
  const fromMath = verifyWithMath(key.rawPublic, signature.hash, bytesToBigIntBE(parsed.r), bytesToBigIntBE(parsed.s));
  assert.equal(fromMath.accepted, true);
  assert.equal(fromMath.reason, 'r bằng x của R1 rút gọn theo n');

  const verified = await verifyMessage(key, message, signature.derSignature);
  assert.equal(verified.accepted, true);
  assert.equal(verified.webcryptoAccepted, true);
  assert.equal(verified.agree, true);
});

test('đối chứng hai chiều với WebCrypto: mỗi bên nhận chữ ký của bên kia', async () => {
  const key = await generateKeyPair();
  const message = utf8Bytes('kiểm tra chéo hai chiều');
  const signature = await signMessage(key, message);

  assert.equal(signature.webcryptoAcceptedOurs, true, 'WebCrypto phải nhận chữ ký tất định của ta');
  assert.equal(signature.oursAcceptedWebcrypto, true, 'Số học của ta phải nhận chữ ký ngẫu nhiên của WebCrypto');
  assert.equal(await verifyViaWebCrypto(key.publicKey, signature.derSignature, message), true);

  // WebCrypto theo §6.3.1 lấy k ngẫu nhiên nên hai lần ký khác byte; ta theo §6.3.2 nên giống nhau.
  const again = await signMessage(key, message);
  assert.equal(again.kHex, signature.kHex, 'k tất định phải lặp lại');
  assert.equal(again.rHex, signature.rHex);
  assert.ok(bytesEqual(again.derSignature, signature.derSignature), 'chữ ký tất định phải lặp lại từng byte');
  assert.equal(again.webcryptoAcceptedOurs, true);
});

test('thông điệp bị sửa thì cả hai đường xác minh đều từ chối', async () => {
  const key = await generateKeyPair();
  const signature = await signMessage(key, utf8Bytes('chuyển 100 đồng'));
  const verified = await verifyMessage(key, utf8Bytes('chuyển 900 đồng'), signature.derSignature);
  assert.equal(verified.accepted, false);
  assert.equal(verified.webcryptoAccepted, false);
  assert.equal(verified.agree, true);
});

test('chữ ký bị sửa một bit hoặc đặt r = 0 đều bị từ chối', async () => {
  const key = await generateKeyPair();
  const message = utf8Bytes('nội dung gốc');
  const signature = await signMessage(key, message);

  const flipped = Uint8Array.from(signature.rawSignature);
  flipped[10] ^= 0x01;
  assert.equal((await verifyMessage(key, message, signatureRawToDer(flipped))).accepted, false);

  const zeroR = signatureRawToDer(new Uint8Array(64));
  assert.equal((await verifyMessage(key, message, zeroR)).accepted, false);
  assert.equal(await verifyViaWebCrypto(key.publicKey, zeroR, message), false);
});

test('khóa công khai của cặp khác thì bị từ chối', async () => {
  const key = await generateKeyPair();
  const other = await generateKeyPair();
  const message = utf8Bytes('chỉ dùng cho khóa thứ nhất');
  const signature = await signMessage(key, message);
  const verified = await verifyMessage(other, message, signature.derSignature);
  assert.equal(verified.accepted, false);
  assert.equal(verified.webcryptoAccepted, false);
});

test('điểm công khai không nằm trên đường cong hoặc là điểm vô cực đều bị loại', async () => {
  const key = await generateKeyPair();
  const broken = Uint8Array.from(key.rawPublic);
  broken[63] ^= 0x01;
  const validation = validatePublicPoint(broken);
  assert.equal(validation.valid, false);
  assert.equal(validation.reason, 'điểm không nằm trên đường cong P-256');
  assert.equal(verifyWithMath(broken, await sha256(utf8Bytes('x')), 1n, 1n).accepted, false);

  const infinity = validatePublicPoint(new Uint8Array(64));
  assert.equal(infinity.valid, false);
  assert.equal(infinity.reason, 'điểm vô cực bị loại');
});

test('giá trị biên của r và s bị từ chối theo §6.4.2 bước 1', async () => {
  const key = await generateKeyPair();
  const hash = await sha256(utf8Bytes('biên'));
  assert.equal(verifyWithMath(key.rawPublic, hash, 0n, 1n).accepted, false);
  assert.equal(verifyWithMath(key.rawPublic, hash, N, 1n).accepted, false);
  assert.equal(verifyWithMath(key.rawPublic, hash, 1n, 0n).accepted, false);
  assert.equal(verifyWithMath(key.rawPublic, hash, N - 1n, N).accepted, false);
});

test('khóa bí mật ngoài khoảng [1, n-1] hoặc sai độ dài bị từ chối khi ký', async () => {
  const key = await generateKeyPair();
  await assert.rejects(() => signMessage({ ...key, d: new Uint8Array(32) }, utf8Bytes('x')), /nằm ngoài khoảng/);
  await assert.rejects(
    () => signMessage({ ...key, d: bigIntToBytesBE(N, FIELD_BYTES) }, utf8Bytes('x')),
    /nằm ngoài khoảng/,
  );
  await assert.rejects(() => signMessage({ ...key, d: key.d.subarray(0, 31) }, utf8Bytes('x')), /32 byte/);
});

test('thông điệp rỗng và thông điệp 1 MB đều ký và xác minh được', async () => {
  const key = await generateKeyPair();
  const empty = new Uint8Array(0);
  const emptySignature = await signMessage(key, empty);
  assert.equal((await verifyMessage(key, empty, emptySignature.derSignature)).accepted, true);

  const big = new Uint8Array(1024 * 1024);
  for (let i = 0; i < big.length; i += 4096) big[i] = i & 0xff;
  const bigSignature = await signMessage(key, big);
  assert.equal((await verifyMessage(key, big, bigSignature.derSignature)).accepted, true);
});

test('dùng lại k làm lộ khóa bí mật', async () => {
  const key = await generateKeyPair();
  const signature = await signMessage(key, utf8Bytes('thông điệp thứ nhất'));
  const demo = demonstrateReusedK(signature.r, bytesToBigIntBE(key.d), signature.k, await sha256(utf8Bytes('thông điệp thứ hai')));
  assert.equal(demo.matches, true);
  assert.equal(bytesToHex(bigIntToBytesBE(demo.recovered, FIELD_BYTES)), bytesToHex(key.d));
  assert.equal(recoverPrivateKey(signature.r, demo.s2, demo.e2, signature.k), bytesToBigIntBE(key.d));
});

test('nhập lại khóa công khai từ PEM rồi xác minh bằng cả hai đường', async () => {
  const key = await generateKeyPair();
  const message = utf8Bytes('kiểm tra nhập khóa');
  const signature = await signMessage(key, message);

  const decoded = pemDecode(pemEncode('PUBLIC KEY', key.spki));
  assert.equal(decoded.label, 'PUBLIC KEY');
  const imported = await importPublicKeyFromSpki(decoded.der);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', imported));
  // WebCrypto xuất khóa công khai ở dạng không nén kèm tiền tố 0x04, tức 65 byte.
  assert.equal(raw.length, 65);
  assert.equal(raw[0], 0x04);
  assert.equal(bytesToHex(raw.subarray(1)), bytesToHex(key.rawPublic));

  assert.equal(await verifyViaWebCrypto(imported, signature.derSignature, message), true);
  const viaImported = await verifyMessage({ publicKey: imported, rawPublic: raw }, message, signature.derSignature);
  assert.equal(viaImported.accepted, true);
  assert.equal(viaImported.webcryptoAccepted, true);

  await assert.rejects(() => importPublicKeyFromSpki(hexToBytes('304502200efd')));
  await assert.rejects(() => importPublicKeyFromSpki(key.pkcs8));
});

test('điểm công khai lấy từ JWK trùng với điểm dạng raw', async () => {
  const key = await generateKeyPair();
  const jwk = await crypto.subtle.exportKey('jwk', key.privateKey);
  const fromJwk = new Uint8Array([...base64UrlToBytes(jwk.x), ...base64UrlToBytes(jwk.y)]);
  assert.equal(bytesToHex(fromJwk), bytesToHex(key.rawPublic));
  assert.equal(fromJwk.length, 64);
  assert.equal(jwk.crv, 'P-256');
});

test('bộ giải mã DER từ chối dữ liệu dị dạng', async () => {
  const key = await generateKeyPair();
  const signature = await signMessage(key, utf8Bytes('der'));

  const trailing = new Uint8Array(signature.derSignature.length + 1);
  trailing.set(signature.derSignature);
  assert.throws(() => parseSignatureDer(trailing), /dữ liệu thừa/);

  assert.throws(() => parseSignatureDer(Uint8Array.of(0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00)), /vô định/);
  assert.throws(() => parseSignatureDer(Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01)), /INTEGER âm/);
  assert.throws(() => parseSignatureDer(Uint8Array.of(0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01)), /không tối thiểu/);
  assert.throws(() => parseSignatureDer(new Uint8Array(64)), /tag/);
  assert.throws(() => parseSpki(hexToBytes('3006020100020101')), /OID|AlgorithmIdentifier|tag/i);
  assert.throws(() => pemDecode('không phải PEM'), /khối PEM/);
});