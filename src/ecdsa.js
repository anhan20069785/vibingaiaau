import { bytesEqual, bytesToHex, base64UrlToBytes, concatBytes } from './codec.js';
import { buildPkcs8, buildSpki, parseEcPrivateKey, parsePkcs8, parseSignatureDer, parseSpki, pemDecode, signatureRawToDer, OID_PRIME256V1 } from './der.js';
import {
  FIELD_BYTES,
  G,
  N,
  bigIntToBytesBE,
  bytesToBigIntBE,
  isOnCurve,
  mod,
  modInv,
  pointAdd,
  rawToPoint,
  scalarMul,
} from './p256.js';
import { bits2int, generateK } from './rfc6979.js';

const ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' };
// dsaEncoding 'der' là mặc định theo chuẩn WebCrypto. Chrome tôn trọng tham số này, còn Node 22
// lại phát ra và chỉ nhận dạng rộng cố định 64 byte, nên phần dưới chuẩn hóa cả hai.
const SIGN_ALGORITHM = { name: 'ECDSA', hash: 'SHA-256', dsaEncoding: 'der' };

// FIPS 186-5 §6.4.1 bước 2: với P-256 thì len(n) bằng hashlen nên E = H.
export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

function pad32(bytes) {
  if (bytes.length > FIELD_BYTES) throw new Error('số lớn hơn 32 byte');
  if (bytes.length === FIELD_BYTES) return bytes;
  const padded = new Uint8Array(FIELD_BYTES);
  padded.set(bytes, FIELD_BYTES - bytes.length);
  return padded;
}

export function derToRaw(derSignature) {
  const { r, s } = parseSignatureDer(derSignature);
  return concatBytes(pad32(r), pad32(s));
}

function rawToRs(rawSignature) {
  return [
    bytesToBigIntBE(rawSignature.subarray(0, FIELD_BYTES)),
    bytesToBigIntBE(rawSignature.subarray(FIELD_BYTES)),
  ];
}

// Chữ ký của WebCrypto có thể là DER hoặc dạng rộng r || s tùy runtime; đưa hết về DER.
export function normalizeSignature(bytes) {
  try {
    parseSignatureDer(bytes);
    return bytes;
  } catch {
    if (bytes.length === 2 * FIELD_BYTES) return signatureRawToDer(bytes);
    throw new Error(`chữ ký WebCrypto không đọc được ở dạng DER lẫn dạng rộng: ${bytes.length} byte`);
  }
}

export async function signViaWebCrypto(privateKey, messageBytes) {
  const produced = new Uint8Array(await crypto.subtle.sign(SIGN_ALGORITHM, privateKey, messageBytes));
  return { der: normalizeSignature(produced), produced };
}

// Thử lần lượt hai cách đóng gói vì Node và trình duyệt khác nhau ở điểm này.
export async function verifyViaWebCrypto(publicKey, derSignature, messageBytes) {
  const attempts = [derSignature];
  try {
    const raw = derToRaw(derSignature);
    attempts.push(raw);
  } catch {
    // Chữ ký không phải DER thì chỉ còn dạng thô để thử.
  }
  for (const candidate of attempts) {
    try {
      if (await crypto.subtle.verify(SIGN_ALGORITHM, publicKey, candidate, messageBytes)) return true;
    } catch {
      // Runtime không nhận dạng đóng gói này, thử dạng còn lại.
    }
  }
  return false;
}

// Kiểm tra điểm công khai theo NIST SP 800-186 Phụ lục D.1.1.1 (kiểm tra một phần):
// loại điểm vô cực, tọa độ trong [0, p-1], và điểm phải nằm trên đường cong.
export function validatePublicPoint(rawPublic) {
  const point = rawToPoint(rawPublic);
  if (point.x === 0n && point.y === 0n) return { valid: false, reason: 'điểm vô cực bị loại' };
  if (!isOnCurve(point.x, point.y)) return { valid: false, reason: 'điểm không nằm trên đường cong P-256' };
  return { valid: true, reason: 'điểm nằm trên đường cong, tọa độ trong [0, p-1]' };
}

export async function generateKeyPair() {
  const pair = await crypto.subtle.generateKey(ALGORITHM, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));

  const d = base64UrlToBytes(jwk.d);
  const rawPublic = concatBytes(base64UrlToBytes(jwk.x), base64UrlToBytes(jwk.y));
  const point = rawToPoint(rawPublic);

  // FIPS 186-5 Phụ lục A.2.1 bước 5: Q = [d]G. Tính lại bằng số học đường cong để đối chứng.
  const derived = scalarMul(bytesToBigIntBE(d), G);
  if (derived === null || derived.x !== point.x || derived.y !== point.y) {
    throw new Error('Q khác [d]G, khóa sinh ra không nhất quán');
  }

  return {
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    d,
    x: bigIntToBytesBE(point.x, FIELD_BYTES),
    y: bigIntToBytesBE(point.y, FIELD_BYTES),
    rawPublic,
    pkcs8,
    spki,
    pointOnCurve: isOnCurve(point.x, point.y),
  };
}

// FIPS 186-5 §6.4.1. Khóa truyền vào là đối tượng của generateKeyPair, đọc các trường
// privateKey, publicKey, d và rawPublic.
export async function signMessage(key, messageBytes) {
  const { privateKey, publicKey, d: secretKeyBytes, rawPublic } = key;
  if (secretKeyBytes.length !== FIELD_BYTES) {
    throw new Error(`khóa bí mật phải đúng 32 byte, nhận ${secretKeyBytes.length} byte`);
  }
  const d = bytesToBigIntBE(secretKeyBytes);
  if (d < 1n || d >= N) throw new Error('khóa bí mật nằm ngoài khoảng [1, n-1]');

  const validation = validatePublicPoint(rawPublic);
  if (!validation.valid) throw new Error(`khóa công khai không hợp lệ: ${validation.reason}`);

  const hash = await sha256(messageBytes);
  const e = bits2int(hash);

  // FIPS 186-5 §6.3.2 và Phụ lục A.3.3: k là hàm tất định của thông điệp và khóa bí mật.
  const k = await generateK(secretKeyBytes, hash);
  const point = scalarMul(k, G);
  if (point === null) throw new Error('điểm R là điểm vô cực');
  const r = mod(point.x, N);
  const s = mod(modInv(k, N) * (e + r * d), N);
  if (r === 0n || s === 0n) throw new Error('r hoặc s bằng 0, theo §6.4.1 bước 11 phải sinh lại k');

  const rawSignature = concatBytes(bigIntToBytesBE(r, FIELD_BYTES), bigIntToBytesBE(s, FIELD_BYTES));
  const derSignature = signatureRawToDer(rawSignature);

  // WebCrypto không dùng RFC 6979: nó lấy k ngẫu nhiên theo §6.3.1 nên byte chữ ký thường khác.
  // Hai phép đối chứng có nghĩa ở đây là hai chiều kiểm tra chéo, không phải so từng byte.
  const webcrypto = await signViaWebCrypto(privateKey, messageBytes);
  const webcryptoAcceptedOurs = publicKey ? await verifyViaWebCrypto(publicKey, derSignature, messageBytes) : null;
  const [webcryptoR, webcryptoS] = rawToRs(derToRaw(webcrypto.der));
  const oursAcceptedWebcrypto = verifyWithMath(rawPublic, hash, webcryptoR, webcryptoS).accepted;

  return {
    hash,
    hashHex: bytesToHex(hash),
    k,
    kHex: bytesToHex(bigIntToBytesBE(k, FIELD_BYTES)),
    e,
    eHex: bytesToHex(bigIntToBytesBE(e, FIELD_BYTES)),
    r,
    s,
    rHex: bytesToHex(bigIntToBytesBE(r, FIELD_BYTES)),
    sHex: bytesToHex(bigIntToBytesBE(s, FIELD_BYTES)),
    rawSignature,
    derSignature,
    webcryptoDerSignature: webcrypto.der,
    webcryptoAcceptedOurs,
    oursAcceptedWebcrypto,
    sameBytesAsWebCrypto: bytesEqual(webcrypto.der, derSignature),
    publicPointValid: validation.valid,
    publicPointReason: validation.reason,
  };
}

// FIPS 186-5 §6.4.2: kiểm tra r, s trong [1, n-1], tính u = e*s^-1, v = r*s^-1,
// R1 = [u]G + [v]Q, chấp nhận khi r bằng x_R1 mod n.
export function verifyWithMath(rawPublic, hashBytes, r, s) {
  if (r < 1n || r > N - 1n) return { accepted: false, reason: 'r nằm ngoài [1, n-1]' };
  if (s < 1n || s > N - 1n) return { accepted: false, reason: 's nằm ngoài [1, n-1]' };

  const validation = validatePublicPoint(rawPublic);
  if (!validation.valid) return { accepted: false, reason: validation.reason };

  const e = bits2int(hashBytes);
  const sInverse = modInv(s, N);
  const u = mod(e * sInverse, N);
  const v = mod(r * sInverse, N);

  const point = pointAdd(scalarMul(u, G), scalarMul(v, rawToPoint(rawPublic)));
  if (point === null) return { accepted: false, reason: 'R1 là điểm vô cực' };

  const accepted = mod(point.x, N) === r;
  return {
    accepted,
    reason: accepted ? 'r bằng x của R1 rút gọn theo n' : 'r khác x của R1 rút gọn theo n',
    u,
    v,
  };
}

// Chạy cả hai đường: số học đường cong tự viết và WebCrypto của runtime.
export async function verifyMessage(key, messageBytes, derSignature) {
  const { r, s } = parseSignatureDer(derSignature);
  const hash = await sha256(messageBytes);
  const math = verifyWithMath(key.rawPublic, hash, bytesToBigIntBE(r), bytesToBigIntBE(s));
  const webcryptoAccepted = key.publicKey ? await verifyViaWebCrypto(key.publicKey, derSignature, messageBytes) : null;

  return {
    accepted: math.accepted,
    webcryptoAccepted,
    agree: webcryptoAccepted === null || math.accepted === webcryptoAccepted,
    reason: math.reason,
    hash,
    hashHex: bytesToHex(hash),
    r: bytesToHex(pad32(r)),
    s: bytesToHex(pad32(s)),
    math,
  };
}

export function importPublicKeyFromSpki(der) {
  return crypto.subtle.importKey('spki', der, ALGORITHM, true, ['verify']);
}

// Nhập khóa bí mật từ PEM của OpenSSL: PKCS#8 ("PRIVATE KEY") hoặc SEC1 ("EC PRIVATE KEY").
// Tệp SEC1 do OpenSSL sinh thường không kèm điểm công khai, khi đó tính Q = [d]G, và trong mọi
// trường hợp đều kiểm tra lại điểm trước khi dùng khóa.
export async function importPrivatePem(pemText) {
  const { label, der } = pemDecode(pemText);
  let parsed;
  if (label === 'PRIVATE KEY') parsed = parsePkcs8(der);
  else if (label === 'EC PRIVATE KEY') parsed = parseEcPrivateKey(der);
  else throw new Error(`nhãn PEM không hỗ trợ: ${label}`);

  if (parsed.curve !== null && parsed.curve !== OID_PRIME256V1) {
    throw new Error(`đường cong ${parsed.curve} không phải P-256`);
  }
  if (parsed.d.length === 0 || parsed.d.length > FIELD_BYTES) {
    throw new Error(`khóa bí mật sai độ dài: ${parsed.d.length} byte`);
  }
  const dValue = bytesToBigIntBE(parsed.d);
  if (dValue < 1n || dValue >= N) throw new Error('khóa bí mật nằm ngoài khoảng [1, n-1]');

  const derived = scalarMul(dValue, G);
  const x = bigIntToBytesBE(derived.x, FIELD_BYTES);
  const y = bigIntToBytesBE(derived.y, FIELD_BYTES);
  const rawPublic = concatBytes(x, y);

  if (parsed.point !== null) {
    const filePoint = rawToPoint(parsed.point);
    if (filePoint.x !== derived.x || filePoint.y !== derived.y) {
      throw new Error('điểm công khai trong tệp không khớp với [d]G');
    }
  }

  const validation = validatePublicPoint(rawPublic);
  if (!validation.valid) throw new Error(`điểm công khai không hợp lệ: ${validation.reason}`);

  const pkcs8 = buildPkcs8(pad32(parsed.d), x, y);
  return {
    privateKey: await crypto.subtle.importKey('pkcs8', pkcs8, ALGORITHM, true, ['sign']),
    publicKey: await crypto.subtle.importKey(
      'raw',
      concatBytes(Uint8Array.of(0x04), rawPublic),
      ALGORITHM,
      true,
      ['verify'],
    ),
    d: pad32(parsed.d),
    x,
    y,
    rawPublic,
    pkcs8,
    spki: buildSpki(x, y),
    pointOnCurve: true,
    pointFromFile: parsed.point !== null,
  };
}

// Minh họa hậu quả của việc dùng lại k: từ hai chữ ký cùng k trên hai thông điệp khác nhau,
// khóa bí mật suy ra được bằng d = (k*s - e) * r^-1 mod n.
export function recoverPrivateKeyFromReusedK(r, s, e, k) {
  return mod((k * s - e) * modInv(r, N), N);
}

export { buildPkcs8, buildSpki, parsePkcs8, parseSignatureDer, parseSpki, signatureRawToDer };