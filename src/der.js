import { base64ToBytes, bytesToBase64, concatBytes } from './codec.js';

export const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
export const OID_PRIME256V1 = '1.2.840.10045.3.1.7';

const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;
const TAG_CONTEXT_0 = 0xa0;
const TAG_CONTEXT_1 = 0xa1;

export function encodeLength(length) {
  if (!Number.isInteger(length) || length < 0) throw new Error(`độ dài DER không hợp lệ: ${length}`);
  if (length < 0x80) return Uint8Array.of(length);
  const bytes = [];
  for (let value = length; value > 0; value = Math.floor(value / 256)) bytes.unshift(value & 0xff);
  if (bytes.length > 4) throw new Error('độ dài DER vượt quá 4 byte');
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

export function tlv(tag, value) {
  return concatBytes(Uint8Array.of(tag), encodeLength(value.length), value);
}

export function sequence(...items) {
  return tlv(TAG_SEQUENCE, concatBytes(...items));
}

export function integerFromBytes(bytes) {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  let body = bytes.subarray(start);
  if (body.length === 0) throw new Error('INTEGER rỗng');
  if (body[0] & 0x80) body = concatBytes(Uint8Array.of(0), body);
  return tlv(TAG_INTEGER, body);
}

export function oidBytes(dotted) {
  const arcs = dotted.split('.').map(Number);
  if (arcs.length < 2 || arcs.some((arc) => !Number.isInteger(arc) || arc < 0)) {
    throw new Error(`OID không hợp lệ: ${dotted}`);
  }
  const [first, second] = arcs;
  if (first > 2 || (first < 2 && second > 39)) throw new Error(`OID không hợp lệ: ${dotted}`);
  const out = [first * 40 + second];
  for (const arc of arcs.slice(2)) {
    if (arc === 0) {
      out.push(0);
      continue;
    }
    const encoded = [];
    for (let value = arc; value > 0; value = Math.floor(value / 128)) encoded.unshift(value & 0x7f);
    for (let i = 0; i < encoded.length - 1; i++) out.push(encoded[i] | 0x80);
    out.push(encoded[encoded.length - 1]);
  }
  return Uint8Array.from(out);
}

export function oid(dotted) {
  return tlv(TAG_OID, oidBytes(dotted));
}

export function octetString(bytes) {
  return tlv(TAG_OCTET_STRING, bytes);
}

export function bitString(bytes) {
  return tlv(TAG_BIT_STRING, concatBytes(Uint8Array.of(0), bytes));
}

// Thẻ ngữ cảnh dạng EXPLICIT (RFC 5915 dùng cho trường [1] chứa khóa công khai), nên bit
// constructed phải bật: 0xa0 | số hiệu.
export function explicitContextTag(tagNumber, value) {
  if (tagNumber < 0 || tagNumber > 30) throw new Error('số hiệu context tag không hợp lệ');
  return tlv(0xa0 | tagNumber, value);
}

export function readTlv(bytes, offset) {
  if (offset + 2 > bytes.length) throw new Error('DER kết thúc sớm');
  const tag = bytes[offset];
  if (tag === 0x00) throw new Error('tag 0x00 không được dùng trong DER');
  if (tag === 0xff) throw new Error('tag 0xff không hợp lệ');
  const first = bytes[offset + 1];
  if (first === 0x80) throw new Error('DER không cho phép độ dài vô định');
  let length;
  let cursor;
  if (first < 0x80) {
    length = first;
    cursor = offset + 2;
  } else {
    const count = first & 0x7f;
    if (count === 0 || offset + 2 + count > bytes.length) throw new Error('trường độ dài DER sai');
    if (bytes[offset + 2] === 0x00) throw new Error('độ dài DER không tối thiểu');
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[offset + 2 + i];
    cursor = offset + 2 + count;
  }
  const end = cursor + length;
  if (end > bytes.length) throw new Error('giá trị DER vượt quá dữ liệu');
  return { tag, valueStart: cursor, valueEnd: end, next: end };
}

export function expectTlv(bytes, offset, tag, label) {
  const node = readTlv(bytes, offset);
  if (node.tag !== tag) {
    throw new Error(`${label}: tag 0x${node.tag.toString(16)} thay vì 0x${tag.toString(16)}`);
  }
  return node;
}

export function readInteger(bytes, offset, label) {
  const node = expectTlv(bytes, offset, TAG_INTEGER, label);
  const value = bytes.subarray(node.valueStart, node.valueEnd);
  if (value.length === 0) throw new Error(`${label}: INTEGER rỗng`);
  if (value[0] & 0x80) throw new Error(`${label}: INTEGER âm`);
  if (value.length > 1 && value[0] === 0x00 && (value[1] & 0x80) === 0) {
    throw new Error(`${label}: INTEGER không tối thiểu`);
  }
  const trimmed = value.length > 1 && value[0] === 0x00 ? value.subarray(1) : value;
  return { value: trimmed, next: node.next };
}

export function parseSignatureDer(der) {
  const outer = expectTlv(der, 0, TAG_SEQUENCE, 'chữ ký');
  if (outer.next !== der.length) throw new Error('chữ ký DER có dữ liệu thừa phía sau');
  const r = readInteger(der, outer.valueStart, 'r');
  const s = readInteger(der, r.next, 's');
  if (s.next !== outer.valueEnd) throw new Error('SEQUENCE chữ ký có dữ liệu thừa');
  return { r: r.value, s: s.value };
}

export function signatureRawToDer(raw) {
  if (raw.length !== 64) throw new Error(`chữ ký dạng raw phải đúng 64 byte, nhận ${raw.length}`);
  return sequence(integerFromBytes(raw.subarray(0, 32)), integerFromBytes(raw.subarray(32)));
}

// RFC 5915: trường [0] chứa tham số đường cong nên bỏ khi tham số đó đã có ở AlgorithmIdentifier
// bên ngoài, đúng như OpenSSL và WebCrypto phát ra.
export function buildEcPrivateKey(d, x, y) {
  return sequence(
    Uint8Array.of(TAG_INTEGER, 0x01, 0x01),
    octetString(d),
    explicitContextTag(1, bitString(concatBytes(Uint8Array.of(0x04), x, y))),
  );
}

export function buildPkcs8(d, x, y) {
  return sequence(
    Uint8Array.of(TAG_INTEGER, 0x01, 0x00),
    sequence(oid(OID_EC_PUBLIC_KEY), oid(OID_PRIME256V1)),
    octetString(buildEcPrivateKey(d, x, y)),
  );
}

export function buildSpki(x, y) {
  return sequence(
    sequence(oid(OID_EC_PUBLIC_KEY), oid(OID_PRIME256V1)),
    bitString(concatBytes(Uint8Array.of(0x04), x, y)),
  );
}

export function parseOid(bytes, offset, label) {
  const node = expectTlv(bytes, offset, TAG_OID, label);
  const value = bytes.subarray(node.valueStart, node.valueEnd);
  if (value.length === 0) throw new Error(`${label}: OID rỗng`);
  if (value[value.length - 1] & 0x80) throw new Error(`${label}: OID kết thúc giữa chừng`);
  const arcs = [];
  const first = value[0];
  arcs.push(first < 80 ? Math.floor(first / 40) : 2, first < 80 ? first % 40 : first - 80);
  let current = 0;
  let hasBits = false;
  for (let i = 1; i < value.length; i++) {
    current = current * 128 + (value[i] & 0x7f);
    hasBits = true;
    if ((value[i] & 0x80) === 0) {
      arcs.push(current);
      current = 0;
      hasBits = false;
    }
  }
  if (hasBits) throw new Error(`${label}: OID kết thúc giữa chừng`);
  return { dotted: arcs.join('.'), next: node.next };
}

function readCurveAlgorithm(bytes, offset, label) {
  const algorithm = expectTlv(bytes, offset, TAG_SEQUENCE, `${label}: AlgorithmIdentifier`);
  const algorithmOid = parseOid(bytes, algorithm.valueStart, `${label}: thuật toán`);
  const curveOid = parseOid(bytes, algorithmOid.next, `${label}: đường cong`);
  if (curveOid.next !== algorithm.valueEnd) throw new Error(`${label}: AlgorithmIdentifier có tham số lạ`);
  return { algorithm: algorithmOid.dotted, curve: curveOid.dotted, next: algorithm.next };
}

function readUncompressedPoint(bytes, offset, label) {
  const node = expectTlv(bytes, offset, TAG_BIT_STRING, label);
  const value = bytes.subarray(node.valueStart, node.valueEnd);
  if (value.length === 0 || value[0] !== 0x00) throw new Error(`${label}: BIT STRING có bit thừa`);
  const point = value.subarray(1);
  if (point.length !== 65 || point[0] !== 0x04) {
    throw new Error(`${label}: điểm công khai phải ở dạng không nén 65 byte`);
  }
  return { point: point.subarray(1), next: node.next };
}

export function parseSpki(der) {
  const outer = expectTlv(der, 0, TAG_SEQUENCE, 'SPKI');
  if (outer.next !== der.length) throw new Error('SPKI có dữ liệu thừa phía sau');
  const algorithm = readCurveAlgorithm(der, outer.valueStart, 'SPKI');
  const point = readUncompressedPoint(der, algorithm.next, 'SPKI: khóa công khai');
  if (point.next !== outer.valueEnd) throw new Error('SPKI có dữ liệu thừa');
  return { algorithm: algorithm.algorithm, curve: algorithm.curve, point: point.point };
}

export function parseEcPrivateKey(der) {
  const outer = expectTlv(der, 0, TAG_SEQUENCE, 'ECPrivateKey');
  if (outer.next !== der.length) throw new Error('ECPrivateKey có dữ liệu thừa phía sau');
  const version = readInteger(der, outer.valueStart, 'ECPrivateKey: version');
  if (version.value.length !== 1 || version.value[0] !== 1) {
    throw new Error('ECPrivateKey: version phải bằng 1');
  }
  const key = expectTlv(der, version.next, TAG_OCTET_STRING, 'ECPrivateKey: khóa bí mật');
  let offset = key.next;
  let curve = null;
  let point = null;
  if (offset < outer.valueEnd && der[offset] === TAG_CONTEXT_0) {
    const node = readTlv(der, offset);
    curve = parseOid(der, node.valueStart, 'ECPrivateKey: đường cong').dotted;
    offset = node.next;
  }
  if (offset < outer.valueEnd && der[offset] === TAG_CONTEXT_1) {
    const node = readTlv(der, offset);
    const inner = expectTlv(der, node.valueStart, TAG_BIT_STRING, 'ECPrivateKey: khóa công khai');
    const value = der.subarray(inner.valueStart, inner.valueEnd);
    if (value.length === 0 || value[0] !== 0x00) throw new Error('ECPrivateKey: BIT STRING có bit thừa');
    const raw = value.subarray(1);
    if (raw.length !== 65 || raw[0] !== 0x04) throw new Error('ECPrivateKey: điểm công khai không hợp lệ');
    point = raw.subarray(1);
    offset = node.next;
  }
  if (offset !== outer.valueEnd) throw new Error(`ECPrivateKey: phần tử lạ ở byte ${offset}`);
  return { curve, d: der.subarray(key.valueStart, key.valueEnd), point };
}

export function parsePkcs8(der) {
  const outer = expectTlv(der, 0, TAG_SEQUENCE, 'PKCS#8');
  if (outer.next !== der.length) throw new Error('PKCS#8 có dữ liệu thừa phía sau');
  const version = readInteger(der, outer.valueStart, 'PKCS#8: version');
  if (version.value.length !== 1 || (version.value[0] !== 0 && version.value[0] !== 1)) {
    throw new Error('PKCS#8: version phải là 0 hoặc 1');
  }
  const algorithm = readCurveAlgorithm(der, version.next, 'PKCS#8');
  const privateKey = expectTlv(der, algorithm.next, TAG_OCTET_STRING, 'PKCS#8: PrivateKeyInfo');
  if (privateKey.next !== outer.valueEnd) throw new Error('PKCS#8 có dữ liệu thừa');
  const inner = parseEcPrivateKey(der.subarray(privateKey.valueStart, privateKey.valueEnd));
  return { ...inner, algorithm: algorithm.algorithm, curve: inner.curve ?? algorithm.curve };
}

export function pemEncode(label, der) {
  const base64 = bytesToBase64(der);
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

export function pemDecode(text) {
  const match = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(text);
  if (!match) throw new Error('không tìm thấy khối PEM hợp lệ');
  const body = match[2].replace(/\s+/g, '');
  if (body.length === 0) throw new Error('khối PEM rỗng');
  return { label: match[1], der: base64ToBytes(body) };
}