// Sinh số bí mật k theo RFC 6979 mục 3.2, đúng như FIPS 186-5 Phụ lục A.3.3 dẫn chiếu:
// đầu vào là HMAC_DRBG (SP 800-90A) dùng cùng hàm băm với hàm băm xử lý thông điệp.
import { concatBytes } from './codec.js';
import { FIELD_BYTES, N, bigIntToBytesBE, bytesToBigIntBE, mod } from './p256.js';

// len(n) của P-256 là 256 bit.
const QLEN_BITS = 256n;
const HMAC_BYTES = 32;

async function hmacSha256(key, data) {
  const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, data));
}

// bits2int (RFC 6979 mục 2.3.2): giữ qlen bit trái nhất khi độ dài vượt quá qlen.
export function bits2int(bytes) {
  const value = bytesToBigIntBE(bytes);
  const blen = BigInt(bytes.length * 8);
  return blen > QLEN_BITS ? value >> (blen - QLEN_BITS) : value;
}

// int2octets (RFC 6979 mục 2.3.3) cho trường hợp qlen chia hết cho 8.
export function int2octets(value) {
  return bigIntToBytesBE(value, FIELD_BYTES);
}

// bits2octets (RFC 6979 mục 2.3.4): bits2int rồi giảm theo n, không thì giảm hai lần.
export function bits2octets(bytes) {
  return int2octets(mod(bits2int(bytes), N));
}

export async function generateK(privateKeyBytes, hashBytes) {
  if (privateKeyBytes.length !== FIELD_BYTES) throw new Error('khóa bí mật phải đúng 32 byte');
  const seed = concatBytes(int2octets(bytesToBigIntBE(privateKeyBytes)), bits2octets(hashBytes));

  let v = new Uint8Array(HMAC_BYTES).fill(0x01);
  let k = new Uint8Array(HMAC_BYTES).fill(0x00);

  k = await hmacSha256(k, concatBytes(v, Uint8Array.of(0x00), seed));
  v = await hmacSha256(k, v);
  k = await hmacSha256(k, concatBytes(v, Uint8Array.of(0x01), seed));
  v = await hmacSha256(k, v);

  // RFC 6979 3.2 bước h.3: thử lại khi k rơi ra ngoài [1, n-1]; thực tế gần như không xảy ra.
  for (let attempt = 0; attempt < 64; attempt++) {
    let candidate = new Uint8Array(0);
    while (candidate.length < FIELD_BYTES) {
      v = await hmacSha256(k, v);
      candidate = concatBytes(candidate, v);
    }
    const value = bits2int(candidate);
    if (value >= 1n && value < N) return value;
    k = await hmacSha256(k, concatBytes(v, Uint8Array.of(0x00)));
    v = await hmacSha256(k, v);
  }
  throw new Error('RFC 6979 không sinh được k sau 64 lần thử');
}