const HEX_DIGITS = '0123456789abcdef';

export function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    out += HEX_DIGITS[b >> 4] + HEX_DIGITS[b & 15];
  }
  return out;
}

export function hexToBytes(hex) {
  const clean = hex.replace(/[\s:]/g, '');
  if (clean.length === 0) throw new Error('chuỗi hex rỗng');
  if (clean.length % 2 !== 0) throw new Error('chuỗi hex có số ký tự lẻ');
  if (/[^0-9a-fA-F]/.test(clean)) throw new Error('chuỗi hex chứa ký tự không hợp lệ');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function concatBytes(...parts) {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function utf8Bytes(text) {
  return new TextEncoder().encode(text);
}

export function bytesToUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

export function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

export function base64ToBytes(text) {
  const clean = text.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) throw new Error('base64 không hợp lệ');
  const binary = atob(clean);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlToBytes(text) {
  return base64ToBytes(text.replace(/-/g, '+').replace(/_/g, '/'));
}

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}