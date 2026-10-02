// Tham số miền P-256 theo NIST SP 800-186, mục 3.2.1.3 (Weierstrass curve P-256).
// Chỉ dùng cho phần minh họa và cho chữ ký tất định RFC 6979; đường sinh khóa và
// xác minh của sản phẩm do WebCrypto của trình duyệt thực hiện.
export const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
export const A = P - 3n;
export const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
export const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
export const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;
export const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
export const COFACTOR = 1n;
export const FIELD_BYTES = 32;

export const G = { x: GX, y: GY };

export function mod(value, modulus = P) {
  const rest = value % modulus;
  return rest < 0n ? rest + modulus : rest;
}

export function modPow(base, exponent, modulus = P) {
  let result = 1n;
  let factor = mod(base, modulus);
  for (let power = exponent; power > 0n; power >>= 1n) {
    if (power & 1n) result = mod(result * factor, modulus);
    factor = mod(factor * factor, modulus);
  }
  return result;
}

export function modInv(value, modulus = P) {
  let previousRest = mod(value, modulus);
  let rest = modulus;
  let previousCoefficient = 1n;
  let coefficient = 0n;
  while (rest !== 0n) {
    const quotient = previousRest / rest;
    [previousRest, rest] = [rest, previousRest - quotient * rest];
    [previousCoefficient, coefficient] = [coefficient, previousCoefficient - quotient * coefficient];
  }
  if (previousRest !== 1n) throw new Error('phần tử không có nghịch đảo modulo');
  return mod(previousCoefficient, modulus);
}

export function isOnCurve(x, y) {
  if (x < 0n || x >= P || y < 0n || y >= P) return false;
  return mod(y * y - (x * x * x + A * x + B)) === 0n;
}

export function pointDouble(point) {
  if (point === null) return null;
  if (point.y === 0n) return null;
  const slope = mod((3n * point.x * point.x + A) * modInv(2n * point.y));
  const x = mod(slope * slope - 2n * point.x);
  const y = mod(slope * (point.x - x) - point.y);
  return { x, y };
}

export function pointAdd(left, right) {
  if (left === null) return right;
  if (right === null) return left;
  if (left.x === right.x) {
    if (mod(left.y + right.y) === 0n) return null;
    return pointDouble(left);
  }
  const slope = mod((right.y - left.y) * modInv(right.x - left.x));
  const x = mod(slope * slope - left.x - right.x);
  const y = mod(slope * (left.x - x) - left.y);
  return { x, y };
}

export function scalarMul(scalar, point) {
  if (scalar < 0n) throw new Error('scalar không được âm');
  let result = null;
  let addend = point;
  for (let remaining = scalar; remaining > 0n; remaining >>= 1n) {
    if (remaining & 1n) result = pointAdd(result, addend);
    addend = pointDouble(addend);
  }
  return result;
}

export function bytesToBigIntBE(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

export function bigIntToBytesBE(value, length) {
  if (value < 0n) throw new Error('giá trị không được âm');
  if (value >> BigInt(length * 8) !== 0n) throw new Error(`giá trị vượt quá ${length} byte`);
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}

export function pointToRaw(point) {
  if (point === null) throw new Error('điểm vô cực không có biểu diễn raw');
  const out = new Uint8Array(64);
  out.set(bigIntToBytesBE(point.x, FIELD_BYTES), 0);
  out.set(bigIntToBytesBE(point.y, FIELD_BYTES), FIELD_BYTES);
  return out;
}

export function rawToPoint(bytes) {
  const offset = bytes.length === 65 && bytes[0] === 0x04 ? 1 : 0;
  if (bytes.length - offset !== 64) throw new Error('điểm raw phải là 64 byte, hoặc 65 byte có tiền tố 0x04');
  return {
    x: bytesToBigIntBE(bytes.subarray(offset, offset + FIELD_BYTES)),
    y: bytesToBigIntBE(bytes.subarray(offset + FIELD_BYTES, offset + 2 * FIELD_BYTES)),
  };
}