// Dữ liệu hiển thị lấy nguyên văn từ NIST SP 800-186 (2/2023) và NIST FIPS 186-5 (2/2023).
export const P256_PARAMETERS = [
  ['p', 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff'],
  ['a', 'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc'],
  ['b', '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'],
  ['Gx', '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'],
  ['Gy', '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'],
  ['n', 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'],
  ['h', '01'],
  ['Seed', 'c49d360886e704936a6678e1139d26b7819f7e90'],
];

export const P256_FACT = {
  section: 'SP 800-186, 3.2.1.3',
  field: 'GF(p) với p = 2^256 - 2^224 + 2^192 + 2^96 - 1, p là số nguyên tố dạng Mersenne tổng quát',
  cofactor: 'h = 1',
  securityStrength: '128 bit (Bảng 1 của SP 800-186)',
  usage: 'ECDSA và thiết lập khóa EC (Bảng 2 của SP 800-186)',
  oid: '1.2.840.10045.3.1.7 (định danh này không in trong SP 800-186, lấy từ ANSI X9.62 / RFC 5480)',
};

// FIPS 186-5, Bảng 1 trong §6.1.1: bit length của n, độ mạnh bảo mật.
export const FIPS_SECURITY_PARAMETERS = [
  { nBits: '224 đến 255', strength: 'khoảng len(n)/2, tối thiểu 112 bit' },
  { nBits: '256 đến 383', strength: 'khoảng len(n)/2, tối thiểu 128 bit' },
  { nBits: '384 đến 511', strength: 'khoảng len(n)/2, tối thiểu 192 bit' },
  { nBits: 'từ 512 trở lên', strength: 'khoảng len(n)/2, tối thiểu 256 bit' },
];

// SP 800-186, Bảng 2 trong §3.1.2: đường cong và mục đích được phép.
export const CURVE_USAGE = [
  { curves: 'K-233, B-233, K-283, B-283, K-409, B-409, K-571, B-571', usage: 'Deprecated', status: 'deprecated' },
  { curves: 'P-224, P-256, P-384, P-521', usage: 'ECDSA, EC key establishment', status: 'approved' },
  { curves: 'Edwards25519, Edwards448', usage: 'EdDSA', status: 'approved' },
  { curves: 'Curve25519, W-25519, Curve448, E448, W-448', usage: 'Not to be used for ECDSA or EdDSA directly', status: 'restricted' },
];

export const CURVE_STATUS = {
  p224: { label: 'P-224', strength: '112 bit', status: 'approved' },
  p256: { label: 'P-256', strength: '128 bit', status: 'approved' },
  p384: { label: 'P-384', strength: '192 bit', status: 'approved' },
  p521: { label: 'P-521', strength: '256 bit', status: 'approved' },
  p192: { label: 'P-192', strength: 'không còn trong Bảng 1', status: 'legacy' },
};

export function groupHex(hex, size = 8) {
  return (hex.match(new RegExp(`.{1,${size}}`, 'g')) ?? []).join(' ');
}