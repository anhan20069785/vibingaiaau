import { bytesToBigIntBE, mod, modInv, N } from './p256.js';

// Chữ ký thứ hai dùng lại đúng k: s2 = k^-1 (e2 + r d) mod n.
export function signWithReusedK(k, e2, r, d) {
  return mod(modInv(k, N) * (e2 + r * d), N);
}

// Từ (r, s2, e2, k) suy ra khóa bí mật: d = (s2*k - e2) * r^-1 mod n.
export function recoverPrivateKey(r, s2, e2, k) {
  return mod((s2 * k - e2) * modInv(r, N), N);
}

export function demonstrateReusedK(r, d, k, secondHashBytes) {
  const e2 = bytesToBigIntBE(secondHashBytes);
  const s2 = signWithReusedK(k, e2, r, d);
  const recovered = recoverPrivateKey(r, s2, e2, k);
  return { e2, s2, recovered, matches: recovered === d };
}