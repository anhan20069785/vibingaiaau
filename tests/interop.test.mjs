import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

globalThis.crypto ??= webcrypto;

const { generateKeyPair, signMessage, verifyMessage, importPublicKeyFromSpki, importPrivatePem } = await import(
  '../src/ecdsa.js'
);
const { pemEncode, pemDecode } = await import('../src/der.js');
const { bytesToHex, utf8Bytes } = await import('../src/codec.js');

function opensslAvailable() {
  try {
    execFileSync('openssl', ['version'], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

const available = opensslAvailable();

function run(dir, args) {
  return execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' }).toString();
}

test('đối chiếu OpenSSL: khóa và chữ ký của ta được OpenSSL chấp nhận, và ngược lại', { skip: !available && 'không có openssl trong PATH' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ecdsa-interop-'));
  try {
    const message = utf8Bytes('đối chiếu với OpenSSL, P-256 và SHA-256');
    writeFileSync(join(dir, 'message.bin'), message);

    // Chiều 1: ta ký, OpenSSL xác minh.
    const key = await generateKeyPair();
    const signature = await signMessage(key, message);
    writeFileSync(join(dir, 'ours-public.pem'), pemEncode('PUBLIC KEY', key.spki));
    writeFileSync(join(dir, 'ours-signature.der'), signature.derSignature);
    const verifyOurs = run(dir, [
      'dgst',
      '-sha256',
      '-verify',
      'ours-public.pem',
      '-signature',
      'ours-signature.der',
      'message.bin',
    ]);
    assert.match(verifyOurs, /Verified OK/);

    // Chiều 2: OpenSSL sinh khóa và ký, ta nhập khóa và xác minh.
    run(dir, ['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', 'ossl-key.pem']);
    run(dir, ['ec', '-in', 'ossl-key.pem', '-pubout', '-out', 'ossl-public.pem']);
    run(dir, ['dgst', '-sha256', '-sign', 'ossl-key.pem', '-out', 'ossl-signature.der', 'message.bin']);

    const osslPublicPem = readFileSync(join(dir, 'ossl-public.pem'), 'utf8');
    const imported = await importPublicKeyFromSpki(pemDecode(osslPublicPem).der);
    const rawPublic = new Uint8Array(await crypto.subtle.exportKey('raw', imported)).subarray(1);
    const osslSignature = new Uint8Array(readFileSync(join(dir, 'ossl-signature.der')));
    const accepted = await verifyMessage({ publicKey: imported, rawPublic }, message, osslSignature);
    assert.equal(accepted.accepted, true, 'số học đường cong phải nhận chữ ký của OpenSSL');
    assert.equal(accepted.webcryptoAccepted, true, 'WebCrypto phải nhận chữ ký của OpenSSL');
    assert.equal(accepted.agree, true);

    // Chiều 3: nhập khóa bí mật SEC1 của OpenSSL, ký bằng khóa đó, OpenSSL xác minh lại.
    const importedKey = await importPrivatePem(readFileSync(join(dir, 'ossl-key.pem'), 'utf8'));
    assert.equal(importedKey.pointFromFile, true, 'OpenSSL 1.0.2 có kèm điểm công khai trong tệp SEC1');
    assert.equal(
      bytesToHex(importedKey.rawPublic),
      bytesToHex(rawPublic),
      'điểm công khai đọc từ tệp phải trùng điểm OpenSSL công bố',
    );

    const ourSignature = await signMessage(importedKey, message);
    writeFileSync(join(dir, 'ours-from-ossl-key.der'), ourSignature.derSignature);
    const verifyOursFromOsslKey = run(dir, [
      'dgst',
      '-sha256',
      '-verify',
      'ossl-public.pem',
      '-signature',
      'ours-from-ossl-key.der',
      'message.bin',
    ]);
    assert.match(verifyOursFromOsslKey, /Verified OK/);

    // Chiều 4: chữ ký của ta trên thông điệp khác thì OpenSSL phải từ chối.
    writeFileSync(join(dir, 'other.bin'), utf8Bytes('thông điệp khác'));
    let rejected = false;
    try {
      run(dir, ['dgst', '-sha256', '-verify', 'ours-public.pem', '-signature', 'ours-signature.der', 'other.bin']);
    } catch (error) {
      rejected = true;
      assert.match(String(error.stdout ?? ''), /Verification failure|Verification Failure/i);
    }
    assert.equal(rejected, true, 'OpenSSL phải từ chối khi thông điệp bị đổi');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});