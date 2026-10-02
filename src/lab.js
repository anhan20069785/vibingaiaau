// Bàn ECDSA P-256. Giao diện chỉ gọi các hàm thuần trong src/. Mọi số hiển thị đều do
// chính phiên chạy này tính ra, không có số liệu mẫu.
import { bytesEqual, bytesToHex, hexToBytes, utf8Bytes } from './codec.js';
import { pemDecode, pemEncode, parseSignatureDer } from './der.js';
import {
  generateKeyPair,
  importPublicKeyFromSpki,
  sha256,
  signMessage,
  validatePublicPoint,
  verifyMessage,
  verifyViaWebCrypto,
} from './ecdsa.js';
import { CURVE_USAGE, FIPS_SECURITY_PARAMETERS, P256_FACT, P256_PARAMETERS, groupHex } from './nist.js';
import { FIELD_BYTES, N, bytesToBigIntBE, rawToPoint } from './p256.js';
import { demonstrateReusedK } from './reused-k.js';

const MAX_MESSAGE_BYTES = 65536;

const state = {
  key: null,
  signature: null,
  signedBytes: null,
};

const findings = [];
const elements = {};

function cacheElements() {
  for (const node of document.querySelectorAll('[data-el]')) elements[node.dataset.el] = node;
}

function setText(name, value) {
  const node = elements[name];
  if (node) node.textContent = value;
}

function setBusy(busy, label = '') {
  for (const node of document.querySelectorAll('[data-busy]')) {
    const blocked = node.dataset.needsKey === 'true' && !state.key;
    node.disabled = busy || blocked;
  }
  if (label) setText('statusLine', label);
}

function report(step, expected, observed, ok) {
  findings.push({ step, expected, observed, ok });
  renderFindings();
}

function renderFindings() {
  const body = elements.findingBody;
  body.replaceChildren();
  for (const item of findings) {
    const row = document.createElement('tr');
    const stepCell = document.createElement('td');
    stepCell.textContent = item.step;
    const expectedCell = document.createElement('td');
    expectedCell.textContent = item.expected;
    const observedCell = document.createElement('td');
    observedCell.textContent = item.observed;
    const verdictCell = document.createElement('td');
    verdictCell.className = item.ok ? 'verdict-ok' : 'verdict-bad';
    verdictCell.textContent = item.ok ? 'đúng kỳ vọng' : 'lệch kỳ vọng';
    row.append(stepCell, expectedCell, observedCell, verdictCell);
    body.append(row);
  }
  const wrong = findings.filter((item) => !item.ok).length;
  elements.findingSummary.textContent =
    findings.length === 0
      ? 'Chưa chạy ca nào.'
      : `${findings.length} ca đã chạy, ${wrong} ca lệch kỳ vọng.`;
  elements.findingEmpty.hidden = findings.length > 0;
  elements.findingTable.hidden = findings.length === 0;
}

function currentBytes() {
  const bytes = utf8Bytes(elements.messageInput.value);
  if (bytes.length > MAX_MESSAGE_BYTES) {
    throw new Error(`nội dung ${bytes.length} byte, vượt giới hạn ${MAX_MESSAGE_BYTES} byte`);
  }
  return bytes;
}

function requireKey() {
  if (state.key) return true;
  report('Điều kiện tiên quyết', 'đã có khóa', 'chưa sinh khóa', false);
  return false;
}

function requireSignature() {
  if (state.signature) return true;
  report('Điều kiện tiên quyết', 'đã có chữ ký', 'chưa ký thông điệp nào', false);
  return false;
}

function setOutcome(kind, text) {
  elements.verifyOutcome.className = `result result-${kind}`;
  elements.verifyOutcome.textContent = text;
}

async function handleGenerateKey() {
  setBusy(true, 'Đang sinh khóa P-256.');
  try {
    state.key = await generateKeyPair();
    state.signature = null;
    state.signedBytes = null;
    elements.rawSignature.value = '';
    elements.derSignature.value = '';
    elements.derHex.value = '';
    elements.pkcs8Pem.value = pemEncode('PRIVATE KEY', state.key.pkcs8);
    elements.spkiPem.value = pemEncode('PUBLIC KEY', state.key.spki);
    elements.importedPoint.value = '';
    elements.pastedSignature.value = '';

    const point = rawToPoint(state.key.rawPublic);
    elements.dValue.value = bytesToHex(state.key.d);
    elements.xValue.value = bytesToHex(state.key.x);
    elements.yValue.value = bytesToHex(state.key.y);
    elements.rawPublic.value = bytesToHex(state.key.rawPublic);
    setText(
      'keyNote',
      `Q tính lại bằng số học đường cong trùng với khóa công khai: trùng. Điểm nằm trên đường cong: ${state.key.pointOnCurve ? 'đúng' : 'sai'}.`,
    );
    const dValue = bytesToBigIntBE(state.key.d);
    setText('dLength', `${state.key.d.length} byte, d nằm trong [1, n-1]: ${dValue >= 1n && dValue < N ? 'đúng' : 'sai'}`);
    setText('pointNote', `x và y đều 32 byte, điểm ở dạng không nén là 64 byte cộng tiền tố 0x04 khi đóng gói.`);
    setOutcome('idle', 'Chưa xác minh lần nào.');
    setText('hashValue', 'chưa tính');
    setText('kValue', 'chưa sinh');
    setText('eValue', 'chưa tính');
    setText('rValue', 'chưa tính');
    setText('sValue', 'chưa tính');
    setText('compareNote', 'Chưa có chữ ký để đối chiếu hai dạng biểu diễn.');
    findings.length = 0;
    renderFindings();
    report('Sinh khóa', 'điểm công khai nằm trên đường cong', state.key.pointOnCurve ? 'đúng' : 'sai', state.key.pointOnCurve);
  } catch (error) {
    report('Sinh khóa', 'không lỗi', String(error.message ?? error), false);
  } finally {
    setBusy(false, 'Sẵn sàng.');
  }
}

async function handleSign() {
  if (!requireKey()) return;
  setBusy(true, 'Đang băm và ký.');
  try {
    const bytes = currentBytes();
    const signature = await signMessage(state.key, bytes);
    state.signature = signature;
    state.signedBytes = bytes;

    elements.rawSignature.value = bytesToHex(signature.rawSignature);
    elements.derSignature.value = bytesToHex(signature.derSignature);
    elements.derHex.value = groupHex(bytesToHex(signature.derSignature));
    setText('hashValue', signature.hashHex);
    setText('kValue', signature.kHex);
    setText('eValue', signature.eHex);
    setText('rValue', signature.rHex);
    setText('sValue', signature.sHex);
    setText('messageLength', `${bytes.length} byte`);
    setOutcome('idle', 'Đã ký. Bấm "Xác minh nội dung hiện tại" để kiểm tra.');
    report(
      'Ký: hai chiều kiểm tra chéo với WebCrypto',
      'WebCrypto nhận chữ ký của ta, ta nhận chữ ký của WebCrypto',
      `WebCrypto ${signature.webcryptoAcceptedOurs ? 'nhận' : 'không nhận'} chữ ký của ta; số học của ta ${signature.oursAcceptedWebcrypto ? 'nhận' : 'không nhận'} chữ ký của WebCrypto; byte hai bên ${signature.sameBytesAsWebCrypto ? 'trùng nhau' : 'khác nhau vì WebCrypto lấy k ngẫu nhiên theo §6.3.1'}`,
      signature.webcryptoAcceptedOurs === true && signature.oursAcceptedWebcrypto === true,
    );
    handleCompareRawDer();
  } catch (error) {
    report('Ký', 'không lỗi', String(error.message ?? error), false);
  } finally {
    setBusy(false, 'Sẵn sàng.');
  }
}

async function handleHashOnly() {
  setBusy(true, 'Đang băm.');
  try {
    const bytes = currentBytes();
    setText('hashValue', bytesToHex(await sha256(bytes)));
    setText('messageLength', `${bytes.length} byte`);
  } catch (error) {
    report('Băm nội dung', 'không lỗi', String(error.message ?? error), false);
  } finally {
    setBusy(false, 'Sẵn sàng.');
  }
}

// Chạy cả hai đường: số học đường cong tự viết và WebCrypto của trình duyệt.
async function runVerification(derSignature, messageBytes, label, expectation) {
  const validation = validatePublicPoint(state.key.rawPublic);
  if (!validation.valid) {
    setOutcome('fail', `Khóa công khai không hợp lệ: ${validation.reason}`);
    report(label, 'khóa hợp lệ', validation.reason, false);
    return null;
  }
  const result = await verifyMessage(state.key, messageBytes, derSignature);
  const agreed = result.agree;
  const matchesExpectation = expectation === null || result.accepted === expectation;
  setOutcome(result.accepted ? 'pass' : 'fail', result.accepted
    ? `Chấp nhận. ${result.reason}.`
    : `Từ chối. ${result.reason}.`);
  setText('verifyHash', result.hashHex);
  setText('verifyR', result.r);
  setText('verifyS', result.s);
  setText('verifySteps', `u và v tính theo §6.4.2, R1 không phải điểm vô cực, x_R1 mod n so với r: ${result.math.accepted ? 'bằng nhau' : 'khác nhau'}.`);
  report(
    label,
    expectation === null ? 'hai đường tính đồng ý' : expectation ? 'chấp nhận' : 'từ chối',
    `${result.accepted ? 'chấp nhận' : 'từ chối'}; WebCrypto ${result.webcryptoAccepted ? 'chấp nhận' : 'từ chối'}`,
    agreed && matchesExpectation,
  );
  return result;
}

async function handleVerifyCurrent() {
  if (!requireKey() || !requireSignature()) return;
  setBusy(true, 'Đang xác minh nội dung hiện tại.');
  try {
    const bytes = currentBytes();
    const unchanged = bytesEqual(bytes, state.signedBytes);
    await runVerification(state.signature.derSignature, bytes, unchanged ? 'Xác minh bản đã ký' : 'Xác minh nội dung đã sửa', unchanged ? true : false);
  } catch (error) {
    report('Xác minh nội dung hiện tại', 'không lỗi', String(error.message ?? error), false);
  } finally {
    setBusy(false, 'Sẵn sàng.');
  }
}

function handleVerifyTampered() {
  if (!requireKey() || !requireSignature()) return;
  const tampered = Uint8Array.from(state.signedBytes);
  const before = tampered[tampered.length - 1];
  tampered[tampered.length - 1] ^= 0x01;
  const label = `Xác minh bản sửa 1 bit (byte cuối 0x${before.toString(16).padStart(2, '0')} thành 0x${tampered[tampered.length - 1].toString(16).padStart(2, '0')})`;
  setBusy(true, 'Đang xác minh bản sửa.');
  runVerification(state.signature.derSignature, tampered, label, false)
    .catch((error) => report('Xác minh bản sửa 1 bit', 'không lỗi', String(error.message ?? error), false))
    .finally(() => setBusy(false, 'Sẵn sàng.'));
}

async function handleVerifyWrongKey() {
  if (!requireKey() || !requireSignature()) return;
  setBusy(true, 'Đang thử với khóa khác.');
  try {
    const other = await generateKeyPair();
    const result = await verifyMessage(other, state.signedBytes, state.signature.derSignature);
    report(
      'Khóa công khai của cặp khác',
      'từ chối',
      `số học ${result.accepted ? 'chấp nhận' : 'từ chối'}, WebCrypto ${result.webcryptoAccepted ? 'chấp nhận' : 'từ chối'}`,
      result.accepted === false && result.webcryptoAccepted === false,
    );
  } catch (error) {
    report('Khóa công khai của cặp khác', 'không lỗi', String(error.message ?? error), false);
  } finally {
    setBusy(false, 'Sẵn sàng.');
  }
}

function handleCompareRawDer() {
  try {
    const raw = hexToBytes(elements.rawSignature.value);
    const der = hexToBytes(elements.derSignature.value);
    if (raw.length !== 64) throw new Error(`dạng raw cần 64 byte, nhận ${raw.length}`);
    const parsed = parseSignatureDer(der);
    const same = bytesEqual(parsed.r, raw.subarray(0, 32)) && bytesEqual(parsed.s, raw.subarray(32));
    const rNeedsPad = parsed.r.length < 32;
    const sNeedsPad = parsed.s.length < 32;
    setText(
      'compareNote',
      same
        ? `Hai dạng cùng một cặp số. r chiếm ${parsed.r.length} byte, s chiếm ${parsed.s.length} byte trong DER.${rNeedsPad || sNeedsPad ? ' Một trong hai số ngắn hơn 32 byte vì DER bỏ byte 0x00 đứng đầu.' : ''}`
        : 'Hai dạng không khớp.',
    );
    report('Đối chiếu raw và DER', 'cùng một cặp (r, s)', same ? 'khớp' : 'không khớp', same);
  } catch (error) {
    setText('compareNote', String(error.message ?? error));
    report('Đối chiếu raw và DER', 'không lỗi', String(error.message ?? error), false);
  }
}

async function handleReusedK() {
  if (!requireKey() || !requireSignature()) return;
  setBusy(true, 'Đang thử dùng lại k.');
  try {
    const secondHash = await sha256(utf8Bytes('thông điệp thứ hai'));
    const demo = demonstrateReusedK(state.signature.r, bytesToBigIntBE(state.key.d), state.signature.k, secondHash);
    report(
      'Dùng lại k cho thông điệp thứ hai',
      'suy ra được khóa bí mật',
      demo.matches
        ? 'khóa bí mật suy ra đúng, đây là hậu quả khi vi phạm §6.3'
        : 'không suy ra được',
      demo.matches,
    );
  } catch (error) {
    report('Dùng lại k', 'không lỗi', String(error.message ?? error), false);
  } finally {
    setBusy(false, 'Sẵn sàng.');
  }
}

async function handleImportSpki() {
  const text = elements.spkiImport.value.trim();
  if (!text) {
    report('Nhập khóa công khai', 'không lỗi', 'ô nhập trống', false);
    return;
  }
  try {
    let der;
    try {
      der = pemDecode(text).der;
    } catch {
      der = hexToBytes(text);
    }
    const key = await importPublicKeyFromSpki(der);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
    const validation = validatePublicPoint(raw);
    elements.importedPoint.value = bytesToHex(raw);
    let detail = `nhập được, ${validation.valid ? 'điểm hợp lệ' : `điểm không hợp lệ: ${validation.reason}`}`;
    if (state.signature && state.signedBytes) {
      const verified = await verifyViaWebCrypto(key, state.signature.derSignature, state.signedBytes);
      detail += verified ? ', chữ ký hiện có hợp lệ với khóa này' : ', chữ ký hiện có không hợp lệ với khóa này';
    }
    report('Nhập khóa công khai', 'không lỗi', detail, validation.valid);
  } catch (error) {
    report('Nhập khóa công khai', 'không lỗi', String(error.message ?? error), false);
  }
}

async function handleVerifyExternal() {
  if (!requireKey()) return;
  const text = elements.pastedSignature.value.trim();
  if (!text) {
    report('Xác minh chữ ký ngoài', 'không lỗi', 'ô nhập trống', false);
    return;
  }
  setBusy(true, 'Đang xác minh chữ ký ngoài.');
  try {
    let der;
    try {
      der = pemDecode(text).der;
    } catch {
      der = hexToBytes(text);
    }
    const bytes = currentBytes();
    await runVerification(der, bytes, 'Xác minh chữ ký ngoài', null);
  } catch (error) {
    report('Xác minh chữ ký ngoài', 'không lỗi', String(error.message ?? error), false);
  } finally {
    setBusy(false, 'Sẵn sàng.');
  }
}

function handleToggleDetails(event) {
  const button = event.currentTarget;
  const target = document.getElementById(button.getAttribute('aria-controls'));
  const expanded = button.getAttribute('aria-expanded') === 'true';
  button.setAttribute('aria-expanded', String(!expanded));
  if (target) target.hidden = expanded;
}

async function handleCopy(event) {
  const button = event.currentTarget;
  const target = elements[button.dataset.copyTarget];
  if (!target || !target.value) return;
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(target.value);
    button.textContent = 'Đã sao chép';
  } catch {
    button.textContent = 'Không sao chép được';
  }
  setTimeout(() => {
    button.textContent = original;
  }, 1200);
}

function renderParameters() {
  for (const [name, value] of P256_PARAMETERS) {
    const row = document.createElement('tr');
    const nameCell = document.createElement('th');
    nameCell.scope = 'row';
    nameCell.textContent = name;
    const valueCell = document.createElement('td');
    valueCell.className = 'hex';
    valueCell.textContent = groupHex(value);
    row.append(nameCell, valueCell);
    elements.parameterBody.append(row);
  }

  for (const row of FIPS_SECURITY_PARAMETERS) {
    const tr = document.createElement('tr');
    for (const text of [row.nBits, row.strength]) {
      const cell = document.createElement('td');
      cell.textContent = text;
      tr.append(cell);
    }
    elements.securityBody.append(tr);
  }

  for (const row of CURVE_USAGE) {
    const tr = document.createElement('tr');
    tr.className = `usage-${row.status}`;
    for (const text of [row.curves, row.usage]) {
      const cell = document.createElement('td');
      cell.textContent = text;
      tr.append(cell);
    }
    elements.usageBody.append(tr);
  }

  setText(
    'curveFact',
    `${P256_FACT.section} quy định trường ${P256_FACT.field}, hệ số ${P256_FACT.cofactor}, độ mạnh bảo mật ${P256_FACT.securityStrength}, dùng cho ${P256_FACT.usage}. OID trong chứng thư: ${P256_FACT.oid}.`,
  );
}

function wireEvents() {
  elements.generateKey.addEventListener('click', handleGenerateKey);
  elements.signMessage.addEventListener('click', handleSign);
  elements.hashMessage.addEventListener('click', handleHashOnly);
  elements.verifyCurrent.addEventListener('click', handleVerifyCurrent);
  elements.verifyTampered.addEventListener('click', handleVerifyTampered);
  elements.verifyWrongKey.addEventListener('click', handleVerifyWrongKey);
  elements.compareRawDer.addEventListener('click', handleCompareRawDer);
  elements.reuseK.addEventListener('click', handleReusedK);
  elements.importSpki.addEventListener('click', handleImportSpki);
  elements.verifyExternal.addEventListener('click', handleVerifyExternal);
  for (const button of document.querySelectorAll('[data-toggle-details]')) {
    button.addEventListener('click', handleToggleDetails);
  }
  for (const button of document.querySelectorAll('[data-copy-target]')) {
    button.addEventListener('click', handleCopy);
  }
}

function init() {
  cacheElements();
  renderParameters();
  wireEvents();
  setText('statusLine', 'Sẵn sàng. Bắt đầu bằng nút sinh khóa.');
  setText('platformNote', `${FIELD_BYTES} byte cho mỗi trường; chữ ký DER thường 70 đến 72 byte vì có thêm byte 0x00 khi bit cao của r hoặc s bằng 1.`);
  state.key = null;
  setBusy(false);
  renderFindings();
  setOutcome('idle', 'Chưa xác minh lần nào.');
}

document.addEventListener('DOMContentLoaded', init);