/* ============================================================================
   Password Generator & Reverse - script.js
   Bagian 1: logika inti (Lampiran C PRD) - tidak menyentuh DOM, bisa diuji di
             console atau Node.
   Bagian 2: penghubung UI.
   CATATAN: ini BUKAN enkripsi standar. Jangan dipakai melindungi data penting.
   ============================================================================ */

'use strict';

/* ========== KONSTANTA ========== */
const VERSION = 'v1';          // versi algoritma (ikut masuk ke seed RNG)
const MAX_LEN = 99;            // maks. byte teks (A)
const MAX_B = 1024;            // maks. panjang password (B)

const SETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digit: '0123456789',
  sym1: '!@#$%^&*-_+=?',
  sym2: '"\'(),./:;<>[\\]`{|}~'
};

function fail(code, detail) {
  const e = new Error(code);
  e.code = code;
  e.detail = detail;
  throw e;
}

/* ========== SET KARAKTER (X) ========== */
// selectedKeys: array nama grup, mis. ['lower','upper','digit']
// customText  : string karakter custom (boleh kosong)
// Hasil       : array karakter unik, terurut menurut kode ASCII
function normalizeCharset(selectedKeys, customText) {
  let all = '';
  for (const k of selectedKeys) all += SETS[k] || '';
  for (const ch of String(customText).trim()) {
    const c = ch.charCodeAt(0);
    if (ch.length !== 1 || c < 33 || c > 126) fail('ERR_X_BAD_CHAR', ch);
    all += ch;
  }
  return Array.from(new Set(all.split('')))
    .sort((a, b) => a.charCodeAt(0) - b.charCodeAt(0));
}

/* ========== UTF-8 ========== */
function toBytes(str) {
  return new TextEncoder().encode(str);
}
function fromBytes(bytes) {
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
    .decode(bytes);
}

/* ========== PARSE INPUT ANGKA ========== */
function parseB(B) {
  const s = String(B).trim();
  if (!/^\d{1,5}$/.test(s) || parseInt(s, 10) < 1) fail('ERR_B_INVALID');
  const n = parseInt(s, 10);
  if (n > MAX_B) fail('ERR_B_TOO_BIG');
  return n;
}
function parseC(C) {
  const s = String(C).trim();
  if (!/^\d{1,16}$/.test(s)) fail('ERR_C_INVALID');
  return BigInt(s).toString();            // "007" -> "7"
}

/* ========== PENANDA PANJANG (di awal & akhir password) ========== */
function hasAllDigits(X) {
  return '0123456789'.split('').every(d => X.includes(d));
}
function markerWidth(M, decimal) {
  if (decimal) return String(MAX_LEN).length;     // 2
  let w = 1, cap = M;
  while (cap <= MAX_LEN) { cap *= M; w++; }       // M^w > MAX_LEN
  return w;
}
function encodeMarker(N, X, decimal, W) {
  if (decimal) return String(N).padStart(W, '0');
  const M = X.length;
  let s = '';
  for (let i = 0; i < W; i++) { s = X[N % M] + s; N = Math.floor(N / M); }
  return s;
}
function decodeMarker(s, X, decimal) {
  const M = X.length;
  let n = 0;
  for (const ch of s) {
    if (decimal) {
      if (ch < '0' || ch > '9') return -1;
      n = n * 10 + (ch.charCodeAt(0) - 48);
    } else {
      const v = X.indexOf(ch);
      if (v < 0) return -1;
      n = n * M + v;
    }
  }
  return n;
}

/* ========== KAPASITAS ========== */
// P terkecil sehingga M^P >= 256^N
function minPayload(N, M) {
  const target = 1n << BigInt(8 * N);
  const Mn = BigInt(M);
  let P = 0, cap = 1n;
  while (cap < target) { cap *= Mn; P++; }
  return P;
}
// B minimal untuk petunjuk di UI (null jika belum bisa dihitung)
function minLength(A, X) {
  const N = toBytes(A).length;
  if (N < 1 || N > MAX_LEN || X.length < 2) return null;
  const W = markerWidth(X.length, hasAllDigits(X));
  return minPayload(N, X.length) + 2 * W;
}

/* ========== RNG BERSEED (deterministik) ========== */
// Hash string -> 4 angka 32-bit (adaptasi domain publik dari cyrb128)
function hash128(str) {
  let h1 = 1779033703, h2 = 3144134277, h3 = 1013904242, h4 = 2773480762;
  for (let i = 0, k; i < str.length; i++) {
    k = str.charCodeAt(i);
    h1 = h2 ^ Math.imul(h1 ^ k, 597399067);
    h2 = h3 ^ Math.imul(h2 ^ k, 2869860233);
    h3 = h4 ^ Math.imul(h3 ^ k, 951274213);
    h4 = h1 ^ Math.imul(h4 ^ k, 2716044179);
  }
  h1 = Math.imul(h3 ^ (h1 >>> 18), 597399067);
  h2 = Math.imul(h4 ^ (h2 >>> 22), 2869860233);
  h3 = Math.imul(h1 ^ (h3 >>> 17), 951274213);
  h4 = Math.imul(h2 ^ (h4 >>> 19), 2716044179);
  h1 ^= (h2 ^ h3 ^ h4); h2 ^= h1; h3 ^= h1; h4 ^= h1;
  return [h1 >>> 0, h2 >>> 0, h3 >>> 0, h4 >>> 0];
}
// Pembangkit sfc32 (domain publik). Mengembalikan fungsi rnd(n) -> 0..n-1
function makeRng(seedStr) {
  let [a, b, c, d] = hash128(seedStr);
  function next() {
    a |= 0; b |= 0; c |= 0; d |= 0;
    const t = (a + b | 0) + d | 0;
    d = d + 1 | 0;
    a = b ^ b >>> 9;
    b = c + (c << 3) | 0;
    c = (c << 21 | c >>> 11);
    c = c + t | 0;
    return t >>> 0;
  }
  for (let i = 0; i < 15; i++) next();            // buang 15 nilai awal
  return n => Math.floor(next() * n / 4294967296);
}

/* ========== KUNCI TURUNAN SEED ========== */
// Urutan pengambilan RNG: (1) tabel T, (2) k1[0..P-1], (3) k2[0..P-1]
function buildCipher(seed, B, N, X, P) {
  const M = X.length;
  const rnd = makeRng([VERSION, seed, B, N, X.join('')].join('|'));
  const T = Array.from({ length: M }, (_, i) => i);
  for (let i = M - 1; i > 0; i--) {               // Fisher-Yates
    const j = rnd(i + 1);
    const tmp = T[i]; T[i] = T[j]; T[j] = tmp;
  }
  const Tinv = new Array(M);
  for (let i = 0; i < M; i++) Tinv[T[i]] = i;
  const k1 = new Array(P), k2 = new Array(P);
  for (let i = 0; i < P; i++) k1[i] = rnd(M);
  for (let i = 0; i < P; i++) k2[i] = rnd(M);
  return { T, Tinv, k1, k2 };
}

/* ========== PENGACAKAN 2 PUTARAN (maju lalu mundur) ========== */
function mod(a, M) { return ((a % M) + M) % M; }

function mix(x, T, k1, k2, M) {
  const P = x.length;
  const y = new Array(P), z = new Array(P);
  let prev = 0;
  for (let i = 0; i < P; i++) {                   // putaran 1: kiri -> kanan
    y[i] = T[(x[i] + k1[i] + prev) % M];
    prev = y[i];
  }
  prev = 0;
  for (let i = P - 1; i >= 0; i--) {              // putaran 2: kanan -> kiri
    z[i] = T[(y[i] + k2[i] + prev) % M];
    prev = z[i];
  }
  return z;
}

function unmix(z, Tinv, k1, k2, M) {
  const P = z.length;
  const y = new Array(P), x = new Array(P);
  for (let i = 0; i < P; i++) {                   // batalkan putaran 2
    const next = i + 1 < P ? z[i + 1] : 0;
    y[i] = mod(Tinv[z[i]] - k2[i] - next, M);
  }
  for (let i = 0; i < P; i++) {                   // batalkan putaran 1
    const prev = i > 0 ? y[i - 1] : 0;
    x[i] = mod(Tinv[y[i]] - k1[i] - prev, M);
  }
  return x;
}

/* ========== GENERATE: (A, B, C, X) -> D ========== */
function generate(A, B, C, X) {
  if (A.length === 0) fail('ERR_A_EMPTY');
  const bytes = toBytes(A);
  const N = bytes.length;
  if (N > MAX_LEN) fail('ERR_A_TOO_LONG', N);
  if (fromBytes(bytes) !== A) fail('ERR_A_UNICODE');
  const b = parseB(B);
  const seed = parseC(C);
  const M = X.length;
  if (M < 2) fail('ERR_X_TOO_FEW');

  const decimal = hasAllDigits(X);
  const W = markerWidth(M, decimal);
  const P = b - 2 * W;
  const Pmin = minPayload(N, M);
  if (P < Pmin) fail('ERR_B_TOO_SMALL', Pmin + 2 * W);

  let V = 0n;                                     // byte -> bilangan besar
  for (const byte of bytes) V = (V << 8n) | BigInt(byte);
  const Mn = BigInt(M);
  const x = new Array(P).fill(0);                 // bilangan besar -> digit basis M
  for (let i = P - 1; i >= 0; i--) { x[i] = Number(V % Mn); V = V / Mn; }

  const { T, k1, k2 } = buildCipher(seed, b, N, X, P);
  const z = mix(x, T, k1, k2, M);
  const marker = encodeMarker(N, X, decimal, W);
  const D = marker + z.map(d => X[d]).join('') + marker;

  if (reverse(D, b, seed, X) !== A) fail('ERR_INTERNAL');   // cek mandiri
  return D;
}

/* ========== REVERSE: (D, B, C, X) -> A ========== */
function reverse(D, B, C, X) {
  D = String(D).trim();
  if (D.length === 0) fail('ERR_D_EMPTY');
  const b = parseB(B);
  const seed = parseC(C);
  const M = X.length;
  if (M < 2) fail('ERR_X_TOO_FEW');
  if (D.length !== b) fail('ERR_D_LEN', D.length);

  const idx = new Array(b);
  for (let i = 0; i < b; i++) {
    idx[i] = X.indexOf(D[i]);
    if (idx[i] < 0) fail('ERR_D_CHAR', D[i]);
  }
  const decimal = hasAllDigits(X);
  const W = markerWidth(M, decimal);
  if (b < 2 * W + 1) fail('ERR_MARKER');
  const m1 = D.slice(0, W), m2 = D.slice(b - W);
  if (m1 !== m2) fail('ERR_MARKER');
  const N = decodeMarker(m1, X, decimal);
  if (N < 1 || N > MAX_LEN) fail('ERR_MARKER');
  const P = b - 2 * W;
  if (P < minPayload(N, M)) fail('ERR_MARKER');

  const z = idx.slice(W, W + P);
  const { Tinv, k1, k2 } = buildCipher(seed, b, N, X, P);
  const x = unmix(z, Tinv, k1, k2, M);

  const Mn = BigInt(M);
  let V = 0n;
  for (const d of x) V = V * Mn + BigInt(d);
  if (V >= (1n << BigInt(8 * N))) fail('ERR_DECODE');
  const bytes = new Uint8Array(N);
  for (let i = N - 1; i >= 0; i--) { bytes[i] = Number(V & 255n); V >>= 8n; }
  try { return fromBytes(bytes); } catch (e) { fail('ERR_DECODE'); }
}


/* ============================================================================
   BAGIAN 2 - PENGHUBUNG UI (menyentuh DOM)
   ============================================================================ */

const VIEW_IDS = { menu: 'view-menu', generate: 'view-generate', reverse: 'view-reverse' };
const PREFIX = { generate: 'gen', reverse: 'rev' };
const COPY_BUTTON = { generate: 'btn-copy-gen', reverse: 'btn-copy-rev' };
const TEXT_FIELDS = {
  generate: ['gen-a', 'gen-b', 'gen-c', 'gen-custom'],
  reverse: ['rev-d', 'rev-b', 'rev-c', 'rev-custom']
};
const DEFAULT_CHECKED = ['lower', 'upper', 'digit'];   // FR-X2

const COPY_LABEL = 'Copy';
const COPIED_LABEL = 'Tersalin!';
const COPY_FAILED = 'Gagal menyalin, salin manual';
const COPIED_MS = 2000;                                // FR-C3

// Pesan error (PRD bagian 9). Parameter = err.detail dari logika inti.
const MESSAGES = {
  ERR_A_EMPTY: () => 'Teks (A) tidak boleh kosong.',
  ERR_A_TOO_LONG: n => 'Teks (A) terlalu panjang: ' + n + ' byte. Maksimal 99 byte.',
  ERR_A_UNICODE: () => 'Teks (A) mengandung karakter yang tidak valid.',
  ERR_B_INVALID: () => 'Panjang password (B) harus bilangan bulat, minimal 1.',
  ERR_B_TOO_BIG: () => 'Panjang password (B) maksimal 1024.',
  ERR_B_TOO_SMALL: min => 'Panjang password (B) terlalu pendek. Minimal ' + min + ' untuk teks dan karakter ini.',
  ERR_C_INVALID: () => 'Seed (C) harus angka bulat 0 atau lebih, maksimal 16 digit.',
  ERR_X_TOO_FEW: () => 'Pilih minimal 2 karakter yang berbeda.',
  ERR_X_BAD_CHAR: c => 'Karakter custom tidak didukung: "' + c + '". Gunakan karakter ASCII yang bisa dicetak, tanpa spasi.',
  ERR_D_EMPTY: () => 'Password (D) tidak boleh kosong.',
  ERR_D_LEN: (n, b) => 'Panjang password yang ditempel ' + n + ', tetapi B = ' + b + '. Samakan keduanya.',
  ERR_D_CHAR: c => 'Karakter "' + c + '" ada di password tetapi tidak ada di set karakter. ' +
    'Pilih set karakter yang sama dengan saat Generate.',
  ERR_MARKER: () => 'Angka panjang di awal dan akhir password tidak valid atau tidak sama. ' +
    'Periksa password dan set karakter.',
  ERR_DECODE: () => 'Gagal membaca password. Pastikan seed, panjang, dan karakter sama persis dengan saat Generate.',
  ERR_INTERNAL: () => 'Terjadi kesalahan internal. Ubah input atau muat ulang halaman.'
};

// Field yang diberi garis tepi merah untuk tiap kode error (PRD 8.4)
const ERROR_FIELDS = {
  generate: {
    ERR_A_EMPTY: ['gen-a'], ERR_A_TOO_LONG: ['gen-a'], ERR_A_UNICODE: ['gen-a'],
    ERR_B_INVALID: ['gen-b'], ERR_B_TOO_BIG: ['gen-b'], ERR_B_TOO_SMALL: ['gen-b'],
    ERR_C_INVALID: ['gen-c'],
    ERR_X_TOO_FEW: ['gen-custom'], ERR_X_BAD_CHAR: ['gen-custom']
  },
  reverse: {
    ERR_D_EMPTY: ['rev-d'], ERR_D_LEN: ['rev-d', 'rev-b'], ERR_D_CHAR: ['rev-d'], ERR_MARKER: ['rev-d'],
    ERR_B_INVALID: ['rev-b'], ERR_B_TOO_BIG: ['rev-b'],
    ERR_C_INVALID: ['rev-c'],
    ERR_X_TOO_FEW: ['rev-custom'], ERR_X_BAD_CHAR: ['rev-custom']
  }
};

const copyTimers = {};

function $(id) {
  return document.getElementById(id);
}

/* ---------- Tampilan ---------- */

// Tampilkan 'menu' | 'generate' | 'reverse'. Tampilan lain disembunyikan.
function showView(name, moveFocus) {
  for (const key of Object.keys(VIEW_IDS)) {
    $(VIEW_IDS[key]).hidden = key !== name;
  }
  if (moveFocus !== false) {
    const heading = $(VIEW_IDS[name]).querySelector('h1');
    if (heading) heading.focus({ preventScroll: true });   // untuk pembaca layar
    window.scrollTo(0, 0);
  }
}

/* ---------- Set karakter ---------- */

// prefix: 'gen' | 'rev'. Baca centang + custom -> X (bisa melempar ERR_X_BAD_CHAR)
function readCharset(prefix) {
  const keys = Array.from(
    document.querySelectorAll('#' + prefix + '-charset input[name="charset"]:checked')
  ).map(cb => cb.value);
  return normalizeCharset(keys, $(prefix + '-custom').value);
}

function tryCharset(prefix) {
  try { return readCharset(prefix); } catch (e) { return null; }
}

/* ---------- Petunjuk live ---------- */

// Perbarui "N byte", "Minimal: X", dan "Total karakter unik: M"
function updateHints() {
  const A = $('gen-a').value;
  $('gen-bytes').textContent = toBytes(A).length + ' byte';

  const xGen = tryCharset('gen');
  $('gen-count').textContent = 'Total karakter unik: ' + (xGen ? xGen.length : '-');
  const min = xGen ? minLength(A, xGen) : null;
  $('gen-min').textContent = 'Minimal: ' + (min === null ? '-' : min);

  const xRev = tryCharset('rev');
  $('rev-count').textContent = 'Total karakter unik: ' + (xRev ? xRev.length : '-');
}

/* ---------- Hasil dan error ---------- */

// Sembunyikan hasil, hapus teks hasil, pesan error, dan tanda field bermasalah
function clearFeedback(view) {
  const p = PREFIX[view];
  $(p + '-result').hidden = true;
  $(p + '-output').textContent = '';
  $(p + '-error').textContent = '';
  $(p + '-copy-msg').textContent = '';
  for (const id of TEXT_FIELDS[view]) {
    const el = $(id);
    el.classList.remove('invalid');
    el.removeAttribute('aria-invalid');
  }
  const btn = $(COPY_BUTTON[view]);
  clearTimeout(copyTimers[btn.id]);
  btn.textContent = COPY_LABEL;
}

function showResult(view, text) {
  const p = PREFIX[view];
  $(p + '-output').textContent = text;
  $(p + '-result').hidden = false;
  $(p + '-result').scrollIntoView({ block: 'nearest' });
}

function currentB(view) {
  const raw = $(PREFIX[view] + '-b').value;
  try { return String(parseB(raw)); } catch (e) { return raw.trim(); }
}

// Ubah kode error -> pesan (tabel Bagian 9). Hanya satu pesan yang tampil.
function showError(view, err) {
  const p = PREFIX[view];
  const code = err && MESSAGES[err.code] ? err.code : 'ERR_INTERNAL';
  const message = code === 'ERR_D_LEN'
    ? MESSAGES.ERR_D_LEN(err.detail, currentB(view))
    : MESSAGES[code](err ? err.detail : undefined);

  const box = $(p + '-error');
  box.textContent = message;                      // textContent: isi input tidak dijalankan sebagai HTML
  for (const id of ERROR_FIELDS[view][code] || []) {
    const el = $(id);
    el.classList.add('invalid');
    el.setAttribute('aria-invalid', 'true');
  }
  box.scrollIntoView({ block: 'nearest' });
}

/* ---------- Aksi ---------- */

function onGenerate() {
  clearFeedback('generate');
  try {
    const X = readCharset('gen');
    const D = generate($('gen-a').value, $('gen-b').value, $('gen-c').value, X);
    showResult('generate', D);
  } catch (err) {
    showError('generate', err);
  }
}

function onReverse() {
  clearFeedback('reverse');
  try {
    const X = readCharset('rev');
    const A = reverse($('rev-d').value, $('rev-b').value, $('rev-c').value, X);
    showResult('reverse', A);
  } catch (err) {
    showError('reverse', err);
  }
}

/* ---------- Copy (FR-C1 sampai FR-C5) ---------- */

function selectContents(el) {
  const sel = window.getSelection();
  const range = document.createRange();
  range.selectNodeContents(el);
  sel.removeAllRanges();
  sel.addRange(range);
}

// Cadangan: seleksi isi kotak hasil lalu document.execCommand('copy')
function legacyCopy(el) {
  let ok = false;
  try {
    selectContents(el);
    ok = document.execCommand('copy');
  } catch (e) {
    ok = false;
  }
  if (ok) window.getSelection().removeAllRanges();
  return ok;
}

function copyResult(view) {
  const p = PREFIX[view];
  const out = $(p + '-output');
  const btn = $(COPY_BUTTON[view]);
  const msg = $(p + '-copy-msg');
  const text = out.textContent;                   // isi persis, tanpa spasi/enter tambahan
  msg.textContent = '';

  const finish = ok => {
    if (ok) {
      btn.textContent = COPIED_LABEL;
      clearTimeout(copyTimers[btn.id]);
      copyTimers[btn.id] = setTimeout(() => { btn.textContent = COPY_LABEL; }, COPIED_MS);
    } else {
      selectContents(out);                        // teks tetap terseleksi untuk disalin manual
      msg.textContent = COPY_FAILED;
    }
  };

  const api = navigator.clipboard;
  if (api && typeof api.writeText === 'function') {
    let pending;
    try { pending = api.writeText(text); } catch (e) { pending = Promise.reject(e); }
    Promise.resolve(pending).then(() => finish(true), () => finish(legacyCopy(out)));
  } else {
    finish(legacyCopy(out));
  }
}

/* ---------- Reset (FR-03) ---------- */

// Kosongkan semua input dan hasil; pemilih karakter kembali ke default
function resetAll() {
  for (const view of Object.keys(PREFIX)) {
    for (const id of TEXT_FIELDS[view]) $(id).value = '';
    const boxes = document.querySelectorAll('#' + PREFIX[view] + '-charset input[name="charset"]');
    for (const cb of boxes) cb.checked = DEFAULT_CHECKED.includes(cb.value);
    clearFeedback(view);
  }
  window.getSelection().removeAllRanges();
  updateHints();
}

/* ---------- Inisialisasi ---------- */

function goBack() {
  resetAll();
  showView('menu');
}

function initUI() {
  $('btn-go-generate').addEventListener('click', () => showView('generate'));
  $('btn-go-reverse').addEventListener('click', () => showView('reverse'));
  $('btn-back-gen').addEventListener('click', goBack);
  $('btn-back-rev').addEventListener('click', goBack);
  $('btn-generate').addEventListener('click', onGenerate);
  $('btn-reverse').addEventListener('click', onReverse);
  $('btn-copy-gen').addEventListener('click', () => copyResult('generate'));
  $('btn-copy-rev').addEventListener('click', () => copyResult('reverse'));

  for (const view of Object.keys(PREFIX)) {
    const section = $(VIEW_IDS[view]);
    const action = view === 'generate' ? onGenerate : onReverse;

    // FR-04: input diubah setelah hasil muncul -> hasil disembunyikan
    const onEdit = () => { clearFeedback(view); updateHints(); };
    section.addEventListener('input', onEdit);
    section.addEventListener('change', onEdit);

    // FR-05: Enter di field mana pun = klik tombol aksi
    section.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.isComposing && e.target.tagName === 'INPUT') {
        e.preventDefault();
        action();
      }
    });
  }

  // Kembali lewat riwayat browser (bfcache): jangan tampilkan data lama
  window.addEventListener('pageshow', e => {
    if (e.persisted) { resetAll(); showView('menu', false); }
  });

  resetAll();
  showView('menu', false);                        // FR-02: saat dibuka yang tampil adalah Menu
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initUI);
  else initUI();
}

// Hanya untuk pengujian di Node; diabaikan di browser.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SETS, normalizeCharset, minLength, generate, reverse };
}
