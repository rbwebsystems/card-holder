'use strict';

/* =========================================================
   Card Holder — şəxsi, şifrəli kart və sənəd saxlayıcısı.
   Bütün məlumat yalnız bu cihazda (IndexedDB) saxlanılır və
   AES-GCM 256 ilə şifrələnir. Açar ana şifrədən PBKDF2 ilə alınır.
   ========================================================= */

const APP_VERSION = '5';
const $ = (s, r = document) => r.querySelector(s);
const app = $('#app');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const uid = () => (crypto.randomUUID ? crypto.randomUUID() : [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, '0')).join(''));

/* ---------------- IndexedDB ---------------- */
let db;
function openDB() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('card-holder', 1);
    r.onupgradeneeded = () => {
      r.result.createObjectStore('meta');
      r.result.createObjectStore('items', { keyPath: 'id' });
    };
    r.onsuccess = () => { db = r.result; res(); };
    r.onerror = () => rej(r.error);
  });
}
const req = (r) => new Promise((res, rej) => { r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
const store = (name, mode = 'readonly') => db.transaction(name, mode).objectStore(name);
const getMeta = (k) => req(store('meta').get(k));
const setMeta = (k, v) => req(store('meta', 'readwrite').put(v, k));
const allRecs = () => req(store('items').getAll());
const putRec = (r) => req(store('items', 'readwrite').put(r));
const delRec = (id) => req(store('items', 'readwrite').delete(id));
function writeAll(recs, meta) {
  return new Promise((res, rej) => {
    const t = db.transaction(['items', 'meta'], 'readwrite');
    const s = t.objectStore('items');
    s.clear();
    recs.forEach((r) => s.put(r));
    if (meta) Object.entries(meta).forEach(([k, v]) => t.objectStore('meta').put(v, k));
    t.oncomplete = res;
    t.onerror = () => rej(t.error);
  });
}

/* ---------------- Kriptoqrafiya ---------------- */
const te = new TextEncoder();
const td = new TextDecoder();
const ITER = 600000;

async function deriveKey(pw, salt, iter) {
  const base = await crypto.subtle.importKey('raw', te.encode(pw.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
async function seal(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(obj))));
  return { iv, ct };
}
async function unseal(key, { iv, ct }) {
  return JSON.parse(td.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct)));
}
async function checkKey(key, check) {
  try { return (await unseal(key, check)).ok === 'card-holder'; } catch { return false; }
}
function b64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const boxOut = (b) => ({ iv: b64(new Uint8Array(b.iv)), ct: b64(new Uint8Array(b.ct)) });
const boxIn = (b) => ({ iv: unb64(b.iv), ct: unb64(b.ct) });

/* ---------------- Vəziyyət ---------------- */
const S = {
  vault: null, key: null, items: [],
  view: 'list', id: null, filter: 'all', q: '',
  draft: null, revealed: new Set(), picking: false,
  settings: { lockAfter: 120, lockOnHide: true }
};

/* ---------------- İkonlar ---------------- */
const svg = (p) => `<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${p}</svg>`;
const I = {
  back: svg('<path d="M15 18l-6-6 6-6"/>'),
  plus: svg('<path d="M12 5v14M5 12h14"/>'),
  lock: svg('<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>'),
  gear: svg('<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>'),
  eye: svg('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12z"/><circle cx="12" cy="12" r="3"/>'),
  eyeOff: svg('<path d="M17.9 17.9A10.4 10.4 0 0 1 12 20C5 20 1 12 1 12a18.5 18.5 0 0 1 5.1-5.9M9.9 4.2A9.1 9.1 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.2 3.2M14.1 14.1a3 3 0 1 1-4.2-4.2M1 1l22 22"/>'),
  copy: svg('<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>'),
  edit: svg('<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>'),
  trash: svg('<path d="M3 6h18M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>'),
  camera: svg('<path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/>'),
  search: svg('<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>'),
  x: svg('<path d="M18 6L6 18M6 6l12 12"/>'),
  card: svg('<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M2 10h20"/>'),
  doc: svg('<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="11" r="2.5"/><path d="M5.5 17c.6-1.8 2-2.6 3.5-2.6s2.9.8 3.5 2.6M15 9h3M15 13h3"/>'),
  note: svg('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h5"/>'),
  download: svg('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>'),
  upload: svg('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/>'),
  key: svg('<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3L21 2M16 7l3 3M19 4l2 2"/>'),
  alert: svg('<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01"/>'),
  shield: svg('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'),
  flip: svg('<path d="M3 12a9 9 0 0 1 15.5-6.2L21 8M21 3v5h-5M21 12a9 9 0 0 1-15.5 6.2L3 16M3 21v-5h5"/>'),
  more: svg('<circle cx="5" cy="12" r="1.3"/><circle cx="12" cy="12" r="1.3"/><circle cx="19" cy="12" r="1.3"/>'),
  user: '<svg viewBox="0 0 40 48" class="sil" aria-hidden="true"><circle cx="20" cy="17" r="9" fill="currentColor"/><path d="M3 48c1-11 8-17 17-17s16 6 17 17z" fill="currentColor"/></svg>',
  nfc: '<svg viewBox="0 0 24 24" class="nfc" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M7 9.5A3.5 3.5 0 0 1 7 14.5M10.5 7A7 7 0 0 1 10.5 17M14 4.5A10.5 10.5 0 0 1 14 19.5"/></svg>'
};

/* ---------------- Real kart görünüşü ---------------- */
const CHIP = `<svg viewBox="0 0 50 38" class="emv" aria-hidden="true"><defs><linearGradient id="emvg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#f7e7a1"/><stop offset=".45" stop-color="#d4af47"/><stop offset=".7" stop-color="#b8922e"/><stop offset="1" stop-color="#f1d98a"/></linearGradient></defs><rect x="1" y="1" width="48" height="36" rx="7" fill="url(#emvg)" stroke="#9c7a22" stroke-width=".8"/><path d="M1 13h14M1 25h14M35 13h14M35 25h14M15 1v11a3 3 0 0 0 3 3h14a3 3 0 0 0 3-3V1M15 37V26a3 3 0 0 1 3-3h14a3 3 0 0 1 3 3v11M18 15v8M32 15v8" stroke="#8a6a1c" stroke-width="1" fill="none" opacity=".75"/></svg>`;
const circles = (a, b, mid) => `<svg viewBox="0 0 52 32" class="logo circles" aria-hidden="true"><circle cx="16" cy="16" r="16" fill="${a}"/><circle cx="36" cy="16" r="16" fill="${b}"/><path d="M26 3.51A16 16 0 0 1 26 28.49A16 16 0 0 1 26 3.51Z" fill="${mid}"/></svg>`;
const wordmark = (t, size = 26, w = 80) => `<svg viewBox="0 0 ${w} 28" class="logo word" aria-hidden="true"><text x="${w}" y="23" text-anchor="end" font-family="Arial Black, Helvetica, Arial, sans-serif" font-weight="900" font-style="italic" font-size="${size}" fill="currentColor" letter-spacing="1">${t}</text></svg>`;
const LOGO = {
  VISA: wordmark('VISA'),
  Mastercard: circles('#eb001b', '#f79e1b', '#ff5f00'),
  Maestro: circles('#e7001b', '#00a2e5', '#7375cf'),
  AMEX: '<svg viewBox="0 0 64 28" class="logo" aria-hidden="true"><rect width="64" height="28" rx="4" fill="#2e77bc"/><text x="32" y="19.5" text-anchor="middle" font-family="Arial Black, Arial, sans-serif" font-weight="900" font-size="14" fill="#fff" letter-spacing="1">AMEX</text></svg>',
  'МИР': wordmark('МИР', 24, 66),
  UnionPay: wordmark('UnionPay', 18, 96)
};
function cardFace(it, reveal = false) {
  const f = it.fields || {};
  const n = digits(f.number);
  const show = reveal || S.revealed.has(it.id + ':number');
  const num = n ? (show ? groupCard(n) : '•••• •••• •••• ' + n.slice(-4)) : '•••• •••• •••• ••••';
  const sub = it.title && f.bank ? `<small>${esc(it.title)}</small>` : '';
  const sk = skin(it);
  return `<div class="cf front ${sk.cls}"${sk.style}>
    <div class="cf-top"><span class="cf-bank">${esc(f.bank || it.title || 'Bank kartı')}${sub}</span>${I.nfc}</div>
    <div class="cf-chip">${CHIP}</div>
    <div class="cf-num">${esc(num)}</div>
    <div class="cf-bot">
      <div class="cf-meta">
        <span class="cf-valid"><small>VALID<br>THRU</small><b>${esc(f.expiry || '••/••')}</b></span>
        <span class="cf-holder">${esc(f.holder || '')}</span>
      </div>
      ${LOGO[brand(n)] || ''}
    </div>
  </div>`;
}
function cardBack(it) {
  const f = it.fields || {};
  const cvv = f.cvv ? (S.revealed.has(it.id + ':cvv') ? f.cvv : '•'.repeat(f.cvv.length)) : '';
  const sk = skin(it);
  return `<div class="cf back ${sk.cls}"${sk.style}>
    <div class="cf-stripe"></div>
    <div class="cf-sigrow"><div class="cf-sig"><span>${esc(f.holder || '')}</span></div><div class="cf-cvv">${esc(cvv)}</div></div>
    <p class="cf-fine">${esc(f.bank || '')}${f.iban ? ` · ${esc(f.iban)}` : ''}<br>Bu kart sahibinə məxsusdur. Tapılarsa, banka qaytarın.</p>
    <div class="cf-backlogo">${LOGO[brand(f.number)] || ''}</div>
  </div>`;
}
const DOC_STYLE = { 'Şəxsiyyət vəsiqəsi': 'id', 'Pasport': 'passport', 'Sürücülük vəsiqəsi': 'dl', 'Tibbi sığorta': 'med', 'Avtomobil qeydiyyatı': 'car' };
function docFace(it, reveal = false) {
  const f = it.fields || {};
  const st = DOC_STYLE[f.docType] || 'paper';
  const show = reveal || S.revealed.has(it.id + ':number');
  const num = f.number ? (show ? f.number : mask({ secret: 'partial' }, f.number)) : '';
  const cell = (l, v, cls = '') => (v ? `<div class="df-cell ${cls}"><small>${esc(l)}</small><b>${esc(v)}</b></div>` : '');
  const photo = safeImg(it.photo);
  return `<div class="df d-${st}">
    <div class="df-head"><span>${esc((f.docType || 'Sənəd').toLocaleUpperCase('az'))}</span><span class="df-title">${esc(it.title || '')}</span></div>
    <div class="df-body">
      <div class="df-photo">${photo ? `<img src="${esc(photo)}" alt="">` : I.user}</div>
      <div class="df-fields">
        ${cell('Ad, soyad', f.fullName, 'wide')}
        ${cell('Sənəd nömrəsi', num, 'mono')}
        ${cell('Doğum tarixi', fmtDate(f.birthDate))}
        ${cell('Verilib', fmtDate(f.issueDate))}
        ${cell('Etibarlıdır', fmtDate(f.expiryDate))}
      </div>
    </div>
    <div class="df-sign">${esc(f.fullName || '')}</div>
  </div>`;
}
const buzz = () => navigator.vibrate?.(8);

/* ---------------- Element növləri ---------------- */
const TYPES = {
  card: {
    label: 'Bank kartı', plural: 'Kartlar', icon: I.card,
    fields: [
      { k: 'bank', l: 'Bank', ph: 'Məs: Kapital Bank' },
      { k: 'holder', l: 'Kart sahibi', ph: 'AD SOYAD', upper: true },
      { k: 'number', l: 'Kart nömrəsi', ph: '0000 0000 0000 0000', im: 'numeric', secret: 'last4', fmt: 'card' },
      { k: 'expiry', l: 'Bitmə tarixi', ph: 'AA/İİ', im: 'numeric', fmt: 'exp' },
      { k: 'cvv', l: 'CVV / CVC', im: 'numeric', secret: true, max: 4, fmt: 'digits' },
      { k: 'pin', l: 'PIN', im: 'numeric', secret: true, max: 8, fmt: 'digits' },
      { k: 'iban', l: 'IBAN / hesab nömrəsi', upper: true },
      { k: 'note', l: 'Qeyd', area: true }
    ]
  },
  doc: {
    label: 'Sənəd', plural: 'Sənədlər', icon: I.doc,
    fields: [
      { k: 'docType', l: 'Sənəd növü', select: ['Şəxsiyyət vəsiqəsi', 'Pasport', 'Sürücülük vəsiqəsi', 'Tibbi sığorta', 'Doğum şəhadətnaməsi', 'Diplom', 'Avtomobil qeydiyyatı', 'Digər'] },
      { k: 'fullName', l: 'Ad, soyad' },
      { k: 'number', l: 'Sənəd nömrəsi', secret: 'partial', upper: true },
      { k: 'fin', l: 'FİN kod', secret: true, upper: true, max: 7 },
      { k: 'birthDate', l: 'Doğum tarixi', date: true },
      { k: 'issueDate', l: 'Verilmə tarixi', date: true },
      { k: 'expiryDate', l: 'Etibarlılıq müddəti', date: true },
      { k: 'issuedBy', l: 'Verən orqan' },
      { k: 'note', l: 'Qeyd', area: true }
    ]
  },
  note: {
    label: 'Qeyd', plural: 'Qeydlər', icon: I.note,
    fields: [
      { k: 'login', l: 'İstifadəçi adı / hesab' },
      { k: 'secret', l: 'Gizli məlumat (şifrə, kod)', secret: true },
      { k: 'note', l: 'Mətn', area: true }
    ]
  }
};
// Real kartlara bənzəyən hazır rənglər. finish: parlaq (gloss), mat (matte), metal; ink: açıq kartda tünd yazı.
const PRESETS = {
  classic: { l: 'Klassik mavi' }, red: { l: 'Qırmızı' }, green: { l: 'Yaşıl' }, orange: { l: 'Narıncı' },
  purple: { l: 'Tünd bənövşəyi' }, indigo: { l: 'İndiqo' }, violet: { l: 'Bənövşəyi' }, rose: { l: 'Çəhrayı' },
  emerald: { l: 'Zümrüd' }, sky: { l: 'Səma' }, amber: { l: 'Kəhrəba' }, slate: { l: 'Boz' }, black: { l: 'Qara' },
  gold: { l: 'Gold', finish: 'metal' }, platinum: { l: 'Platinum', finish: 'metal', ink: 1 },
  silver: { l: 'Gümüşü', finish: 'metal', ink: 1 }, blackmetal: { l: 'Black metal', finish: 'metal' },
  pearl: { l: 'İnci ağ', ink: 1 }
};
const FINISHES = [['gloss', 'Parlaq'], ['matte', 'Mat'], ['metal', 'Metal']];
const hex = (v, d) => (/^#[0-9a-f]{6}$/i.test(v || '') ? v : d);
const lum = (h) => { const n = parseInt(h.slice(1), 16); return (0.299 * (n >> 16) + 0.587 * ((n >> 8) & 255) + 0.114 * (n & 255)) / 255; };
const toHex = (...c) => '#' + c.map((x) => Math.round(x).toString(16).padStart(2, '0')).join('');
// Kartın görünüşü: rəng sinfi, əhatə, yazı rəngi və xüsusi rənglər
function skin(it) {
  const c = it.color === 'custom' || PRESETS[it.color] ? it.color : 'indigo';
  const fin = FINISHES.some(([v]) => v === it.finish) ? it.finish : PRESETS[c]?.finish || 'gloss';
  let ink = !!PRESETS[c]?.ink;
  let style = '';
  if (c === 'custom') {
    const c1 = hex(it.c1, '#5b5ff0');
    const c2 = hex(it.c2, c1);
    style = ` style="--c1:${c1};--c2:${c2}"`;
    ink = (lum(c1) + lum(c2)) / 2 > 0.62;
  }
  return { cls: `c-${c} f-${fin}${ink ? ' ink-dark' : ''}`, style };
}
// Kartın şəklindən iki əsas rəngi götür (sol-yuxarı və sağ-aşağı hissə, median ilə — yazılar təsir etməsin)
async function colorsFromImage(src) {
  const img = new Image();
  img.src = src;
  await img.decode();
  const W = 60, H = 38;
  const c = document.createElement('canvas');
  c.width = W; c.height = H;
  const g = c.getContext('2d', { willReadFrequently: true });
  const w = img.naturalWidth, h = img.naturalHeight;
  g.drawImage(img, w * 0.12, h * 0.12, w * 0.76, h * 0.76, 0, 0, W, H);
  const d = g.getImageData(0, 0, W, H).data;
  const median = (x0, y0, x1, y1) => {
    const ch = [[], [], []];
    for (let y = y0; y < y1; y++) for (let x = x0; x < x1; x++) {
      const i = (y * W + x) * 4;
      ch[0].push(d[i]); ch[1].push(d[i + 1]); ch[2].push(d[i + 2]);
    }
    return toHex(...ch.map((a) => a.sort((p, q) => p - q)[a.length >> 1]));
  };
  return [median(0, 0, W * 0.45, H * 0.5), median(W * 0.55, H * 0.5, W, H)];
}

/* ---------------- Köməkçilər ---------------- */
const digits = (s) => String(s || '').replace(/\D/g, '');
function brand(num) {
  const n = digits(num);
  if (/^4/.test(n)) return 'VISA';
  if (/^(5[1-5]|2[2-7])/.test(n)) return 'Mastercard';
  if (/^3[47]/.test(n)) return 'AMEX';
  if (/^220[0-4]/.test(n)) return 'МИР';
  if (/^(50|5[6-9]|6[0-9])/.test(n)) return 'Maestro';
  if (/^62/.test(n)) return 'UnionPay';
  return '';
}
function luhn(num) {
  const n = digits(num);
  if (n.length < 12) return false;
  let sum = 0;
  for (let i = 0; i < n.length; i++) {
    let d = +n[n.length - 1 - i];
    if (i % 2) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
  }
  return sum % 10 === 0;
}
const groupCard = (n) => digits(n).replace(/(.{4})/g, '$1 ').trim();
function mask(f, v) {
  if (f.secret === 'last4') { const d = digits(v); return '•••• •••• •••• ' + d.slice(-4); }
  if (f.secret === 'partial') return '•'.repeat(Math.max(3, v.length - 3)) + v.slice(-3);
  return '•'.repeat(Math.min(8, Math.max(4, v.length)));
}
const fmtDate = (v) => { const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v || ''); return m ? `${m[3]}.${m[2]}.${m[1]}` : v; };
function expiryOf(item) {
  if (item.type === 'card') {
    const m = /^(\d{2})\/(\d{2})$/.exec(item.fields.expiry || '');
    return m ? new Date(2000 + +m[2], +m[1], 0, 23, 59) : null;
  }
  if (item.type === 'doc' && item.fields.expiryDate) return new Date(item.fields.expiryDate + 'T23:59');
  return null;
}
function expiryBadge(item) {
  const d = expiryOf(item);
  if (!d || isNaN(d)) return '';
  const days = Math.ceil((d - Date.now()) / 86400000);
  if (days < 0) return '<span class="badge red">Müddəti bitib</span>';
  if (days <= 60) return `<span class="badge amber">${days} gün qalıb</span>`;
  return '';
}
function titleOf(it) {
  if (it.title) return it.title;
  const f = it.fields;
  if (it.type === 'card') return [f.bank, digits(f.number).slice(-4)].filter(Boolean).join(' ·· ') || 'Bank kartı';
  if (it.type === 'doc') return f.docType || 'Sənəd';
  return 'Qeyd';
}
function subOf(it) {
  const f = it.fields;
  if (it.type === 'doc') return [it.title ? f.docType : '', f.fullName].filter(Boolean).join(' · ');
  if (it.type === 'note') return f.login || (f.note || '').slice(0, 60);
  return '';
}
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast.t);
  toast.t = setTimeout(() => { t.hidden = true; }, 1800);
}
async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('Kopyalandı — 45 saniyəyə buferdən silinəcək');
    clearTimeout(copy.t);
    copy.t = setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 45000);
  } catch { toast('Kopyalamaq alınmadı'); }
}
async function compressImage(file, portrait = false) {
  const url = URL.createObjectURL(file);
  try {
    const img = await new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = rej; i.src = url; });
    const w = img.naturalWidth, h = img.naturalHeight;
    const c = document.createElement('canvas');
    if (portrait) {
      // 3:4 nisbətində mərkəzdən kəs (vəsiqə şəkli kimi)
      const r = 0.75;
      const cw = w / h > r ? h * r : w;
      const ch = w / h > r ? h : w / r;
      c.width = 360; c.height = 480;
      c.getContext('2d').drawImage(img, (w - cw) / 2, (h - ch) / 2, cw, ch, 0, 0, 360, 480);
      return c.toDataURL('image/jpeg', 0.85);
    }
    const sc = Math.min(1, 1800 / Math.max(w, h));
    c.width = Math.round(w * sc);
    c.height = Math.round(h * sc);
    c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
    return c.toDataURL('image/jpeg', 0.85);
  } finally { URL.revokeObjectURL(url); }
}
const safeImg = (src) => (typeof src === 'string' && /^data:image\/(jpeg|png|webp|gif);base64,/.test(src) ? src : '');

/* ---------------- Dialoqlar ---------------- */
function modal({ title, text = '', fields = [], ok = 'Təsdiq', cancel = 'Ləğv et', danger = false, validate }) {
  return new Promise((resolve) => {
    const wrap = document.createElement('div');
    wrap.className = 'modal-wrap';
    wrap.innerHTML = `<form class="modal" novalidate>
      <h3>${esc(title)}</h3>${text ? `<p class="muted">${esc(text)}</p>` : ''}
      ${fields.map((f) => `<label class="fld"><span>${esc(f.label)}</span><input name="${esc(f.name)}" type="${f.type || 'text'}" autocomplete="off" ${f.placeholder ? `placeholder="${esc(f.placeholder)}"` : ''}></label>`).join('')}
      <p class="err" hidden></p>
      <div class="modal-acts">${cancel ? `<button type="button" class="btn ghost" data-x>${esc(cancel)}</button>` : ''}<button class="btn ${danger ? 'danger' : 'primary'}">${esc(ok)}</button></div>
    </form>`;
    document.body.append(wrap);
    const form = $('form', wrap);
    const err = $('.err', wrap);
    const close = (v) => { wrap.remove(); resolve(v); };
    $('[data-x]', wrap)?.addEventListener('click', () => close(null));
    wrap.addEventListener('click', (e) => { if (e.target === wrap) close(null); });
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const out = {};
      fields.forEach((f) => { out[f.name] = form.elements[f.name].value; });
      if (validate) {
        const btn = $('.btn:last-child', form);
        btn.disabled = true;
        const msg = await validate(out);
        btn.disabled = false;
        if (msg) { err.textContent = msg; err.hidden = false; return; }
      }
      close(fields.length ? out : true);
    });
    setTimeout(() => $('input', wrap)?.focus(), 50);
  });
}
function sheet(title, options) {
  return new Promise((resolve) => {
    const wrap = document.createElement('div');
    wrap.className = 'modal-wrap';
    wrap.innerHTML = `<div class="modal sheet"><h3>${esc(title)}</h3>
      ${options.map((o) => `<button class="sheet-opt" data-v="${esc(o.v)}"><span class="ico">${o.icon}</span><span><b>${esc(o.label)}</b><small>${esc(o.hint || '')}</small></span></button>`).join('')}
      <button class="btn ghost block" data-x>Ləğv et</button></div>`;
    document.body.append(wrap);
    wrap.addEventListener('click', (e) => {
      const o = e.target.closest('[data-v]');
      if (o) { wrap.remove(); resolve(o.dataset.v); }
      else if (e.target === wrap || e.target.closest('[data-x]')) { wrap.remove(); resolve(null); }
    });
  });
}

/* ---------------- Naviqasiya ---------------- */
function animateIn(back = false) {
  const p = $('.page', app);
  if (!p) return;
  p.classList.remove('enter', 'enter-back');
  void p.offsetWidth;
  p.classList.add(back ? 'enter-back' : 'enter');
}
function go(view, id = null) {
  S.view = view; S.id = id; S.flipped = false;
  history.pushState({ view, id }, '');
  render();
  window.scrollTo(0, 0);
  animateIn();
}
window.addEventListener('popstate', (e) => {
  if (!S.key) return;
  const st = e.state || { view: 'list' };
  S.view = st.view; S.id = st.id; S.flipped = false;
  render();
  animateIn(true);
});

/* ---------------- Kilid ---------------- */
let lastActive = Date.now();
let hiddenAt = null;
['pointerdown', 'keydown', 'scroll'].forEach((ev) => document.addEventListener(ev, () => { lastActive = Date.now(); }, { passive: true }));
setInterval(() => {
  if (S.key && Date.now() - lastActive > S.settings.lockAfter * 1000) lock();
}, 5000);
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    hiddenAt = Date.now();
    if (S.key && S.settings.lockOnHide && !S.picking) lock();
  } else {
    if (S.key && hiddenAt && Date.now() - hiddenAt > S.settings.lockAfter * 1000) lock();
    hiddenAt = null;
    S.picking = false;
    lastActive = Date.now();
  }
});
function lock() {
  if (S.pendingReload) { S.key = null; S.items = []; S.reloading = true; location.reload(); return; }
  S.key = null; S.items = []; S.draft = null; S.revealed.clear(); S.q = '';
  document.querySelectorAll('.modal-wrap, .viewer').forEach((m) => m.remove());
  history.replaceState({ view: 'list' }, '');
  S.view = 'list'; S.id = null;
  render();
}

/* ---------------- Məlumat əməliyyatları ---------------- */
async function loadItems() {
  S.items = [];
  for (const r of await allRecs()) {
    try { S.items.push(await unseal(S.key, r)); } catch { console.warn('Açılmadı:', r.id); }
  }
}
async function saveItem(item) {
  await putRec({ id: item.id, ...(await seal(S.key, item)) });
  const i = S.items.findIndex((x) => x.id === item.id);
  if (i >= 0) S.items[i] = item; else S.items.push(item);
}
async function createVault(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(pw, salt, ITER);
  const vault = { salt, iter: ITER, check: await seal(key, { ok: 'card-holder' }) };
  await setMeta('vault', vault);
  S.vault = vault; S.key = key; S.items = [];
  navigator.storage?.persist?.();
}

/* ---------------- Ehtiyat nüsxə ---------------- */
async function exportBackup() {
  const recs = await allRecs();
  const v = S.vault;
  const data = {
    app: 'card-holder', v: 1, created: new Date().toISOString(),
    salt: b64(v.salt), iter: v.iter, check: boxOut(v.check),
    items: recs.map((r) => ({ id: r.id, ...boxOut(r) }))
  };
  const name = `card-holder-${new Date().toISOString().slice(0, 10)}.json`;
  const blob = new Blob([JSON.stringify(data)], { type: 'application/json' });
  const file = new File([blob], name, { type: 'application/json' });
  if (navigator.canShare?.({ files: [file] }) && matchMedia('(pointer: coarse)').matches) {
    try { S.picking = true; await navigator.share({ files: [file], title: 'Card Holder ehtiyat nüsxəsi' }); return; }
    catch (e) { if (e.name === 'AbortError') return; }
  }
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
  toast('Ehtiyat nüsxə yükləndi');
}
function parseBackup(text) {
  const d = JSON.parse(text);
  if (d.app !== 'card-holder' || !d.salt || !d.check || !Array.isArray(d.items)) throw new Error('format');
  return { salt: unb64(d.salt), iter: d.iter || ITER, check: boxIn(d.check), items: d.items.map((r) => ({ id: String(r.id), ...boxIn(r) })) };
}
function pickFile(accept) {
  return new Promise((resolve) => {
    const inp = document.createElement('input');
    inp.type = 'file'; inp.accept = accept;
    inp.onchange = () => resolve(inp.files[0] || null);
    S.picking = true;
    inp.click();
  });
}
async function readBackupFile() {
  const f = await pickFile('application/json,.json');
  if (!f) return null;
  try { return parseBackup(await f.text()); } catch { toast('Bu fayl Card Holder ehtiyat nüsxəsi deyil'); return null; }
}
async function restoreFresh() {
  const bk = await readBackupFile();
  if (!bk) return;
  let key;
  const ok = await modal({
    title: 'Ehtiyat nüsxəni bərpa et', text: 'Nüsxə yaradılarkən istifadə etdiyiniz ana şifrəni daxil edin.',
    fields: [{ name: 'pw', label: 'Ana şifrə', type: 'password' }], ok: 'Bərpa et',
    validate: async ({ pw }) => {
      key = await deriveKey(pw, bk.salt, bk.iter);
      return (await checkKey(key, bk.check)) ? '' : 'Şifrə yanlışdır';
    }
  });
  if (!ok) return;
  const vault = { salt: bk.salt, iter: bk.iter, check: bk.check };
  await writeAll(bk.items, { vault });
  S.vault = vault; S.key = key;
  await loadItems();
  navigator.storage?.persist?.();
  history.replaceState({ view: 'list' }, '');
  render();
  toast(`${S.items.length} element bərpa edildi`);
}
async function importMerge() {
  const bk = await readBackupFile();
  if (!bk) return;
  let key = (await checkKey(S.key, bk.check)) ? S.key : null;
  if (!key) {
    const ok = await modal({
      title: 'Nüsxənin şifrəsi', text: 'Bu nüsxə başqa şifrə ilə yaradılıb. Həmin şifrəni daxil edin.',
      fields: [{ name: 'pw', label: 'Nüsxənin ana şifrəsi', type: 'password' }], ok: 'Davam et',
      validate: async ({ pw }) => {
        const k = await deriveKey(pw, bk.salt, bk.iter);
        if (!(await checkKey(k, bk.check))) return 'Şifrə yanlışdır';
        key = k; return '';
      }
    });
    if (!ok) return;
  }
  let added = 0, updated = 0;
  for (const r of bk.items) {
    let it;
    try { it = await unseal(key, r); } catch { continue; }
    const cur = S.items.find((x) => x.id === it.id);
    if (!cur) added++;
    else if ((it.updatedAt || 0) > (cur.updatedAt || 0)) updated++;
    else continue;
    await saveItem(it);
  }
  render();
  toast(`${added} yeni, ${updated} yenilənmiş element`);
}

/* ---------------- Ekranlar ---------------- */
function topbar(title, left = '', right = '') {
  return `<header class="topbar"><div class="tb-side">${left}</div><h1>${esc(title)}</h1><div class="tb-side right">${right}</div></header>`;
}
const iconBtn = (act, icon, label, extra = '') => `<button class="icon-btn" data-act="${act}" aria-label="${esc(label)}" title="${esc(label)}" ${extra}>${icon}</button>`;

function renderSetup() {
  app.innerHTML = `<section class="auth">
    <img class="auth-logo" src="icons/icon-192.png" alt="">
    <h1>Kartlarım</h1>
    <p class="muted">Kart və sənəd məlumatlarınız yalnız bu telefonda, şifrəli saxlanılır. Başlamaq üçün ana şifrə yaradın.</p>
    <form id="f-setup" class="form" autocomplete="off">
      <label class="fld"><span>Ana şifrə (ən azı 8 simvol)</span><input name="pw" type="password" autocomplete="new-password" required></label>
      <label class="fld"><span>Şifrəni təkrarlayın</span><input name="pw2" type="password" autocomplete="new-password" required></label>
      <div class="warn">${I.alert}<span>Bu şifrəni unutsanız məlumatı bərpa etmək <b>mümkün deyil</b>. Heç bir server yoxdur.</span></div>
      <p class="err" hidden></p>
      <button class="btn primary block">Yarat</button>
    </form>
    <button class="btn ghost block" data-act="restoreFresh">${I.upload} Ehtiyat nüsxədən bərpa et</button>
  </section>`;
}

function renderLock() {
  app.innerHTML = `<section class="auth">
    <img class="auth-logo" src="icons/icon-192.png" alt="">
    <h1>Kilidlənib</h1>
    <form id="f-unlock" class="form" autocomplete="off">
      <label class="fld"><span>Ana şifrə</span><input name="pw" type="password" autocomplete="current-password" required></label>
      <p class="err" hidden></p>
      <button class="btn primary block">Aç</button>
    </form>
  </section>`;
  setTimeout(() => $('#f-unlock input')?.focus(), 50);
}

function listItemHTML(it) {
  const exp = expiryOf(it);
  const meta = expiryBadge(it) || (exp && !isNaN(exp) ? `<span class="ri-meta">${exp.getFullYear()}</span>` : '');
  return `<button class="row-item" data-act="open" data-id="${esc(it.id)}">
    <span class="ri-ico t-${it.type}">${TYPES[it.type].icon}</span>
    <span class="ri-main"><b>${esc(titleOf(it))}</b><small>${esc(subOf(it))}</small></span>
    ${meta}
  </button>`;
}
function daysLeft(it) {
  const d = expiryOf(it);
  return d && !isNaN(d) ? Math.ceil((d - Date.now()) / 86400000) : null;
}
const AZ_MONTHS = ['yanvar', 'fevral', 'mart', 'aprel', 'may', 'iyun', 'iyul', 'avqust', 'sentyabr', 'oktyabr', 'noyabr', 'dekabr'];
const azDate = (d, withYear = false) => `${d.getDate()} ${AZ_MONTHS[d.getMonth()]}${withYear ? ' ' + d.getFullYear() : ''}`;
const azDateTime = (d) => `${azDate(d, true)}, ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
function statusLine() {
  const date = azDate(new Date());
  const soon = S.items.filter((i) => { const n = daysLeft(i); return n !== null && n <= 60; })
    .sort((a, b) => daysLeft(a) - daysLeft(b));
  let st = '<span class="st-ok">hər şey qaydasındadır</span>';
  if (soon.length === 1) {
    const n = daysLeft(soon[0]);
    st = `<span class="st-warn">${esc(titleOf(soon[0]))} — ${n < 0 ? 'müddəti bitib' : n + ' gün qalıb'}</span>`;
  } else if (soon.length > 1) st = `<span class="st-warn">${soon.length} elementin müddəti bitir</span>`;
  return `${esc(date)} · ${st}`;
}
const cardSlides = () => [...document.querySelectorAll('#carousel .slide')];
const currentCard = () => S.items.find((i) => i.id === cardSlides()[S.slide]?.dataset.id);
function slideInner(c) {
  return `<div class="face-box flip" data-act="open" data-id="${esc(c.id)}" role="button" aria-label="${esc(titleOf(c))}"><div class="flip-in">${cardFace(c)}${cardBack(c)}</div></div>`;
}
const qaBtn = (act, icon, label) => `<button class="qa-btn" data-act="${act}"><span class="qa-ic">${icon}</span><span>${esc(label)}</span></button>`;
function updateCardPanel() {
  const c = currentCard();
  const qa = $('#qa'), info = $('#card-info');
  if (!c || !qa) return;
  const shown = S.revealed.has(c.id + ':number');
  qa.innerHTML = qaBtn('qaCopy', I.copy, 'Kopyala') + qaBtn('qaShow', shown ? I.eyeOff : I.eye, shown ? 'Gizlət' : 'Göstər')
    + qaBtn('qaFlip', I.flip, 'Çevir') + qaBtn('qaMore', I.more, 'Ətraflı');
  const f = c.fields;
  const row = (l, v) => (v ? `<div class="info-row"><span>${esc(l)}</span><b>${v}</b></div>` : '');
  info.innerHTML = `<div class="panel">${row('Bank', esc(f.bank))}${row('Kart sahibi', esc(f.holder))}${row('Bitmə tarixi', (expiryBadge(c) ? expiryBadge(c) + ' ' : '') + esc(f.expiry || ''))}</div>`;
  info.hidden = !(f.bank || f.holder || f.expiry);
  document.querySelectorAll('.dots span').forEach((d, i) => d.classList.toggle('on', i === S.slide));
}
function afterList() {
  const car = $('#carousel');
  if (!car) return;
  const slides = cardSlides();
  const step = () => (slides[1] ? slides[1].offsetLeft - slides[0].offsetLeft : slides[0].offsetWidth) || 1;
  S.slide = Math.min(S.slide || 0, slides.length - 1);
  car.scrollLeft = S.slide * step();
  updateCardPanel();
  car.addEventListener('scroll', () => {
    const i = Math.max(0, Math.min(slides.length - 1, Math.round(car.scrollLeft / step())));
    if (i !== S.slide) {
      // əvvəlki kart çevrilmişdisə, geri çevir
      slides[S.slide]?.querySelector('.flip')?.classList.remove('on');
      S.slide = i;
      updateCardPanel();
    }
  }, { passive: true });
}
function filteredItems() {
  const q = S.q.trim().toLocaleLowerCase('az');
  return S.items
    .filter((it) => S.filter === 'all' || it.type === S.filter)
    .filter((it) => !q || [titleOf(it), ...Object.values(it.fields)].join(' ').toLocaleLowerCase('az').includes(q))
    .sort((a, b) => titleOf(a).localeCompare(titleOf(b), 'az'));
}
function listHTML() {
  const items = filteredItems();
  if (!S.items.length) {
    return `<div class="empty">${I.shield}<h2>Hələ heç nə yoxdur</h2><p class="muted">Aşağıdakı <b>+</b> düyməsi ilə ilk kartınızı və ya sənədinizi əlavə edin.</p></div>`;
  }
  if (!items.length) return '<div class="empty"><p class="muted">Heç nə tapılmadı</p></div>';
  const cards = items.filter((i) => i.type === 'card');
  const rest = ['doc', 'note'].map((t) => {
    const g = items.filter((i) => i.type === t);
    return g.length ? `<section class="group"><h2 class="sec-h">${TYPES[t].plural} <span>${g.length}</span></h2>
      <div class="rows">${g.map(listItemHTML).join('')}</div></section>` : '';
  }).join('');
  if (!cards.length) return rest;
  return `<section class="group"><h2 class="sec-h">Kartlar <span>${cards.length}</span></h2>
      <div class="carousel" id="carousel">${cards.map((c) => `<div class="slide" data-id="${esc(c.id)}">${slideInner(c)}</div>`).join('')}</div>
      ${cards.length > 1 ? `<div class="dots" aria-hidden="true">${cards.map(() => '<span></span>').join('')}</div>` : ''}
      <div class="qa" id="qa"></div>
      <div id="card-info"></div>
    </section>${rest}`;
}
function renderList() {
  app.innerHTML = `<header class="hero">
      <div class="hero-top"><h1>Cüzdan</h1><div class="hero-acts">${iconBtn('settings', I.gear, 'Ayarlar')}${iconBtn('lock', I.lock, 'Kilidlə')}</div></div>
      <p class="hero-sub">${statusLine()}</p>
    </header>
    <div class="page">
      ${S.items.length > 3 ? `<label class="search">${I.search}<input id="q" type="search" placeholder="Axtar…" value="${esc(S.q)}" autocomplete="off"></label>` : ''}
      <div id="list">${listHTML()}</div>
    </div>
    <button class="fab" data-act="add" aria-label="Əlavə et">${I.plus}</button>`;
  afterList();
}

function bigCardHTML(it) {
  return `<button class="face-box flip ${S.flipped ? 'on' : ''}" data-act="flip" aria-label="Kartı çevir">
      <div class="flip-in">${cardFace(it)}${cardBack(it)}</div>
    </button>
    <p class="hint">Arxa üzü üçün karta toxunun</p>`;
}
function bigDocHTML(it) {
  return `<button class="face-box doc-big" data-act="reveal" data-k="${esc(it.id)}:number" aria-label="Nömrəni göstər/gizlət">${docFace(it)}</button>`;
}
function renderDetail() {
  const it = S.items.find((x) => x.id === S.id);
  if (!it) { S.view = 'list'; return renderList(); }
  const T = TYPES[it.type];
  const rows = T.fields.map((f) => {
    const v = it.fields[f.k];
    if (!v) return '';
    const k = `${it.id}:${f.k}`;
    const shown = !f.secret || S.revealed.has(k);
    let disp = f.date ? fmtDate(v) : f.fmt === 'card' ? groupCard(v) : v;
    if (!shown) disp = mask(f, v);
    return `<div class="drow">
      <div class="drow-main"><div class="drow-l">${esc(f.l)}</div><div class="drow-v ${f.area ? 'pre' : ''} ${f.secret || f.fmt ? 'mono' : ''}">${esc(disp)}</div></div>
      <div class="drow-acts">
        ${f.secret ? iconBtn('reveal', shown ? I.eyeOff : I.eye, shown ? 'Gizlət' : 'Göstər', `data-k="${esc(k)}"`) : ''}
        ${iconBtn('copy', I.copy, 'Kopyala', `data-k="${esc(f.k)}"`)}
      </div></div>`;
  }).join('');
  const imgs = (it.images || []).map(safeImg).filter(Boolean);
  app.innerHTML = `${topbar(titleOf(it), iconBtn('back', I.back, 'Geri'), iconBtn('edit', I.edit, 'Redaktə et'))}
    <div class="page">
      ${it.type === 'card' ? bigCardHTML(it) : it.type === 'doc' ? bigDocHTML(it) : `<div class="doc-head"><span class="ri-ico big t-${it.type}">${T.icon}</span><div><b>${esc(titleOf(it))}</b><small class="muted">${esc(subOf(it) || T.label)}</small></div></div>`}
      ${expiryBadge(it) ? `<div class="center">${expiryBadge(it)}</div>` : ''}
      <div class="panel">${rows || '<p class="muted pad">Məlumat yoxdur</p>'}</div>
      ${imgs.length ? `<h2 class="group-h">Şəkillər</h2><div class="thumbs">${imgs.map((src, i) => `<button class="thumb" data-act="viewImg" data-i="${i}"><img src="${esc(src)}" alt="Şəkil ${i + 1}"></button>`).join('')}</div>` : ''}
      <button class="btn danger-ghost block" data-act="delete">${I.trash} Sil</button>
      <p class="muted small center">Son dəyişiklik: ${azDateTime(new Date(it.updatedAt))}</p>
    </div>`;
}

function fieldInput(f, v) {
  const val = esc(v || '');
  let ctrl;
  if (f.select) {
    ctrl = `<select data-f="${f.k}"><option value="">Seçin…</option>${f.select.map((o) => `<option ${o === v ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
  } else if (f.area) {
    ctrl = `<textarea data-f="${f.k}" rows="3">${val}</textarea>`;
  } else {
    const type = f.date ? 'date' : f.secret && f.fmt === 'digits' ? 'password' : 'text';
    ctrl = `<input data-f="${f.k}" type="${type}" value="${val}" ${f.ph ? `placeholder="${esc(f.ph)}"` : ''} ${f.im ? `inputmode="${f.im}"` : ''} ${f.max ? `maxlength="${f.max}"` : ''} ${f.upper ? 'autocapitalize="characters"' : ''} autocomplete="off" autocorrect="off" spellcheck="false">`;
  }
  return `<label class="fld"><span>${esc(f.l)}</span>${ctrl}</label>`;
}
function colorPickerHTML(d) {
  const fin = FINISHES.some(([v]) => v === d.finish) ? d.finish : PRESETS[d.color]?.finish || 'gloss';
  const custom = d.color === 'custom';
  return `<div class="fld"><span>Kartın rəngi</span>
    <button type="button" class="btn ghost photo-color" data-act="colorFromPhoto">${I.camera} Kartın şəklindən rəngi götür</button>
    <div class="colors">
      ${Object.entries(PRESETS).map(([c, p]) => `<button type="button" class="swatch c-${c} ${d.color === c ? 'on' : ''}" data-act="color" data-v="${c}" title="${esc(p.l)}" aria-label="${esc(p.l)}"></button>`).join('')}
      <button type="button" class="swatch custom ${custom ? 'on' : ''}" data-act="color" data-v="custom" title="Öz rəngim" aria-label="Öz rəngim"></button>
    </div>
    <div class="color-name muted small">${esc(custom ? 'Öz rəngim' : PRESETS[d.color]?.l || '')}</div>
    ${custom ? `<div class="cpicks">
      <label class="cpick"><input type="color" data-c="c1" value="${hex(d.c1, '#5b5ff0')}"><span>Rəng 1</span></label>
      <label class="cpick"><input type="color" data-c="c2" value="${hex(d.c2, hex(d.c1, '#a855f7'))}"><span>Rəng 2</span></label>
    </div>` : ''}
    <div class="seg" role="group" aria-label="Səth">${FINISHES.map(([v, l]) => `<button type="button" class="${fin === v ? 'on' : ''}" data-act="finish" data-v="${v}">${l}</button>`).join('')}</div>
  </div>`;
}
function previewHTML() {
  const d = S.draft;
  return d.type === 'card' ? cardFace(d, true) : docFace(d, true);
}
function renderEdit() {
  const d = S.draft;
  if (!d) { S.view = 'list'; return renderList(); }
  const T = TYPES[d.type];
  app.innerHTML = `${topbar(d.createdAt ? 'Redaktə' : 'Yeni: ' + T.label, iconBtn('back', I.x, 'Ləğv et'), '')}
    <form id="f-edit" class="page form" autocomplete="off" novalidate>
      ${d.type !== 'note' ? `<div class="face-box preview ${d.type === 'doc' ? 'doc-big' : ''}" id="preview">${previewHTML()}</div>` : ''}
      ${d.type === 'doc' ? `<div class="fld"><span>Vəsiqə şəkli (kartda görünür)</span><div class="photo-row">
        <div class="df-photo small">${safeImg(d.photo) ? `<img src="${esc(safeImg(d.photo))}" alt="">` : I.user}</div>
        <button type="button" class="btn ghost" data-act="addPhoto">${I.camera} ${d.photo ? 'Dəyiş' : 'Seç'}</button>
        ${d.photo ? `<button type="button" class="icon-btn" data-act="rmPhoto" aria-label="Şəkli sil">${I.trash}</button>` : ''}
      </div></div>` : ''}
      <label class="fld"><span>Ad (siyahıda görünür, istəyə bağlı)</span><input data-f="title" value="${esc(d.title)}" placeholder="${d.type === 'card' ? 'Məs: Maaş kartı' : d.type === 'doc' ? 'Məs: Mənim vəsiqəm' : 'Məs: Wi-Fi şifrəsi'}"></label>
      ${d.type === 'card' ? colorPickerHTML(d) : ''}
      ${T.fields.map((f) => fieldInput(f, d.fields[f.k])).join('')}
      <div class="fld"><span>Şəkillər (ön/arxa üz və s.)</span>
        <div class="thumbs">${d.images.map((src, i) => `<div class="thumb"><img src="${esc(safeImg(src))}" alt=""><button type="button" class="thumb-x" data-act="rmImg" data-i="${i}" aria-label="Sil">${I.x}</button></div>`).join('')}
        <button type="button" class="thumb add" data-act="addImg">${I.camera}<span>Əlavə et</span></button></div>
      </div>
      <p class="err" hidden></p>
      <button class="btn primary block">Yadda saxla</button>
    </form>`;
}

function renderSettings() {
  const st = S.settings;
  const opts = [[30, '30 saniyə'], [60, '1 dəqiqə'], [120, '2 dəqiqə'], [300, '5 dəqiqə'], [900, '15 dəqiqə']];
  app.innerHTML = `${topbar('Ayarlar', iconBtn('back', I.back, 'Geri'), '')}
    <div class="page">
      <h2 class="group-h">Təhlükəsizlik</h2>
      <div class="panel">
        <label class="srow"><span>Fəaliyyətsizlikdən sonra kilidlə</span>
          <select id="s-lockAfter">${opts.map(([v, l]) => `<option value="${v}" ${st.lockAfter === v ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
        <label class="srow"><span>Tətbiqdən çıxanda dərhal kilidlə</span><input id="s-lockOnHide" type="checkbox" class="switch" ${st.lockOnHide ? 'checked' : ''}></label>
        <button class="srow btnrow" data-act="chpw"><span>${I.key} Ana şifrəni dəyiş</span></button>
      </div>
      <h2 class="group-h">Ehtiyat nüsxə</h2>
      <div class="panel">
        <button class="srow btnrow" data-act="export"><span>${I.download} Şifrəli nüsxəni çıxar</span></button>
        <button class="srow btnrow" data-act="import"><span>${I.upload} Nüsxədən idxal et</span></button>
      </div>
      <p class="muted small">Nüsxə faylı ana şifrənizlə şifrəlidir. Telefon itərsə məlumat da itməsin deyə, onu vaxtaşırı iCloud/Google Drive-a və ya kompüterə saxlayın.</p>
      <h2 class="group-h">Məlumat</h2>
      <div class="panel">
        <div class="srow"><span>Elementlər</span><span class="muted">${S.items.length}</span></div>
        <div class="srow"><span>İstifadə olunan yaddaş</span><span class="muted" id="s-usage">…</span></div>
        <button class="srow btnrow danger-text" data-act="wipe"><span>${I.trash} Bütün məlumatı sil</span></button>
      </div>
      <p class="muted small center">Kartlarım v${APP_VERSION} · AES-256-GCM · PBKDF2 ${S.vault.iter.toLocaleString('az')} təkrar</p>
    </div>`;
  navigator.storage?.estimate?.().then((e) => {
    const el = $('#s-usage');
    if (el) el.textContent = `${(e.usage / 1048576).toFixed(1)} MB`;
  });
}

function render() {
  if (!S.vault) return renderSetup();
  if (!S.key) return renderLock();
  ({ detail: renderDetail, edit: renderEdit, settings: renderSettings }[S.view] || renderList)();
}

function openViewer(images, i) {
  const v = document.createElement('div');
  v.className = 'viewer';
  v.innerHTML = `<img src="${esc(images[i])}" alt=""><button class="icon-btn viewer-x" aria-label="Bağla">${I.x}</button>`;
  v.addEventListener('click', () => v.remove());
  document.body.append(v);
}

/* ---------------- Hadisələr ---------------- */
app.addEventListener('click', async (e) => {
  const el = e.target.closest('[data-act]');
  if (!el) return;
  const act = el.dataset.act;
  const cur = S.items.find((x) => x.id === S.id);
  switch (act) {
    case 'restoreFresh': return restoreFresh();
    case 'lock': return lock();
    case 'settings': return go('settings');
    case 'back': return history.back();
    case 'open': return go('detail', el.dataset.id);
    case 'filter':
      S.filter = el.dataset.v;
      return renderList();
    case 'add': {
      const t = await sheet('Nə əlavə edək?', [
        { v: 'card', icon: I.card, label: 'Bank kartı', hint: 'Nömrə, bitmə tarixi, CVV, PIN' },
        { v: 'doc', icon: I.doc, label: 'Sənəd', hint: 'Vəsiqə, pasport, sürücülük və s.' },
        { v: 'note', icon: I.note, label: 'Qeyd', hint: 'Şifrə, kod və ya istənilən mətn' }
      ]);
      if (!t) return;
      S.draft = { id: uid(), type: t, title: '', color: 'indigo', fields: {}, images: [], createdAt: 0, updatedAt: 0 };
      return go('edit');
    }
    case 'edit':
      S.draft = structuredClone(cur);
      S.draft.images = S.draft.images || [];
      return go('edit', cur.id);
    case 'color':
      S.draft.color = el.dataset.v;
      if (el.dataset.v !== 'custom') S.draft.finish = PRESETS[el.dataset.v].finish || 'gloss';
      return renderEdit();
    case 'finish':
      S.draft.finish = el.dataset.v;
      return renderEdit();
    case 'colorFromPhoto': {
      const src = (S.draft.images || []).map(safeImg).find(Boolean);
      if (!src) return toast('Əvvəlcə aşağıda kartın şəklini əlavə edin');
      try {
        const [c1, c2] = await colorsFromImage(src);
        Object.assign(S.draft, { color: 'custom', c1, c2 });
        renderEdit();
        toast('Rənglər şəkildən götürüldü');
      } catch { toast('Rəngi götürmək alınmadı'); }
      return;
    }
    case 'flip':
      S.flipped = !S.flipped;
      el.classList.toggle('on', S.flipped);
      buzz();
      return;
    case 'qaCopy': {
      const c = currentCard();
      if (!c?.fields.number) return toast('Kart nömrəsi yoxdur');
      buzz();
      return copy(digits(c.fields.number));
    }
    case 'qaShow': {
      const c = currentCard();
      if (!c) return;
      const k = c.id + ':number';
      S.revealed.has(k) ? S.revealed.delete(k) : S.revealed.add(k);
      const slide = cardSlides()[S.slide];
      const flipped = slide.querySelector('.flip')?.classList.contains('on');
      slide.innerHTML = slideInner(c);
      if (flipped) slide.querySelector('.flip').classList.add('on');
      buzz();
      return updateCardPanel();
    }
    case 'qaFlip':
      cardSlides()[S.slide]?.querySelector('.flip')?.classList.toggle('on');
      buzz();
      return;
    case 'qaMore':
      return go('detail', currentCard()?.id);
    case 'addPhoto': {
      const inp = document.createElement('input');
      inp.type = 'file'; inp.accept = 'image/*';
      inp.onchange = async () => {
        const f = inp.files[0];
        if (!f) return;
        try { S.draft.photo = await compressImage(f, true); } catch { return toast('Şəkil oxunmadı'); }
        if (S.view === 'edit') renderEdit();
      };
      S.picking = true;
      inp.click();
      return;
    }
    case 'rmPhoto':
      S.draft.photo = '';
      return renderEdit();
    case 'addImg': {
      const inp = document.createElement('input');
      inp.type = 'file'; inp.accept = 'image/*'; inp.multiple = true;
      inp.onchange = async () => {
        for (const f of inp.files) {
          try { S.draft.images.push(await compressImage(f)); } catch { toast('Şəkil oxunmadı'); }
        }
        if (S.view === 'edit') renderEdit();
      };
      S.picking = true;
      inp.click();
      return;
    }
    case 'rmImg':
      S.draft.images.splice(+el.dataset.i, 1);
      return renderEdit();
    case 'viewImg':
      return openViewer((cur.images || []).map(safeImg).filter(Boolean), +el.dataset.i);
    case 'reveal': {
      const k = el.dataset.k;
      S.revealed.has(k) ? S.revealed.delete(k) : S.revealed.add(k);
      buzz();
      return renderDetail();
    }
    case 'copy': {
      const f = TYPES[cur.type].fields.find((x) => x.k === el.dataset.k);
      const v = cur.fields[f.k] || '';
      buzz();
      return copy(f.fmt === 'card' ? digits(v) : f.date ? fmtDate(v) : v);
    }
    case 'delete': {
      const ok = await modal({ title: 'Silinsin?', text: `"${titleOf(cur)}" birdəfəlik silinəcək.`, ok: 'Sil', danger: true });
      if (!ok) return;
      await delRec(cur.id);
      S.items = S.items.filter((x) => x.id !== cur.id);
      toast('Silindi');
      return history.back();
    }
    case 'export': return exportBackup();
    case 'import': return importMerge();
    case 'chpw': return changePassword();
    case 'wipe': {
      const r = await modal({
        title: 'Hər şey silinsin?', text: 'Bütün kartlar, sənədlər və ana şifrə bu cihazdan silinəcək. Təsdiq üçün SİL yazın.',
        fields: [{ name: 'c', label: 'Təsdiq', placeholder: 'SİL' }], ok: 'Hamısını sil', danger: true,
        validate: ({ c }) => (c.trim().toLocaleUpperCase('az') === 'SİL' ? '' : 'SİL yazın')
      });
      if (!r) return;
      db.close();
      indexedDB.deleteDatabase('card-holder');
      location.reload();
    }
  }
});

app.addEventListener('input', (e) => {
  const el = e.target;
  if (el.id === 'q') { S.q = el.value; S.slide = 0; $('#list').innerHTML = listHTML(); afterList(); return; }
  if (el.dataset.c && S.draft) {
    S.draft[el.dataset.c] = hex(el.value, '#5b5ff0');
    $('#preview').innerHTML = previewHTML();
    return;
  }
  const k = el.dataset.f;
  if (!k || !S.draft) return;
  const f = TYPES[S.draft.type].fields.find((x) => x.k === k);
  let v = el.value;
  if (f?.fmt === 'card') v = groupCard(v).slice(0, 23);
  else if (f?.fmt === 'exp') { const d = digits(v).slice(0, 4); v = d.length > 2 ? d.slice(0, 2) + '/' + d.slice(2) : d; }
  else if (f?.fmt === 'digits') v = digits(v);
  if (f?.upper) v = v.toLocaleUpperCase('az');
  if (v !== el.value) el.value = v;
  if (k === 'title') S.draft.title = v; else S.draft.fields[k] = v;
  const pv = $('#preview');
  if (pv) pv.innerHTML = previewHTML();
});

app.addEventListener('change', async (e) => {
  const el = e.target;
  if (el.id === 's-lockAfter') S.settings.lockAfter = +el.value;
  else if (el.id === 's-lockOnHide') S.settings.lockOnHide = el.checked;
  else return;
  await setMeta('settings', S.settings);
  toast('Yadda saxlanıldı');
});

app.addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const err = $('.err', form);
  const btn = $('button.primary', form);
  const fail = (m) => { err.textContent = m; err.hidden = false; };
  err && (err.hidden = true);

  if (form.id === 'f-setup') {
    const { pw, pw2 } = Object.fromEntries(new FormData(form));
    if (pw.length < 8) return fail('Şifrə ən azı 8 simvol olmalıdır');
    if (pw !== pw2) return fail('Şifrələr uyğun gəlmir');
    btn.disabled = true; btn.textContent = 'Yaradılır…';
    await createVault(pw);
    history.replaceState({ view: 'list' }, '');
    return render();
  }

  if (form.id === 'f-unlock') {
    const fails = (await getMeta('fails')) || { n: 0, until: 0 };
    if (Date.now() < fails.until) return fail(`Çox cəhd. ${Math.ceil((fails.until - Date.now()) / 1000)} saniyə gözləyin.`);
    btn.disabled = true; btn.textContent = 'Açılır…';
    const pw = form.elements.pw.value;
    const key = await deriveKey(pw, S.vault.salt, S.vault.iter);
    if (!(await checkKey(key, S.vault.check))) {
      fails.n++;
      if (fails.n >= 5) fails.until = Date.now() + 30000 * 2 ** (fails.n - 5);
      await setMeta('fails', fails);
      btn.disabled = false; btn.textContent = 'Aç';
      form.elements.pw.select();
      return fail('Şifrə yanlışdır');
    }
    await setMeta('fails', { n: 0, until: 0 });
    S.key = key;
    await loadItems();
    lastActive = Date.now();
    history.replaceState({ view: 'list' }, '');
    return render();
  }

  if (form.id === 'f-edit') {
    const d = S.draft;
    if (d.type === 'card' && d.fields.number && !luhn(d.fields.number)) {
      const ok = await modal({ title: 'Kart nömrəsi səhv görünür', text: 'Nömrə yoxlamadan keçmədi. Yenə də saxlanılsın?', ok: 'Saxla' });
      if (!ok) return;
    }
    if (d.type === 'card' && d.fields.expiry && !/^(0[1-9]|1[0-2])\/\d{2}$/.test(d.fields.expiry)) return fail('Bitmə tarixi AA/İİ formatında olmalıdır (məs: 08/28)');
    if (!titleOf(d) || (!d.title && !Object.values(d.fields).some(Boolean) && !d.images.length)) return fail('Ən azı bir sahəni doldurun');
    const isNew = !d.createdAt;
    const now = Date.now();
    d.createdAt = d.createdAt || now;
    d.updatedAt = now;
    Object.keys(d.fields).forEach((k) => { if (typeof d.fields[k] === 'string') d.fields[k] = d.fields[k].trim(); });
    btn.disabled = true;
    await saveItem(structuredClone(d));
    S.draft = null;
    toast('Yadda saxlanıldı');
    if (isNew) {
      S.view = 'detail'; S.id = d.id;
      history.replaceState({ view: 'detail', id: d.id }, '');
      render();
    } else history.back();
  }
});

async function changePassword() {
  let oldOk = false;
  const r = await modal({
    title: 'Ana şifrəni dəyiş',
    fields: [
      { name: 'old', label: 'Hazırkı şifrə', type: 'password' },
      { name: 'pw', label: 'Yeni şifrə (ən azı 8 simvol)', type: 'password' },
      { name: 'pw2', label: 'Yeni şifrəni təkrarlayın', type: 'password' }
    ],
    ok: 'Dəyiş',
    validate: async ({ old, pw, pw2 }) => {
      if (!oldOk) {
        const k = await deriveKey(old, S.vault.salt, S.vault.iter);
        if (!(await checkKey(k, S.vault.check))) return 'Hazırkı şifrə yanlışdır';
        oldOk = true;
      }
      if (pw.length < 8) return 'Yeni şifrə ən azı 8 simvol olmalıdır';
      if (pw !== pw2) return 'Yeni şifrələr uyğun gəlmir';
      return '';
    }
  });
  if (!r) return;
  toast('Yenidən şifrələnir…');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(r.pw, salt, ITER);
  const vault = { salt, iter: ITER, check: await seal(key, { ok: 'card-holder' }) };
  const recs = [];
  for (const it of S.items) recs.push({ id: it.id, ...(await seal(key, it)) });
  await writeAll(recs, { vault });
  S.vault = vault; S.key = key;
  toast('Ana şifrə dəyişdirildi');
}

/* ---------------- Başlanğıc ---------------- */
(async function init() {
  if ('serviceWorker' in navigator && location.protocol !== 'file:') {
    const hadController = !!navigator.serviceWorker.controller;
    navigator.serviceWorker.register('sw.js', { updateViaCache: 'none' }).then((reg) => {
      reg.update().catch(() => {});
      // Tətbiq hər dəfə önə gələndə yeni versiyanı yoxla
      document.addEventListener('visibilitychange', () => { if (!document.hidden) reg.update().catch(() => {}); });
    }).catch(() => {});
    // Yeni versiya aktiv olanda: kilidlidirsə dərhal, açıqdırsa növbəti kilidlənmədə yenilə
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (!hadController || S.reloading) return;
      if (S.key) { S.pendingReload = true; return; }
      S.reloading = true;
      location.reload();
    });
  }
  await openDB();
  S.vault = (await getMeta('vault')) || null;
  S.settings = { ...S.settings, ...((await getMeta('settings')) || {}) };
  history.replaceState({ view: 'list' }, '');
  render();
})();
