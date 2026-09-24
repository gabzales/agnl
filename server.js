const express = require('express');
const cookieSession = require('cookie-session');
const expressLayouts = require('express-ejs-layouts');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const https = require('https');
const multer = require('multer');
const crypto = require('crypto');

// Load .env FIRST before anything reads process.env
require('dotenv').config();

// ══════════════════════════════════════════════════════════════════
// LIVE LOG VIEWER (admin) -- supaya log asli bisa dilihat dari web tanpa buka Vercel.
//
// Cara kerja:
//  - console.log/warn/error DIBUNGKUS: output tetap ke stdout (Vercel logs tetap jalan),
//    ditambah disalin ke ring buffer di memori (maks 600 entri, per instance).
//  - Secret (token, key, password, cookie, JWT, header Bearer) di-REDACT otomatis.
//  - Penyimpanan lintas instance: buffer di-flush ke Supabase (dripstore_logs.json) paling
//    cepat tiap 60 dtk dan HANYA kalau ada entri warn/error baru. Log 'info' sifatnya
//    memori saja. Ini disengaja: project ini pernah kena limit egress Supabase, jadi
//    logging TIDAK boleh menulis ke DB tiap kejadian.
//  - Halaman /admin/logs membaca gabungan: memori instance ini + log tersimpan.
// ══════════════════════════════════════════════════════════════════
const LOG_MAX = 600;
const LOG_PERSIST_MAX = 300;
const LOG_FLUSH_MS = Math.max(100, Number(process.env.LOG_FLUSH_MS) || 60000);
let _logFlushTimer = null;
const _logRing = [];
let _logSeq = 0;
let _logDirtyImportant = 0;
let _logLastFlush = 0;
const _logBoot = new Date().toISOString();
const _logInstance = crypto.randomBytes(3).toString('hex');
const { AsyncLocalStorage } = require('async_hooks');
// Konteks request: supaya tiap panggilan ke provider DripStore tahu SIAPA pemicunya
// (route mana / background). Ini kunci diagnosa "kenapa kuota habis".
const _reqCtx = new AsyncLocalStorage();
const _dsStats = { since: Date.now(), calls: {}, byWho: {}, ok: 0, rateLimited: 0, err: 0, last429At: 0 };
const _reqCounts = new Map();
const _gateStats = { redirected: 0, passed: 0, rejected: 0 };
let _logFlushImpl = null; // diisi setelah modul DB siap

const _SECRET_PATTERNS = [
  [/(authorization["']?\s*[:=]\s*["']?)(bearer\s+)?[A-Za-z0-9._\-~+\/=]{8,}/gi, '$1[REDACTED]'],
  [/(bearer\s+)[A-Za-z0-9._\-~+\/=]{8,}/gi, '$1[REDACTED]'],
  [/((?:api[_-]?token|apitoken|api[_-]?key|apikey|secret(?:[_-]?key)?|password|passwd|pass|token|signature|sig|cookie|set-cookie|service[_-]?role[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|x-api-key|x-signature)["']?\s*[:=]\s*["']?)[^\s"',;&}]{4,}/gi, '$1[REDACTED]'],
  [/(vpr_session(?:\.sig)?=)[^\s;]+/gi, '$1[REDACTED]'],
  [/(cf_gate=)[^\s;]+/gi, '$1[REDACTED]'],
  [/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, '[REDACTED_JWT]'],
  [/\b(sb_secret_|sbp_|sk_live_|sk_test_|ghp_|gho_)[A-Za-z0-9_\-]{8,}/g, '[REDACTED_KEY]'],
  [/\b[0-9a-f]{32,}\b/gi, '[REDACTED_HEX]'],
];
function _logRedact(str) {
  let out = String(str);
  for (const [re, rep] of _SECRET_PATTERNS) out = out.replace(re, rep);
  return out;
}
function _logFormat(args) {
  return args.map(a => {
    if (a instanceof Error) return (a.stack || a.message || String(a)).split('\n').slice(0, 4).join(' | ');
    if (typeof a === 'string') return a;
    try { return JSON.stringify(a); } catch { return String(a); }
  }).join(' ');
}
function _logCategory(msg) {
  const m = msg.toLowerCase();
  if (/dripstore|drip-store|provider/.test(m)) return 'dripstore';
  if (/webhook|genspay|pakasir|check-payment|payment|qris/.test(m)) return 'payment';
  if (/site-gate|turnstile|cf-check|cloudflare/.test(m)) return 'security';
  if (/supabase|\[db\]|writedb|readfresh/.test(m)) return 'database';
  return 'app';
}
function pushLog(level, msg, extra) {
  const text = _logRedact(msg).slice(0, 1200);
  const entry = { id: ++_logSeq, t: Date.now(), lv: level, cat: (extra && extra.cat) || _logCategory(text), msg: text, inst: _logInstance };
  if (extra && extra.meta) entry.meta = extra.meta;
  _logRing.push(entry);
  // Buffer penuh: buang entri 'info' tertua dulu, supaya warn/error tidak terdesak
  // oleh banyaknya log info (mis. tiap panggilan provider).
  while (_logRing.length > LOG_MAX) {
    const i = _logRing.findIndex(e => e.lv === 'info');
    _logRing.splice(i >= 0 ? i : 0, 1);
  }
  // Error dari penyimpanan log itu sendiri TIDAK boleh memicu flush lagi (feedback loop
  // saat Supabase down: flush gagal -> error dicatat -> flush lagi -> ...).
  if ((level === 'warn' || level === 'error') && !text.includes('app_logs.json')) {
    _logDirtyImportant++;
    if (_logFlushImpl) {
      const wait = LOG_FLUSH_MS - (Date.now() - _logLastFlush);
      if (wait <= 0) { try { _logFlushImpl(); } catch (_) {} }
      else if (!_logFlushTimer) {
        // Flush TRAILING: entri penting yang kena throttle tetap tersimpan begitu jendela
        // lewat, walau tidak ada warn/error lagi setelahnya.
        _logFlushTimer = setTimeout(() => { _logFlushTimer = null; try { _logFlushImpl(); } catch (_) {} }, wait + 50);
        if (_logFlushTimer.unref) _logFlushTimer.unref();
      }
    }
  }
  return entry;
}
['log', 'info', 'warn', 'error'].forEach((fn) => {
  const orig = console[fn].bind(console);
  const level = fn === 'error' ? 'error' : fn === 'warn' ? 'warn' : 'info';
  console[fn] = (...args) => {
    try { pushLog(level, _logFormat(args)); } catch (_) {}
    orig(...args);
  };
});
process.on('unhandledRejection', (r) => { try { pushLog('error', 'UnhandledRejection: ' + (r && (r.stack || r.message) || String(r)), { cat: 'app' }); } catch (_) {} });
process.on('uncaughtException', (e) => { try { pushLog('error', 'UncaughtException: ' + (e && (e.stack || e.message) || String(e)), { cat: 'app' }); } catch (_) {} });

// PENTING — KEAMANAN: session cookie ditandatangani (signed) pakai secret ini.
// Sebelumnya ada fallback string HARDCODED di source code
// ('agha-nl-fallback-secret-2024-xK9mP3qR'). Itu lubang keamanan serius:
// siapa pun yang baca source code ini (termasuk lewat zip project ini) bisa
// tahu secret-nya, lalu memalsukan cookie session sendiri — termasuk bikin
// cookie isAdmin:true atau menyamar jadi reseller manapun untuk menguras
// saldo wallet mereka — TANPA perlu password sama sekali.
// Sekarang: kalau SESSION_SECRET tidak di-set, generate secret acak yang
// unik per kali server nyala (bukan string tetap yang bisa dibaca orang).
// Konsekuensinya session akan ke-reset tiap restart server kalau kamu belum
// set SESSION_SECRET — supaya aman SEKALIGUS stabil di production, WAJIB
// set SESSION_SECRET di environment variables (Vercel/hosting kamu).
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// Production warning tapi JANGAN exit — Vercel kadat lambat inject env
if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  console.warn('⚠️  SESSION_SECRET belum di-set! Pakai secret acak sementara (reset tiap restart server).');
  console.warn('⚠️  WAJIB set SESSION_SECRET di environment variables untuk keamanan & session yang stabil.');
}

// Load DB module AFTER dotenv so env vars are available
const db = require('./supabase');

const app = express();
const PORT = process.env.PORT || 3000;

// Rate limiting untuk QR Code
const qrRateLimit = new Map();
const QR_RATE_LIMIT = 30;
const QR_RATE_WINDOW = 60000;

// Rate limiting untuk login (brute force protection)
const loginFailMap = new Map();
const LOGIN_MAX_FAIL = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 menit

const checkLoginBlocked = (ip) => {
  cleanupRateMap(loginFailMap, Date.now());
  const rec = loginFailMap.get(ip);
  if (!rec) return { blocked: false };
  if (Date.now() > rec.resetAt) { loginFailMap.delete(ip); return { blocked: false }; }
  return { blocked: rec.count >= LOGIN_MAX_FAIL, wait: Math.ceil((rec.resetAt - Date.now()) / 60000) };
};

const recordLoginFail = (ip) => {
  const now = Date.now();
  const rec = loginFailMap.get(ip);
  if (!rec || now > rec.resetAt) loginFailMap.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
  else { rec.count++; loginFailMap.set(ip, rec); }
};

const clearLoginFail = (ip) => loginFailMap.delete(ip);

// ── Cloudflare Turnstile verification ────────────────────────────────────────
async function verifyTurnstile(token) {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) return true; // Turnstile tidak dikonfigurasi, skip verifikasi

  return new Promise((resolve) => {
    const body = JSON.stringify({
      secret,
      response: token,
    });

    const options = {
      hostname: 'challenges.cloudflare.com',
      path: '/turnstile/v0/siteverify',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json.success === true);
        } catch {
          resolve(false);
        }
      });
    });

    req.on('error', () => resolve(false));
    req.write(body);
    req.end();
  });
}
// Varian detail untuk gate: bedakan token DITOLAK (bot) vs Cloudflare TIDAK TERJANGKAU
// (timeout/error jaringan/5xx). Login/register tetap pakai verifyTurnstile() di atas
// yang fail-closed; hanya gate pengunjung yang fail-open supaya toko tidak mati
// total kalau challenges.cloudflare.com sedang bermasalah.
function verifyTurnstileDetailed(token, remoteIp) {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) return Promise.resolve({ ok: true, unreachable: false });
  return new Promise((resolve) => {
    const payload = { secret, response: token };
    if (remoteIp) payload.remoteip = remoteIp;
    const body = JSON.stringify(payload);
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    const req = https.request({
      hostname: 'challenges.cloudflare.com', path: '/turnstile/v0/siteverify', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 4000
    }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        if (res.statusCode >= 500) return finish({ ok: false, unreachable: true });
        try { finish({ ok: JSON.parse(data).success === true, unreachable: false }); }
        catch { finish({ ok: false, unreachable: true }); }
      });
    });
    req.on('timeout', () => { req.destroy(); finish({ ok: false, unreachable: true }); });
    req.on('error', () => finish({ ok: false, unreachable: true }));
    req.write(body);
    req.end();
  });
}
// ─────────────────────────────────────────────────────────────────────────────

// Invoice rate limiting (cegah brute force order code enumeration)
const invoiceRateMap = new Map();
const INVOICE_RATE_LIMIT = 10;
const INVOICE_RATE_WINDOW = 5 * 60 * 1000;

const checkInvoiceRateLimit = (ip) => {
  cleanupRateMap(invoiceRateMap, Date.now());
  const now = Date.now();
  const rec = invoiceRateMap.get(ip);
  if (!rec || now > rec.resetAt) {
    invoiceRateMap.set(ip, { count: 1, resetAt: now + INVOICE_RATE_WINDOW });
    return true;
  }
  if (rec.count >= INVOICE_RATE_LIMIT) return false;
  rec.count++;
  return true;
};

// ── Validasi kekuatan password (dipakai di /api/auth/register dan
// /register, dua-duanya harus konsisten). Sebelumnya TIDAK ADA validasi
// sama sekali -- password 6 karakter tanpa angka ("danang") langsung
// diterima. Aturan minimal yang wajar: minimal 8 karakter, ada huruf
// DAN ada angka (tidak mewajibkan simbol supaya tidak terlalu
// menyulitkan pengguna awam toko digital ini). ──
function validatePasswordStrength(password) {
  if (!password || password.length < 8) {
    return 'Password minimal 8 karakter';
  }
  if (!/[a-zA-Z]/.test(password)) {
    return 'Password harus mengandung huruf';
  }
  if (!/[0-9]/.test(password)) {
    return 'Password harus mengandung angka';
  }
  return null; // valid
}

// API rate limiting untuk endpoint publik
const apiRateMap = new Map();
const checkApiRateLimit = (ip, limit = 60, windowMs = 60000) => {
  cleanupRateMap(apiRateMap, Date.now());
  const now = Date.now();
  const rec = apiRateMap.get(ip);
  if (!rec || now > rec.resetAt) {
    apiRateMap.set(ip, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (rec.count >= limit) return false;
  rec.count++;
  return true;
};

// ── RATE LIMIT KHUSUS PEMBAYARAN (kebijakan wajib GensPay per 15 Agustus 2026) ──
// GensPay memblokir IP yang melakukan polling/generate QRIS berlebihan
// ("high-frequency request") dan mewajibkan merchant membatasi maksimal
// 30 request / 3 menit PER PENGGUNA untuk endpoint create-order &
// check-payment. Dibatasi per user ID (bukan per IP) karena endpoint ini
// sudah requireAuth — lebih akurat dan tidak mengganggu user lain yang
// kebetulan satu jaringan/NAT dengan user yang memang sedang di-throttle.
const paymentRateMap = new Map();
const PAYMENT_RATE_LIMIT = 30;
const PAYMENT_RATE_WINDOW = 3 * 60 * 1000;
const checkPaymentRateLimit = (userId) => {
  cleanupRateMap(paymentRateMap, Date.now());
  const now = Date.now();
  const rec = paymentRateMap.get(userId);
  if (!rec || now > rec.resetAt) {
    paymentRateMap.set(userId, { count: 1, resetAt: now + PAYMENT_RATE_WINDOW });
    return true;
  }
  if (rec.count >= PAYMENT_RATE_LIMIT) return false;
  rec.count++;
  return true;
};
// Vercel-friendly housekeeping: cleanup hanya saat limiter dipakai.
// Tidak perlu setInterval global yang bisa mempertahankan instance serverless.
const cleanupRateMap = (map, now, maxEntries = 5000) => {
  if (map.size <= maxEntries) return;
  for (const [k, v] of map) {
    if (!v || now > v.resetAt) map.delete(k);
    if (map.size <= Math.floor(maxEntries * 0.8)) break;
  }
};

// ══════════════════════════════════════════════════════════════════
// SISTEM KEY DENGAN DURASI (per-hari & per-jam)
// ══════════════════════════════════════════════════════════════════
// Format key di stok (product.keys, array of string):
//   - "ABCD1234"        -> key generic, tanpa durasi spesifik
//   - "ABCD1234=30d"    -> key berlaku 30 HARI
//   - "ABCD1234=12h"    -> key berlaku 12 JAM
//
// FIX (dilaporkan client 21 Agu 2026): separator SEBELUMNYA pakai titik dua
// (":"), tapi key cheat "silent" ada yang isinya sendiri mengandung ":",
// jadi bentrok sama parsing (misal "abc:def:xyz" salah kesplit jadi durasi).
// Sekarang pakai "=" sebagai separator durasi -- karakter ini jauh lebih
// jarang muncul di key cheat manapun.
//
// Admin BEBAS pilih durasi berapa aja & unit apa aja per-baris key saat
// restock (tidak dikunci ke daftar durasi produk) -- cukup ketik
// "KEY=30d" atau "KEY=12h" satu per baris di textarea restock, sistem yang
// mem-parsing otomatis. Kalau baris key tidak ada "=", dianggap generic.
//
// parseKeyDuration("ABCD=30d") -> { raw: "ABCD", value: 30, unit: 'd' }
// parseKeyDuration("ABCD=12h") -> { raw: "ABCD", value: 12, unit: 'h' }
// parseKeyDuration("ABCD")     -> { raw: "ABCD", value: null, unit: null }
function parseKeyDuration(keyStr) {
  const idx = keyStr.lastIndexOf('=');
  if (idx === -1) return { raw: keyStr, value: null, unit: null };
  const raw = keyStr.slice(0, idx);
  const durationPart = keyStr.slice(idx + 1).trim().toLowerCase();
  const m = durationPart.match(/^(\d+)\s*(d|h)?$/);
  if (!m) return { raw: keyStr, value: null, unit: null }; // format tidak dikenali, treat sebagai generic (raw = seluruh string asli)
  return { raw, value: parseInt(m[1]), unit: m[2] || 'd' }; // default ke hari kalau unit tidak ditulis (backward-compat sama key lama format "KEY=30")
}

// isGenericKey: true kalau key tidak punya durasi sama sekali (tanpa "=").
function isUsableLocalKey(keyStr) {
  const s = String(keyStr || '').trim();
  if (!s) return false;
  // Placeholder lama bukan inventory nyata.
  if (/^(?:stok|stock|produk)\s+(?:tidak\s+tersedia|unavailable)\s*:/i.test(s)) return false;
  // Jangan menganggap semua string bertanda '=' sebagai invalid inventory:
  // karakter '=' bisa saja menjadi bagian dari key legacy. Key bertanda '='
  // yang suffix-nya valid akan dipakai oleh keyMatchesDuration(), sedangkan
  // key bertanda '=' yang malformed tidak dianggap generic oleh isGenericKey().
  return true;
}

function isGenericKey(keyStr) {
  const s = String(keyStr || '').trim();
  // Generic = benar-benar tidak punya tag durasi. Key bertanda durasi harus
  // selalu dipakai melalui pasangan value+unit yang tepat.
  return isUsableLocalKey(s) && !s.includes('=');
}

// keyMatchesDuration: cocokkan key stok dengan durasi+unit yang dipesan
// customer. selectedUnit default 'd' (hari) untuk backward-compat sama
// pemanggil lama yang cuma kirim angka hari tanpa unit.
function keyMatchesDuration(keyStr, selectedValue, selectedUnit) {
  const parsed = parseKeyDuration(keyStr);
  if (parsed.value === null) return false;
  const unit = selectedUnit || 'd';
  return parsed.value === selectedValue && parsed.unit === unit;
}

// ══════════════════════════════════════════════════════════════════

// Lock set untuk mencegah race condition pada alokasi key
const processingOrders = new Set();
// Lock per-user untuk operasi wallet (beli pakai saldo). Tanpa ini, dua
// request /wallet/buy yang nyaris bersamaan (double-click, atau script abuse)
// bisa sama-sama baca saldo & stok key SEBELUM salah satu sempat nulis balik
// — hasilnya: saldo cuma kepotong sekali tapi key kekirim dua kali (double-spend).
const walletLocks = new Set();

// Riwayat webhook payment gateway yang masuk (GensPay/dll), buat debug kalau
// ada laporan "sudah bayar tapi key/saldo belum otomatis masuk".
const webhookLog = [];
function logWebhook(gateway, entry) {
  webhookLog.unshift({ gateway, time: new Date().toISOString(), ...entry });
  if (webhookLog.length > 30) webhookLog.length = 30;
}

const checkQrRateLimit = (ip) => {
  cleanupRateMap(qrRateLimit, Date.now());
  const now = Date.now();
  const record = qrRateLimit.get(ip);
  if (record) {
    const windowStart = now - QR_RATE_WINDOW;
    const recentRequests = record.filter(ts => ts > windowStart);
    if (recentRequests.length >= QR_RATE_LIMIT) {
      return false;
    }
    recentRequests.push(now);
    qrRateLimit.set(ip, recentRequests);
  } else {
    qrRateLimit.set(ip, [now]);
  }
  return true;
};

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('layout', 'layout');
app.set('trust proxy', 1);

// ── REAL CLIENT IP di belakang Cloudflare ────────────────────────────────────
// Kalau domain diproxy Cloudflare (awan oranye), req.ip = IP edge Cloudflare,
// bukan IP pengunjung -> SEMUA rate-limit per IP (login, invoice, API) bakal
// menganggap seluruh pengunjung itu 1 orang. Header CF-Connecting-IP hanya
// dipercaya kalau request memang datang lewat Cloudflare (ada CF-Ray), dan
// hanya diaktifkan saat CLOUDFLARE_PROXY=on supaya orang yang akses langsung
// ke *.vercel.app tidak bisa memalsukan IP lewat header ini.
const CLOUDFLARE_PROXY = String(process.env.CLOUDFLARE_PROXY || '').toLowerCase() === 'on';
if (CLOUDFLARE_PROXY) {
  app.use((req, res, next) => {
    const cfIp = req.headers['cf-connecting-ip'];
    if (cfIp && req.headers['cf-ray'] && /^[0-9a-fA-F:.]{3,45}$/.test(String(cfIp))) {
      Object.defineProperty(req, 'ip', { value: String(cfIp), configurable: true });
    }
    next();
  });
}

// ── REQUEST LOGGER (untuk /admin/logs) ──────────────────────────────────────
// Tidak mencatat tiap page view (banjir). Yang dicatat sebagai entri: webhook, hasil
// challenge gate, error 4xx/5xx (kecuali 404 biasa), request lambat. Sisanya hanya
// dihitung per route. Juga membuka konteks request supaya panggilan provider tahu pemicunya.
function _normPath(p) {
  return String(p).replace(/\/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, '/:id').replace(/\/\d+/g, '/:id').slice(0, 60);
}
app.use((req, res, next) => {
  const p = req.path;
  if (/\.(?:css|js|mjs|map|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf|mp4|webm)$/i.test(p) || p.startsWith('/uploads/') || p.startsWith('/admin/logs')) return next();
  const t0 = Date.now();
  _reqCtx.run({ method: req.method, path: _normPath(p), ip: req.ip }, () => {
    res.on('finish', () => {
      try {
        const st = res.statusCode, ms = Date.now() - t0;
        const key = req.method + ' ' + _normPath(p);
        if (_reqCounts.size < 300 || _reqCounts.has(key)) _reqCounts.set(key, (_reqCounts.get(key) || 0) + 1);
        const loc = String(res.getHeader('location') || '');
        if (st === 302 && loc.startsWith('/cf-check')) _gateStats.redirected++;
        if (p === '/cf-check/verify') { if (st === 200) _gateStats.passed++; else if (st === 403) _gateStats.rejected++; }
        const isAdminProbe = p.startsWith('/admin') || p.startsWith('/vpr-secure');
        if (st === 404 && !isAdminProbe) return;
        const important = st >= 400 || ms > 4000 || p.startsWith('/webhook/') || p.startsWith('/cf-check/verify') || p.startsWith('/cf-check/unavailable');
        if (!important) return;
        const cat = p.startsWith('/webhook/') ? 'payment' : p.startsWith('/cf-check') ? 'security' : /^\/api\/(catalog|products)\//.test(p) ? 'dripstore' : 'app';
        const ua = String(req.headers['user-agent'] || '-').replace(/[\r\n\t]/g, ' ').slice(0, 60);
        pushLog(st >= 500 ? 'error' : (st >= 400 ? 'warn' : 'info'), `${req.method} ${p.slice(0, 120)} -> ${st} ${ms}ms ip=${req.ip} ua="${ua}"`, { cat });
      } catch (_) {}
    });
    next();
  });
});

app.use(expressLayouts);
// `verify` di sini nyimpen raw body string ke req.rawBody -- dibutuhkan
// khusus buat verifikasi signature webhook GensPay (lihat app.post('/webhook/genspay')),
// karena signature dihitung dari string JSON MENTAH persis seperti yang
// dikirim GensPay, bukan dari object hasil re-serialize (urutan key bisa
// beda kalau di-JSON.stringify ulang dari object yang sudah di-parse).
app.use(express.json({ limit: '256kb',
  verify: (req, res, buf) => { req.rawBody = buf.toString('utf8'); }
}));
app.use(express.urlencoded({ extended: true }));
// NOTE: di Vercel, express.static() diabaikan sepenuhnya -- public/**
// otomatis diserve lewat CDN Vercel (lihat vercel.json untuk header cache-nya).
// maxAge di sini cuma berlaku untuk local dev / VPS non-Vercel, supaya
// behavior-nya konsisten dengan yang di production.
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '7d', immutable: true }));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads'), { maxAge: '7d', immutable: true }));
app.use('/uploads/avatars', express.static(path.join(__dirname, 'public/uploads/avatars'), { maxAge: '7d', immutable: true }));

// Vercel: file di /uploads tidak persistent - redirect ke Supabase Storage
if (process.env.VERCEL === '1' || process.env.NOW_REGION) {
  app.get('/uploads/logo-main.png', (req, res) => {
    const supabaseUrl = process.env.SUPABASE_URL || '';
    const storageUrl = supabaseUrl ? supabaseUrl + '/storage/v1/object/public/product-images/logo-main.png' : null;
    if (storageUrl) return res.redirect(302, storageUrl);
    res.setHeader('Content-Type', 'image/svg+xml');
    res.send('<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 40 40"><rect width="40" height="40" rx="8" fill="#dc2626"/><text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" fill="#fff" font-size="14" font-weight="bold">FX</text></svg>');
  });
  app.get('/uploads/logo-text.png', (req, res) => {
    const supabaseUrl = process.env.SUPABASE_URL || '';
    const storageUrl = supabaseUrl ? supabaseUrl + '/storage/v1/object/public/product-images/logo-text.png' : null;
    if (storageUrl) return res.redirect(302, storageUrl);
    res.status(404).send('Logo text not found');
  });
  app.get('/uploads/banner-reseller.jpg', (req, res) => {
    const supabaseUrl = process.env.SUPABASE_URL || '';
    const storageUrl = supabaseUrl ? supabaseUrl + '/storage/v1/object/public/product-images/banner-reseller.jpg' : null;
    if (storageUrl) return res.redirect(302, storageUrl);
    res.status(404).send('Banner not found');
  });
}

app.use(cookieSession({
  name: 'vpr_session',
  secret: SESSION_SECRET,
  maxAge: 7 * 24 * 60 * 60 * 1000,
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
}));

// ══════════════════════════════════════════════════════════════════
// GOOGLE OAUTH LOGIN (opsional, diminta client 21 Agu 2026 -- "daftar
// bisa pilih menggunakan login akun ggl (optional)")
// ══════════════════════════════════════════════════════════════════
// Perlu GOOGLE_CLIENT_ID & GOOGLE_CLIENT_SECRET di environment variable,
// didapat dari Google Cloud Console > APIs & Services > Credentials >
// buat OAuth 2.0 Client ID (tipe "Web application"). Authorized redirect
// URI yang harus didaftarkan di sana: https://domainkamu.com/auth/google/callback
//
// Kalau env var belum diisi, seluruh fitur Google Login otomatis
// dinonaktifkan (tombol "Login dengan Google" disembunyikan di
// login.ejs/register.ejs) -- TIDAK bikin app crash meski belum disetup.
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GOOGLE_OAUTH_ENABLED = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

if (GOOGLE_OAUTH_ENABLED) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback',
    // FIX KEAMANAN (audit 22 Agu 2026): `state: true` mengaktifkan proteksi
    // CSRF standar OAuth 2.0 bawaan passport-oauth2 -- generate nonce acak,
    // simpan di session, kirim sebagai parameter `state` ke Google, lalu
    // verifikasi nonce yang di-echo balik cocok dengan yang tersimpan di
    // session sebelum melanjutkan login. Tanpa ini, attacker berpotensi
    // memulai OAuth flow dengan akun Google miliknya sendiri, mendapat
    // authorization code, lalu memancing korban untuk "menyelesaikan"
    // callback tersebut -- yang bisa berujung akun korban ter-link ke akun
    // Google attacker, atau skenario CSRF serupa. Ini kompatibel dengan
    // cookie-session yang dipakai app ini (nonce disimpan di req.session
    // sementara, bukan butuh passport.session() yang memang sengaja tidak
    // dipakai di sini -- lihat komentar di bawah).
    state: true,
  }, async (accessToken, refreshToken, profile, done) => {
    // NOTE: fungsi ini HANYA mencocokkan/membuat user, TIDAK menyentuh
    // req.session -- itu dilakukan manual di route callback (lihat di
    // bawah) karena app ini pakai cookie-session, bukan session store
    // biasa, jadi passport.session()/serializeUser tidak dipakai sama
    // sekali (redundant untuk arsitektur stateless-cookie ini).
    try {
      const users = await readFresh('users.json');
      const email = profile.emails?.[0]?.value || null;
      let user = users.find(u => u.googleId === profile.id) || (email && users.find(u => u.email === email));
      if (!user) {
        user = {
          id: uuidv4(),
          username: profile.displayName || (email ? email.split('@')[0] : 'user' + Date.now()),
          email,
          googleId: profile.id,
          password: null, // akun Google tidak punya password lokal
          wa: null, // dilengkapi belakangan di halaman lengkapi profil, lihat /complete-profile
          photo: profile.photos?.[0]?.value || null,
          balance: 0,
          createdAt: new Date().toISOString()
        };
        users.push(user);
        await writeDB('users.json', users);
      } else if (!user.googleId) {
        // User lama daftar manual, sekarang login pertama kali pakai Google dengan email yang sama -> link akun
        user.googleId = profile.id;
        await writeDB('users.json', users);
      }
      done(null, user);
    } catch (err) { done(err, null); }
  }));
  app.use(passport.initialize());
}
// ══════════════════════════════════════════════════════════════════

// ── FIX: Regenerate session object tiap request (cookie-session quirk) ──
app.use((req, res, next) => {
  // Pastikan session object tidak null
  if (!req.session) req.session = {};
  next();
});

// ══════════════════════════════════════════════════════════════════
// SITE CHALLENGE GATE -- halaman pengecekan fullscreen (mirip "Checking your
// browser" Cloudflare) untuk pengunjung baru. Pakai Cloudflare Turnstile
// (mode managed) jadi tidak butuh domain diproxy Cloudflare.
//
// Aktif kalau: SITE_CHALLENGE=on  DAN  TURNSTILE_SITE_KEY + TURNSTILE_SECRET_KEY terisi.
// Mati total kalau salah satunya tidak ada (aman, tidak bikin toko terkunci).
//
// Lolos challenge -> cookie `cf_gate` (HMAC, terikat User-Agent, TTL 12 jam).
// Yang TIDAK pernah kena gate: webhook pembayaran, OAuth callback, robots/
// sitemap, aset statis, dan crawler mesin pencari terverifikasi (SEO aman).
// Kalau challenges.cloudflare.com sedang down (terbukti dari probe server) -> fail-open
// sementara 10 menit, pengunjung tetap masuk. Token yang DITOLAK tetap fail-closed.
// ══════════════════════════════════════════════════════════════════
const SITE_CHALLENGE_ON = String(process.env.SITE_CHALLENGE || '').toLowerCase() === 'on'
  && !!process.env.TURNSTILE_SITE_KEY && !!process.env.TURNSTILE_SECRET_KEY;
const GATE_COOKIE = 'cf_gate';
const GATE_TTL_MS = 12 * 60 * 60 * 1000;

function _gateSign(exp, ua) {
  return crypto.createHmac('sha256', SESSION_SECRET + '|gate')
    .update(exp + '|' + crypto.createHash('sha256').update(String(ua || '')).digest('hex'))
    .digest('hex').slice(0, 40);
}
function _gateParseCookie(req) {
  const raw = req.headers.cookie || '';
  const m = raw.split(';').map(x => x.trim()).find(x => x.startsWith(GATE_COOKIE + '='));
  return m ? decodeURIComponent(m.slice(GATE_COOKIE.length + 1)) : '';
}
function _gateIsValid(req) {
  const v = _gateParseCookie(req);
  const i = v.indexOf('.');
  if (i < 1) return false;
  const exp = v.slice(0, i), sig = v.slice(i + 1);
  if (!/^\d{10,15}$/.test(exp) || Number(exp) < Date.now()) return false;
  const want = _gateSign(exp, req.headers['user-agent']);
  if (sig.length !== want.length) return false;
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want));
}
function _gateSetCookie(req, res) {
  const exp = String(Date.now() + GATE_TTL_MS);
  const val = exp + '.' + _gateSign(exp, req.headers['user-agent']);
  res.cookie(GATE_COOKIE, val, {
    maxAge: GATE_TTL_MS, httpOnly: true, sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production', path: '/'
  });
}
// Path yang WAJIB lolos tanpa challenge (server-to-server / mesin).
const GATE_BYPASS_PREFIX = ['/webhook/', '/auth/google', '/uploads/', '/css/', '/js/', '/img/', '/images/', '/fonts/', '/assets/', '/cf-check'];
const GATE_BYPASS_EXACT = new Set(['/robots.txt', '/sitemap.xml', '/favicon.ico', '/manifest.json', '/sw.js', '/health', '/ads.txt']);
// Crawler mesin pencari/preview link yang sah. UA bisa dipalsukan, tapi risikonya
// cuma "lolos gate" (bukan bypass auth) -- gate ini lapisan anti-bot, bukan auth.
const GATE_GOOD_BOTS = /(googlebot|adsbot-google|mediapartners-google|bingbot|duckduckbot|yandexbot|baiduspider|facebookexternalhit|twitterbot|whatsapp|telegrambot|slackbot|linkedinbot|applebot)/i;

app.use((req, res, next) => {
  if (!SITE_CHALLENGE_ON) return next();
  if (GATE_BYPASS_EXACT.has(req.path)) return next();
  if (GATE_BYPASS_PREFIX.some(p => req.path.startsWith(p))) return next();
  if (/\.(?:css|js|mjs|map|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf|mp4|webm|txt|xml|json)$/i.test(req.path)) return next();
  if (GATE_GOOD_BOTS.test(req.headers['user-agent'] || '')) return next();
  if (_gateIsValid(req)) return next();
  // Request non-GET (POST form/API) dari klien tanpa cookie: tolak jelas, jangan redirect.
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return res.status(403).json({ success: false, message: 'Verifikasi keamanan diperlukan. Muat ulang halaman.' });
  }
  const next_ = encodeURIComponent(req.originalUrl.slice(0, 500));
  return res.redirect(302, '/cf-check?next=' + next_);
});

// Cegah open-redirect: hanya path relatif internal.
function _gateSafeNext(n) {
  n = String(n || '/');
  if (!n.startsWith('/') || n.startsWith('//') || n.startsWith('/\\') || /[\r\n]/.test(n)) return '/';
  if (n.startsWith('/cf-check')) return '/';
  return n;
}

app.get('/cf-check', (req, res) => {
  res.set('Cache-Control', 'no-store, max-age=0');
  if (!SITE_CHALLENGE_ON || _gateIsValid(req)) return res.redirect(302, _gateSafeNext(req.query.next));
  const nextUrl = _gateSafeNext(req.query.next);
  const siteName = String((res.locals.settings && res.locals.settings.siteName) || 'AGHA NL').replace(/[<>&"']/g, '');
  res.status(200).type('html').send(`<!DOCTYPE html>
<html lang="id"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<title>Memverifikasi browser Anda - ${siteName}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;background:#0f1115;color:#e8eaf0;display:flex;align-items:center;justify-content:center;padding:24px}
.box{width:100%;max-width:460px;text-align:center}
h1{font-size:1.55rem;font-weight:700;margin-bottom:10px}
p{color:#9aa3b2;font-size:.95rem;line-height:1.5;margin-bottom:26px}
.spin{width:38px;height:38px;border:3px solid #2a2f3a;border-top-color:#f6821f;border-radius:50%;margin:0 auto 22px;animation:s 1s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}
.ts{display:flex;justify-content:center;min-height:65px}
.foot{margin-top:30px;font-size:.75rem;color:#5d6675}
.err{color:#ff8a80;margin-top:14px;font-size:.85rem;display:none}
noscript p{color:#ff8a80}
</style></head><body>
<div class="box">
  <div class="spin" id="spin"></div>
  <h1>Memeriksa keamanan koneksi Anda</h1>
  <p>${siteName} memverifikasi bahwa Anda manusia sebelum melanjutkan. Proses ini otomatis dan hanya beberapa detik.</p>
  <div class="ts"><div class="cf-turnstile" data-sitekey="${String(process.env.TURNSTILE_SITE_KEY).replace(/[^A-Za-z0-9_-]/g, '')}" data-callback="onOk" data-error-callback="onErr" data-expired-callback="onErr" data-theme="dark" data-appearance="always"></div></div>
  <div class="err" id="err">Verifikasi gagal. <a href="" style="color:#f6821f">Coba lagi</a></div>
  <noscript><p>Aktifkan JavaScript untuk melanjutkan.</p></noscript>
  <div class="foot">Dilindungi oleh Cloudflare Turnstile</div>
</div>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer onerror="onLoadFail()"></script>
<script>
var NEXT=${JSON.stringify(nextUrl).replace(/</g, '\\u003c')};
function onOk(token){
  fetch('/cf-check/verify',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({token:token})})
    .then(function(r){return r.json()})
    .then(function(d){ if(d&&d.success){ location.replace(NEXT); } else { onErr(); } })
    .catch(function(){ onErr(); });
}
function onErr(){ document.getElementById('spin').style.display='none'; document.getElementById('err').style.display='block'; }
// Script Turnstile gagal dimuat (Cloudflare down / diblok jaringan): minta server
// loloskan sementara (server tetap memutuskan; ini bukan bypass dari sisi klien).
function onLoadFail(){
  fetch('/cf-check/unavailable',{method:'POST',credentials:'same-origin'})
    .then(function(r){return r.json()}).then(function(d){ if(d&&d.success){ location.replace(NEXT); } else { onErr(); } })
    .catch(function(){ onErr(); });
}
setTimeout(function(){ if(!window.turnstile){ onLoadFail(); } }, 8000);
</script></body></html>`);
});

// Klien melapor script Turnstile tidak bisa dimuat. Server TIDAK percaya begitu saja:
// ia probe sendiri challenges.cloudflare.com. Hanya kalau probe juga gagal -> loloskan
// sementara (10 menit). Kalau Cloudflare sehat, laporan klien diabaikan (cegah bypass
// dengan sengaja memblok script di browser).
app.post('/cf-check/unavailable', async (req, res) => {
  res.set('Cache-Control', 'no-store, max-age=0');
  if (!SITE_CHALLENGE_ON) return res.json({ success: true });
  if (!checkApiRateLimit(req.ip, 6, 10 * 60 * 1000)) return res.status(429).json({ success: false });
  const probe = await verifyTurnstileDetailed('probe', req.ip);
  if (!probe.unreachable) return res.status(403).json({ success: false });
  console.warn('[site-gate] probe server juga gagal ke Turnstile, fail-open untuk', req.ip);
  const exp = String(Date.now() + 10 * 60 * 1000);
  res.cookie(GATE_COOKIE, exp + '.' + _gateSign(exp, req.headers['user-agent']), {
    maxAge: 10 * 60 * 1000, httpOnly: true, sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production', path: '/'
  });
  return res.json({ success: true, degraded: true });
});

app.post('/cf-check/verify', async (req, res) => {
  res.set('Cache-Control', 'no-store, max-age=0');
  if (!SITE_CHALLENGE_ON) return res.json({ success: true });
  if (!checkApiRateLimit(req.ip, 20, 10 * 60 * 1000)) {
    return res.status(429).json({ success: false, message: 'Terlalu banyak percobaan. Coba lagi nanti.' });
  }
  const token = String((req.body && req.body.token) || '');
  if (!token || token.length > 2048) return res.status(400).json({ success: false });
  const v = await verifyTurnstileDetailed(token, req.ip);
  if (v.unreachable) {
    // FAIL-OPEN: Cloudflare Turnstile tidak terjangkau -> loloskan (tapi cookie
    // hanya 10 menit supaya challenge diulang begitu layanan pulih).
    console.warn('[site-gate] Turnstile tidak terjangkau, fail-open untuk', req.ip);
    const exp = String(Date.now() + 10 * 60 * 1000);
    res.cookie(GATE_COOKIE, exp + '.' + _gateSign(exp, req.headers['user-agent']), {
      maxAge: 10 * 60 * 1000, httpOnly: true, sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production', path: '/'
    });
    return res.json({ success: true, degraded: true });
  }
  if (!v.ok) return res.status(403).json({ success: false });
  _gateSetCookie(req, res);
  return res.json({ success: true });
});


// SECURITY: helper untuk embed data JSON ke dalam <script> block di EJS
// dengan aman. JSON.stringify() biasa TIDAK aman kalau string di dalamnya
// mengandung "</script>" — itu akan memutus tag <script> di HTML dan bisa
// jadi stored XSS (misal lewat nama produk yang diinput admin). Fungsi ini
// meng-escape karakter '<' jadi '\u003c' sehingga JSON tetap valid & sama
// persis secara data, tapi tidak bisa memutus tag HTML manapun.
// Dipakai di views lewat <%- safeJson(dataVariable) %> menggantikan
// <%- JSON.stringify(dataVariable) %> untuk data yang di-inject ke <script>.
app.locals.safeJson = (data) => JSON.stringify(data).replace(/</g, '\\u003c');

// Inject settings + isAdmin ke semua view otomatis
app.use(async (req, res, next) => {
  // Kalau cache settings kosong, fetch dari Supabase dulu
  let settings = readDB('settings.json');
  if (!settings || Object.keys(settings).length === 0) {
    try {
      settings = await Promise.race([
        db.readFresh('settings.json'),
        new Promise(resolve => setTimeout(() => resolve({}), 1500))
      ]);
    } catch { settings = {}; }
  }
  res.locals.settings = settings || {};
  res.locals.isAdmin = !!(req.session?.isAdmin || req.session?.userId === 'admin');
  res.locals.user = getSessionUser(req);
  res.locals.googleOAuthEnabled = GOOGLE_OAUTH_ENABLED;
  res.locals.hexToRgba = hexToRgba;
  res.locals.parseProductDescription = parseProductDescription;
  // ── SEO: URL kanonik situs (diminta client 22 Agu 2026) ──
  // Dipakai untuk <link rel="canonical">, Open Graph og:url, dan sitemap.xml.
  // Prioritas: domain custom yang diisi admin (settings.siteUrl) -> header
  // request asli (aman di belakang proxy Vercel) -> fallback req.protocol/host.
  res.locals.siteUrl = (settings?.siteUrl || `${req.headers['x-forwarded-proto'] || req.protocol}://${req.headers['x-forwarded-host'] || req.get('host')}`).replace(/\/$/, '');
  next();
});

// Setup upload — gunakan /tmp di Vercel (satu-satunya writable path)
const isVercel = process.env.VERCEL === '1' || process.env.NOW_REGION;

// ══════════════════════════════════════════════════════════════════
// FIX KEAMANAN (audit 22 Agu 2026): validasi MAGIC BYTES untuk file
// upload gambar. Multer fileFilter yang lama HANYA cek `file.mimetype`
// dari header Content-Type request -- itu diklaim oleh CLIENT, bisa
// dipalsukan dengan mudah (upload file .html/.php/.js apapun tapi kirim
// header "Content-Type: image/jpeg"). Kalau file itu nanti dibuka
// langsung di browser (mis. avatar/produk), ada risiko stored XSS atau
// worse tergantung bagaimana file itu di-render/diserve nantinya.
// Fungsi ini cek byte AWAL file (signature asli tiap format gambar),
// bukan cuma percaya klaim client -- defense-in-depth, dijalankan
// SETELAH multer fileFilter (yang tetap dipertahankan sebagai lapis
// pertama yang cepat), sebelum file dianggap final tersimpan.
function verifyImageMagicBytes(filePath) {
  try {
    const buf = Buffer.alloc(12);
    const fd = fs.openSync(filePath, 'r');
    fs.readSync(fd, buf, 0, 12, 0);
    fs.closeSync(fd);

    // JPEG: FF D8 FF
    if (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return true;
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47) return true;
    // GIF: "GIF87a" atau "GIF89a"
    if (buf.slice(0, 6).toString('ascii') === 'GIF87a' || buf.slice(0, 6).toString('ascii') === 'GIF89a') return true;
    // WEBP: "RIFF" (byte 0-3) + "WEBP" (byte 8-11)
    if (buf.slice(0, 4).toString('ascii') === 'RIFF' && buf.slice(8, 12).toString('ascii') === 'WEBP') return true;

    return false;
  } catch (e) {
    return false; // gagal baca file = anggap tidak valid, lebih aman daripada meloloskan
  }
}

// Middleware generik: pasang SETELAH multer upload single file, sebelum
// handler utama route. Kalau magic bytes tidak cocok gambar asli, hapus
// file yang sudah kepalang tersimpan dan tolak request.
function requireValidImageMagicBytes(req, res, next) {
  if (!req.file) return next(); // tidak ada file = biar divalidasi logic lain di handler
  if (!verifyImageMagicBytes(req.file.path)) {
    fs.unlink(req.file.path, () => {}); // best-effort cleanup, tidak perlu tunggu hasilnya
    return res.status(400).json({ success: false, message: 'File yang diupload bukan gambar asli (gagal validasi format file).' });
  }
  next();
}

// Versi buffer-based (untuk multer.memoryStorage(), req.file.buffer bukan
// req.file.path) -- dipakai endpoint yang upload langsung ke Supabase
// Storage tanpa nyimpen file sementara ke disk lokal dulu.
function verifyImageMagicBytesBuffer(buffer) {
  if (!buffer || buffer.length < 12) return false;
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return true;
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) return true;
  if (buffer.slice(0, 6).toString('ascii') === 'GIF87a' || buffer.slice(0, 6).toString('ascii') === 'GIF89a') return true;
  if (buffer.slice(0, 4).toString('ascii') === 'RIFF' && buffer.slice(8, 12).toString('ascii') === 'WEBP') return true;
  return false;
}

function requireValidImageMagicBytesBuffer(req, res, next) {
  if (!req.file) return next();
  if (!verifyImageMagicBytesBuffer(req.file.buffer)) {
    return res.status(400).json({ success: false, message: 'File yang diupload bukan gambar asli (gagal validasi format file).' });
  }
  next();
}

const uploadsBase = isVercel ? '/tmp' : path.join(__dirname, 'public', 'uploads');
const uploadsDir = isVercel ? '/tmp/products' : path.join(__dirname, 'public', 'uploads', 'products');

// Buat direktori lokal hanya jika bukan Vercel
if (!isVercel) {
  if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = isVercel ? '/tmp/products' : path.join(__dirname, 'public', 'uploads', 'products');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Hanya file gambar yang diizinkan'), false);
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: fileFilter
});

// Database helpers (Supabase)
const dbPath = path.join(__dirname, 'database');
if (!isVercel && !fs.existsSync(dbPath)) fs.mkdirSync(dbPath, { recursive: true });

const readDB = db.readDB;
const writeDB = db.writeDB;
const readFresh = db.readFresh;

// Banner lama (seed default "Open Reseller") tersimpan tanpa field `id` dan
// pakai key `url` bukan `imageUrl` — akibatnya tombol "Hapus"/"Toggle" di
// admin panel selalu gagal mencocokkan banner tersebut (id undefined !== id
// yang dikirim dari client) sehingga banner itu seolah tidak bisa dihapus.
// Banner default ini memang tidak diperlukan, jadi begitu terbaca langsung
// dibuang otomatis. Banner lain yang memang tidak punya `id` (kasus lama
// lainnya) tetap dipertahankan, hanya dibenahi id & imageUrl-nya.
function normalizeBanners(settings) {
  if (!Array.isArray(settings.banners)) return false;
  let changed = false;
  const isLegacyDefaultReseller = b => !b.id && b.url === '/uploads/banner-reseller.jpg' && b.title === 'Open Reseller' && b.link === '/reseller';
  const filtered = settings.banners.filter(b => !isLegacyDefaultReseller(b));
  if (filtered.length !== settings.banners.length) { settings.banners = filtered; changed = true; }
  settings.banners.forEach(b => {
    if (!b.id) { b.id = uuidv4(); changed = true; }
    if (!b.imageUrl && b.url) { b.imageUrl = b.url; changed = true; }
  });
  return changed;
}
const readSmart = db.readSmart; // TTL-based: auto-refresh jika cache >60 detik
const refreshForWrite = (...files) => Promise.all(files.map(f => db.refreshFromDB(f)));

// ── PERFORMANCE: leaderboard computation, di-cache & dioptimasi ──
// Sebelumnya logic ini di-copy-paste di beberapa tempat berbeda (homepage
// SSR, /leaderboard, /api/leaderboard), masing-masing men-scan ULANG
// seluruh transactions.forEach() lalu, untuk tiap user unik hasil agregasi,
// memanggil users.find() — yaitu scan ulang SELURUH array users untuk satu
// pencarian (N+1 pattern, O(transaksi × user_unik)).
// Fungsi ini menggantikan itu dengan:
//   1. Single-pass Map-based lookup untuk username (O(transaksi + user),
//      bukan O(transaksi × user_unik)) — hasil akhirnya identik, cuma
//      caranya dihitung yang lebih efisien.
//   2. Cache hasil selama LEADERBOARD_CACHE_TTL, supaya tidak dihitung
//      ulang dari nol pada tiap request dalam window waktu pendek.
let _leaderboardCache = null;
let _leaderboardCacheAt = 0;
const LEADERBOARD_CACHE_TTL = 30000; // 30 detik — leaderboard tidak butuh update per detik

const computeLeaderboard = () => {
  const now = Date.now();
  if (_leaderboardCache && (now - _leaderboardCacheAt) < LEADERBOARD_CACHE_TTL) {
    return _leaderboardCache;
  }

  const transactions = readDB('transactions.json');
  const users = readDB('users.json');

  // Map untuk lookup username O(1), dibangun sekali (bukan .find() berulang)
  const userById = new Map(users.map(u => [u.id, u]));

  const userStats = {};
  transactions.forEach(t => {
    if (t.status === 'done' && t.userId) {
      if (!userStats[t.userId]) userStats[t.userId] = { userId: t.userId, totalTransactions: 0, totalSpent: 0 };
      userStats[t.userId].totalTransactions++;
      userStats[t.userId].totalSpent += t.price;
    }
  });

  const entries = Object.values(userStats).map(stat => {
    const user = userById.get(stat.userId);
    return {
      userId: stat.userId,
      username: user?.username || 'User',
      photo: user?.photo || null,
      totalTransactions: stat.totalTransactions,
      totalSpent: stat.totalSpent,
      isReal: true
    };
  });

  entries.sort((a, b) => b.totalTransactions - a.totalTransactions || b.totalSpent - a.totalSpent);
  entries.forEach((item, i) => { item.rank = i + 1; });

  _leaderboardCache = entries;
  _leaderboardCacheAt = now;
  return entries;
};

// ── PERFORMANCE: user lookup Map, dipakai untuk hindari .find() berulang
// di tempat lain yang butuh cocokkan user by id/username (mis. testimonial
// photo attach) tanpa perlu cache TTL seperti leaderboard.
const buildUserLookupMaps = (users) => ({
  byId: new Map(users.map(u => [u.id, u])),
  byUsername: new Map(users.map(u => [u.username, u]))
});

// Initialize database files with defaults (only if truly missing)
const initDB = async () => {
  // JANGAN hardcode username/password admin di source code (ini yang
  // sebelumnya bocor lewat GitHub). Kalau env var tidak diset, generate
  // password random tiap kali server start dari nol, dan print SEKALI ke
  // log server (bukan ke kode) supaya bisa langsung dipakai lalu diganti.
  const crypto = require('crypto');
  const fallbackUsername = process.env.INITIAL_ADMIN_USERNAME || 'admin';
  const fallbackPassword = process.env.INITIAL_ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
  if (!process.env.INITIAL_ADMIN_PASSWORD) {
    console.log('🔐 Belum ada INITIAL_ADMIN_PASSWORD di env. Password admin awal di-generate random:');
    console.log(`   username: ${fallbackUsername}`);
    console.log(`   password: ${fallbackPassword}`);
    console.log('   GANTI password ini lewat Admin Panel setelah login pertama!');
  }

  const defaultSettings = {
    siteName: 'AGHA NL',
    gamePanelName: 'AGHA NL',
    // FIX SEO (diminta client 22 Agu 2026, target keyword "topup mod ff"):
    // deskripsi lebih spesifik menyebut nama game & jenis produk yang
    // dijual, supaya relevan untuk pencarian "topup mod ff", "key mod ff",
    // dll -- sebelumnya cuma "key mod aplikasi premium" (terlalu generik,
    // tidak menyebut game spesifik apapun).
    about: 'AGHA NL DIGITAL STORE adalah toko topup, files, dan access game terpercaya #1 di Indonesia. Proses cepat, 100% aman, dan harga terbaik dengan support 24 jam.',
    seoKeywords: 'agha nl, topup mod ff, key mod ff, cheat free fire, mod menu ff, topup mod game, jual key cheat, mod aplikasi premium, topup mod mobile legends',
    siteUrl: 'https://agha.nlstoreshop.my.id',
    marqueeText: 'TOP UP & FILES GAME TERMURAH, AMAN, DAN CEPAT!',
    contact: {
      whatsapp: '6282253090432',
      telegram: 'AghaNLOfficial',
      email: 'support@agha.nlstoreshop.my.id',
      youtube: '',
      waChannel: '',
      waGroup: '',
    },
    fonnteToken: '',
    pakasir: { apiKey: '', project: '', mode: 'production' },
    genspay: { apiKey: '', baseUrl: 'https://genspay.my.id/api/v1' },
    dripstore: { apiToken: '', baseUrl: 'https://dripclientstore.shop/api/v1', fulfillmentMode: 'live', balanceGuardEnabled: true, autoRestockEnabled: false, lowStockThreshold: 3, restockQty: 10 },
    apiGateway: 'pakasir',
    adminUsername: fallbackUsername,
    adminPassword: bcrypt.hashSync(fallbackPassword, 12),
    logoUrl: '/uploads/logo-main.png',
    logoTextUrl: '/uploads/logo-text.png',
    buyerGroupName: 'BUYER VIP BY AGHA NL',
    buyerGroupUrl: 'https://chat.whatsapp.com/DUSkETDjlxa5aksYJ0ar1m',
    resellerGroupName: 'RESELLER VIP BY AGHA NL',
    resellerGroupUrl: 'https://chat.whatsapp.com/GO9mZ1wec8LJwVmlpeSW7G',
    theme: {
      primaryColor: '#dc2626',
      secondaryColor: '#7b2cbf',
      accentColor: '#a3123a',
      backgroundColor: '#0a0a0a',
      cardBackground: '#141414',
      borderColor: '#3a1414',
      glowColor: '#dc2626',
    },
    categories: ['freefire', 'mlbb', 'pubgm', 'sertifikat'],
    categoryLabels: { freefire: 'FREE FIRE', mlbb: 'MOBILE LEGENDS', pubgm: 'PUBG MOBILE', sertifikat: 'SERTIFIKAT' },
    resellerEnabled: true,
    resellerPrice: 50000,
    resellerDiscount: 20,
    resellerNote: 'Dapatkan diskon eksklusif untuk semua produk!',
    resellerMinDeposit: 50000,
    memberMinDeposit: 10000,
    popularProductIds: [],
    fakeLeaderboard: [],
    banners: []
  };

  const arrayFiles = ['users.json', 'products.json', 'transactions.json', 'testimonials.json', 'notifications.json', 'keyspool.json', 'vouchers.json', 'dripstore_restock_requests.json'];

  // Seed arrays only if they don't exist at all
  for (const filename of arrayFiles) {
    const current = readDB(filename);
    if (!Array.isArray(current)) {
      await writeDB(filename, []);
    }
  }

  // Settings: merge defaults + existing. Jangan overwrite data yang sudah ada.
  const currentSettings = readDB('settings.json');
  if (!currentSettings || Object.keys(currentSettings).length === 0) {
    // Supabase kosong — push default penuh
    await writeDB('settings.json', defaultSettings);
    console.log('✅ Settings seeded with defaults');
  } else {
    // Merge: tambah field yang belum ada, jangan overwrite yang sudah ada
    let dirty = false;
    for (const [k, v] of Object.entries(defaultSettings)) {
      if (currentSettings[k] === undefined || currentSettings[k] === null) {
        currentSettings[k] = v;
        dirty = true;
      }
    }
    if (dirty) {
      await writeDB('settings.json', currentSettings);
      console.log('✅ Settings merged missing fields');
    }
  }

  // ── MIGRASI PRODUK LAMA ke sistem kategori baru (diminta client 22 Agu
  // 2026: gabung "platform" Android/iOS/PC hardcode jadi 1 sistem
  // "categories" yang admin atur bebas) ──
  // Sebelumnya produk lama masih tersimpan dengan field `platforms` (array
  // lama) atau `category` (string tunggal) di DATABASE-nya sendiri --
  // homepage/admin-product-edit sudah punya fallback tampilan yang baca
  // field lama ini, TAPI itu cuma "ngakalin" di level render, datanya
  // sendiri di database belum ikut berubah. Kalau admin belum pernah
  // buka+simpan ulang produk lama itu satu-satu, filter kategori baru
  // (yang scan field `categories`) tidak akan pernah menemukan produk itu
  // sama sekali. Migrasi ini jalan SEKALI tiap server start, permanen
  // convert field lama jadi `categories` array di database, supaya tidak
  // perlu admin re-save produk manual satu-satu.
  const productsForMigration = readDB('products.json');
  if (Array.isArray(productsForMigration) && productsForMigration.length > 0) {
    let productsMigrated = false;
    productsForMigration.forEach(p => {
      if (!Array.isArray(p.categories) || p.categories.length === 0) {
        if (Array.isArray(p.platforms) && p.platforms.length > 0) {
          p.categories = p.platforms;
          productsMigrated = true;
        } else if (p.category) {
          p.categories = [p.category];
          productsMigrated = true;
        }
      }
    });
    if (productsMigrated) {
      await writeDB('products.json', productsForMigration);
      console.log('✅ Produk lama dimigrasi ke sistem kategori baru (categories array)');
    }
  }
};

// Vercel: export app langsung (Vercel tidak pakai app.listen)
// Lokal: jalankan server setelah DB siap
if (isVercel) {
  // ── VERCEL FIX: pastikan DB init selesai sebelum request diproses ──
  let dbReady = false;
  let dbInitPromise = null;

  const ensureDBReady = async () => {
    if (dbReady) return;
    if (!dbInitPromise) {
      dbInitPromise = db.initializeDB().then(() => initDB()).then(() => { dbReady = true; });
    }
    await dbInitPromise;
  };

  // Vercel: jangan menahan request sampai initializeDB() selesai. Cold-start
  // initialization sebelumnya bisa menunggu Supabase + seed/migration lalu
  // membuat halaman terlihat stuck. Jalankan warm-up sekali di background;
  // route publik memakai readSmart/readFresh sendiri bila cache belum siap.
  app.use((req, res, next) => {
    ensureDBReady().catch(e => console.error('[DB] Background init failed:', e.message));
    next();
  });

  module.exports = app;
} else {
  // Lokal / VPS: tunggu DB siap baru listen
  db.initializeDB().then(() => {
    initDB(); // seed defaults only if missing
    app.listen(PORT, () => {
      console.log(`✅ Server berjalan di http://localhost:${PORT}`);
      console.log(`📁 Database: ${dbPath}`);
      console.log(`🔐 Admin: /admin`);
    });
  }).catch(err => {
    console.error('Fatal: Failed to initialize database:', err);
    process.exit(1);
  });
  module.exports = app;
}

// Helper: dapatkan user dari session (support admin yang tidak ada di users.json)
// Helper: konversi warna hex ("#dc2626") jadi rgba string dengan alpha
// tertentu. Dipakai supaya elemen UI yang butuh warna tema TRANSPARAN
// (background badge, border tipis, dll) tetap ikut warna tema custom dari
// admin panel (settings.theme.*), bukan hardcode merah. Kalau input bukan
// hex valid (mis. sudah rgba/CSS var lain), balikin fallback rgba abu netral.
function hexToRgba(hex, alpha) {
  if (!hex || typeof hex !== 'string' || !hex.startsWith('#')) return `rgba(148,163,184,${alpha})`;
  const clean = hex.replace('#', '');
  const full = clean.length === 3 ? clean.split('').map(c => c + c).join('') : clean;
  if (full.length !== 6) return `rgba(148,163,184,${alpha})`;
  const r = parseInt(full.slice(0, 2), 16), g = parseInt(full.slice(2, 4), 16), b = parseInt(full.slice(4, 6), 16);
  if ([r, g, b].some(isNaN)) return `rgba(148,163,184,${alpha})`;
  return `rgba(${r},${g},${b},${alpha})`;
}

const getSessionUser = (req) => {
  if (req.session?.isAdmin) {
    const s = readDB('settings.json');
    return { id: 'admin', username: s.adminUsername || 'Admin', isAdmin: true, photo: null, role: 'admin', is_reseller: false };
  }
  if (req.session?.userId) return readDB('users.json').find(u => u.id === req.session.userId) || null;
  return null;
};

// Auth middleware
const requireAuth = (req, res, next) => {
  if (!req.session?.userId) {
    if (req.xhr || req.headers['content-type']?.includes('application/json')) {
      return res.json({ success: false, message: 'Silakan login terlebih dahulu', redirect: '/login' });
    }
    return res.redirect('/login?redirect=' + encodeURIComponent(req.originalUrl));
  }
  next();
};

// Semua route admin bersifat dinamis & privat: jangan pernah di-cache browser/proxy.
app.use('/admin', (req, res, next) => { res.set('Cache-Control', 'no-store, max-age=0'); next(); });

const requireAdmin = async (req, res, next) => {
  if (!req.session?.isAdmin && req.session?.userId !== 'admin') {
    // Balas 404 bukan 403 agar penyerang tidak tahu route admin ada
    return res.status(404).send('Not found');
  }

  // ── Single-Device Admin Lock ──────────────────────────────────
  // Mencegah 2 orang (mis: web dev + client) login admin bersamaan di
  // device berbeda. Login bersamaan menyebabkan race condition saat
  // keduanya baca-ubah-simpan data produk di waktu hampir sama, sehingga
  // perubahan salah satu pihak tertimpa / produk "berubah-ubah" saat refresh.
  //
  // PENTING: pakai readFresh (bukan readDB) di sini. Vercel menjalankan
  // banyak instance serverless yang TIDAK berbagi memori — kalau pakai
  // cache lokal, satu instance bisa "telat tahu" kalau device lain baru
  // saja ambil alih sesi, dan tetap meloloskan device yang seharusnya
  // sudah diblokir. Ini satu-satunya pengecekan yang wajib selalu fresh.
  const lock = await db.readFresh('admin-lock.json');
  if (isLockActive(lock) && lock.sessionId !== req.session.adminSessionId) {
    req.session = null; // paksa logout sesi yang sudah digantikan
    if (ADMIN_PAGE_ROUTES.has(req.path)) {
      return res.redirect('/vpr-secure-panel-8x?kicked=1');
    }
    return res.status(401).json({
      success: false,
      sessionRevoked: true,
      message: `Sesi admin Anda diakhiri karena ada login dari perangkat lain (${lock.device || 'perangkat lain'}).`
    });
  }

  // Sesi ini pemegang lock yang sah → perpanjang heartbeat (di-throttle,
  // supaya tidak nulis ke Supabase di setiap request)
  touchAdminLock(req.session.adminSessionId, lock);

  next();
};

// Halaman admin yang dimuat lewat navigasi browser biasa (bukan fetch/XHR)
// → kalau lock-nya hilang, redirect ke halaman login, bukan balas JSON.
const ADMIN_PAGE_ROUTES = new Set(['/admin', '/admin/product-edit', '/admin/theme-settings', '/admin/logs']);

// Lock dianggap kosong/expired kalau tidak ada heartbeat selama ini
// (mis: tab ditutup / koneksi putus tanpa logout resmi).
const ADMIN_LOCK_TIMEOUT_MS = 6 * 60 * 1000; // 6 menit

const parseDeviceLabel = (ua = '') => {
  let browser = 'Browser';
  if (/edg/i.test(ua)) browser = 'Edge';
  else if (/chrome/i.test(ua)) browser = 'Chrome';
  else if (/firefox/i.test(ua)) browser = 'Firefox';
  else if (/safari/i.test(ua)) browser = 'Safari';
  let os = 'Unknown';
  if (/android/i.test(ua)) os = 'Android';
  else if (/iphone|ipad|ios/i.test(ua)) os = 'iOS';
  else if (/windows/i.test(ua)) os = 'Windows';
  else if (/mac os/i.test(ua)) os = 'Mac';
  else if (/linux/i.test(ua)) os = 'Linux';
  return `${browser} · ${os}`;
};

const isLockActive = (lock) => {
  if (!lock || !lock.sessionId || !lock.lastSeen) return false;
  return (Date.now() - new Date(lock.lastSeen).getTime()) < ADMIN_LOCK_TIMEOUT_MS;
};

// Klaim lock untuk sesi admin yang baru login. Dipanggil SETELAH password
// terverifikasi & lock lama dipastikan kosong/expired (lihat route login).
const acquireAdminLock = async (req) => {
  const sessionId = uuidv4();
  await writeDB('admin-lock.json', {
    sessionId,
    ip: req.ip,
    device: parseDeviceLabel(req.headers['user-agent'] || ''),
    loginAt: new Date().toISOString(),
    lastSeen: new Date().toISOString()
  });
  return sessionId;
};

// Lepas lock saat logout resmi — supaya device lain bisa langsung login
// tanpa harus menunggu timeout.
const releaseAdminLock = async (sessionId) => {
  if (!sessionId) return;
  try {
    const lock = await db.readFresh('admin-lock.json');
    if (lock && lock.sessionId === sessionId) await writeDB('admin-lock.json', {});
  } catch {}
};

// Heartbeat di-throttle per sessionId supaya tidak nulis ke Supabase di
// setiap request admin (cukup tiap ≥60 detik aktivitas). `lock` di sini
// sudah hasil readFresh dari requireAdmin, jadi tidak perlu baca ulang.
const lastHeartbeatAt = new Map();
const touchAdminLock = (sessionId, lock) => {
  if (!sessionId || !lock || lock.sessionId !== sessionId) return;
  const now = Date.now();
  if (now - (lastHeartbeatAt.get(sessionId) || 0) < 60000) return;
  lastHeartbeatAt.set(sessionId, now);
  writeDB('admin-lock.json', { ...lock, lastSeen: new Date().toISOString() }).catch(() => {});
};

// Helper functions
// FIX KEAMANAN (audit 22 Agu 2026): Math.random() bukan cryptographically
// secure -- untuk kode yang berfungsi sebagai "kunci akses" ke data
// transaksi (dipakai di /invoice untuk lacak pesanan tanpa akun), lebih
// aman pakai crypto.randomBytes() yang tidak predictable. Kombinasi rate
// limit (lihat checkInvoiceRateLimit) + entropy kode ini (32^8 ≈ 1 triliun
// kombinasi) sudah memadai terhadap brute-force dari 1 IP, ini upgrade
// defense-in-depth tambahan.
const generateOrderCode = () => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const randomBytes = crypto.randomBytes(8);
  let code = 'FX-';
  for (let i = 0; i < 4; i++) code += chars[randomBytes[i] % chars.length];
  code += '-';
  for (let i = 4; i < 8; i++) code += chars[randomBytes[i] % chars.length];
  return code;
};

const formatDate = (date = new Date()) => {
  const d = new Date(date);
  const day = String(d.getDate()).padStart(2, '0');
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const year = d.getFullYear();
  const hours = String(d.getHours()).padStart(2, '0');
  const minutes = String(d.getMinutes()).padStart(2, '0');
  return `${day}/${month}/${year} ${hours}:${minutes}`;
};

// ── PakKasir API (app.pakasir.com) ──
const createQRISPaymentPakasir = (orderId, amount, settings) => {
  return new Promise((resolve, reject) => {
    const apiKey = settings.pakasir?.apiKey?.trim() || '';
    const project = settings.pakasir?.project?.trim() || '';
    if (!apiKey || !project) return reject(new Error('API Key atau Project PakKasir belum dikonfigurasi'));

    const body = JSON.stringify({ project, order_id: orderId, amount, api_key: apiKey });
    const req = https.request({
      hostname: 'app.pakasir.com', port: 443,
      path: '/api/transactioncreate/qris', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      timeout: 15000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const r = JSON.parse(data);
          const qr = r.payment?.payment_number || r.payment_number || r.qr_string || r.data?.payment_number;
          if (!qr) return reject(new Error(r.message || `Pakasir error: ${data.slice(0,100)}`));
          resolve({ qr_string: qr, total_payment: r.payment?.total_payment || amount, expired_at: r.payment?.expired_at || null });
        } catch(e) { reject(new Error('Gagal parse response PakKasir')); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('PakKasir timeout')); });
    req.on('error', e => reject(_dsTransientError('Network error: ' + e.message)));
    req.write(body); req.end();
  });
};

// ── GensPay API (genspay.my.id) ──
// 📖 Dokumentasi Integrasi: https://genspay.my.id/docs
// Base URL API: https://genspay.my.id/api/v1
// Cara pakai (SESUAI dokumentasi resmi, sama seperti diterapkan di
// project GhostNewEra):
//   1. Buat project di Dashboard → menu Project → dapat API Key
//   2. Kirim API Key di header X-API-Key pada SETIAP request
//   3. POST /transaction/create untuk generate QRIS (body wajib include
//      payment_method: "qris")
//   4. TIDAK ADA endpoint GET status manual / cancel -- status transaksi
//      HANYA dikirim lewat webhook (event "transaction.updated", lihat
//      app.post('/webhook/genspay')).
const createQRISPaymentGenspay = (orderId, amount, settings) => {
  return new Promise((resolve, reject) => {
    const baseUrl = (settings.genspay?.baseUrl || process.env.GENSPAY_BASE_URL || 'https://genspay.my.id/api/v1').trim();
    const apiKey = (settings.genspay?.apiKey || process.env.GENSPAY_API_KEY || '').trim();
    if (!apiKey) return reject(new Error('API Key GensPay belum dikonfigurasi'));

    let url;
    try { url = new URL(baseUrl.replace(/\/+$/, '') + '/transaction/create'); } catch (e) { return reject(new Error('Base URL GensPay tidak valid')); }

    const body = JSON.stringify({ amount, order_id: orderId, payment_method: 'qris' });
    const req = https.request({
      hostname: url.hostname, port: url.port || 443,
      path: url.pathname + url.search, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey, 'Content-Length': Buffer.byteLength(body) },
      timeout: 15000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const r = JSON.parse(data);
          const qr = r.data?.qr_string;
          if (!r.success || !qr) return reject(new Error(r.error || r.message || `GensPay error (HTTP ${res.statusCode}): ${data.slice(0,150)}`));
          resolve({ qr_string: qr, total_payment: r.data?.amount || amount, expired_at: r.data?.expiry_time || null });
        } catch(e) { reject(new Error(`Gagal parse response GensPay (HTTP ${res.statusCode}): ${data.slice(0,200) || '(response kosong)'}`)); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('GensPay timeout')); });
    req.on('error', e => reject(new Error('Network error: ' + e.message)));
    req.write(body); req.end();
  });
};

// ══════════════════════════════════════════════════════════════════
// DRIP STORE RESELLER API (dripclientstore.shop) — supplier key/stok
// buat produk-produk mod-menu (dokumentasi dari client library resmi
// yang dikasih owner DripStore ke client aghanl, 16 Sep 2026).
//
// BEDA PENTING dari GensPay/Pakasir: ini BUKAN payment gateway, ini API
// buat BELI STOK KEY dari supplier (motong saldo reseller DripStore
// tiap generate). Dipakai buat 2 hal:
//   1. Tombol manual "Restock dari DripStore" di admin-product-edit
//   2. Auto-restock opsional: begitu stok durasi tertentu tersisa
//      <= threshold pas ada penjualan, otomatis generate key baru
//      (lihat maybeAutoRestockDripstore() di bawah)
//
// Auth: header X-API-Token (BUKAN X-API-Key kayak GensPay).
// Endpoint dasar: balance.php, products.php, generate_key.php (POST),
// reset_apis.php, reset_key.php (POST), key_history.php.
// Rate limit: retry SEKALI kalau kena 429, hormati header Retry-After
// (persis seperti client Node.js resmi dari DripStore).
//
// CATATAN JUJUR: dokumentasi yang kami terima cuma nunjukkin CONTOH
// ERROR (401/403/423/429/5xx) secara detail, TIDAK ada contoh response
// SUKSES generate_key.php. extractDripstoreKeys() di bawah nyoba
// beberapa bentuk response yang umum (data.keys, data.key, dst) --
// kalau ternyata bentuknya beda, error akan nunjukkin RAW response biar
// gampang di-debug, bukan gagal diam-diam.
// Error sementara (timeout / network / 5xx / respons non-JSON dari proxy) ditandai
// `transient` supaya GET boleh diulang SEKALI. POST (generate_key.php) TIDAK
// pernah diulang otomatis karena bisa membeli key dua kali.
function _dsTransientError(message) {
  const err = new Error(message);
  err.transient = true;
  return err;
}

// ── CIRCUIT BREAKER + COALESCING + MICRO-CACHE (fix limit "Daily request limit reached") ──
// AKAR MASALAH (audit 23 Sep 2026): begitu provider balas 429, kode lama tetap
// nembak request baru di SETIAP page load / cek stok / checkout, padahal
// provider sudah bilang "retry-after". Tiap request yang ditolak tetap
// dihitung ke kuota harian, jadi limit tidak pernah sempat pulih. Sekarang:
//   1. Kena 429  -> breaker BUKA sampai waktu retry-after (min 60s). Selama
//      buka, SEMUA GET langsung fail-fast TANPA menyentuh jaringan/provider.
//      POST generate_key.php TIDAK diblok breaker "soft" supaya order yang
//      sudah dibayar tetap dicoba; tapi kalau limit HARIAN (bukan per menit)
//      breaker dipaksa lebih lama (lihat _dsBackoffSeconds).
//   2. GET identik yang sedang jalan digabung jadi 1 request (coalescing).
//   3. GET products.php / balance.php di-cache singkat di memori supaya
//      urutan checkout (create -> guard -> fulfil) tidak memukul provider
//      berkali-kali dalam hitungan detik.
const _dsBreaker = { openUntil: 0, reason: '', hits429: 0 };
const _dsInflight = new Map();   // key -> Promise (coalescing GET identik)
const _dsMicroCache = new Map(); // key -> { at, ttl, value }
const DS_MICRO_TTL = { 'products.php': 20000, 'balance.php': 8000 }; // ms
const DS_MIN_BACKOFF_SEC = 60;
const DS_DAILY_LIMIT_BACKOFF_SEC = 15 * 60; // limit HARIAN: jangan coba lagi 15 menit

function _dsBackoffSeconds(message, headerWait) {
  const isDaily = /daily/i.test(String(message || ''));
  let sec = Number.isFinite(headerWait) ? headerWait : DS_MIN_BACKOFF_SEC;
  sec = Math.max(DS_MIN_BACKOFF_SEC, sec);
  if (isDaily) sec = Math.max(sec, DS_DAILY_LIMIT_BACKOFF_SEC);
  return Math.min(sec, 3600);
}
function _dsTripBreaker(message, headerWait) {
  const sec = _dsBackoffSeconds(message, headerWait);
  const until = Date.now() + sec * 1000;
  if (until > _dsBreaker.openUntil) {
    _dsBreaker.openUntil = until;
    _dsBreaker.reason = String(message || 'Rate limit DripStore');
    _dsBreaker.hits429++;
    console.warn(`[dripstore breaker] BUKA ${sec}s: ${_dsBreaker.reason}. Semua GET ke provider dihentikan sampai ${new Date(until).toISOString()}`);
  }
}
function dripstoreBreakerState() {
  const remaining = Math.max(0, _dsBreaker.openUntil - Date.now());
  return { open: remaining > 0, retryAfterSec: Math.ceil(remaining / 1000), reason: _dsBreaker.reason };
}
function _dsBreakerError() {
  const st = dripstoreBreakerState();
  const err = new Error(`Provider DripStore sedang dibatasi (rate limit). Dicoba lagi otomatis dalam ${st.retryAfterSec}s. ${st.reason}`);
  err.rateLimited = true;
  err.retryAfterSec = st.retryAfterSec;
  return err;
}

async function dripstoreCall(settings, endpoint, params = {}, method = 'GET', _retried = false) {
  const isGet = String(method).toUpperCase() === 'GET';

  if (isGet) {
    // Breaker terbuka: fail-fast, JANGAN sentuh provider.
    if (dripstoreBreakerState().open) throw _dsBreakerError();

    const cacheKey = endpoint + '?' + new URLSearchParams(params).toString() + '|' + _getDripstoreCatalogSignature(settings);
    const ttl = DS_MICRO_TTL[endpoint] || 0;
    if (ttl) {
      const hit = _dsMicroCache.get(cacheKey);
      if (hit && (Date.now() - hit.at) < ttl) return hit.value;
    }
    // Coalescing: request GET identik yang sedang terbang dibagi hasilnya.
    if (_dsInflight.has(cacheKey)) return _dsInflight.get(cacheKey);

    const p = (async () => {
      try {
        let value;
        try {
          value = await _dripstoreCallOnce(settings, endpoint, params, method, _retried);
        } catch (e) {
          if (!e?.transient || _retried) throw e;
          await new Promise(r => setTimeout(r, 250));
          value = await _dripstoreCallOnce(settings, endpoint, params, method, true);
        }
        if (ttl) _dsMicroCache.set(cacheKey, { at: Date.now(), ttl, value });
        return value;
      } finally {
        _dsInflight.delete(cacheKey);
      }
    })();
    _dsInflight.set(cacheKey, p);
    return p;
  }

  // POST (generate_key.php / reset): tidak pernah di-retry & tidak di-cache.
  return _dripstoreCallOnce(settings, endpoint, params, method, _retried);
}

// Wrapper pencatat: setiap request NYATA ke provider (bukan yang dilayani cache/breaker)
// dicatat beserta pemicunya. Parameter TIDAK dicatat (bisa berisi data sensitif).
function _dripstoreCallOnce(settings, endpoint, params = {}, method = 'GET', _retried = false) {
  const t0 = Date.now();
  const ctx = _reqCtx.getStore();
  const who = ctx ? `${ctx.method} ${ctx.path}` : 'background/warm';
  const m = String(method).toUpperCase();
  const key = `${m} ${endpoint}`;
  _dsStats.calls[key] = (_dsStats.calls[key] || 0) + 1;
  const wk = (Object.keys(_dsStats.byWho).length < 40 || _dsStats.byWho[who] !== undefined) ? who : 'lainnya';
  _dsStats.byWho[wk] = (_dsStats.byWho[wk] || 0) + 1;
  return _dripstoreCallOnceRaw(settings, endpoint, params, m, _retried).then((v) => {
    _dsStats.ok++;
    pushLog('info', `[dripstore] ${key} OK ${Date.now() - t0}ms <- ${who}${_retried ? ' (retry)' : ''}`, { cat: 'dripstore' });
    return v;
  }, (e) => {
    const rl = !!(e && e.rateLimited);
    if (rl) { _dsStats.rateLimited++; _dsStats.last429At = Date.now(); } else { _dsStats.err++; }
    pushLog(rl ? 'warn' : 'error', `[dripstore] ${key} GAGAL ${Date.now() - t0}ms <- ${who}: ${(e && e.message) || e}`, { cat: 'dripstore' });
    throw e;
  });
}

function _dripstoreCallOnceRaw(settings, endpoint, params = {}, method = 'GET', _retried = false) {
  return new Promise((resolve, reject) => {
    const token = (settings.dripstore?.apiToken || '').trim();
    const baseUrl = (settings.dripstore?.baseUrl || 'https://dripclientstore.shop/api/v1').trim();
    if (!token) return reject(new Error('API Token DripStore belum dikonfigurasi di Settings'));
    let url;
    try { url = new URL(baseUrl.replace(/\/+$/, '') + '/' + endpoint.replace(/^\/+/, '')); } catch (e) { return reject(new Error('Base URL DripStore tidak valid')); }
    const isGet = method.toUpperCase() === 'GET';
    let body = '';
    const headers = { 'X-API-Token': token, 'Accept': 'application/json' };
    if (isGet) {
      const qs = new URLSearchParams(params).toString();
      if (qs) url.search = qs;
    } else {
      body = new URLSearchParams(params).toString();
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      headers['Content-Length'] = Buffer.byteLength(body);
    }
    const req = https.request({
      hostname: url.hostname, port: url.port || 443,
      path: url.pathname + url.search, method: method.toUpperCase(),
      headers, timeout: isGet ? 4000 : 5000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', async () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch (e) { return reject(_dsTransientError(`Respons DripStore bukan JSON valid (HTTP ${res.statusCode}): ${data.slice(0, 200)}`)); }
        if (res.statusCode === 401) return reject(new Error(parsed.error || 'Token DripStore tidak valid / sudah dicabut'));
        if (res.statusCode === 403) return reject(new Error(parsed.error || 'Akses ditolak DripStore (kemungkinan IP server kamu diblokir)'));
        if (res.statusCode === 423) return reject(new Error(parsed.error || 'Batas reset key tercapai (maks 3x seumur hidup per key)'));
        if (res.statusCode === 429) {
          let wait = 60;
          const ra = res.headers['retry-after'];
          if (ra && /^\d+$/.test(ra)) wait = Math.min(120, Math.max(1, parseInt(ra, 10)));
          // Jangan pernah menahan request HTTP sampai 60-120 detik hanya karena 429.
          // Di Vercel ini bisa membuat user merasa website hang dan membakar waktu
          // function. Kalau provider minta retry > 2 detik, fail-fast; caller memakai
          // cache/last-known-good atau menampilkan status sementara.
          if (!_retried && wait <= 2) {
            await new Promise(r => setTimeout(r, wait * 1000));
            try { resolve(await _dripstoreCallOnce(settings, endpoint, params, method, true)); } catch (e) { reject(e); }
            return;
          }
          // Trip breaker: hentikan SEMUA GET berikutnya sampai limit pulih.
          _dsTripBreaker(parsed.error || parsed.message || 'Rate limit DripStore tercapai', (ra && /^\d+$/.test(ra)) ? parseInt(ra, 10) : NaN);
          const rl = new Error(`${parsed.error || 'Rate limit DripStore tercapai'} (retry-after ${wait}s)`);
          rl.rateLimited = true;
          return reject(rl);
        }
        if (res.statusCode >= 500) return reject(_dsTransientError(`DripStore server error ${res.statusCode}: ${parsed.error || 'coba lagi nanti'}`));
        if (parsed.success === false) return reject(new Error(parsed.error || parsed.message || 'DripStore mengembalikan success:false tanpa pesan error'));
        resolve(parsed);
      });
    });
    req.on('timeout', () => { req.destroy(); reject(_dsTransientError('DripStore timeout (' + (isGet ? 4 : 5) + ' detik)')); });
    req.on('error', e => reject(new Error('Network error: ' + e.message)));
    if (!isGet && body) req.write(body);
    req.end();
  });
}

// Coba beberapa bentuk response generate_key.php yang umum dipakai API
// sejenis. Kalau gak ketemu satupun, lempar RAW response di error message
// (jangan silent-fail) biar gampang disesuaikan begitu tau bentuk aslinya.
function extractDripstoreKeys(resp) {
  const candidates = [
    resp?.data?.keys, resp?.keys, resp?.data?.key_list, resp?.key_list,
    (typeof resp?.data?.key === 'string' ? [resp.data.key] : null),
    (typeof resp?.key === 'string' ? [resp.key] : null),
    (Array.isArray(resp?.data) ? resp.data : null),
  ];
  for (const c of candidates) {
    if (Array.isArray(c) && c.length > 0) return c.map(k => (typeof k === 'string' ? k : (k?.key || k?.license_key || JSON.stringify(k))));
  }
  throw new Error('Key berhasil digenerate tapi bentuk response tidak dikenali, cek manual: ' + JSON.stringify(resp).slice(0, 300));
}


// ── DripStore Product Auto-Mapping ────────────────────────────────────────────
// Mengubah daftar product/variant dari products.php menjadi mapping yang bisa
// dipakai AGHA NL tanpa admin perlu mengisi variant_id satu per satu.
function _dsFirst(obj, keys) {
  for (const key of keys) {
    if (obj && obj[key] !== undefined && obj[key] !== null && obj[key] !== '') return obj[key];
  }
  return null;
}

function _dsNormalizeName(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[_|/\\-]+/g, ' ')
    .replace(/[^a-z0-9\s]/g, ' ')
    // Buang label durasi agar nama produk tetap bisa dicocokkan. Tahun/thn
    // juga dibuang supaya `Gbox 1 thn` == `Gbox 365 hari`.
    .replace(/\b\d+\s*(hari|day|days|d|jam|hour|hours|h|thn|th|tahun|year|years|yr|yrs)\b/gi, ' ')
    .replace(/\b(\d+)\s*(thn|th|tahun|year|years|yr|yrs)\b/gi, ' ')
    .replace(/\b\d+d\b/gi, ' ')
    .replace(/\b\d+h\b/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function _dsDurationFromText(value) {
  const text = String(value || '').toLowerCase().trim();
  let m = text.match(/(^|\b)(\d+)\s*(hours?|hrs?|jam|h)\b/);
  if (m) return { days: parseInt(m[2], 10), unit: 'h' };

  // Provider bisa menulis durasi tahun sebagai `1 tahun`, `1 thn`, `1 th`,
  // `1 year`, dst. Di sistem internal, satuan provider tetap dinormalisasi
  // menjadi hari untuk menjaga schema pricingOptions tetap kompatibel.
  m = text.match(/(^|\b)(\d+)\s*(tahun|thn|th|years?|yr|yrs|year)\b/);
  if (m) return { days: parseInt(m[2], 10) * 365, unit: 'd', sourceUnit: 'y' };

  m = text.match(/(^|\b)(\d+)\s*(days?|hari|d)\b/);
  if (m) return { days: parseInt(m[2], 10), unit: 'd' };
  m = text.match(/(?:^|[^0-9])(\d+)h(?:$|[^a-z0-9])/);
  if (m) return { days: parseInt(m[1], 10), unit: 'h' };
  m = text.match(/(?:^|[^0-9])(\d+)d(?:$|[^a-z0-9])/);
  if (m) return { days: parseInt(m[1], 10), unit: 'd' };
  return null;
}

// Normalisasi satu item/option produk untuk halaman beli. `pricingOptions`
// adalah sumber data durasi + harga, sedangkan `items` hanya representasi
// tampilan lama. Kalau keduanya beda, jangan biarkan menu memakai items stale.
function normalizeProductBuyOptions(product) {
  const rawOptions = Array.isArray(product?.pricingOptions) ? product.pricingOptions : [];
  const rawItems = Array.isArray(product?.items) ? product.items : [];
  const outOptions = [];
  const outItems = [];

  if (rawOptions.length) {
    rawOptions.forEach((raw, index) => {
      const opt = { ...raw };
      const item = rawItems[index] || null;
      const parsedLabel = item?.l ? parseDurationLabel(item.l) : null;

      // Legacy Gbox/produk tahun pernah tersimpan sebagai days=1 + label
      // `1 THN`. Perbaiki nilai internal menjadi 365d agar provider mapping
      // dan create-order menggunakan variant yang benar.
      if (parsedLabel?.unit === 'y') {
        opt.days = parsedLabel.value * 365;
        opt.unit = 'd';
      } else {
        opt.days = Number(opt.days);
        opt.unit = opt.unit === 'h' ? 'h' : 'd';
      }
      if (!Number.isFinite(opt.days) || opt.days <= 0) return;

      const label = String(item?.l || `${product.name || 'PRODUK'} ${formatDurationLabel(opt.days, opt.unit)}`);
      const price = Number(opt.price ?? item?.p ?? 0);
      const resellerPrice = opt.reseller_price != null ? opt.reseller_price : (item?.reseller_price ?? null);
      const strikePrice = opt.strike_price != null ? opt.strike_price : (item?.strike_price ?? null);

      outOptions.push(opt);
      outItems.push({
        ...item,
        l: label,
        p: Number.isFinite(price) ? price : 0,
        reseller_price: resellerPrice,
        strike_price: strikePrice,
        durationValue: opt.days,
        durationUnit: opt.unit
      });
    });
  } else if (rawItems.length) {
    // Backward compatibility untuk produk lama yang hanya punya items.
    rawItems.forEach(item => {
      const parsed = parseDurationLabel(item?.l || '');
      const days = parsed ? (parsed.unit === 'y' ? parsed.value * 365 : parsed.value) : null;
      const unit = parsed?.unit === 'h' ? 'h' : 'd';
      outItems.push({ ...item, durationValue: days, durationUnit: unit });
      if (days) outOptions.push({
        days, unit, price: Number(item?.p || 0),
        reseller_price: item?.reseller_price ?? null,
        strike_price: item?.strike_price ?? null,
        dripstoreVariantId: null
      });
    });
  }

  return { ...product, pricingOptions: outOptions, items: outItems };
}

function parseDurationLabel(value) {
  const text = String(value || '').trim();
  let m = text.match(/(\d+)\s*(JAM|HOURS?|H)\b/i);
  if (m) return { value: Number(m[1]), unit: 'h' };
  m = text.match(/(\d+)\s*(THN|TH|TAHUN|YEARS?|YEAR|YR|YRS)\b/i);
  if (m) return { value: Number(m[1]), unit: 'y' };
  m = text.match(/(\d+)\s*(DAYS?|HARI|D)\b/i);
  if (m) return { value: Number(m[1]), unit: 'd' };
  m = text.match(/(?:^|[^0-9])(\d+)h(?:$|[^a-z0-9])/i);
  if (m) return { value: Number(m[1]), unit: 'h' };
  m = text.match(/(?:^|[^0-9])(\d+)d(?:$|[^a-z0-9])/i);
  if (m) return { value: Number(m[1]), unit: 'd' };
  return null;
}

function _dsExtractProductItems(resp) {
  const out = [];
  const seen = new Set();
  const productNameKeys = ['product_name', 'productName', 'product_title', 'productTitle'];
  const variantNameKeys = ['variant_name', 'variantName', 'variant_title', 'variantTitle', 'label', 'l', 'variant'];
  const childKeys = ['variants', 'options', 'plans', 'items', 'products', 'data', 'result'];

  const walk = (node, parentProductName = '') => {
    if (!node) return;
    if (Array.isArray(node)) { node.forEach(x => walk(x, parentProductName)); return; }
    if (typeof node !== 'object') return;

    // PENTING: `name` pada object variant biasanya adalah NAMA VARIANT
    // (mis. "3 hari"), bukan nama produk. Versi lama mengambil `name` di sini
    // sebagai productName lalu menimpa inheritance parent saat masuk ke
    // `variants[]`; akibatnya mapping XREG -> AIM HACK gagal total karena
    // productName menjadi "3 hari".
    const explicitProduct = _dsFirst(node, productNameKeys);
    const genericName = _dsFirst(node, ['name', 'title']);
    const productField = _dsFirst(node, ['product']);
    let productName = typeof explicitProduct === 'string' ? explicitProduct : parentProductName;
    if (!productName && typeof productField === 'string') productName = productField;

    const variantId = _dsFirst(node, ['variant_id', 'variantId', 'id']);
    const explicitVariantName = _dsFirst(node, variantNameKeys);
    const variantName = explicitVariantName != null ? explicitVariantName : genericName;
    const explicitDays = _dsFirst(node, ['days', 'duration_days', 'durationDays']);
    const explicitHours = _dsFirst(node, ['hours', 'duration_hours', 'durationHours']);
    const explicitDuration = _dsFirst(node, ['duration', 'duration_label', 'durationLabel']);
    const explicitUnit = _dsFirst(node, ['unit', 'duration_unit', 'durationUnit']);
    let duration = null;
    const unitText = String(explicitUnit || '').toLowerCase().trim();
    const isYearUnit = /^(y|yr|yrs|year|years|th|thn|tahun)$/i.test(unitText);
    if (explicitHours !== null && Number(explicitHours) > 0) duration = { days: Number(explicitHours), unit: 'h' };
    else if (explicitDays !== null && Number(explicitDays) > 0) {
      if (isYearUnit) duration = { days: Number(explicitDays) * 365, unit: 'd', sourceUnit: 'y' };
      else duration = { days: Number(explicitDays), unit: unitText === 'h' ? 'h' : 'd' };
    }
    if (!duration && explicitDuration != null) duration = _dsDurationFromText(String(explicitDuration));
    if (!duration) duration = _dsDurationFromText(`${variantName || ''}`);

    // Kalau node memiliki nested variants/items dan belum punya product name,
    // generic `name`/`title` di node ini biasanya adalah nama PRODUK. Pakai
    // sebagai parent, tetapi jangan jadikan node container sebagai variant
    // hanya karena ia memiliki id yang kebetulan ada.
    const hasChildren = childKeys.some(k => node[k] !== undefined);
    const containerName = (!productName && typeof genericName === 'string' && hasChildren)
      ? genericName.trim() : '';
    const inheritedForChildren = productName || containerName || parentProductName;
    if (containerName) productName = containerName;

    if (variantId !== null && (productName || variantName) && duration && !seen.has(String(variantId))) {
      // Jangan emit container product sebagai variant bila ia hanya memiliki
      // nested variants/items dan durasinya datang dari nama produk kebetulan.
      const looksLikeContainer = hasChildren && !explicitVariantName && !explicitDays && !explicitHours && !explicitDuration;
      if (!looksLikeContainer) {
        seen.add(String(variantId));
        out.push({
          variantId: String(variantId),
          productName: String(productName || parentProductName || '').trim(),
          variantName: String(variantName || genericName || '').trim(),
          days: Number(duration.days),
          unit: duration.unit === 'h' ? 'h' : 'd',
          raw: node,
        });
      }
    }

    for (const key of childKeys) {
      if (node[key] !== undefined) walk(node[key], inheritedForChildren);
    }
  };
  walk(resp, '');
  return out;
}

const DRIPSTORE_PRODUCT_ALIASES = {
  // XREG on AGHA NL is fulfilled from the provider's AIM HACK catalog.
  'xreg apk mod': ['aim hack', 'aim hack android+ ios', 'aim hack android ios'],
  // Typo/casing mismatch that exists between the AGHA product name and
  // DripStore catalog; use an explicit alias instead of broad fuzzy matching.
  'drip clint apk mod': ['drip client apk mod'],
  // BUG FIX (audit 20 Sep 2026, dikoreksi setelah cari langsung ke katalog
  // DripStore lewat /admin/dripstore/catalog-search): nama yang dikasih
  // owner DripStore lewat caption Telegram ("HG SAFE VERSION APKMOD")
  // TERNYATA BUKAN nama asli di sistemnya. Nama asli yang benar-benar
  // tersimpan di katalog API DripStore adalah "HG CHEAT SAFE VERSION MOD"
  // (ID variant 1 hari: 193, 10 hari: 194) -- beda kata "CHEAT" nyempil di
  // depan "SAFE", dan tidak ada kata "APKMOD" sama sekali. Pelajaran: kalau
  // ke depan ada produk baru yang tetap CEK MANUAL padahal ownernya bilang
  // ada stok, JANGAN percaya caption promosi -- selalu cek nama asli lewat
  // fitur pencarian katalog dulu sebelum menambah alias di sini.
  // Ejaan lokal "save" dan "safe" tetap didaftarkan sekaligus supaya aman
  // biarpun nama produk di admin panel diganti-ganti lagi ke depannya.
  'hg save apk mod': ['hg cheat safe version mod'],
  'hg safe apk mod': ['hg cheat safe version mod']
};

function _dsProviderNameCandidates(localName) {
  const normalized = _dsNormalizeName(localName);
  const aliases = DRIPSTORE_PRODUCT_ALIASES[normalized] || [];
  return [String(localName || ''), ...aliases];
}

function _dsNameMatchWithAliases(localName, supplierName) {
  return _dsProviderNameCandidates(localName).some(candidate => _dsNameMatch(candidate, supplierName));
}

function _dsNameMatch(localName, supplierName) {
  const a = _dsNormalizeName(localName);
  const b = _dsNormalizeName(supplierName);
  if (!a || !b) return false;
  if (a === b) return true;
  // Hanya izinkan containment untuk nama yang cukup panjang. Jangan pakai
  // token-overlap fuzzy karena dua produk seperti "DRIP CLINT APK MOD" dan
  // "DRIP CLINT ROOT" bisa sama-sama lolos dan berujung mapping salah.
  return (a.length >= 4 && b.includes(a)) || (b.length >= 4 && a.includes(b));
}

let _productsWriteQueue = Promise.resolve();

// SINGLE WRITER untuk products.json.
// Stok adalah satu dokumen JSON bersama; lock per-product saja tidak cukup
// karena writeDB() menulis seluruh array. Semua operasi yang mengubah inventory
// atau mapping yang bisa berjalan bersamaan harus lewat writer global ini supaya
// tidak ada lost-update (mis. checkout key lokal tertimpa oleh auto-map).
function withProductsWriteLock(task) {
  const run = _productsWriteQueue.then(async () => {
    const release = await acquirePersistentNamedLock('products-json-write-lock', { waitMs: 10000, staleMs: 60000 });
    if (!release) throw new Error('Stok/data produk sedang diproses transaksi lain. Coba lagi sebentar.');
    try {
      return await task();
    } finally {
      await release();
    }
  }, async () => {
    const release = await acquirePersistentNamedLock('products-json-write-lock', { waitMs: 10000, staleMs: 60000 });
    if (!release) throw new Error('Stok/data produk sedang diproses transaksi lain. Coba lagi sebentar.');
    try {
      return await task();
    } finally {
      await release();
    }
  });
  _productsWriteQueue = run.catch(() => undefined);
  return run;
}

async function autoMapDripstoreProducts({ restockLowStock = false } = {}) {
  const settings = await readFresh('settings.json');
  if (!settings.dripstore?.apiToken) throw new Error('API Token DripStore belum dikonfigurasi di Settings');

  const resp = await dripstoreCall(settings, 'products.php');
  const supplierItems = _dsExtractProductItems(resp);
  if (!supplierItems.length) {
    throw new Error('Daftar produk DripStore kosong / format response products.php belum dikenali. Klik Sync lagi setelah memastikan endpoint products.php mengembalikan data produk + variant_id.');
  }

  return withProductsWriteLock(async () => {
    const products = await readFresh('products.json');
    let mapped = 0, unchanged = 0, unmatched = 0;
    const unmatchedList = [];
    const restockTargets = [];

    for (const product of products) {
      if (!Array.isArray(product.pricingOptions) && !Array.isArray(product.items)) continue;
      const normalized = normalizeProductBuyOptions(product);
      product.pricingOptions = normalized.pricingOptions;
      product.items = normalized.items;
      for (const opt of product.pricingOptions) {
        const normalizedOptDays = Number(opt.days);
        const normalizedOptUnit = opt.unit === 'h' ? 'h' : 'd';
        const candidates = supplierItems
          .filter(s => Number(s.days) === normalizedOptDays && (s.unit || 'd') === normalizedOptUnit && _dsNameMatchWithAliases(product.name, s.productName));
        if (!candidates.length) {
          unmatched++;
          unmatchedList.push(`${product.name} — ${opt.days}${opt.unit === 'h' ? 'h' : 'd'}`);
          continue;
        }
        // Prioritaskan kecocokan exact-normalized name, lalu yang paling panjang.
        candidates.sort((x, y) => {
          const xe = _dsNormalizeName(x.productName) === _dsNormalizeName(product.name) ? 1 : 0;
          const ye = _dsNormalizeName(y.productName) === _dsNormalizeName(product.name) ? 1 : 0;
          if (xe !== ye) return ye - xe;
          return String(y.productName).length - String(x.productName).length;
        });
        const chosen = candidates[0];
        if (String(opt.dripstoreVariantId || '') !== chosen.variantId) {
          opt.dripstoreVariantId = chosen.variantId;
          mapped++;
        } else unchanged++;
        restockTargets.push({ productId: product.id, days: opt.days, unit: opt.unit || 'd', variantId: chosen.variantId });
      }
    }

    await writeDB('products.json', products);

    // Jangan melakukan generate key di request mapping ini. Di Vercel/serverless,
    // kalau ada banyak produk dengan stok <= threshold, generate dilakukan satu per
    // satu dan request bisa timeout sehingga browser cuma menerima "Failed to fetch".
    // Mapping sekarang hanya menyimpan variant_id dan mengembalikan target restock;
    // frontend akan memanggil endpoint restock-one per durasi secara terpisah.
    return {
      supplierVariants: supplierItems.length,
      mapped,
      unchanged,
      unmatched,
      unmatchedList: unmatchedList.slice(0, 20),
      restocked: 0,
      restockErrors: [],
      restockTargets: restockTargets.slice(0, 100)
    };
  });
}

// Restock satu produk+durasi dalam request pendek. Dipanggil setelah auto-mapping
// selesai supaya tidak membuat satu request panjang yang mudah timeout di Vercel.
async function createDripstoreRestockRequest({ productId, days, unit = 'd', quantity, source = 'auto' }) {
  const d = Number(days), qty = Number(quantity);
  const u = unit === 'h' ? 'h' : 'd';
  if (!productId || !Number.isInteger(d) || d <= 0) throw new Error('Target restock tidak valid');
  if (!Number.isInteger(qty) || qty <= 0 || qty > 1000) throw new Error('Jumlah restock harus 1-1000 key');

  const settings = await readFresh('settings.json');
  if (!settings.dripstore?.apiToken) throw new Error('API Token DripStore belum dikonfigurasi di Settings');
  const lock = await acquirePersistentNamedLock(`restock-request-create:${String(productId)}:${d}${u}`, { waitMs: 7000, staleMs: 60000 });
  if (!lock) throw new Error('Pembuatan proposal restock sedang diproses. Coba lagi sebentar.');
  try {
    const products = await readFresh('products.json');
    const product = products.find(p => String(p.id) === String(productId));
    if (!product) throw new Error('Produk tidak ditemukan');
    const opt = (product.pricingOptions || []).find(o => Number(o.days) === d && (o.unit || 'd') === u);
    if (!opt) throw new Error('Opsi harga durasi ini tidak ditemukan di produk');
    if (!opt.dripstoreVariantId) throw new Error('Durasi ini belum di-mapping ke Variant ID DripStore');

    const requests = await readFresh('dripstore_restock_requests.json').catch(() => []);
    const duplicate = requests.find(r => r.status === 'pending' && String(r.productId) === String(productId) && Number(r.days) === d && (r.unit || 'd') === u);
    if (duplicate) return duplicate;

    const remaining = getLocalOptionStock(product, { days: d, unit: u });
    const request = {
      id: uuidv4(),
      status: 'pending',
      source,
      productId: String(productId),
      productName: product.name,
      days: d,
      unit: u,
      quantity: qty,
      remainingBefore: remaining,
      variantId: String(opt.dripstoreVariantId),
      createdAt: new Date().toISOString(),
      approvedAt: null,
      rejectedAt: null,
      approvedBy: null,
      transactionId: null,
      added: 0,
      error: null
    };
    requests.unshift(request);
    await writeDB('dripstore_restock_requests.json', requests.slice(0, 500));
    return request;
  } finally {
    await lock();
  }
}

async function restockOneDripstoreTarget(target) {
  const productId = String(target?.productId || '');
  const days = Number(target?.days);
  const unit = target?.unit === 'h' ? 'h' : 'd';
  const settings = await readFresh('settings.json');
  const ds = settings.dripstore || {};
  const qty = Number.isInteger(Number(target?.quantity)) && Number(target.quantity) > 0
    ? Number(target.quantity)
    : (Number(ds.restockQty) > 0 ? Number(ds.restockQty) : 10);
  return createDripstoreRestockRequest({ productId, days, unit, quantity: qty, source: target?.source || 'auto' });
}

async function approveDripstoreRestockRequest(requestId, adminName = 'admin') {
  const lockKey = `request:${requestId}`;
  if (_dripstoreRestockLocks.has(lockKey)) throw new Error('Restock request sedang diproses');
  _dripstoreRestockLocks.add(lockKey);
  let releasePersistent = null;
  try {
    releasePersistent = await acquirePersistentNamedLock(`dripstore-restock-request:${String(requestId)}`, { waitMs: 10000, staleMs: 60000 });
    if (!releasePersistent) throw new Error('Restock request sedang diproses di instance lain. Coba lagi sebentar.');

    let requests = await readFresh('dripstore_restock_requests.json').catch(() => []);
    const request = requests.find(r => r.id === requestId);
    if (!request) throw new Error('Restock request tidak ditemukan');
    if (request.status !== 'pending') throw new Error(`Request sudah ${request.status}`);

    const settings = await readFresh('settings.json');
    if (!settings.dripstore?.apiToken) throw new Error('API Token DripStore belum dikonfigurasi di Settings');
    const products = await readFresh('products.json');
    const product = products.find(p => String(p.id) === String(request.productId));
    if (!product) throw new Error('Produk tidak ditemukan');
    const normalized = normalizeProductBuyOptions(product);
    const opt = (normalized.pricingOptions || []).find(o => Number(o.days) === Number(request.days) && (o.unit || 'd') === (request.unit || 'd'));
    if (!opt) throw new Error('Opsi durasi pada produk sudah tidak tersedia');

    // Resolve provider dari katalog TERKINI sebelum purchase. Mapping tersimpan
    // hanya metadata; request lama tidak boleh membeli variant yang sudah berubah.
    const providerProducts = await dripstoreCall(settings, 'products.php');
    const currentVariantId = resolveDripstoreVariantFromCatalog(providerProducts, normalized.name, opt);
    if (!currentVariantId) throw new Error('Variant DripStore terkini untuk produk + durasi ini tidak ditemukan');

    // Purchase tetap eksklusif di jalur approval admin.
    const purchase = await dripstoreGenerateKey(settings, String(currentVariantId), Number(request.quantity));
    const newKeys = Array.isArray(purchase.keys) ? purchase.keys.map(k => String(k || '').trim()).filter(k => k) : [];
    if (!newKeys.length) throw new Error('DripStore tidak mengembalikan key setelah purchase');
    const tag = `=${Number(request.days)}${request.unit === 'h' ? 'h' : 'd'}`;
    const taggedKeys = newKeys.map(k => `${k}${tag}`);

    // Simpan hasil purchase di bawah lock stok produk supaya tidak menimpa
    // key yang baru saja di-consume checkout instance lain.
    const saved = await withPersistentProductStockLock(request.productId, async () => {
      const freshProducts = await readFresh('products.json');
      const freshProduct = freshProducts.find(p => String(p.id) === String(request.productId));
      if (!freshProduct) throw new Error('Produk hilang saat menyimpan key');
      const existing = new Set(normalizeUsableLocalKeys(freshProduct.keys));
      const unique = taggedKeys.filter(k => !existing.has(k));
      const existingRaw = Array.isArray(freshProduct.keys) ? freshProduct.keys.map(k => String(k || '').trim()).filter(k => k) : [];
      freshProduct.keys = [...existingRaw, ...unique];
      await writeDB('products.json', freshProducts);
      return { unique, product: freshProduct };
    });

    request.status = 'approved';
    request.approvedAt = new Date().toISOString();
    request.approvedBy = adminName;
    request.added = saved.unique.length;
    request.variantId = String(currentVariantId);
    request.error = null;
    request.transactionId = purchase.transactionId || null;
    requests = await readFresh('dripstore_restock_requests.json').catch(() => requests);
    const idx = requests.findIndex(r => r.id === requestId);
    if (idx !== -1) requests[idx] = request;
    await writeDB('dripstore_restock_requests.json', requests.slice(0, 500));
    console.log(`DRIPSTORE PURCHASE APPROVED ${request.id}: ${request.productName} ${request.days}${request.unit} +${saved.unique.length}`);
    return request;
  } catch (e) {
    const requests = await readFresh('dripstore_restock_requests.json').catch(() => []);
    const idx = requests.findIndex(r => r.id === requestId);
    if (idx !== -1 && requests[idx].status === 'pending') {
      requests[idx].error = e.message;
      await writeDB('dripstore_restock_requests.json', requests.slice(0, 500));
    }
    throw e;
  } finally {
    if (releasePersistent) await releasePersistent();
    _dripstoreRestockLocks.delete(lockKey);
  }
}

function _dsParseMoney(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  // DripStore responses can expose USD amounts as `$1.40`, `USD 1.40`,
  // `1,40`, or plain numeric strings. Normalize the display formatting before
  // doing balance/price math; Number('$1.40') otherwise becomes NaN and makes
  // every provider variant look unavailable.
  let text = String(value).trim().replace(/[^0-9,.-]/g, '');
  if (!text) return null;
  if (text.includes(',') && text.includes('.')) {
    if (text.lastIndexOf(',') > text.lastIndexOf('.')) {
      text = text.replace(/\./g, '').replace(',', '.');
    } else {
      text = text.replace(/,/g, '');
    }
  } else if (text.includes(',')) {
    const parts = text.split(',');
    text = parts.length === 2 && parts[1].length <= 2 ? parts[0] + '.' + parts[1] : parts.join('');
  }
  const n = Number(text);
  return Number.isFinite(n) ? n : null;
}

async function getDripstoreBalanceValue(settings) {
  const resp = await dripstoreCall(settings, 'balance.php');
  const raw = resp?.data?.balance ?? resp?.balance ?? resp?.data?.credits ?? resp?.credits ?? resp?.data?.saldo ?? resp?.saldo ?? resp?.data?.amount ?? resp?.amount ?? resp?.data?.balance_usd ?? resp?.balance_usd;
  return _dsParseMoney(raw);
}

function _dsFindVariantCost(resp, variantId) {
  const target = String(variantId);
  let found = null;
  const walk = (node, inheritedProduct='') => {
    if (found !== null || node == null) return;
    if (Array.isArray(node)) { for (const x of node) walk(x, inheritedProduct); return; }
    if (typeof node !== 'object') return;
    const id = _dsFirst(node, ['variant_id','variantId','id']);
    const name = _dsFirst(node, ['variant_name','variantName','name','title']);
    const product = _dsFirst(node, ['product_name','productName','product_title','productTitle','product']) || inheritedProduct;
    if (id != null && String(id) === target) {
      const raw = _dsFirst(node, ['unit_price','unitPrice','price','cost','cost_price','costPrice','price_usd','priceUsd','unitPriceUsd','unit_price_usd','cost_usd','costUsd','unit_cost','unitCost','reseller_price','resellerPrice','selling_price','sellingPrice','p']);
      const n = _dsParseMoney(raw);
      if (n !== null && n >= 0) found = n;
    }
    for (const k of ['variants','options','plans','items','products','data','result']) if (node[k] !== undefined) walk(node[k], product || inheritedProduct);
  };
  walk(resp);
  return found;
}

let _dripstoreCatalogCache = null;
let _dripstoreCatalogCacheAt = 0;
let _dripstoreCatalogInflight = null;
let _dripstoreCatalogCacheSignature = '';
// Negative cache: setelah refresh GAGAL (429/timeout/dsb), jangan coba lagi di
// setiap request. Tanpa ini tiap pengunjung memicu 2 request provider baru.
let _dripstoreFailUntil = 0;
const DRIPSTORE_FAIL_COOLDOWN_MS = 45000;
// Last-known-good: dipakai HANYA untuk TAMPILAN stok (katalog / halaman beli)
// ketika provider sedang lambat/gagal. Checkout dan fulfillment tetap memanggil
// provider secara LIVE (checkDripstoreOptionAvailability), jadi stok tampilan
// yang agak basi tidak pernah bisa menghasilkan pembelian tanpa saldo.
let _dripstoreLastGood = null; // { signature, balance, balanceAt, products, productsAt, at }
const DRIPSTORE_CATALOG_CACHE_TTL = 30000;
const DRIPSTORE_CATALOG_TIMEOUT_MS = 4500;
const DRIPSTORE_SNAPSHOT_FILE = 'dripstore_snapshot.json';
const DRIPSTORE_STALE_BALANCE_MAX_MS = 10 * 60 * 1000;   // saldo basi maks 10 menit utk tampilan
const DRIPSTORE_STALE_PRODUCTS_MAX_MS = 60 * 60 * 1000;  // katalog/harga jarang berubah
const DRIPSTORE_STALE_DISPLAY_MAX_MS = 24 * 60 * 60 * 1000; // katalog basi maks 24 jam khusus utk tampilan stok

function _getDripstoreCatalogSignature(settings) {
  const ds = settings?.dripstore || {};
  const token = String(ds.apiToken || '').trim();
  if (!token) return '';
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex').slice(0, 16);
  return `${String(ds.baseUrl || 'https://dripclientstore.shop/api/v1').trim()}|${tokenHash}`;
}

// Ambil last-known-good dari memori instance ini, atau dari snapshot yang
// disimpan di Supabase (dibagi lintas instance Vercel).
function _dsLastGood(settings) {
  const signature = _getDripstoreCatalogSignature(settings);
  if (!signature) return null;
  let lg = _dripstoreLastGood;
  if (lg && lg.signature !== signature) lg = null;
  if (!lg) {
    const persisted = readDB(DRIPSTORE_SNAPSHOT_FILE);
    if (persisted && persisted.signature === signature && persisted.products) lg = persisted;
  }
  return lg || null;
}

function getLastGoodDripstoreSnapshot(settings) {
  const lg = _dsLastGood(settings);
  if (!lg) return null;
  const now = Date.now();
  const balance = (lg.balance !== null && lg.balance !== undefined && (now - Number(lg.balanceAt || 0)) < DRIPSTORE_STALE_BALANCE_MAX_MS) ? lg.balance : null;
  const products = (lg.products && (now - Number(lg.productsAt || 0)) < DRIPSTORE_STALE_PRODUCTS_MAX_MS) ? lg.products : null;
  if (balance === null || !products) return null;
  return { balance, products, stale: true, ageMs: now - Number(lg.balanceAt || 0) };
}

// Untuk TAMPILAN stok (tombol Beli / Cek stok / Habis) yang dibutuhkan hanya katalog
// + stok variant, BUKAN saldo. Versi ketat di atas (wajib saldo <10 menit) dipakai
// untuk guard checkout. Tanpa varian ini, saat provider kena limit > 10 menit semua
// produk provider-backed jatuh ke "Cek stok" walau katalog terakhir masih ada.
// Stok di sini bisa basi; itu tidak berbahaya karena checkout tetap memverifikasi
// ulang (guard + generate_key.php adalah otoritas akhir).
function getDisplayDripstoreSnapshot(settings) {
  const strict = getLastGoodDripstoreSnapshot(settings);
  if (strict) return strict;
  const lg = _dsLastGood(settings);
  if (!lg || !lg.products) return null;
  const now = Date.now();
  if ((now - Number(lg.productsAt || 0)) >= DRIPSTORE_STALE_DISPLAY_MAX_MS) return null;
  return { balance: null, products: lg.products, stale: true, displayOnly: true, ageMs: now - Number(lg.productsAt || 0) };
}

async function _loadPersistedDripstoreSnapshot(settings, maxWaitMs = 1200) {
  const signature = _getDripstoreCatalogSignature(settings);
  if (!signature) return null;
  let persisted = null;
  try {
    persisted = await Promise.race([
      readFresh(DRIPSTORE_SNAPSHOT_FILE),
      new Promise(resolve => setTimeout(() => resolve(readDB(DRIPSTORE_SNAPSHOT_FILE)), maxWaitMs))
    ]);
  } catch (_) { persisted = readDB(DRIPSTORE_SNAPSHOT_FILE); }
  if (!persisted || persisted.signature !== signature || !persisted.products) return null;
  return persisted;
}

// Dipanggil setelah pembelian key / perubahan token: cache segar dibuang dan
// saldo lama tidak boleh dipakai lagi sebagai fallback.
function _invalidateDripstoreSnapshot({ full = false } = {}) {
  _dripstoreCatalogCache = null;
  _dripstoreCatalogCacheAt = 0;
  // Saldo berubah setelah generate_key: buang micro-cache balance saja
  // (products.php tetap boleh di-cache, harganya tidak ikut berubah).
  for (const k of Array.from(_dsMicroCache.keys())) if (k.startsWith('balance.php')) _dsMicroCache.delete(k);
  if (full) {
    _dripstoreLastGood = null;
    _dripstoreCatalogInflight = null;
    _dripstoreCatalogCacheSignature = '';
    _dripstoreFailUntil = 0;
    _dsMicroCache.clear();
    writeDB(DRIPSTORE_SNAPSHOT_FILE, {}).catch(() => {});
    return;
  }
  if (_dripstoreLastGood) _dripstoreLastGood = { ..._dripstoreLastGood, balanceAt: 0, at: 0 };
  const persisted = readDB(DRIPSTORE_SNAPSHOT_FILE);
  if (persisted && persisted.signature) writeDB(DRIPSTORE_SNAPSHOT_FILE, { ...persisted, balanceAt: 0, at: 0 }).catch(() => {});
}

async function getDripstoreCatalogSnapshot(settings, opts = {}) {
  const ds = settings.dripstore || {};
  if (!ds.apiToken) return { balance: null, products: null };
  const maxWaitMs = Number(opts.maxWaitMs) > 0 ? Number(opts.maxWaitMs) : DRIPSTORE_CATALOG_TIMEOUT_MS;
  const force = !!opts.force;
  const signature = _getDripstoreCatalogSignature(settings);
  if (signature !== _dripstoreCatalogCacheSignature) {
    _dripstoreCatalogCache = null;
    _dripstoreCatalogCacheAt = 0;
    _dripstoreLastGood = null;
    _dripstoreCatalogCacheSignature = signature;
  }
  const now = Date.now();
  if (!force && _dripstoreCatalogCache && (now - _dripstoreCatalogCacheAt) < DRIPSTORE_CATALOG_CACHE_TTL) return _dripstoreCatalogCache;

  const fallback = () => getDisplayDripstoreSnapshot(settings) || { balance: null, products: null, stale: true };

  // Provider sedang dibatasi / baru gagal: layani dari last-known-good TANPA
  // menyentuh provider. force=true (admin) tetap boleh mencoba, tapi tetap
  // dihentikan kalau breaker rate-limit sedang terbuka.
  const brk = dripstoreBreakerState();
  if (brk.open) {
    const lg = getDisplayDripstoreSnapshot(settings);
    return lg || { balance: null, products: null, stale: true, error: _dsBreakerError().message, rateLimited: true, retryAfterSec: brk.retryAfterSec };
  }
  if (!force && Date.now() < _dripstoreFailUntil) return fallback();

  const timeoutFallback = new Promise(resolve => setTimeout(() => resolve(fallback()), maxWaitMs));

  if (_dripstoreCatalogInflight) return Promise.race([_dripstoreCatalogInflight, timeoutFallback]);

  // Instance Vercel lain mungkin baru saja mengambil snapshot: pakai itu kalau
  // masih segar, jadi cold-start tidak selalu memanggil provider dari nol.
  if (!force) {
    const persisted = await _loadPersistedDripstoreSnapshot(settings);
    if (persisted) {
      if (!_dripstoreLastGood || Number(persisted.balanceAt || 0) > Number(_dripstoreLastGood.balanceAt || 0)) _dripstoreLastGood = persisted;
      if (persisted.balance !== null && persisted.balance !== undefined && (Date.now() - Number(persisted.at || 0)) < DRIPSTORE_CATALOG_CACHE_TTL) {
        _dripstoreCatalogCache = { balance: persisted.balance, products: persisted.products };
        _dripstoreCatalogCacheAt = Number(persisted.at);
        return _dripstoreCatalogCache;
      }
    }
    if (_dripstoreCatalogInflight) return Promise.race([_dripstoreCatalogInflight, timeoutFallback]);
  }

  const refresh = (async () => {
    try {
      const results = await Promise.allSettled([
        getDripstoreBalanceValue(settings),
        dripstoreCall(settings, 'products.php')
      ]);
      const freshBalance = results[0].status === 'fulfilled' ? results[0].value : null;
      const freshProducts = results[1].status === 'fulfilled' ? results[1].value : null;
      const t = Date.now();
      const prev = _dsLastGood(settings) || {};
      const record = {
        signature,
        balance: freshBalance !== null ? freshBalance : (prev.balance ?? null),
        balanceAt: freshBalance !== null ? t : Number(prev.balanceAt || 0),
        products: freshProducts || prev.products || null,
        productsAt: freshProducts ? t : Number(prev.productsAt || 0),
        at: (freshBalance !== null && freshProducts) ? t : Number(prev.at || 0)
      };
      _dripstoreLastGood = record;
      if (freshBalance !== null && freshProducts) {
        _dripstoreFailUntil = 0;
        _dripstoreCatalogCache = { balance: freshBalance, products: freshProducts };
        _dripstoreCatalogCacheAt = t;
        // Simpan supaya instance lain (dan cold-start berikutnya) punya data.
        // Dibatasi 800ms supaya tidak menahan respons kalau Supabase lambat.
        await Promise.race([
          writeDB(DRIPSTORE_SNAPSHOT_FILE, record).catch(() => {}),
          new Promise(r => setTimeout(r, 800))
        ]);
        return _dripstoreCatalogCache;
      }
      // Sebagian gagal: tampilkan last-known-good (ditandai stale), jangan
      // langsung "Cek stok". Cache segar TIDAK diisi, jadi request berikutnya
      // mencoba provider lagi.
      const reason = results.find(r => r.status === 'rejected')?.reason?.message || 'provider tidak merespons';
      _dripstoreFailUntil = Date.now() + DRIPSTORE_FAIL_COOLDOWN_MS;
      console.warn('[dripstore snapshot] refresh gagal sebagian:', reason);
      return getDisplayDripstoreSnapshot(settings) || { balance: null, products: null, stale: true, error: reason };
    } finally {
      _dripstoreCatalogInflight = null;
    }
  })();
  _dripstoreCatalogInflight = refresh;
  return Promise.race([refresh, timeoutFallback]);
}

// Fast path untuk halaman publik: hanya cache memori yang masih segar.
function getCachedDripstoreCatalogSnapshot(settings) {
  const ds = settings?.dripstore || {};
  if (!ds.apiToken || !_dripstoreCatalogCache) return null;
  const signature = _getDripstoreCatalogSignature(settings);
  if (signature !== _dripstoreCatalogCacheSignature) return null;
  if ((Date.now() - _dripstoreCatalogCacheAt) >= DRIPSTORE_CATALOG_CACHE_TTL) return null;
  return _dripstoreCatalogCache;
}
function warmDripstoreCatalog(settings) {
  if (!settings?.dripstore?.apiToken) return;
  if (_dripstoreCatalogInflight) return;
  // Jangan pernah 'warm' saat provider sedang dibatasi / baru gagal, dan jangan
  // warm kalau cache masih segar. Sebelumnya dipanggil di SETIAP page load.
  if (dripstoreBreakerState().open || Date.now() < _dripstoreFailUntil) return;
  if (getCachedDripstoreCatalogSnapshot(settings)) return;
  getDripstoreCatalogSnapshot(settings).catch(() => {});
}

function _dsFindVariantExplicitStock(resp, variantId) {
  const target = String(variantId);
  let found = null;
  const walk = (node) => {
    if (found !== null || node == null) return;
    if (Array.isArray(node)) { for (const x of node) walk(x); return; }
    if (typeof node !== 'object') return;
    const id = _dsFirst(node, ['variant_id','variantId','id']);
    if (id != null && String(id) === target) {
      const raw = _dsFirst(node, ['available_stock','availableStock','stock','quantity_available','quantityAvailable','qty']);
      const n = Number(raw);
      if (Number.isFinite(n) && n >= 0) { found = Math.floor(n); return; }
    }
    for (const k of ['variants','options','plans','items','products','data','result']) if (node[k] !== undefined) walk(node[k]);
  };
  walk(resp);
  return found;
}

function _dsMoneyCents(value) {
  const n = _dsParseMoney(value);
  if (n === null || !Number.isFinite(n)) return null;
  // Provider kita menampilkan nominal USD hingga 2 desimal. Hitung dalam
  // integer cents supaya floor(balance / cost) tidak kena error floating-point
  // seperti 1.34 / 0.67 = 1.999999....
  return Math.round(n * 100);
}

function getDripstoreVirtualStock(snapshot, variantId) {
  if (!snapshot?.products) return null;
  if (snapshot.balance === null || snapshot.balance === undefined) return null;
  const costCents = _dsMoneyCents(_dsFindVariantCost(snapshot.products, variantId));
  const balanceCents = _dsMoneyCents(snapshot.balance);
  if (costCents === null || costCents <= 0 || balanceCents === null) return null;
  if (balanceCents < 0) return 0;
  return Math.max(0, Math.floor(balanceCents / costCents));
}

function resolveDripstoreVariantFromCatalog(productsResp, productName, opt) {
  if (!productsResp || !productName || !opt) return null;
  const items = _dsExtractProductItems(productsResp);
  const matches = items.filter(item =>
    Number(item.days) === Number(opt.days) &&
    (item.unit || 'd') === (opt.unit || 'd') &&
    _dsNameMatchWithAliases(productName, item.productName)
  );
  if (matches.length) {
    matches.sort((a,b) => {
      const ae = _dsNormalizeName(a.productName) === _dsNormalizeName(productName) ? 1 : 0;
      const be = _dsNormalizeName(b.productName) === _dsNormalizeName(productName) ? 1 : 0;
      return be - ae || String(b.productName).length - String(a.productName).length;
    });
    return matches[0].variantId;
  }
  // Katalog provider berhasil dibaca tetapi pasangan product+durasi tidak ada.
  // Jangan menggunakan ID lama karena bisa menunjuk ke variant yang sudah
  // berubah; false-positive stock lebih berbahaya daripada status unknown.
  return null;
}

function findDripstoreVariantForOption(snapshot, productName, opt) {
  if (!snapshot?.products || !productName || !opt) return null;

  // Prefer the explicitly auto-mapped Variant ID, but NEVER trust it blindly:
  // the current provider catalog must still contain that ID and its current
  // price. This avoids the old bug where a perfectly valid mapping became
  // invisible because the provider's product/variant name formatting changed
  // (for example `PATO BLUE — 7 hari` vs `7 hari`).
  const mappedId = String(opt?.dripstoreVariantId || '').trim();
  if (mappedId) {
    const mappedStock = getDripstoreVirtualStock(snapshot, mappedId);
    if (mappedStock !== null) return { variantId: mappedId, stock: mappedStock };
  }

  const variantId = resolveDripstoreVariantFromCatalog(snapshot.products, productName, opt);
  if (!variantId) return null;
  const stock = getDripstoreVirtualStock(snapshot, variantId);
  if (stock === null) return null;
  return { variantId: String(variantId), stock };
}

function normalizeUsableLocalKeys(keys) {
  const seen = new Set();
  const out = [];
  for (const raw of (Array.isArray(keys) ? keys : [])) {
    const key = String(raw ?? '').trim();
    if (!isUsableLocalKey(key) || seen.has(key)) continue;
    seen.add(key);
    out.push(key);
  }
  return out;
}

function countLocalDurationStock(keys, days, unit) {
  return normalizeUsableLocalKeys(keys).filter(k => keyMatchesDuration(k, days, unit)).length;
}

function getLocalOptionStock(product, opt) {
  const keys = Array.isArray(product?.keys) ? product.keys : [];
  if (Number(opt?.days) > 0) return countLocalDurationStock(keys, Number(opt.days), opt.unit === 'h' ? 'h' : 'd');
  return normalizeUsableLocalKeys(keys).filter(isGenericKey).length;
}

function getOptionStockView(product, opt, snapshot, mode, providerConfigured = false) {
  const normalizedMode = ['live','hybrid','local'].includes(mode) ? mode : 'live';
  const localStock = getLocalOptionStock(product, opt);
  if (normalizedMode === 'local') {
    return { stock: localStock, localStock, providerStock: 0, providerKnown: false, providerBacked: false, variantId: null };
  }

  const resolved = findDripstoreVariantForOption(snapshot, product.name, opt);
  // LIVE berarti provider adalah satu-satunya sumber fulfillment. Jadi variant
  // yang belum ter-resolve TIDAK BOLEH terlihat punya stok lokal. Di HYBRID,
  // lokal tetap boleh tampil dan dipakai sebagai fallback.
  // Stok lokal AGHA selalu merupakan stok nyata dan harus tetap dihitung,
  // terlepas dari mode DripStore. DripStore hanya menjadi sumber tambahan /
  // fallback. Sebelumnya mode `live` membuang localStock menjadi 0 sehingga
  // key yang sebenarnya tersimpan di products.json (contoh XREG) dianggap
  // kosong hanya karena tidak punya variant DripStore.
  const providerBacked = normalizedMode === 'live'
    ? !!providerConfigured
    : (!!opt?.dripstoreVariantId || !!resolved);
  if (!providerBacked) {
    return { stock: localStock, localStock, providerStock: 0, providerKnown: false, providerBacked: false, variantId: null };
  }
  if (!snapshot) {
    // Provider belum terverifikasi. Jangan mengarang stok provider; stok lokal
    // tetap valid dan tetap tampil.
    return { stock: localStock, localStock, providerStock: 0, providerKnown: false, providerBacked: true, variantId: null };
  }
  if (!resolved) {
    // Tidak ada variant provider yang cocok. Ini bukan berarti stok lokal habis.
    return { stock: localStock, localStock, providerStock: 0, providerKnown: false, providerBacked: true, variantId: null };
  }

  const providerStock = Math.max(0, Number(resolved.stock) || 0);
  // Combined availability: stok lokal + stok provider. Fulfillment tetap
  // local-first; provider dipakai sebagai fallback saat localStock = 0.
  const stock = localStock + providerStock;
  return { stock, localStock, providerStock, providerKnown: true, providerBacked: true, variantId: resolved.variantId };
}


// Satu-satunya jalur untuk mengonsumsi key lokal. Semua pembelian lokal
// (hybrid/local checkout, wallet, admin confirm) lewat helper ini supaya:
// - durasi + unit harus exact;
// - tidak pernah mengambil key durasi lain;
// - tidak double-sell saat 2 request bersamaan, termasuk lintas instance Vercel.
async function consumeLocalProductKey(productId, selectedDays, selectedUnit = 'd') {
  return withPersistentProductStockLock(productId, async () => {
    const freshProducts = await readFresh('products.json');
    const freshProduct = freshProducts.find(p => String(p.id) === String(productId));
    if (!freshProduct) return { key: null, products: freshProducts, committed: false };

    const keys = Array.isArray(freshProduct.keys) ? freshProduct.keys : [];
    const days = Number(selectedDays);
    const unit = selectedUnit === 'h' ? 'h' : 'd';
    let idx = -1;
    if (Number.isFinite(days) && days > 0) {
      idx = keys.findIndex(k => keyMatchesDuration(k, days, unit));
    } else {
      idx = keys.findIndex(k => isGenericKey(k));
    }

    if (idx < 0) return { key: null, products: freshProducts, committed: false };
    const stored = String(keys[idx] || '').trim();
    const parsed = parseKeyDuration(stored);
    const key = parsed.value === null ? stored : parsed.raw;
    if (!key || !isUsableLocalKey(stored)) return { key: null, products: freshProducts, committed: false };

    // Identical key strings cannot be sold safely twice. Remove every duplicate
    // of the consumed key so legacy duplicate rows can never become double-sales.
    freshProduct.keys = keys.filter(k => String(k || '').trim() !== stored);

    freshProduct.sold = (freshProduct.sold || 0) + 1;
    await writeDB('products.json', freshProducts);
    return { key, products: freshProducts, product: freshProduct, committed: true };
  });
}

function getCombinedOptionStock(snapshot, productName, opt, localStock = 0) {
  const resolved = findDripstoreVariantForOption(snapshot, productName, opt);
  return Math.max(0, Number(localStock) || 0) + (resolved ? resolved.stock : 0);
}

function buildProductStockSummary(rawProduct, settings, snapshot = null) {
  const product = normalizeProductBuyOptions(rawProduct);
  const mode = ['live', 'hybrid', 'local'].includes(settings?.dripstore?.fulfillmentMode)
    ? settings.dripstore.fulfillmentMode : 'live';
  const options = Array.isArray(product.pricingOptions) ? product.pricingOptions : [];
  const providerConfigured = !!settings?.dripstore?.apiToken;
  const optionViews = options.map(opt => getOptionStockView(product, opt, snapshot, mode, providerConfigured));
  const stockByOption = optionViews.map((view, index) => ({
    index,
    days: Number(options[index]?.days),
    unit: options[index]?.unit === 'h' ? 'h' : 'd',
    stock: Math.max(0, Number(view.stock) || 0),
    localStock: Math.max(0, Number(view.localStock) || 0),
    providerStock: Math.max(0, Number(view.providerStock) || 0),
    providerKnown: !!view.providerKnown,
    providerBacked: !!view.providerBacked,
    variantId: view.variantId || null
  }));
  const stockCount = stockByOption.length
    ? Math.max(...stockByOption.map(x => x.stock), 0)
    : getLocalOptionStock(product, { days: null, unit: 'd' });
  return {
    product,
    mode,
    stockByOption,
    stockCount: Math.max(0, Number(stockCount) || 0),
    providerStockUnknown: stockByOption.some(x => x.providerBacked && !x.providerKnown),
    usableLocalKeyCount: countUsableLocalKeys(product.keys).length,
    genericLocalKeyCount: countUsableLocalKeys(product.keys).filter(isGenericKey).length
  };
}

function countUsableLocalKeys(keys) {
  return normalizeUsableLocalKeys(keys);
}

async function checkDripstoreVariantAvailability(settings, variantId, quantity = 1) {
  const ds = settings.dripstore || {};
  if (!ds.apiToken) return { ok: false, reason: 'API Token DripStore belum dikonfigurasi' };
  const qty = Number(quantity);
  if (!Number.isInteger(qty) || qty <= 0 || qty > 1000) {
    return { ok: false, reason: 'Jumlah key provider tidak valid (1-1000)' };
  }
  let balance, productsResp;
  if (dripstoreBreakerState().open) {
    // Provider sedang rate-limit: jangan tambah hit. Pakai last-known-good
    // (saldo maks 10 menit) untuk guard; generate_key.php tetap otoritas akhir.
    const lg = getLastGoodDripstoreSnapshot(settings);
    if (!lg) throw _dsBreakerError();
    balance = lg.balance; productsResp = lg.products;
  } else {
    [balance, productsResp] = await Promise.all([
      getDripstoreBalanceValue(settings),
      dripstoreCall(settings, 'products.php')
    ]);
  }
  const unitCost = _dsFindVariantCost(productsResp, variantId);
  if (balance === null) return { ok: false, guarded: false, balance: null, unitCost, variantId: String(variantId), reason: 'Saldo provider tidak dapat diverifikasi' };
  if (unitCost === null || !Number.isFinite(Number(unitCost)) || Number(unitCost) <= 0) {
    return { ok: false, guarded: false, balance, unitCost: null, variantId: String(variantId), reason: 'Harga variant provider tidak tersedia / tidak valid di products.php' };
  }
  const balanceCents = _dsMoneyCents(balance);
  const unitCostCents = _dsMoneyCents(unitCost);
  if (balanceCents === null || unitCostCents === null || unitCostCents <= 0) {
    return { ok: false, guarded: false, balance, unitCost, variantId: String(variantId), reason: 'Nominal provider tidak valid' };
  }
  const requiredCents = unitCostCents * qty;
  const required = requiredCents / 100;
  return { ok: balanceCents >= requiredCents, guarded: true, balance, unitCost, required, variantId: String(variantId), shortfall: Math.max(0, required - balanceCents / 100) };
}

async function checkDripstoreOptionAvailability(settings, productName, opt, quantity = 1) {
  const ds = settings.dripstore || {};
  if (!ds.apiToken) return { ok: false, reason: 'API Token DripStore belum dikonfigurasi di Settings' };
  const qty = Number(quantity);
  if (!Number.isInteger(qty) || qty <= 0 || qty > 1000) return { ok: false, reason: 'Jumlah key provider tidak valid (1-1000)' };
  let productsResp, balance;
  if (dripstoreBreakerState().open) {
    const lg = getLastGoodDripstoreSnapshot(settings);
    if (!lg) throw _dsBreakerError();
    productsResp = lg.products; balance = lg.balance;
  } else {
    productsResp = await dripstoreCall(settings, 'products.php');
  }
  const variantId = resolveDripstoreVariantFromCatalog(productsResp, productName, opt);
  if (!variantId) return { ok: false, reason: 'Variant DripStore untuk produk + durasi ini tidak ditemukan' };
  if (balance === undefined) balance = await getDripstoreBalanceValue(settings);
  const unitCost = _dsFindVariantCost(productsResp, variantId);
  if (balance === null) return { ok: false, guarded: false, variantId: String(variantId), unitCost, balance: null, reason: 'Saldo provider tidak dapat diverifikasi' };
  if (unitCost === null || !Number.isFinite(Number(unitCost)) || Number(unitCost) <= 0) {
    return { ok: false, guarded: false, variantId: String(variantId), unitCost: null, balance, reason: 'Harga variant provider tidak valid' };
  }
  const balanceCents = _dsMoneyCents(balance);
  const unitCostCents = _dsMoneyCents(unitCost);
  if (balanceCents === null || unitCostCents === null || unitCostCents <= 0) {
    return { ok: false, guarded: false, variantId: String(variantId), unitCost, balance, reason: 'Nominal provider tidak valid' };
  }
  const requiredCents = unitCostCents * qty;
  const required = requiredCents / 100;
  return { ok: balanceCents >= requiredCents, guarded: true, variantId: String(variantId), unitCost, balance, required, shortfall: Math.max(0, required - balanceCents / 100) };
}

// Serialize provider purchases so two paid orders cannot both pass the
// balance pre-check against the same saldo snapshot and then race each other.
// The lock is process-local; the provider's own API remains the final authority.
let _dripstorePurchaseQueue = Promise.resolve();

function withDripstorePurchaseLock(task) {
  const run = _dripstorePurchaseQueue.then(async () => {
    const release = await acquirePersistentNamedLock('dripstore-purchase-lock', { waitMs: 10000, staleMs: 60000 });
    if (!release) throw new Error('Pembelian provider sedang diproses transaksi lain. Coba lagi sebentar.');
    try {
      return await task();
    } finally {
      await release();
    }
  }, async () => {
    const release = await acquirePersistentNamedLock('dripstore-purchase-lock', { waitMs: 10000, staleMs: 60000 });
    if (!release) throw new Error('Pembelian provider sedang diproses transaksi lain. Coba lagi sebentar.');
    try {
      return await task();
    } finally {
      await release();
    }
  });
  _dripstorePurchaseQueue = run.catch(() => undefined);
  return run;
}

async function dripstoreGenerateKey(settings, variantId, quantity) {
  const qty = Number(quantity);
  if (!Number.isInteger(qty) || qty <= 0 || qty > 1000) throw new Error('Jumlah key DripStore harus 1-1000');
  return withDripstorePurchaseLock(async () => {
    const guard = settings.dripstore?.balanceGuardEnabled !== false;
    if (guard) {
      const availability = await checkDripstoreVariantAvailability(settings, variantId, qty);
      if (!availability.ok) {
        if (availability.reason && availability.balance == null) throw new Error(availability.reason);
        const bal = availability.balance == null ? '?' : Number(availability.balance).toFixed(2);
        const req = availability.required == null ? '?' : Number(availability.required).toFixed(2);
        throw new Error(`Saldo DripStore tidak cukup / tidak terverifikasi untuk variant ini. Saldo $${bal}, kebutuhan minimal $${req}.`);
      }
    }
    const resp = await dripstoreCall(settings, 'generate_key.php', { variant_id: variantId, quantity }, 'POST');
    const keys = extractDripstoreKeys(resp);
    const transactionId = resp?.data?.transaction_id || resp?.data?.transactionId || resp?.transaction_id || resp?.transactionId || resp?.data?.purchase_id || resp?.purchase_id || null;
    // Saldo provider berubah setelah generate_key. Jangan biarkan halaman publik
    // memakai snapshot sebelum pembelian selama TTL cache penuh.
    _invalidateDripstoreSnapshot();
    return { keys, transactionId };
  });
}

// LIVE PROVIDER FULFILLMENT:
// Kalau suatu durasi sudah di-map ke Variant ID DripStore, produk tersebut
// TIDAK memakai stok lokal sebagai persediaan utama. Setiap customer yang
// benar-benar selesai membayar memicu purchase 1 key ke DripStore. Dengan
// begitu saldo reseller provider baru berkurang saat ada penjualan nyata,
// bukan saat sync/auto-restock.
const _dripstoreLiveLocks = new Set();

async function fulfillProductFromDripstore(transaction, settings) {
  const days = Number(transaction?.selectedDays);
  const unit = transaction?.selectedUnit === 'h' ? 'h' : 'd';
  if (!Number.isFinite(days) || days <= 0) return null;

  const products = await readFresh('products.json');
  const rawProduct = products.find(p => String(p.id) === String(transaction.productId));
  const product = rawProduct ? normalizeProductBuyOptions(rawProduct) : null;
  if (!product) return null;
  const opt = (product.pricingOptions || []).find(o => Number(o.days) === days && (o.unit || 'd') === unit);
  const mode = settings.dripstore?.fulfillmentMode || 'live';
  if (mode === 'local' || !opt) return null;

  // Selalu resolve dari katalog provider TERKINI. Mapping tersimpan hanya
  // fallback; ini mencegah Variant ID lama menunjuk ke paket yang salah.
  let providerProducts;
  if (dripstoreBreakerState().open) {
    const lg = getLastGoodDripstoreSnapshot(settings);
    if (!lg?.products) throw _dsBreakerError();
    providerProducts = lg.products;
  } else {
    providerProducts = await dripstoreCall(settings, 'products.php');
  }
  const currentVariantId = resolveDripstoreVariantFromCatalog(providerProducts, product.name, opt);
  if (!currentVariantId) return null;

  const lockKey = `live:${transaction.id}`;
  if (_dripstoreLiveLocks.has(lockKey)) {
    throw new Error('Pesanan sedang mengambil key dari DripStore, tunggu sebentar.');
  }
  _dripstoreLiveLocks.add(lockKey);
  try {
    const purchase = await dripstoreGenerateKey(settings, String(currentVariantId), 1);
    const key = purchase.keys?.[0];
    if (!key) throw new Error('DripStore berhasil merespons tetapi tidak mengembalikan key.');
    return {
      key,
      source: 'dripstore_live',
      variantId: String(currentVariantId),
      providerTransactionId: purchase.transactionId || null
    };
  } finally {
    _dripstoreLiveLocks.delete(lockKey);
  }
}

// LOCK sederhana in-memory (per productId+days+unit) supaya kalau ada 2+
// pembelian nyaris bersamaan sama-sama bikin stok jatuh ke bawah threshold,
// restock DripStore CUMA jalan SEKALI, bukan double/triple sekaligus.
// FIX bug (audit 16 Sep 2026): sebelumnya tiap penjualan yang bikin
// remaining<=threshold langsung fire-and-forget generate_key sendiri-sendiri
// tanpa saling tau -- kalau ada 5 pembelian beruntun pas stok lagi mepet,
// bisa kepicu 5x restock sekaligus (5x restockQty ke-generate & motong
// saldo DripStore, padahal cukup 1x). Ini in-memory (reset kalau server
// redeploy/restart) -- cukup untuk skala toko ini, gak perlu Redis dkk.
const _dripstoreRestockLocks = new Set();

// Auto-restock: dipanggil (fire-and-forget, TIDAK di-await di alur
// pembelian) tiap kali 1 key berhasil terjual. Kalau stok durasi itu
// abis nyisa <= threshold, otomatis generate key baru dari DripStore
// dan langsung tambahin ke stok produk. Sengaja dibungkus try/catch
// total di sini + di titik pemanggilannya -- KEGAGALAN RESTOCK TIDAK
// BOLEH PERNAH mengganggu transaksi pembeli yang sedang berjalan.
async function maybeAutoRestockDripstore(productId, days, unit) {
  // AUTO-RESTOCK TIDAK BOLEH PURCHASE. Hanya membuat proposal pending.
  try {
    const settings = await readFresh('settings.json');
    const ds = settings.dripstore || {};
    if (!ds.autoRestockEnabled || !ds.apiToken) return;
    const products = await readFresh('products.json');
    const product = products.find(p => String(p.id) === String(productId));
    if (!product) return;
    const opt = (product.pricingOptions || []).find(o => Number(o.days) === Number(days) && (o.unit || 'd') === (unit || 'd'));
    if (!opt?.dripstoreVariantId) return;
    const remaining = (product.keys || []).filter(k => keyMatchesDuration(k, Number(days), unit)).length;
    const threshold = Number.isFinite(Number(ds.lowStockThreshold)) ? Number(ds.lowStockThreshold) : 3;
    if (remaining > threshold) return;
    await createDripstoreRestockRequest({
      productId, days: Number(days), unit: unit || 'd',
      quantity: Number(ds.restockQty) > 0 ? Number(ds.restockQty) : 10,
      source: 'auto'
    });
  } catch (e) {
    console.error('❌ [auto-restock proposal] gagal:', e.message);
  }
}

// ── Dispatcher gateway QRIS dinamis ──
// settings.apiGateway: 'pakasir' (default) | 'genspay'
// Semua call site lama tetap manggil createQRISPayment(orderId, amount, settings)
// apa adanya -- dispatcher ini yang nentuin ke gateway mana request-nya pergi.
const createQRISPayment = (orderId, amount, settings) => {
  const gateway = settings.apiGateway || 'pakasir';
  if (gateway === 'genspay') return createQRISPaymentGenspay(orderId, amount, settings);
  return createQRISPaymentPakasir(orderId, amount, settings);
};

// Kirim notifikasi WhatsApp otomatis ke admin via Fonnte (jika token dikonfigurasi)
const sendWhatsAppNotif = (target, message, settings) => {
  return new Promise((resolve) => {
    const token = settings?.fonnteToken?.trim() || '';
    if (!token || !target) return resolve(false);
    const body = `target=${encodeURIComponent(target)}&message=${encodeURIComponent(message)}`;
    const req = https.request({
      hostname: 'api.fonnte.com', port: 443,
      path: '/send', method: 'POST',
      headers: {
        'Authorization': token,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body)
      },
      timeout: 10000
    }, (res) => {
      res.on('data', () => {});
      res.on('end', () => resolve(true));
    });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.write(body); req.end();
  });
};

const checkPaymentStatusPakasir = (orderId, amount, settings) => {
  return new Promise((resolve, reject) => {
    const apiKey = settings.pakasir?.apiKey?.trim() || '';
    const project = settings.pakasir?.project?.trim() || '';
    if (!apiKey || !project) return reject(new Error('API Key PakKasir belum dikonfigurasi'));

    const q = `project=${encodeURIComponent(project)}&amount=${parseInt(amount)}&order_id=${encodeURIComponent(orderId)}&api_key=${encodeURIComponent(apiKey)}`;
    const req = https.request({
      hostname: 'app.pakasir.com', port: 443,
      path: `/api/transactiondetail?${q}`, method: 'GET', timeout: 10000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { reject(new Error('Gagal parse response status')); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('PakKasir status timeout')); });
    req.on('error', e => reject(new Error('Network error: ' + e.message)));
    req.end();
  });
};

// PENTING: dokumentasi resmi GensPay (genspay.my.id/docs) TIDAK menyediakan
// endpoint GET untuk cek status transaksi -- GensPay sepenuhnya mengandalkan
// WEBHOOK (POST ke Webhook URL project kamu, event "transaction.updated")
// buat kasih tau perubahan status. Fungsi ini reject dengan jelas supaya
// polling /check-payment tidak diam-diam gagal terus tanpa penjelasan;
// finalize order untuk GensPay HARUS lewat webhook (lihat
// app.post('/webhook/genspay') di bawah).
const checkPaymentStatusGenspay = (orderId, amount, settings) => {
  return Promise.reject(new Error(
    'GensPay tidak menyediakan endpoint cek status manual -- status transaksi HANYA dikirim via webhook. ' +
    'Pastikan Webhook URL sudah didaftarkan di dashboard GensPay (Settings project).'
  ));
};

// Dispatcher, sama polanya seperti createQRISPayment di atas.
const checkPaymentStatus = (orderId, amount, settings, gatewayOverride) => {
  const gateway = gatewayOverride || settings.apiGateway || 'pakasir';
  if (gateway === 'genspay') return checkPaymentStatusGenspay(orderId, amount, settings);
  return checkPaymentStatusPakasir(orderId, amount, settings);
};

// Routes - Public
// ══════════════════════════════════════════════════════════════════
// SETUP ENDPOINT — Reset admin password + push semua settings
// Akses: /agha-setup?secret=SETUP_SECRET (dari env var)
// Set SETUP_SECRET di Vercel env vars, lalu akses URL-nya via browser.
// Setelah berhasil, HAPUS SETUP_SECRET dari env Vercel untuk keamanan.
// ══════════════════════════════════════════════════════════════════
app.get('/agha-setup', async (req, res) => {
  const secret = process.env.SETUP_SECRET;
  if (!secret || req.query.secret !== secret) {
    return res.status(403).send('❌ Akses ditolak. Set SETUP_SECRET di env Vercel dulu.');
  }

  try {
    const currentSettings = await db.readFresh('settings.json') || {};

    // JANGAN hardcode password fallback di sini juga — endpoint ini bisa
    // dipicu ulang kapan saja oleh siapapun yang tahu SETUP_SECRET, jadi
    // fallback HARUS random per-run, bukan string tetap yang bisa dibaca
    // dari source code (lihat penjelasan yang sama di initDB()).
    const newUsername = process.env.INITIAL_ADMIN_USERNAME || 'admin';
    const newPassword = process.env.INITIAL_ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
    const newHash     = bcrypt.hashSync(newPassword, 12);

    const updatedSettings = {
      ...currentSettings,
      siteName:      'AGHA NL',
      gamePanelName: 'AGHA NL',
      about:         'AGHA NL DIGITAL STORE menyediakan layanan topup, files, dan access game terbaik #1 indonesia.',
      marqueeText:   'TOP UP & FILES GAME TERMURAH, AMAN, DAN CEPAT!',
      siteUrl: currentSettings.siteUrl || 'https://agha.nlstoreshop.my.id',
      contact: {
        ...(currentSettings.contact || {}),
        whatsapp:  currentSettings.contact?.whatsapp || '6282253090432',
        telegram:  currentSettings.contact?.telegram || 'AghaNLOfficial',
        email:     currentSettings.contact?.email || 'support@agha.nlstoreshop.my.id',
        youtube:   currentSettings.contact?.youtube || '',
        waChannel: currentSettings.contact?.waChannel || '',
        waGroup:   currentSettings.contact?.waGroup || '',
      },
      adminUsername: newUsername,
      adminPassword: newHash,
      logoUrl: currentSettings.logoUrl || '/uploads/logo-main.png',
      logoTextUrl: currentSettings.logoTextUrl || '/uploads/logo-text.png',
      buyerGroupName: currentSettings.buyerGroupName || 'BUYER VIP BY AGHA NL',
      buyerGroupUrl: currentSettings.buyerGroupUrl || 'https://chat.whatsapp.com/DUSkETDjlxa5aksYJ0ar1m',
      resellerGroupName: currentSettings.resellerGroupName || 'RESELLER VIP BY AGHA NL',
      resellerGroupUrl: currentSettings.resellerGroupUrl || 'https://chat.whatsapp.com/GO9mZ1wec8LJwVmlpeSW7G',
      theme: currentSettings.theme || {
        primaryColor: '#dc2626', secondaryColor: '#7b2cbf', accentColor: '#a3123a',
        backgroundColor: '#0a0a0a', cardBackground: '#141414', borderColor: '#3a1414', glowColor: '#dc2626',
      },
    };

    await db.writeDB('settings.json', updatedSettings);

    // Verify
    const saved   = await db.readFresh('settings.json');
    const verify  = bcrypt.compareSync(newPassword, saved.adminPassword);

    res.send(`
      <!DOCTYPE html><html><head><meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>Setup Result</title>
      <style>body{font-family:monospace;background:#121214;color:#e2e8f0;padding:24px;max-width:500px;margin:0 auto;}
      .ok{color:#4ade80;} .err{color:#f87171;} .box{background:#1c1c1f;border:1px solid rgba(220,38,38,.3);border-radius:10px;padding:20px;margin:16px 0;}
      h2{color:#f87171;} a{color:#f87171;}</style></head><body>
      <h2>${verify ? '✅ SETUP BERHASIL' : '❌ SETUP GAGAL'}</h2>
      <div class="box">
        <p class="ok">✅ adminUsername : <strong>${saved.adminUsername}</strong></p>
        <p class="${verify?'ok':'err'}">${verify?'✅':'❌'} password hash  : ${verify?'MATCH — password benar':'TIDAK MATCH — ada masalah!'}</p>
        <p class="ok">✅ whatsapp      : ${saved.contact?.whatsapp}</p>
        <p class="ok">✅ telegram      : ${saved.contact?.telegram}</p>
        <p class="ok">✅ waChannel     : ${saved.contact?.waChannel}</p>
        <p class="ok">✅ waGroup       : ${saved.contact?.waGroup}</p>
      </div>
      <div class="box">
        <p>🔐 <strong>Login Admin:</strong></p>
        <p>URL&nbsp;&nbsp;&nbsp;&nbsp;: <a href="/vpr-secure-panel-8x">/vpr-secure-panel-8x</a></p>
        <p>Username: <strong>${newUsername}</strong></p>
        <p>Password: <strong>${newPassword}</strong></p>
      </div>
      <p style="color:rgba(148,163,184,.5);font-size:11px;">⚠️ Setelah berhasil login, HAPUS SETUP_SECRET dari env Vercel!</p>
      </body></html>
    `);
  } catch (err) {
    res.status(500).send(`❌ Error: ${err.message}`);
  }
});

// ══════════════════════════════════════════════════════════════════
// SEO: robots.txt & sitemap.xml (diminta client 22 Agu 2026)
// ══════════════════════════════════════════════════════════════════
app.get('/robots.txt', (req, res) => {
  const siteUrl = (req.headers['x-forwarded-proto'] || req.protocol) + '://' + (req.headers['x-forwarded-host'] || req.get('host'));
  res.type('text/plain').send(
`User-agent: *
Allow: /
Disallow: /vpr-secure-panel-8x
Disallow: /admin
Disallow: /dashboard
Disallow: /invoice
Disallow: /activate-key
Disallow: /complete-profile
Disallow: /api/

Sitemap: ${siteUrl}/sitemap.xml`
  );
});

app.get('/sitemap.xml', async (req, res) => {
  try {
    const siteUrl = (req.headers['x-forwarded-proto'] || req.protocol) + '://' + (req.headers['x-forwarded-host'] || req.get('host'));
    const products = (await readSmart('products.json')).filter(p => p.status === 'active');

    // Halaman statis penting untuk SEO
    const staticUrls = [
      { loc: '/', priority: '1.0', changefreq: 'daily' },
      { loc: '/informasi?tab=cara-beli', priority: '0.6', changefreq: 'monthly' },
      { loc: '/informasi?tab=faq', priority: '0.6', changefreq: 'monthly' },
      { loc: '/informasi?tab=syarat', priority: '0.4', changefreq: 'monthly' },
      { loc: '/reseller', priority: '0.7', changefreq: 'weekly' },
      { loc: '/leaderboard', priority: '0.5', changefreq: 'daily' },
      { loc: '/login', priority: '0.3', changefreq: 'yearly' },
      { loc: '/register', priority: '0.3', changefreq: 'yearly' },
    ];

    // Halaman produk dinamis -- ini yang paling penting untuk SEO produk
    // spesifik (mis. "topup mod ff [nama produk]" bisa nemu halaman ini
    // langsung dari Google).
    const productUrls = products.map(p => ({
      loc: `/buy/${p.id}`,
      priority: '0.8',
      changefreq: 'weekly'
    }));

    const allUrls = [...staticUrls, ...productUrls];
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${allUrls.map(u => `  <url>
    <loc>${siteUrl}${u.loc}</loc>
    <changefreq>${u.changefreq}</changefreq>
    <priority>${u.priority}</priority>
  </url>`).join('\n')}
</urlset>`;

    res.type('application/xml').send(xml);
  } catch (error) {
    res.status(500).type('text/plain').send('Error generating sitemap');
  }
});

app.get('/', async (req, res) => {
  // FIX (egress): route publik dengan traffic tinggi -- pakai readSmart
  // (cache ber-TTL), BUKAN readFresh (selalu fetch Supabase). readFresh di
  // sini dulu bikin setiap visitor menarik ulang seluruh blob products.json
  // dari Supabase, menghabiskan kuota cached egress free tier dengan cepat.
  const products = (await readSmart('products.json')).filter(p => p.status === 'active');

  // ── Leaderboard real-time (hanya dari transaksi sukses) ──
  // FIX (diminta client 26 Agu 2026): sebelumnya leaderboard di homepage
  // dicampur dengan fakeLeaderboard (entri buatan admin dari Admin Panel),
  // jadi bisa ada nama fiktif nyelip di Top Pembeli. Sekarang homepage
  // HANYA menampilkan data transaksi asli dari computeLeaderboard() --
  // fakeLeaderboard tidak lagi dipakai di sini (tetap ada di kode untuk
  // /leaderboard kalau suatu saat admin butuh, tapi tidak digabung ke
  // homepage). Field `photo` juga ikut dibawa supaya avatar bisa pakai
  // foto profil asli pembeli, bukan cuma inisial huruf.
  // PERFORMANCE: pakai computeLeaderboard() yang di-cache 30 detik, supaya
  // homepage (traffic tertinggi) tidak scan ulang seluruh transactions dari
  // nol di setiap request.
  const leaderboardEntries = computeLeaderboard()
    .map(e => ({ username: e.username, photo: e.photo, totalTransactions: e.totalTransactions, totalSpent: e.totalSpent }))
    .slice(0, 8);

  // ── Server-side fake testimonials ──
  const fakeTestimonials = [
    { id:'fake1', name:'Rizky F.',    rating:5, text:'Mod FF-nya mantap, udah 3 bulan pakai dan aman-aman aja. Fitur lengkap dari ESP sampai fly hack. CS juga responsif banget!', productName:'FREE FIRE MAX',      date:'2025-05-20', verified:true },
    { id:'fake2', name:'Andi S.',     rating:5, text:'ML mod-nya lengkap banget! Map hack, drone view, sampai skin all hero ada. Auto update jadi nggak perlu repot tiap update.', productName:'MOBILE LEGENDS',    date:'2025-05-18', verified:true },
    { id:'fake3', name:'Dimas P.',    rating:5, text:'Support fast response! Pas ada masalah langsung dibantu sampai beres. PUBG mod-nya juga smooth, nggak lag sama sekali.', productName:'PUBG MOBILE',   date:'2025-05-15', verified:true },
    { id:'fake4', name:'farhan',      rating:5, text:'Beli sertifikat anti-banned udah 2x dan alhamdulillah akun tetap aman. Worth it banget harganya segitu.', productName:'SERTIFIKAT', date:'2025-05-10', verified:true },
    { id:'fake5', name:'Wanda M.',    rating:4, text:'Produknya bagus, pengiriman key cepet banget. Cuma kadang agak lag di device lama tapi overall oke lah.', productName:'MOBILE LEGENDS',    date:'2025-05-08', verified:true },
    { id:'fake6', name:'ACA',         rating:5, text:'Udah lama langganan di sini, belum pernah kecewa. Proses beli gampang, bayar QRIS langsung dapat key. Recommended!', productName:'FREE FIRE MAX',      date:'2025-05-05', verified:true },
    { id:'fake7', name:'bintang',     rating:5, text:'Lifetime PUBGM worth it banget. Udah 6 bulan masih lancar jaya, fitur no recoil-nya mantul.', productName:'PUBG MOBILE',   date:'2025-04-28', verified:true },
    { id:'fake8', name:'Rizky',       rating:4, text:'Kalau FF mod-nya top. Pernah ada issue tapi langsung di-handle sama admin. Keep up the good work!', productName:'FREE FIRE MAX',      date:'2025-04-20', verified:true },
    { id:'fake9', name:'Kevin',       rating:5, text:'CODM mod anti-recoil smooth banget. Rank dari Silver langsung naik ke Platinum dalam seminggu haha.', productName:'CODM',    date:'2025-04-15', verified:true },
    { id:'fake10',name:'abil',        rating:5, text:'Ini toko mod menu terpercaya yang pernah aku coba. Transaksi aman, key langsung masuk, CS ramah.', productName:'FREE FIRE MAX',      date:'2025-04-10', verified:true },
    { id:'fake11',name:'Hergi',       rating:5, text:'Valorant ESP-nya akurat banget. Sudah 2 bulan pake dan belum ada masalah sama sekali. Pelayanan top!', productName:'VALORANT', date:'2025-04-05', verified:true },
    { id:'fake12',name:'rehan',       rating:5, text:'HOK mod-nya mantap, map hack dan skin unlock semua ada. Proses beli cepet dan key langsung terkirim.', productName:'HOK',     date:'2025-03-28', verified:true },
  ];
  const realTestimonials = readDB('testimonials.json').filter(t => t.verified);
  const testiUsernames = new Set(realTestimonials.map(t => (t.username||'').toLowerCase()));
  const paddedFake = fakeTestimonials.filter(f => !testiUsernames.has((f.name||'').toLowerCase()));
  const testimonialsForHome = [...realTestimonials, ...paddedFake].slice(0, 12);
  const avgRating = testimonialsForHome.length
    ? (testimonialsForHome.reduce((s, t) => s + (t.rating || 0), 0) / testimonialsForHome.length).toFixed(1)
    : '4.9';
  const ratingCounts = {1:0,2:0,3:0,4:0,5:0};
  testimonialsForHome.forEach(t => { if (t.rating >= 1 && t.rating <= 5) ratingCounts[t.rating]++; });
  const totalSold = products.reduce((s, p) => s + (p.sold || 0), 0);
  // Pakai res.locals.settings yang sudah di-fetch oleh middleware (readFresh fallback)
  const settings = res.locals.settings || readDB('settings.json');
  const user = res.locals.user || getSessionUser(req);

  // LIVE PROVIDER: stok katalog tidak boleh bergantung hanya pada jumlah key
  // lokal. Produk dengan mapping DripStore tetap tersedia selama minimal satu
  // key variant masih mampu dibeli dari saldo provider. Snapshot provider
  // dicache singkat agar homepage tidak menembak API sekali per produk.
  let homeProviderSnapshot = null;
  const homeDsMode = settings.dripstore?.fulfillmentMode || 'live';
  if ((homeDsMode === 'live' || homeDsMode === 'hybrid') && settings.dripstore?.apiToken) {
    homeProviderSnapshot = getCachedDripstoreCatalogSnapshot(settings);
    // IMPORTANT: on a Vercel cold start there is no in-memory provider cache.
    // Rendering immediately with null snapshot makes every LIVE product look
    // like stock=0 even though DripStore has balance/variants. Fetch one
    // catalog snapshot for the first render; later requests use the cache.
    if (!homeProviderSnapshot) {
      homeProviderSnapshot = await getDripstoreCatalogSnapshot(settings, { maxWaitMs: 3500 }).catch(() => null);
      if (!homeProviderSnapshot?.products) homeProviderSnapshot = getDisplayDripstoreSnapshot(settings) || homeProviderSnapshot;
    }
    warmDripstoreCatalog(settings);
  }
  const homeProducts = products.map(rawProduct => {
    const summary = buildProductStockSummary(rawProduct, settings, homeProviderSnapshot);
    const providerStock = summary.stockByOption.length ? Math.max(...summary.stockByOption.map(v => v.providerKnown ? v.providerStock : 0), 0) : 0;
    const hasProviderBacked = summary.stockByOption.some(v => v.providerBacked);
    return { ...summary.product, _liveProviderStock: providerStock, _catalogStock: summary.stockCount,
      _providerStockUnknown: summary.providerStockUnknown, _hasProviderBacked: hasProviderBacked,
      _stockByOption: summary.stockByOption };
  });

  res.render('pages/home', {
    products: homeProducts,
    settings,
    user,
    categories: settings.categories || [],
    categoryLabels: settings.categoryLabels || {},
    resellerSettings: {
      enabled: settings.resellerEnabled !== false,
      price: settings.resellerPrice || 50000,
      discount: settings.resellerDiscount || 20
    },
    leaderboardEntries,
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
    testimonialsForHome,
    avgRating,
    ratingCounts,
    totalSold
  });
});

// Auth routes
app.get('/login', (req, res) => {
  if (req.session?.userId) return res.redirect('/');
  res.render('pages/login', {
    error: null,
    redirect: req.query.redirect || '/',
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
  });
});

app.post('/login', async (req, res) => {
  const ip = req.ip;
  const { blocked, wait } = checkLoginBlocked(ip);
  if (blocked) {
    return res.render('pages/login', {
      error: `Terlalu banyak percobaan login. Coba lagi dalam ${wait} menit.`,
      redirect: req.body.redirect || '/',
      turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
    });
  }

  // ── Verifikasi Cloudflare Turnstile ─────────────────────────────────────
  if (process.env.TURNSTILE_SECRET_KEY) {
    const token = req.body['cf-turnstile-response'];
    if (!token) {
      return res.render('pages/login', {
        error: 'Verifikasi keamanan diperlukan. Mohon selesaikan captcha.',
        redirect: req.body.redirect || '/',
        turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
      });
    }
    const valid = await verifyTurnstile(token);
    if (!valid) {
      return res.render('pages/login', {
        error: 'Verifikasi keamanan gagal. Coba lagi.',
        redirect: req.body.redirect || '/',
        turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
      });
    }
  }
  // ────────────────────────────────────────────────────────────────────────

  const { username, password } = req.body;
  const settings = readDB('settings.json');

  // Admin login diblokir dari /login — gunakan halaman khusus
  if (username === settings.adminUsername) {
    recordLoginFail(ip);
    return res.render('pages/login', {
      error: 'Username atau password salah.',
      redirect: req.body.redirect || '/',
      turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
    });
  }

  // Check user
  const users = readDB('users.json');
  const user = users.find(u => u.username === username);

  // BUG FIX (audit 19 Sep 2026): akun yang daftar via Google OAuth punya
  // password: null (lihat GoogleStrategy callback di atas). bcrypt.compare()
  // MELEMPAR error kalau hash-nya bukan string ("Illegal arguments: string,
  // object"), bukan cuma balas false. Sebelumnya kode ini langsung
  // await bcrypt.compare(password, user.password) tanpa cek user.password
  // dulu -- kalau ada pengunjung (siapa saja, tidak perlu login) mengetik
  // username akun Google-only ke form login manual ini, promise yang
  // reject itu TIDAK PERNAH ditangkap (tidak ada try/catch di route ini),
  // jadi jadi unhandled promise rejection: request menggantung tanpa
  // respons sampai timeout, dan di Node modern proses server bisa ikut
  // crash (unhandled rejection = uncaught exception secara default).
  // Ini DoS trivial: attacker cukup tahu satu username akun Google buat
  // bikin server down berulang kali. Fix: skip bcrypt.compare kalau akun
  // ini tidak punya password lokal sama sekali.
  if (user && user.password && await bcrypt.compare(password, user.password)) {
    clearLoginFail(ip);
    req.session.userId = user.id;
    req.session.isAdmin = (user.role === 'admin');
    return res.redirect(req.body.redirect || (req.session.isAdmin ? '/admin' : '/'));
  }

  recordLoginFail(ip);
  const remaining = LOGIN_MAX_FAIL - (loginFailMap.get(ip)?.count || 0);
  const errMsg = remaining > 0
    ? `Username atau password salah. Sisa percobaan: ${remaining}`
    : `Terlalu banyak percobaan login. Coba lagi dalam 15 menit.`;
  res.render('pages/login', {
    error: errMsg,
    redirect: req.body.redirect || '/',
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
  });
});

app.get('/register', (req, res) => {
  if (req.session?.userId) return res.redirect('/');
  res.render('pages/register', { error: null });
});

// ══════════════════════════════════════════════════════════════════
// API JSON untuk LOGIN/REGISTER via POPUP (diminta client 22 Agu 2026:
// "login daftar nya tuh di pop up dahsbord bkn di halaman beda") --
// endpoint /login /register HTML lama TETAP ADA sebagai fallback (mis.
// kalau JS disabled, atau diakses langsung via URL), tapi sekarang modal
// popup di homepage manggil endpoint JSON ini supaya submit tidak perlu
// reload/pindah halaman sama sekali. Logic validasinya identik dengan
// /login /register lama, cuma bentuk response-nya JSON bukan render/redirect.
app.post('/api/auth/login', async (req, res) => {
  const ip = req.ip;
  const { blocked, wait } = checkLoginBlocked(ip);
  if (blocked) {
    return res.json({ success: false, message: `Terlalu banyak percobaan login. Coba lagi dalam ${wait} menit.` });
  }

  if (process.env.TURNSTILE_SECRET_KEY) {
    const token = req.body['cf-turnstile-response'];
    if (!token) return res.json({ success: false, message: 'Verifikasi keamanan diperlukan. Mohon selesaikan captcha.' });
    const valid = await verifyTurnstile(token);
    if (!valid) return res.json({ success: false, message: 'Verifikasi keamanan gagal. Coba lagi.' });
  }

  const { username, password } = req.body;
  const settings = readDB('settings.json');

  if (username === settings.adminUsername) {
    recordLoginFail(ip);
    return res.json({ success: false, message: 'Username atau password salah.' });
  }

  const users = readDB('users.json');
  const user = users.find(u => u.username === username);

  // BUG FIX (audit 19 Sep 2026): sama seperti /login -- lihat komentar
  // panjang di route /login untuk penjelasan lengkap kenapa cek
  // `user.password` wajib ada sebelum bcrypt.compare (akun Google OAuth
  // punya password: null, dan bcrypt.compare(pw, null) throw, bukan
  // balas false, sehingga tanpa guard ini request menggantung/crash).
  if (user && user.password && await bcrypt.compare(password, user.password)) {
    clearLoginFail(ip);
    req.session.userId = user.id;
    req.session.isAdmin = (user.role === 'admin');
    return res.json({ success: true, redirect: req.body.redirect || (req.session.isAdmin ? '/admin' : '/') });
  }

  recordLoginFail(ip);
  const remaining = LOGIN_MAX_FAIL - (loginFailMap.get(ip)?.count || 0);
  const errMsg = remaining > 0
    ? `Username atau password salah. Sisa percobaan: ${remaining}`
    : `Terlalu banyak percobaan login. Coba lagi dalam 15 menit.`;
  res.json({ success: false, message: errMsg });
});

app.post('/api/auth/register', async (req, res) => {
  if (!checkApiRateLimit(req.ip, 5, 15 * 60 * 1000)) {
    return res.json({ success: false, message: 'Terlalu banyak percobaan pendaftaran. Coba lagi dalam beberapa menit.' });
  }

  // FIX: endpoint ini sebelumnya sama sekali tidak verifikasi turnstile
  // (beda dengan /api/auth/login yang sudah cek), padahal form Daftar di
  // modal juga punya widget captcha. Disamakan biar konsisten.
  if (process.env.TURNSTILE_SECRET_KEY) {
    const token = req.body['cf-turnstile-response'];
    if (!token) return res.json({ success: false, message: 'Verifikasi keamanan diperlukan. Mohon selesaikan captcha.' });
    const valid = await verifyTurnstile(token);
    if (!valid) return res.json({ success: false, message: 'Verifikasi keamanan gagal. Coba lagi.' });
  }

  const { username, password, confirmPassword, wa } = req.body;

  if (!username || !password || !wa) {
    return res.json({ success: false, message: 'Semua field wajib diisi' });
  }
  const pwError = validatePasswordStrength(password);
  if (pwError) {
    return res.json({ success: false, message: pwError });
  }
  if (confirmPassword && password !== confirmPassword) {
    return res.json({ success: false, message: 'Konfirmasi password tidak cocok' });
  }
  if (username === 'Abdurahman Mulvi') {
    return res.json({ success: false, message: 'Username tidak diizinkan' });
  }

  const users = readDB('users.json');
  if (users.find(u => u.username === username)) {
    return res.json({ success: false, message: 'Username sudah digunakan' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: uuidv4(),
    username,
    password: hashedPassword,
    wa,
    photo: null,
    balance: 0,
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  await writeDB('users.json', users);

  req.session.userId = newUser.id;
  req.session.isAdmin = false;

  res.json({ success: true, redirect: '/' });
});

app.post('/register', async (req, res) => {
  // FIX KEAMANAN (audit 22 Agu 2026): endpoint ini sebelumnya TIDAK ada
  // rate limiting sama sekali -- bisa disalahgunakan buat mass account
  // creation (bot spam ribuan akun palsu), yang membebani database dan
  // juga costly karena tiap request menjalankan bcrypt.hash() (operasi
  // yang sengaja lambat/mahal secara komputasi). Limit ketat (5x/15menit
  // per IP) karena registrasi akun itu action yang jarang dilakukan
  // berkali-kali oleh user normal dalam waktu singkat.
  if (!checkApiRateLimit(req.ip, 5, 15 * 60 * 1000)) {
    return res.render('pages/register', { error: 'Terlalu banyak percobaan pendaftaran. Coba lagi dalam beberapa menit.' });
  }
  const { username, password, confirmPassword, wa } = req.body;

  if (!username || !password || !wa) {
    return res.render('pages/register', { error: 'Semua field wajib diisi' });
  }

  const pwError = validatePasswordStrength(password);
  if (pwError) {
    return res.render('pages/register', { error: pwError });
  }

  if (confirmPassword && password !== confirmPassword) {
    return res.render('pages/register', { error: 'Konfirmasi password tidak cocok' });
  }

  if (username === 'Abdurahman Mulvi') {
    return res.render('pages/register', { error: 'Username tidak diizinkan' });
  }

  const users = readDB('users.json');

  if (users.find(u => u.username === username)) {
    return res.render('pages/register', { error: 'Username sudah digunakan' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: uuidv4(),
    username,
    password: hashedPassword,
    wa,
    photo: null,
    balance: 0,
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  await writeDB('users.json', users);

  req.session.userId = newUser.id;
  req.session.isAdmin = false;

  res.redirect('/');
});

// ══════════════════════════════════════════════════════════════════
// GOOGLE OAUTH ROUTES (opsional -- lihat setup passport di atas)
// ══════════════════════════════════════════════════════════════════
app.get('/auth/google', (req, res, next) => {
  if (!GOOGLE_OAUTH_ENABLED) return res.redirect('/login?error=Google login belum diaktifkan admin');
  // redirect tujuan setelah login sukses (mis. balik ke halaman /buy/:id
  // yang lagi dibuka), disimpan sebentar di session sebelum lempar ke Google.
  if (req.query.redirect) req.session.oauthRedirect = req.query.redirect;
  passport.authenticate('google', { scope: ['profile', 'email'], session: false })(req, res, next);
});

app.get('/auth/google/callback', (req, res, next) => {
  if (!GOOGLE_OAUTH_ENABLED) return res.redirect('/login');
  passport.authenticate('google', { session: false, failureRedirect: '/login?error=Login Google gagal' }, (err, user) => {
    if (err || !user) return res.redirect('/login?error=Login Google gagal');
    req.session.userId = user.id;
    req.session.isAdmin = false;
    const redirectTo = req.session.oauthRedirect || (!user.wa ? '/complete-profile' : '/');
    delete req.session.oauthRedirect;
    // Akun Google baru belum ada nomor WA (dipakai buat pengiriman notif
    // key/transaksi) -- giring ke halaman lengkapi profil sekali di awal.
    if (!user.wa) return res.redirect('/complete-profile');
    res.redirect(redirectTo);
  })(req, res, next);
});

// Lengkapi profil (nomor WA) untuk akun yang baru daftar via Google --
// WA dipakai buat kirim notifikasi key/transaksi, jadi tetap wajib diisi
// sekali meski proses signup awalnya "one-click" via Google.
app.get('/complete-profile', requireAuth, (req, res) => {
  const user = getSessionUser(req);
  if (user?.wa) return res.redirect('/');
  res.render('pages/complete-profile', { user });
});

app.post('/complete-profile', requireAuth, async (req, res) => {
  try {
    const { wa } = req.body;
    if (!wa || !wa.trim()) return res.json({ success: false, message: 'Nomor WhatsApp wajib diisi' });
    const users = await readFresh('users.json');
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    user.wa = wa.trim();
    await writeDB('users.json', users);
    res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.get('/logout', async (req, res) => {
  if (req.session?.isAdmin && req.session?.adminSessionId) {
    await releaseAdminLock(req.session.adminSessionId);
  }
  req.session = null;
  res.redirect('/');
});

// ══ AGHA NL: ADMIN SECRET LOGIN GATE (hidden from public) ══
app.get('/vpr-secure-panel-8x', (req, res) => {
  if (req.session?.isAdmin) return res.redirect('/admin');
  const kicked = req.query.kicked === '1';
  res.render('pages/admin-login', {
    error: kicked ? 'Anda logout otomatis karena ada login admin dari perangkat lain.' : null,
    lockedInfo: null,
    username: ''
  });
});

app.post('/vpr-secure-panel-8x', async (req, res) => {
  const ip = req.ip;
  const { blocked, wait } = checkLoginBlocked(ip);
  if (blocked) {
    return res.render('pages/admin-login', {
      error: `Terlalu banyak percobaan. Coba lagi dalam ${wait} menit.`,
      lockedInfo: null, username: ''
    });
  }
  const { username, password, forceTakeover } = req.body;

  // ── FIX: readFresh() ambil langsung dari Supabase, bypass cache ──
  // Ini penting karena di Vercel tiap instance punya cache kosong
  const settings = await db.readFresh('settings.json');

  if (!settings || !settings.adminUsername) {
    return res.render('pages/admin-login', {
      error: 'Konfigurasi admin belum tersedia. Coba beberapa saat lagi.',
      lockedInfo: null, username: ''
    });
  }

  if (username === settings.adminUsername) {
    const match = await bcrypt.compare(password, settings.adminPassword);
    if (match) {
      // ── Single-Device Lock: cek apakah panel sedang dipakai device lain ──
      const currentLock = await db.readFresh('admin-lock.json');
      if (isLockActive(currentLock) && forceTakeover !== '1') {
        const minutesAgo = Math.max(1, Math.round((Date.now() - new Date(currentLock.lastSeen).getTime()) / 60000));
        return res.render('pages/admin-login', {
          error: null,
          username,
          lockedInfo: {
            device: currentLock.device || 'Perangkat tidak diketahui',
            minutesAgo
          }
        });
      }
      clearLoginFail(ip);
      req.session.userId = 'admin';
      req.session.isAdmin = true;
      req.session.adminSessionId = await acquireAdminLock(req);
      return res.redirect('/admin');
    }
  }
  recordLoginFail(ip);
  const remaining = LOGIN_MAX_FAIL - (loginFailMap.get(ip)?.count || 0);
  res.render('pages/admin-login', {
    error: remaining > 0
      ? `Username atau password salah. Sisa percobaan: ${remaining}`
      : 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.',
    lockedInfo: null, username: ''
  });
});


// ── RESELLER ──
app.get('/reseller', (req, res) => {
  // Pakai res.locals.settings yang sudah di-fetch oleh middleware (readFresh fallback)
  const settings = res.locals.settings || readDB('settings.json');
  const user = res.locals.user || getSessionUser(req);
  res.render('pages/reseller', { layout: false, settings, user });
});

app.post('/reseller/join', requireAuth, async (req, res) => {
  try {
    if (req.session.isAdmin) return res.json({ success: false, message: 'Admin tidak perlu join reseller' });
    // Rate limit khusus pembayaran (kebijakan wajib GensPay, lihat checkPaymentRateLimit di atas)
    if (!checkPaymentRateLimit(req.session.userId)) {
      return res.json({ success: false, message: 'Terlalu banyak permintaan, coba lagi sebentar.' });
    }
    const users = readDB('users.json');
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    if (user.is_reseller) return res.json({ success: false, message: 'Kamu sudah menjadi Reseller VIP!' });

    const settings = readDB('settings.json');
    const price = settings.resellerPrice || 50000;
    const orderId = `RES-${Date.now()}`;
    const refId = uuidv4();
    const orderCode = generateOrderCode();

    const qrisMode = settings.qrisMode || 'static';

    let qrString = null, isStatic = false;

    if (qrisMode === 'static') {
      if (!settings.qrisStaticImage) return res.json({ success: false, message: 'Admin belum mengatur QRIS. Hubungi admin.' });
      isStatic = true;
    } else {
      try {
        const r = await createQRISPayment(orderId, price, settings);
        qrString = r.qr_string;
      } catch (e) {
        if (settings.qrisStaticImage) { isStatic = true; }
        else return res.json({ success: false, message: 'QRIS error: ' + e.message });
      }
    }

    const transactions = readDB('transactions.json');
    transactions.push({
      id: refId, orderId, code: orderCode,
      userId: user.id, type: 'reseller',
      productName: 'Upgrade Reseller VIP',
      customerName: user.username, wa: user.wa,
      price, totalPayment: price, qrString, isStatic,
      paymentGateway: settings.apiGateway || 'pakasir',
      status: 'pending', key: null,
      createdAt: new Date().toISOString(), time: formatDate()
    });
    await writeDB('transactions.json', transactions);

    res.json({ success: true, refId, orderId, qrString, orderCode, isStatic, paymentGateway: settings.apiGateway || 'pakasir',
      qrisStaticImage: isStatic ? settings.qrisStaticImage : null });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// ── WALLET (SALDO RESELLER) ──
// Khusus Reseller VIP top-up saldo via QRIS. Setelah dibayar & dikonfirmasi
// (lihat /check-payment/:refId), saldo otomatis bertambah dan bisa langsung
// dipakai untuk beli key tanpa scan QRIS lagi (lihat /wallet/buy).
app.post('/wallet/topup', requireAuth, async (req, res) => {
  try {
    if (req.session.isAdmin) return res.json({ success: false, message: 'Admin tidak memiliki wallet' });
    // Rate limit khusus pembayaran (kebijakan wajib GensPay, lihat checkPaymentRateLimit di atas)
    if (!checkPaymentRateLimit(req.session.userId)) {
      return res.json({ success: false, message: 'Terlalu banyak permintaan, coba lagi sebentar.' });
    }
    const users = readDB('users.json');
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    if (!user.is_reseller) return res.json({ success: false, message: 'Top up saldo khusus untuk Reseller VIP. Gabung reseller dulu yuk!' });

    const settings = readDB('settings.json');
    const minDeposit = settings.resellerMinDeposit || 50000;
    // FIX (bug 14 Sep 2026, sama kayak harga produk): bersihin dulu
    // titik/koma nyempil sebelum parseInt biar "100.000" gak kebaca 100.
    const amount = parseInt(String(req.body.amount||'').replace(/[^\d]/g,''), 10);
    if (isNaN(amount) || amount < minDeposit) {
      return res.json({ success: false, message: `Minimal top up Rp ${minDeposit.toLocaleString('id-ID')}` });
    }

    const orderId = `DEP-${Date.now()}`;
    const refId = uuidv4();
    const orderCode = generateOrderCode();
    const qrisMode = settings.qrisMode || 'static';

    let qrString = null, isStatic = false, totalPayment = amount, expiredAt = null;

    if (qrisMode === 'static') {
      if (!settings.qrisStaticImage) return res.json({ success: false, message: 'Admin belum mengatur QRIS. Hubungi admin.' });
      isStatic = true;
    } else {
      try {
        const r = await createQRISPayment(orderId, amount, settings);
        qrString = r.qr_string;
        // total_payment dari Pakasir = amount + fee mereka (kalau ada). Ini
        // CUMA buat ditampilkan ke user biar nominal yang ditampilkan sama
        // persis dengan yang diminta di QR code-nya. Saldo yang dikreditkan
        // tetap pakai `amount` asli (lihat field `amount` di transaksi di
        // bawah) supaya fee Pakasir tidak ikut numpang masuk ke saldo user.
        totalPayment = r.total_payment || amount;
        expiredAt = r.expired_at || null;
      } catch (e) {
        if (settings.qrisStaticImage) { isStatic = true; }
        else return res.json({ success: false, message: 'QRIS error: ' + e.message });
      }
    }

    const transactions = readDB('transactions.json');
    transactions.push({
      id: refId, orderId, code: orderCode,
      userId: user.id, type: 'deposit',
      productName: 'Top Up Saldo Reseller',
      amount,
      customerName: user.username, wa: user.wa,
      price: amount, totalPayment, expiredAt, qrString, isStatic,
      paymentGateway: settings.apiGateway || 'pakasir',
      status: 'pending', key: null,
      createdAt: new Date().toISOString(), time: formatDate()
    });
    await writeDB('transactions.json', transactions);

    res.json({ success: true, refId, orderId, qrString, orderCode, isStatic, totalPayment, expiredAt, paymentGateway: settings.apiGateway || 'pakasir',
      qrisStaticImage: isStatic ? settings.qrisStaticImage : null });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// Beli key langsung pakai saldo wallet (khusus reseller) — tanpa scan QRIS,
// saldo langsung terpotong dan key langsung diberikan.
app.post('/wallet/buy', requireAuth, async (req, res) => {
  if (walletLocks.has(req.session.userId)) {
    return res.json({ success: false, message: 'Transaksi sebelumnya masih diproses, tunggu sebentar...' });
  }
  walletLocks.add(req.session.userId);
  let releaseWalletLock = null;
  try {
    releaseWalletLock = await acquirePersistentNamedLock(`wallet-purchase:${String(req.session.userId)}`, { waitMs: 7000, staleMs: 60000 });
    if (!releaseWalletLock) return res.json({ success: false, message: 'Transaksi saldo sedang diproses di perangkat lain. Tunggu sebentar.' });
    if (req.session.isAdmin) return res.json({ success: false, message: 'Admin tidak bisa membeli produk' });
    const { productId, duration, durationUnit, customerName, wa, voucherCode } = req.body;

    const users = await readFresh('users.json');
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    if (!user.is_reseller) return res.json({ success: false, message: 'Fitur beli pakai saldo khusus Reseller VIP' });

    const products = await readFresh('products.json');
    const rawProduct = products.find(p => p.id === productId);
    const product = rawProduct ? normalizeProductBuyOptions(rawProduct) : null;
    if (!product || product.status !== 'active') return res.json({ success: false, message: 'Produk tidak ditemukan' });

    const selectedUnit = durationUnit === 'h' ? 'h' : 'd';
    let price = 0, selectedDays = null, matchedOpt = null, matchedItem = null;
    if (product.pricingOptions?.length) {
      if (durationUnit) {
        const days = parseInt(duration, 10);
        matchedOpt = product.pricingOptions.find(o => Number(o.days) === days && (o.unit || 'd') === selectedUnit);
      } else {
        matchedItem = product.items?.find(i => i.l === duration || i.l.includes(duration));
        if (matchedItem) matchedOpt = product.pricingOptions.find(o => Number(o.price) === Number(matchedItem.p));
        if (!matchedOpt) {
          const days = parseInt(duration, 10);
          matchedOpt = product.pricingOptions.find(o => Number(o.days) === days && (o.unit || 'd') === 'd');
        }
      }
    }
    if (matchedOpt) {
      price = Number(matchedOpt.price || 0);
      selectedDays = Number(matchedOpt.days);
    } else {
      matchedItem = matchedItem || product.items?.find(i => i.l === duration || i.l.includes(duration));
      if (!matchedItem) return res.json({ success: false, message: 'Durasi tidak valid' });
      price = Number(matchedItem.p || 0);
      const m = String(duration).match(/(\d+)/);
      selectedDays = m ? parseInt(m[1], 10) : null;
    }

    const settings = await readFresh('settings.json');
    if (matchedItem == null && selectedDays != null) {
      matchedItem = product.items?.find(i => Number(i.durationValue) === Number(selectedDays) && (i.durationUnit || 'd') === selectedUnit);
    }
    const manualResellerPrice = matchedItem?.reseller_price ?? matchedOpt?.reseller_price ?? null;
    if (manualResellerPrice != null && manualResellerPrice >= 0) {
      price = Number(manualResellerPrice);
    } else {
      const disc = settings.resellerDiscount || 20;
      price = Math.round(price * (1 - disc / 100));
    }

    let voucherDiscount = 0, appliedVoucher = null, originalPrice = price;
    if (voucherCode && voucherCode.trim()) {
      const vResult = await validateVoucher(voucherCode, price, req.session.userId);
      if (!vResult.valid) return res.json({ success: false, message: 'Voucher: ' + vResult.error });
      voucherDiscount = vResult.discount;
      price = vResult.finalPrice;
      appliedVoucher = vResult.voucher;
    }

    const balance = Number(user.balance || 0);
    if (balance < price) {
      return res.json({ success: false, message: 'insufficient_balance', shortfall: price - balance,
        needed: price, balance, plainMessage: `Saldo tidak cukup. Kurang Rp ${(price - balance).toLocaleString('id-ID')}, top up dulu yuk!` });
    }

    const fulfillmentMode = settings.dripstore?.fulfillmentMode || 'live';
    let key = null;
    let keySource = 'local_stock';
    let providerTransactionId = null;
    let providerVariantId = null;
    let localInventoryCommitted = false;

    // Selalu coba stok lokal exact terlebih dahulu. Mode DripStore tidak boleh
    // membuat key lokal yang sudah tersedia menjadi tidak terbaca.
    if (selectedDays != null) {
      const local = await consumeLocalProductKey(product.id, selectedDays, selectedUnit);
      if (local.key) {
        key = local.key;
        localInventoryCommitted = !!local.committed;
      }
    } else if (selectedDays == null) {
      const local = await consumeLocalProductKey(product.id, null, selectedUnit);
      if (local.key) {
        key = local.key;
        localInventoryCommitted = !!local.committed;
      }
    }

    // LIVE: selalu provider. HYBRID: provider hanya fallback setelah stok lokal
    // exact benar-benar kosong. Resolver provider membaca katalog TERKINI, jadi
    // mapping ID lama/stale tidak bisa membuat pembelian jatuh ke variant salah.
    if (!key && (fulfillmentMode === 'live' || fulfillmentMode === 'hybrid') && selectedDays != null) {
      try {
        const live = await fulfillProductFromDripstore({
          id: 'wallet-' + Date.now() + '-' + req.session.userId,
          productId: product.id, selectedDays, selectedUnit
        }, settings);
        key = live?.key || null;
        keySource = live?.source || keySource;
        providerTransactionId = live?.providerTransactionId || null;
        providerVariantId = live?.variantId || null;
      } catch (e) {
        return res.json({ success: false, message: (fulfillmentMode === 'hybrid' ? 'Stok lokal habis dan provider tidak dapat memenuhi pesanan: ' : 'Gagal mengambil key dari DripStore: ') + e.message });
      }
    }

    if (!key) {
      return res.json({ success: false, message: selectedDays != null
        ? `Stok ${formatDurationLabel(selectedDays, selectedUnit)} sedang habis. Silakan pilih durasi lain atau tunggu admin.`
        : 'Stok habis' });
    }

    // Key sudah aman didapat. Baru potong wallet. Untuk local key, stok dan sold
    // sudah dipersist dalam consumeLocalProductKey() di bawah lock.
    user.balance = balance - price;
    await writeDB('users.json', users);

    if (!localInventoryCommitted) {
      await incrementProductSold(product.id);
    }

    const refId = uuidv4();
    const orderCode = generateOrderCode();
    const transactions = await readFresh('transactions.json');
    transactions.push({
      id: refId, orderId: `WLT-${Date.now()}`, code: orderCode,
      userId: user.id, productId: product.id, productName: product.name,
      duration, selectedDays, selectedUnit,
      originalPrice: voucherDiscount > 0 ? originalPrice : undefined,
      voucherCode: appliedVoucher ? appliedVoucher.code : undefined,
      voucherDiscount: voucherDiscount > 0 ? voucherDiscount : undefined,
      price, totalPayment: price, paymentMethod: 'wallet',
      customerName: customerName || user.username, wa: wa || user.wa,
      status: 'done', key, keySource,
      providerVariantId: providerVariantId || undefined,
      providerTransactionId: providerTransactionId || undefined,
      paidAt: new Date().toISOString(), createdAt: new Date().toISOString(), time: formatDate()
    });
    await writeDB('transactions.json', transactions);

    if (appliedVoucher) {
      const vouchers = await readFresh('vouchers.json');
      const v = vouchers.find(v => v.id === appliedVoucher.id);
      if (v) {
        v.usedCount = (v.usedCount || 0) + 1;
        v.usages = v.usages || [];
        v.usages.push({ userId: req.session.userId, usedAt: new Date().toISOString(), orderId: refId });
        await writeDB('vouchers.json', vouchers);
      }
    }

    const notifs = await readFresh('notifications.json').catch(() => []);
    notifs.unshift({ id: uuidv4(), type: 'purchase', buyerName: customerName || user.username,
      buyerPhoto: user.photo || null, productName: product.name,
      price, time: new Date().toISOString(), timeStr: formatDate() });
    await writeDB('notifications.json', notifs.slice(0, 50));

    res.json({ success: true, key, code: orderCode, balance: user.balance, voucherDiscount: voucherDiscount || undefined });
  } catch (e) {
    console.error('[wallet/buy] error:', e.message);
    res.json({ success: false, message: 'Terjadi kesalahan: ' + e.message });
  } finally {
    if (releaseWalletLock) await releaseWalletLock();
    walletLocks.delete(req.session.userId);
  }
});

// ── PROFILE PHOTO ──
const avatarUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = isVercel ? '/tmp/avatars' : path.join(__dirname, 'public', 'uploads', 'avatars');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      cb(null, `${req.session.userId}-${Date.now()}${path.extname(file.originalname)}`);
    }
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (['image/jpeg','image/jpg','image/png','image/webp'].includes(file.mimetype)) cb(null, true);
    else cb(new Error('Format harus JPEG/PNG/WebP'));
  }
});

app.post('/profile/photo', requireAuth, avatarUpload.single('photo'), requireValidImageMagicBytes, async (req, res) => {
  try {
    if (!req.file) return res.json({ success: false, message: 'File tidak valid' });

    // Admin tidak punya entry di users.json
    if (req.session.userId === 'admin') {
      return res.json({ success: false, message: 'Admin tidak bisa ganti foto profil dari sini' });
    }

    const users = readDB('users.json');
    const user  = users.find(u => u.id === req.session.userId);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });

    // Hapus foto lama jika ada
    if (user.photo) {
      const oldPath = path.join(__dirname, 'public', user.photo.replace(/^\//, ''));
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }

    if (!isVercel) { user.photo = `/uploads/avatars/${req.file.filename}`; }
    else { try { user.photo = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype); } catch (e) { return res.json({ success: false, message: 'Upload gagal: ' + e.message }); } }
    await writeDB('users.json', users);
    res.json({ success: true, photo: user.photo });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// ── BANNER CAROUSEL ──
const bannerCarouselUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = isVercel ? '/tmp/banners' : path.join(__dirname, 'public', 'uploads', 'banners');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      cb(null, `banner-${Date.now()}${path.extname(file.originalname)}`);
    }
  }),
  limits: { fileSize: 4 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (['image/jpeg','image/jpg','image/png','image/webp'].includes(file.mimetype)) cb(null, true);
    else cb(new Error('Format harus JPEG/PNG/WebP'));
  }
});

app.get('/api/banners', async (req, res) => {
  // FIX (loading lambat): sebelumnya pakai readFresh -- artinya SETIAP kali
  // ada yang buka homepage, server nunggu round-trip penuh ke Supabase dulu
  // sebelum banner carousel bisa muncul (banner ada di atas fold, jadi user
  // ngerasain langsung sebagai "lemot"). readSmart pakai cache ber-TTL 60
  // detik (sama seperti /api/products), jauh lebih cepat dan behavior akhir
  // tetap sama karena banner jarang berubah tiap detik.
  const settings = await readSmart('settings.json');
  if (normalizeBanners(settings)) await writeDB('settings.json', settings);
  res.json((settings.banners || []).filter(b => b.active !== false));
});

app.post('/admin/banners/add', requireAdmin, bannerCarouselUpload.single('bannerImg'), requireValidImageMagicBytes, async (req, res) => {
  try {
    const { title, subtitle, link, imageUrl } = req.body;
    const settings = await readFresh('settings.json');
    if (!settings.banners) settings.banners = [];
    let imgSrc = imageUrl?.trim() || '';
    if (req.file) {
      if (!isVercel) {
        imgSrc = `/uploads/banners/${req.file.filename}`;
      } else {
        try {
          imgSrc = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype);
        } catch (uploadErr) {
          // FIX (loading lambat): sebelumnya di sini ada fallback diam-diam
          // ke base64 data URL kalau upload ke Supabase Storage gagal.
          // Efeknya: banner (yang tampil di atas fold, langsung didownload
          // semua orang yang buka homepage) jadi ke-embed penuh sebagai teks
          // base64 di dalam settings.json -- ikut kebawa tiap kali endpoint
          // /api/banners dipanggil, TIDAK bisa di-cache browser sebagai file
          // gambar (karena bukan URL, tapi inline data), dan base64 sendiri
          // ~33% lebih besar dari file aslinya. Ini kemungkinan besar
          // penyebab homepage kerasa lemot. Sekarang upload yang gagal
          // dikembalikan sebagai error jelas ke admin (cek Supabase Storage:
          // bucket "product-images" ada, RLS policy benar, project tidak
          // paused) daripada diam-diam "berhasil" tapi bikin app berat.
          return res.json({ success: false, message: 'Gagal upload gambar banner ke storage: ' + uploadErr.message + '. Cek Supabase Storage (bucket product-images, RLS policy, atau project sedang paused).' });
        }
      }
    }
    if (!imgSrc) return res.json({ success: false, message: 'Gambar banner wajib diisi' });
    settings.banners.push({
      id: uuidv4(),
      imageUrl: imgSrc,
      title: title?.trim() || '',
      subtitle: subtitle?.trim() || '',
      link: link?.trim() || '/',
      active: true,
      createdAt: new Date().toISOString()
    });
    await writeDB('settings.json', settings);
    res.json({ success: true, banners: settings.banners });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/banners/delete/:id', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const old = (settings.banners || []).find(b => b.id === req.params.id);
    if (old?.imageUrl?.startsWith('/uploads/banners/')) {
      const fp = path.join(__dirname, 'public', old.imageUrl);
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    }
    settings.banners = (settings.banners || []).filter(b => b.id !== req.params.id);
    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/banners/toggle/:id', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const b = (settings.banners || []).find(b => b.id === req.params.id);
    if (b) b.active = !b.active;
    await writeDB('settings.json', settings);
    res.json({ success: true, active: b?.active });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// ── QRIS STATIS UPLOAD ──
const qrisUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = isVercel ? '/tmp' : path.join(__dirname, 'public', 'uploads');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      cb(null, `qris-static${path.extname(file.originalname)}`);
    }
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (['image/jpeg','image/jpg','image/png','image/webp'].includes(file.mimetype)) cb(null, true);
    else cb(new Error('Format harus JPEG/PNG/WebP'));
  }
});

app.post('/admin/qris/upload', requireAdmin, qrisUpload.single('qrisImage'), requireValidImageMagicBytes, async (req, res) => {
  try {
    if (!req.file) return res.json({ success: false, message: 'File tidak valid' });
    const settings = await readFresh('settings.json');
    if (!isVercel) {
      settings.qrisStaticImage = `/uploads/${req.file.filename}`;
    } else {
      try { settings.qrisStaticImage = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype); } catch (e) { return res.json({ success: false, message: e.message }); }
    }
    await writeDB('settings.json', settings);
    res.json({ success: true, path: settings.qrisStaticImage });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.get('/profile/me', requireAuth, (req, res) => {
  if (req.session.isAdmin) {
    const s = readDB('settings.json');
    return res.json({ success: true, user: { id: 'admin', username: s.adminUsername || 'Admin', isAdmin: true, is_reseller: false, photo: null } });
  }
  const users = readDB('users.json');
  const user  = users.find(u => u.id === req.session.userId);
  if (!user) return res.json({ success: false });
  const { password: _, ...safe } = user;
  res.json({ success: true, user: safe });
});

// ── User Dashboard ──
app.get('/dashboard', requireAuth, (req, res) => {
  const transactions = readDB('transactions.json');
  const user = getSessionUser(req);
  const settings = readDB('settings.json');

  // Filter transaksi milik user ini
  const myTransactions = transactions.filter(t => t.userId === req.session.userId);
  const totalOrders = myTransactions.length;
  const successOrders = myTransactions.filter(t => t.status === 'done').length;
  const pendingOrders = myTransactions.filter(t => t.status === 'pending').length;
  const totalSpent = myTransactions.filter(t => t.status === 'done').reduce((s, t) => s + (t.price || 0), 0);
  const doneTransactions = myTransactions.filter(t => t.status === 'done').sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const recentTransactions = myTransactions.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 20);

  res.render('pages/dashboard', {
    user, settings,
    stats: { totalOrders, successOrders, pendingOrders, totalSpent },
    doneTransactions,
    transactions: recentTransactions,
    walletTransactions: myTransactions.filter(t => t.type === 'deposit' || t.type === 'adjustment').sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 15)
  });
});

// Product routes
// FIX (guest checkout, diminta client 21 Agu 2026): dulu wajib requireAuth
// (harus register/login dulu) sebelum bisa lihat halaman produk & checkout.
// Sekarang publik -- guest bisa checkout cukup isi nama+nomor WA (lihat
// /create-order di bawah, yang sekarang auto-create akun kalau belum login).
app.get('/buy/:id', async (req, res) => {
  res.set('Cache-Control', 'no-store, max-age=0');
  const products = await readFresh('products.json');
  let product = products.find(p => p.id === req.params.id);

  if (!product || product.status !== 'active') {
    return res.redirect('/');
  }

  // Pakai res.locals.settings yang sudah di-fetch oleh middleware (readFresh fallback)
  const settings = res.locals.settings || readDB('settings.json');
  const user = res.locals.user || getSessionUser(req);

  const isReseller = !!(user?.is_reseller);
  const resellerDiscount = settings.resellerDiscount || 20;
  // Normalisasi dulu sumber durasi/harga. Ini membuat menu beli selalu
  // konsisten dengan pricingOptions, termasuk produk lama yang items-nya stale.
  product = normalizeProductBuyOptions(product);

  const allKeys = product.keys || [];
  const usableLocalKeys = countUsableLocalKeys(allKeys);
  const genericKeys = usableLocalKeys.filter(k => isGenericKey(k));
  let buyProviderSnapshot = null;
  const buyDsMode = settings.dripstore?.fulfillmentMode || 'live';
  if ((buyDsMode === 'live' || buyDsMode === 'hybrid') && settings.dripstore?.apiToken) {
    // Jangan membuat halaman /buy bergantung pada cache provider yang belum
    // pernah terisi. Coba ambil snapshot singkat saat cold-start; kalau provider
    // lambat, lanjut render tanpa provider dan refresh berjalan di background.
    // Ini mencegah menu durasi kosong sekaligus mencegah request menggantung.
    buyProviderSnapshot = getCachedDripstoreCatalogSnapshot(settings);
    if (!buyProviderSnapshot) {
      buyProviderSnapshot = await getDripstoreCatalogSnapshot(settings, { maxWaitMs: 2500 }).catch(() => null);
      if (!buyProviderSnapshot?.products) buyProviderSnapshot = getDisplayDripstoreSnapshot(settings) || buyProviderSnapshot;
    }
    warmDripstoreCatalog(settings);
  }
  const buyStockSummary = buildProductStockSummary(product, settings, buyProviderSnapshot);
  product = buyStockSummary.product;
  const stockByOption = buyStockSummary.stockByOption;
  if (product.items) {
    product.items = product.items.map((item, idx) => {
      const view = stockByOption[idx] || { stock: getLocalOptionStock(product, { days: item.durationValue, unit: item.durationUnit }), localStock: getLocalOptionStock(product, { days: item.durationValue, unit: item.durationUnit }), providerStock: 0, providerKnown: false, providerBacked: false, variantId: null };
      const stok = Math.max(0, Number(view.stock) || 0);

      let computedResellerPrice = null;
      const pOpt = product.pricingOptions?.[idx] || null;
      if (isReseller) {
        if (item.reseller_price != null && item.reseller_price >= 0) {
          computedResellerPrice = item.reseller_price;
        } else if (pOpt?.reseller_price != null && pOpt.reseller_price >= 0) {
          computedResellerPrice = pOpt.reseller_price;
        } else {
          computedResellerPrice = Math.round(item.p * (1 - resellerDiscount / 100));
        }
      }
      return { ...item, stok, providerBacked: !!view.providerBacked, providerStockKnown: !!view.providerKnown,
        providerStock: Number(view.providerStock || 0), localStock: Number(view.localStock || 0),
        providerVariantId: view.variantId || null, durationValue: item.durationValue != null ? Number(item.durationValue) : (pOpt?.days != null ? Number(pOpt.days) : null), durationUnit: item.durationUnit || pOpt?.unit || 'd',
        reseller_price: computedResellerPrice };
    });
  }

  // Cek apakah user sudah pernah membeli (transaksi sukses) produk ini
  const transactions = readDB('transactions.json');
  const hasPurchased = transactions.some(t =>
    t.userId === user?.id &&
    t.productId === product.id &&
    t.status === 'done'
  );

  // FIX KEAMANAN (audit 22 Agu 2026): field `keys` (array kode cheat ASLI
  // yang belum terjual) TIDAK BOLEH pernah sampai ke response halaman
  // publik ini -- sebelumnya `product` di-passing utuh ke res.render(),
  // termasuk `keys` mentahnya. Template EJS saat ini kebetulan cuma
  // memakai product.keys.length (bukan isinya), TAPI itu rapuh: siapapun
  // yang nambah <%- safeJson(product) %> atau sejenisnya di kemudian hari
  // (utk fitur baru/debug) otomatis membocorkan seluruh stok key gratis ke
  // siapapun yang buka halaman produk tanpa perlu login/bayar sama sekali.
  // Strip di sini, di level backend -- defense-in-depth, bukan bergantung
  // pada disiplin "jangan pernah pakai field ini di template nanti".
  const { keys: _rawKeys, ...productSafe } = product;
  const hasLiveProvider = (product.items || []).some(i => i.providerBacked);
  const hasUnknownProviderStock = buyStockSummary.providerStockUnknown;
  // Stok produk = kapasitas TERBESAR dari variant yang benar-benar dapat dibeli.
  // Jangan menjumlahkan semua durasi menjadi satu stok.
  productSafe.stockCount = buyStockSummary.stockCount;
  productSafe.liveProvider = hasLiveProvider;
  productSafe.providerStockUnknown = hasUnknownProviderStock;

  res.render('pages/buy', { product: productSafe, settings, user, isReseller, hasPurchased, categoryLabels: settings.categoryLabels || {} });
});

// Public catalog stock refresh: SATU request untuk seluruh kartu katalog.
// Ini mencegah homepage harus memanggil /api/products/:id/stock satu per satu.
// Provider tetap hanya dipanggil sekali lewat snapshot cache TTL pendek.
app.get('/api/catalog/stock', async (req, res) => {
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan. Coba lagi nanti.' });
  try {
    res.set('Cache-Control', 'no-store, max-age=0');
    const rawProducts = (await readSmart('products.json')).filter(p => p.status === 'active');
    const settings = await readFresh('settings.json');
    const mode = ['live','hybrid','local'].includes(settings.dripstore?.fulfillmentMode)
      ? settings.dripstore.fulfillmentMode : 'live';
    let snapshot = null;
    if ((mode === 'live' || mode === 'hybrid') && settings.dripstore?.apiToken) {
      snapshot = getCachedDripstoreCatalogSnapshot(settings);
      if (!snapshot) snapshot = await getDripstoreCatalogSnapshot(settings);
    }
    const items = rawProducts.map(raw => {
      const summary = buildProductStockSummary(raw, settings, snapshot);
      return {
        productId: String(raw.id),
        stockCount: summary.stockCount,
        providerStockUnknown: summary.providerStockUnknown,
        items: summary.stockByOption.map(view => ({
          stock: view.stock,
          localStock: view.localStock,
          providerStock: view.providerStock,
          providerKnown: view.providerKnown,
          providerBacked: view.providerBacked,
          variantId: view.variantId
        }))
      };
    });
    const brk = dripstoreBreakerState();
    if (brk.open) res.set('Retry-After', String(brk.retryAfterSec));
    return res.json({ success: true, mode, stale: !!snapshot?.stale, rateLimited: brk.open, retryAfterSec: brk.open ? brk.retryAfterSec : 0, items });
  } catch (e) {
    return res.status(500).json({ success: false, message: e.message });
  }
});

// Public stock refresh endpoint used by the buy page when the first render
// could not verify provider data quickly enough. Never returns actual local keys.
app.get('/api/products/:id/stock', async (req, res) => {
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan. Coba lagi nanti.' });
  try {
    res.set('Cache-Control', 'no-store, max-age=0');
    const rawProducts = await readFresh('products.json');
    const raw = rawProducts.find(p => String(p.id) === String(req.params.id) && p.status === 'active');
    if (!raw) return res.status(404).json({ success: false, message: 'Produk tidak ditemukan' });
    const settings = await readFresh('settings.json');
    const mode = settings.dripstore?.fulfillmentMode || 'live';
    let snapshot = null;
    if ((mode === 'live' || mode === 'hybrid') && settings.dripstore?.apiToken) {
      snapshot = getCachedDripstoreCatalogSnapshot(settings);
      if (!snapshot) snapshot = await getDripstoreCatalogSnapshot(settings);
    }
    const summary = buildProductStockSummary(raw, settings, snapshot);
    const items = summary.stockByOption.map(view => ({
      stock: view.stock,
      localStock: view.localStock,
      providerStock: view.providerStock,
      providerKnown: view.providerKnown,
      providerBacked: view.providerBacked,
      variantId: view.variantId
    }));
    const brk2 = dripstoreBreakerState();
    if (brk2.open) res.set('Retry-After', String(brk2.retryAfterSec));
    return res.json({ success: true, mode, stale: !!snapshot?.stale, rateLimited: brk2.open, retryAfterSec: brk2.open ? brk2.retryAfterSec : 0, items, stockCount: summary.stockCount, providerStockUnknown: summary.providerStockUnknown });
  } catch (e) {
    return res.status(500).json({ success: false, message: e.message });
  }
});

// FIX (guest checkout, diminta client 21 Agu 2026 -- "isi data cukup nama
// dan nomor"): requireAuth dihapus. Kalau belum login (req.session.userId
// kosong), buat akun guest OTOMATIS di sini dari customerName+wa yang
// dikirim form checkout, lalu langsung set session -- supaya SEMUA logic
// existing di bawah (rate limit per-user, transaksi terikat userId, riwayat
// pembelian, dsb) tetap jalan tanpa perlu diubah sama sekali. User yang mau
// akun permanen/riwayat tersimpan tetap bisa daftar manual atau via Google
// (lihat /register, /auth/google) sebelum checkout.
app.post('/create-order', async (req, res) => {
  try {
    const { productId, duration, durationUnit, customerName, wa, voucherCode } = req.body;

    // Guest checkout: kalau belum ada session user sama sekali, buat akun
    // guest baru dari nama+WA yang diisi di form. Kalau nomor WA yang sama
    // pernah dipakai guest sebelumnya, pakai ulang akun itu (supaya riwayat
    // pembelian nyambung meski tanpa password/login eksplisit).
    if (!req.session?.userId) {
      if (!customerName || !customerName.trim() || !wa || !wa.trim()) {
        return res.json({ success: false, message: 'Nama dan nomor WhatsApp wajib diisi' });
      }
      const users = await readFresh('users.json');
      let guestUser = users.find(u => u.isGuest && u.wa === wa.trim());
      if (!guestUser) {
        guestUser = {
          id: uuidv4(),
          username: customerName.trim(),
          wa: wa.trim(),
          password: null,
          isGuest: true, // penanda akun guest checkout, beda dari akun yang daftar manual/Google
          photo: null,
          balance: 0,
          createdAt: new Date().toISOString()
        };
        users.push(guestUser);
        await writeDB('users.json', users);
      }
      req.session.userId = guestUser.id;
      req.session.isAdmin = false;
    }

    // Rate limit khusus pembayaran (kebijakan wajib GensPay, lihat checkPaymentRateLimit di atas)
    if (!checkPaymentRateLimit(req.session.userId)) {
      return res.json({ success: false, message: 'Terlalu banyak permintaan, coba lagi sebentar.' });
    }
    const products = await readFresh('products.json');
    const rawProduct = products.find(p => p.id === productId);
    const product = rawProduct ? normalizeProductBuyOptions(rawProduct) : null;

    if (!product || product.status !== 'active') return res.json({ success: false, message: 'Produk tidak ditemukan' });

    // Stok lokal tidak wajib untuk durasi yang sudah di-map ke DripStore:
    // key dibeli live dari provider setelah pembayaran dikonfirmasi.
    const hasDripstoreMappedOption = (product.pricingOptions || []).some(o => o?.dripstoreVariantId);

    // Support pricingOptions (deem style: {days,unit,price}) dan items (lama: {l,p})
    //
    // FIX (fitur key per-jam, diminta client 21 Agu 2026): sebelumnya durasi
    // dicocokkan cuma dengan ekstrak ANGKA dari label ("PRODUK 30 DAYS" -> 30),
    // jadi kalau produk sekarang punya opsi "30 jam" DAN "30 hari" sekaligus,
    // regex \d+ bakal ambigu (keduanya menghasilkan angka 30). Sekarang
    // frontend WAJIB kirim `durationUnit` ('d'/'h') terpisah dari `duration`,
    // dan matching pricingOptions memakai pasangan (days, unit) -- bukan
    // cuma angka. Fallback lama (match by label/regex) dipertahankan untuk
    // request lama yang belum kirim durationUnit sama sekali (backward-compat
    // dengan produk yang cuma punya opsi hari, unit default 'd').
    const selectedUnit = (durationUnit === 'h') ? 'h' : 'd';
    let price = 0, selectedDays = null;
    if (product.pricingOptions?.length) {
      let opt = null;
      if (durationUnit) {
        // Jalur baru: match presisi via (days, unit)
        const days = parseInt(duration);
        opt = product.pricingOptions.find(o => o.days === days && (o.unit || 'd') === selectedUnit);
        if (!opt) return res.json({ success: false, message: 'Durasi tidak valid' });
        price = opt.price; selectedDays = days;
      } else {
        // Jalur lama (backward-compat): duration bisa berupa label teks ("PRODUK 30 DAYS") atau angka ("30")
        const itemMatch = product.items?.find(i => i.l === duration || i.l.includes(duration));
        if (itemMatch) {
          opt = product.pricingOptions.find(o => o.price === itemMatch.p);
          if (!opt) { price = itemMatch.p; const m = duration.match(/(\d+)/); selectedDays = m ? parseInt(m[1]) : null; }
          else { price = opt.price; selectedDays = opt.days; }
        } else {
          const days = parseInt(duration);
          opt = product.pricingOptions.find(o => o.days === days && (o.unit || 'd') === 'd');
          if (!opt) return res.json({ success: false, message: 'Durasi tidak valid' });
          price = opt.price; selectedDays = days;
        }
      }
    } else {
      const opt = product.items?.find(i => i.l.includes(duration));
      if (!opt) return res.json({ success: false, message: 'Durasi tidak valid' });
      price = opt.p;
      const m = duration.match(/(\d+)/); selectedDays = m ? parseInt(m[1]) : null;
    }

    const settings = readDB('settings.json');
    // Terapkan harga reseller: gunakan harga manual per-produk jika ada,
    // fallback ke global diskon % jika tidak ada
    const orderUser = getSessionUser(req);
    if (orderUser?.is_reseller) {
      // Cari item yang sesuai untuk cek reseller_price manual
      const matchedItem = product.items?.find(i => i.l === duration || i.l.includes(duration));
      const matchedOpt = product.pricingOptions?.find(o => o.days === selectedDays && (o.unit || 'd') === selectedUnit);
      const manualResellerPrice = matchedItem?.reseller_price ?? matchedOpt?.reseller_price ?? null;
      if (manualResellerPrice != null && manualResellerPrice >= 0) {
        price = manualResellerPrice;
      } else {
        const disc = settings.resellerDiscount || 20;
        price = Math.round(price * (1 - disc / 100));
      }
    }

    // Terapkan voucher (setelah diskon reseller)
    let voucherDiscount = 0, appliedVoucher = null, originalPrice = price;
    if (voucherCode && voucherCode.trim()) {
      const vResult = await validateVoucher(voucherCode, price, req.session.userId);
      if (vResult.valid) {
        voucherDiscount = vResult.discount;
        price = vResult.finalPrice;
        appliedVoucher = vResult.voucher;
      } else {
        return res.json({ success: false, message: 'Voucher: ' + vResult.error });
      }
    }

    // PRE-FLIGHT STOCK GUARD: cek kemampuan variant yang BENAR-BENAR akan
    // dipakai saat fulfillment. Di LIVE provider wajib cukup. Di HYBRID provider
    // hanya menjadi fallback ketika stok lokal exact = 0. Guard ini cuma mencegah
    // order yang sudah diketahui mustahil; saat pembayaran selesai, finalizeOrder
    // tetap melakukan re-check balance + harga tepat sebelum generate_key.
    const dsMode = settings.dripstore?.fulfillmentMode || 'live';
    const selectedOpt = product.pricingOptions?.find(o => Number(o.days) === Number(selectedDays) && (o.unit || 'd') === selectedUnit);
    const localDurationStock = selectedOpt ? getLocalOptionStock(product, selectedOpt) : 0;
    const providerNeededAtCreate = !!selectedOpt && (dsMode === 'live' || (dsMode === 'hybrid' && localDurationStock <= 0));
    if (providerNeededAtCreate) {
      if (!settings.dripstore?.apiToken && dsMode === 'live') {
        return res.json({ success: false, message: 'Provider DripStore belum dikonfigurasi untuk produk ini.' });
      }
      if (settings.dripstore?.apiToken && settings.dripstore?.balanceGuardEnabled !== false) {
        try {
          const av = await checkDripstoreOptionAvailability(settings, product.name, selectedOpt, 1);
          if (!av.ok) {
            const bal = av.balance == null ? '?' : Number(av.balance).toFixed(2);
            const reqCost = av.required == null ? '?' : Number(av.required).toFixed(2);
            return res.json({ success: false, message: `Stok variant ini belum tersedia. Saldo provider $${bal}, kebutuhan $${reqCost}.` });
          }
        } catch (e) {
          return res.json({ success: false, message: 'Tidak bisa memverifikasi stok provider sebelum checkout: ' + e.message });
        }
      }
    }

    const qrisMode = settings.qrisMode || 'static';
    const orderId = `FX-${Date.now()}`;
    const refId = uuidv4();
    const orderCode = generateOrderCode();

    let qrString = null, isStatic = false, totalPayment = price, expiredAt = null;

    if (qrisMode === 'static') {
      if (!settings.qrisStaticImage) return res.json({ success: false, message: 'Upload gambar QRIS di admin panel terlebih dahulu.' });
      isStatic = true;
    } else {
      try {
        const r = await createQRISPayment(orderId, price, settings);
        qrString = r.qr_string;
        totalPayment = r.total_payment || price;
        expiredAt = r.expired_at || null;
      } catch (error) {
        if (settings.qrisStaticImage) { isStatic = true; }
        else return res.json({ success: false, message: 'QRIS API error: ' + error.message });
      }
    }

    const transactions = await readFresh('transactions.json');

    // Cegah transaksi duplikat: tolak jika ada pending untuk produk yang sama dalam 30 menit
    const existingPending = transactions.find(t =>
      t.userId === req.session.userId &&
      t.productId === productId &&
      t.status === 'pending' &&
      (Date.now() - new Date(t.createdAt).getTime()) < 30 * 60 * 1000
    );
    if (existingPending) {
      return res.json({ success: false, message: 'Kamu masih memiliki pesanan pending untuk produk ini. Selesaikan pembayaran atau tunggu 30 menit.' });
    }

    transactions.push({
      id: refId, orderId, code: orderCode,
      userId: req.session.userId, productId: product.id, productName: product.name,
      duration, selectedDays, selectedUnit,
      originalPrice: voucherDiscount > 0 ? originalPrice : undefined,
      voucherCode: appliedVoucher ? appliedVoucher.code : undefined,
      voucherDiscount: voucherDiscount > 0 ? voucherDiscount : undefined,
      price, totalPayment,
      customerName, wa, qrString, isStatic,
      paymentGateway: settings.apiGateway || 'pakasir',
      status: 'pending', key: null,
      createdAt: new Date().toISOString(), time: formatDate()
    });
    await writeDB('transactions.json', transactions);

    // Catat pemakaian voucher jika dipakai
    if (appliedVoucher) {
      const vouchers = await readFresh('vouchers.json');
      const v = vouchers.find(v => v.id === appliedVoucher.id);
      if (v) {
        v.usedCount = (v.usedCount || 0) + 1;
        v.usages = v.usages || [];
        v.usages.push({ userId: req.session.userId, usedAt: new Date().toISOString(), orderId: refId });
        await writeDB('vouchers.json', vouchers);
      }
    }

    res.json({ success: true, refId, orderId, qrString, orderCode, isStatic, totalPayment, expiredAt,
      voucherDiscount: voucherDiscount || undefined,
      qrisStaticImage: isStatic ? settings.qrisStaticImage : null });
  } catch (error) {
    console.error('[create-order] error:', error.message);
    res.json({ success: false, message: 'Terjadi kesalahan: ' + error.message });
  }
});

// ══════════════════════════════════════════════════════════════════
// finalizeOrder — tandai transaksi lunas & proses sesuai tipenya
// (reseller upgrade / top up saldo / kirim key produk). Diekstrak dari
// logic /check-payment supaya bisa dipakai bareng dari webhook GensPay
// (lihat app.post('/webhook/genspay') di bawah) TANPA duplikasi logic.
// Selalu re-fetch transaksi terbaru dari Supabase sebelum memutuskan apa
// pun -- transaction.status === 'done' di sini artinya sudah diproses
// instance lain / caller lain, jadi tidak diproses ulang (idempotent).
// ══════════════════════════════════════════════════════════════════
// Persistent per-order fulfillment claim. `processingOrders` di memory saja
// tidak cukup di Vercel karena webhook dan polling bisa masuk ke instance berbeda.
// keyvalue_store punya UNIQUE(key), jadi INSERT atomik menjadi pagar lintas-instance:
// hanya satu request yang boleh mengklaim order sebelum menyentuh stok/provider.
const _localFulfillmentClaims = new Set();
const _localStockQueues = new Map();

const _sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function withLocalStockQueue(productId, task) {
  const key = String(productId);
  const previous = _localStockQueues.get(key) || Promise.resolve();
  const run = previous.then(task, task);
  _localStockQueues.set(key, run);
  return run.finally(() => {
    if (_localStockQueues.get(key) === run) _localStockQueues.delete(key);
  });
}

async function acquirePersistentNamedLock(lockKey, { waitMs = 7000, staleMs = 60000 } = {}) {
  const client = db.getClient();
  if (!client) return async () => {};
  const owner = uuidv4();
  const deadline = Date.now() + waitMs;

  while (Date.now() < deadline) {
    const { error } = await client.from('keyvalue_store').insert({
      key: String(lockKey),
      value: { owner, acquiredAt: new Date().toISOString() }
    });
    if (!error) {
      return async () => {
        try {
          const { data } = await client.from('keyvalue_store').select('value').eq('key', String(lockKey)).maybeSingle();
          if (data?.value?.owner === owner) {
            await client.from('keyvalue_store').delete().eq('key', String(lockKey));
          }
        } catch (e) {
          console.warn('[persistent-lock] release gagal:', e.message);
        }
      };
    }

    const duplicate = error.code === '23505' || /duplicate key|unique constraint/i.test(error.message || '');
    if (!duplicate) throw new Error(error.message || 'Gagal mengunci proses');

    const { data } = await client.from('keyvalue_store').select('value').eq('key', String(lockKey)).maybeSingle();
    const acquiredAt = new Date(data?.value?.acquiredAt || 0).getTime();
    if (acquiredAt && Date.now() - acquiredAt > staleMs) {
      // Hanya hapus lock stale. Dua waiter boleh balapan di sini; UNIQUE(key)
      // pada insert berikutnya tetap menentukan satu pemenang.
      await client.from('keyvalue_store').delete().eq('key', String(lockKey));
      continue;
    }
    await _sleep(150);
  }
  return null;
}

async function withPersistentProductStockLock(productId, task) {
  // Queue lokal tetap per-produk agar dua pembelian produk yang sama tidak
  // saling menunggu terlalu lama di instance yang sama; persistent writer
  // global kemudian menjamin snapshot products.json tidak saling menimpa
  // lintas produk/instance Vercel.
  return withLocalStockQueue(productId, () => withProductsWriteLock(task));
}

async function incrementProductSold(productId) {
  return withPersistentProductStockLock(productId, async () => {
    const products = await readFresh('products.json');
    const product = products.find(p => String(p.id) === String(productId));
    if (!product) return false;
    product.sold = (product.sold || 0) + 1;
    await writeDB('products.json', products);
    return true;
  });
}

async function claimProductFulfillment(refId) {
  const claimKey = `fulfillment-claim:${String(refId)}`;
  const client = db.getClient();

  // Local fallback: tetap mencegah race dalam satu process bila Supabase tidak tersedia.
  if (!client) {
    if (_localFulfillmentClaims.has(claimKey)) return false;
    _localFulfillmentClaims.add(claimKey);
    return true;
  }

  try {
    const { error } = await client.from('keyvalue_store').insert({
      key: claimKey,
      value: { refId: String(refId), claimedAt: new Date().toISOString() }
    });
    if (!error) return true;
    const duplicate = error.code === '23505' || /duplicate key|unique constraint/i.test(error.message || '');
    if (duplicate) {
      const { data } = await client.from('keyvalue_store').select('value').eq('key', claimKey).maybeSingle();
      const claimedAt = new Date(data?.value?.claimedAt || 0).getTime();
      // Kalau claim yatim >5 menit (mis. instance Vercel crash), buka kembali.
      if (claimedAt && Date.now() - claimedAt > 5 * 60 * 1000) {
        await client.from('keyvalue_store').delete().eq('key', claimKey);
        const retry = await client.from('keyvalue_store').insert({
          key: claimKey,
          value: { refId: String(refId), claimedAt: new Date().toISOString(), reclaimed: true }
        });
        if (!retry.error) return true;
        if (retry.error.code === '23505' || /duplicate key|unique constraint/i.test(retry.error.message || '')) return false;
        throw new Error(retry.error.message || 'Gagal mengambil alih fulfillment claim');
      }
      return false;
    }
    throw new Error(error.message || 'Gagal membuat fulfillment claim');
  } catch (e) {
    if (e?.code === '23505' || /duplicate key|unique constraint/i.test(e?.message || '')) return false;
    throw e;
  }
}

async function finalizeOrder(refId, settings) {
  const freshTransactions = await readFresh('transactions.json');
  const transaction = freshTransactions.find(t => t.id === refId);
  if (!transaction) return { status: 'not_found' };
  if (transaction.status === 'done') {
    return { status: 'already_done', type: transaction.type, key: transaction.key, code: transaction.code, outOfStock: transaction.outOfStock };
  }

  // Klaim hanya transaksi produk. Reseller/deposit tidak menyentuh provider key.
  // Bila request lain sudah mengklaim order ini (termasuk instance Vercel lain),
  // jangan pernah menjalankan fulfillment kedua kali.
  if (!transaction.type || transaction.type === 'product') {
    const claimed = await claimProductFulfillment(refId);
    if (!claimed) return { status: 'already_processing', type: 'product', code: transaction.code };
  }

  // Jika transaksi reseller, upgrade status user
  if (transaction.type === 'reseller') {
    const users = await readFresh('users.json');
    const u = users.find(u => u.id === transaction.userId);
    if (u) {
      u.is_reseller = true;
      u.role = 'reseller';
      u.reseller_since = new Date().toISOString();
      u.reseller_code = 'RSL-' + u.username.toUpperCase().slice(0, 4) + '-' + crypto.randomBytes(2).toString('hex').toUpperCase();
      await writeDB('users.json', users);
    }
    transaction.status = 'done';
    transaction.paidAt = new Date().toISOString();
    const txList = await readFresh('transactions.json');
    const txIdx = txList.findIndex(t => t.id === refId);
    if (txIdx !== -1) txList[txIdx] = transaction; else txList.push(transaction);
    await writeDB('transactions.json', txList);
    return { status: 'done', type: 'reseller' };
  }

  // Jika transaksi top up saldo wallet, kreditkan saldo user
  if (transaction.type === 'deposit') {
    const users = await readFresh('users.json');
    const u = users.find(u => u.id === transaction.userId);
    if (u) {
      u.balance = (u.balance || 0) + (transaction.amount || transaction.price || 0);
      await writeDB('users.json', users);
    }
    transaction.status = 'done';
    transaction.paidAt = new Date().toISOString();
    const txList = await readFresh('transactions.json');
    const txIdx = txList.findIndex(t => t.id === refId);
    if (txIdx !== -1) txList[txIdx] = transaction; else txList.push(transaction);
    await writeDB('transactions.json', txList);
    return { status: 'done', type: 'deposit', balance: u?.balance || 0 };
  }

  // Produk biasa: kalau durasi punya Variant ID DripStore, fulfillment
  // dilakukan LIVE dari provider. Ini sengaja dikerjakan SETELAH pembayaran
  // dikonfirmasi, sehingga saldo DripStore hanya berkurang untuk customer nyata.
  let key = null;
  let outOfStock = false;
  let keySource = 'local_stock';
  let providerTransactionId = null;
  let providerVariantId = null;

  const fulfillmentMode = settings.dripstore?.fulfillmentMode || 'live';
  // Local inventory is always tried first. This is intentional even when the
  // setting is `live`: DripStore is a fallback source, not a replacement for
  // keys already stored in AGHA.
  const shouldTryLocalFirst = true;

  let products = await readFresh('products.json');
  let product = products.find(p => p.id === transaction.productId);
  let localInventoryCommitted = false;

  // LOCAL/HYBRID: stok lokal hanya boleh memenuhi durasi+unit yang dibeli.
  // consumeLocalProductKey() mengambil snapshot terbaru dan melakukan write
  // di bawah lock per-product, sehingga dua order tidak dapat mengambil key
  // lokal yang sama sekaligus. Generic key hanya dipakai untuk produk yang
  // memang tidak memiliki durasi spesifik.
  if (!key && !outOfStock && shouldTryLocalFirst && product) {
    const localResult = await consumeLocalProductKey(product.id, transaction.selectedDays, transaction.selectedUnit || 'd');
    products = localResult.products || products;
    product = products.find(p => p.id === transaction.productId) || product;
    if (localResult.key) {
      key = localResult.key;
      localInventoryCommitted = !!localResult.committed;
    }
  }

  if (!key && !outOfStock && (fulfillmentMode === 'live' || fulfillmentMode === 'hybrid')) {
    const liveProvider = await fulfillProductFromDripstore(transaction, settings).catch(e => ({ error: e }));
    if (liveProvider && !liveProvider.error) {
      key = liveProvider.key; keySource = liveProvider.source;
      providerTransactionId = liveProvider.providerTransactionId; providerVariantId = liveProvider.variantId;
    } else if (liveProvider?.error) {
      console.error('[DripStore hybrid fulfillment]', transaction.code, liveProvider.error.message);
      outOfStock = true;
    }
  }

  if (key) {
    // Key lokal sudah menaikkan sold di consumeLocalProductKey(). Untuk provider,
    // increment sold juga masuk lock produk agar dua instance tidak lost-update.
    if (!localInventoryCommitted) {
      await incrementProductSold(transaction.productId);
    }
  } else {
    outOfStock = true;
  }

  transaction.status = 'done';
  transaction.key = key;
  transaction.keySource = keySource;
  transaction.providerVariantId = providerVariantId || undefined;
  transaction.providerTransactionId = providerTransactionId || undefined;
  transaction.outOfStock = outOfStock;
  transaction.paidAt = new Date().toISOString();
  const txListFinal = await readFresh('transactions.json');
  const txIdxFinal = txListFinal.findIndex(t => t.id === refId);
  if (txIdxFinal !== -1) txListFinal[txIdxFinal] = transaction; else txListFinal.push(transaction);
  await writeDB('transactions.json', txListFinal);

  if (outOfStock) {
    const waMsg = `⚠️ STOK HABIS - Pesanan butuh diproses manual!\n\n` +
      `Order: ${transaction.code}\n` +
      `Produk: ${transaction.productName}\n` +
      `Customer: ${transaction.customerName} (${transaction.wa || '-'})\n` +
      `Total: Rp ${Number(transaction.price).toLocaleString('id-ID')}\n\n` +
      `Pembayaran sudah masuk tapi stok key kosong. Segera tambah stok & kirim key manual ke pembeli.`;
    sendWhatsAppNotif(settings.contact?.whatsapp, waMsg, settings).catch(() => {});
  }

  const notifs = readDB('notifications.json');
  const buyer = readDB('users.json').find(u => u.id === transaction.userId);
  notifs.unshift({ id: uuidv4(), type: 'purchase', buyerName: transaction.customerName,
    buyerPhoto: buyer?.photo || null, productName: transaction.productName,
    price: transaction.price, time: transaction.paidAt, timeStr: formatDate(new Date(transaction.paidAt)) });
  await writeDB('notifications.json', notifs.slice(0, 50));

  return { status: 'done', type: 'product', key, code: transaction.code, outOfStock };
}

app.get('/check-payment/:refId', requireAuth, async (req, res) => {
  const refId = req.params.refId;
  // Rate limit khusus pembayaran (kebijakan wajib GensPay, lihat checkPaymentRateLimit
  // di atas) -- polling client bisa manggil endpoint ini berkali-kali sampai status
  // berubah, jadi ini titik paling rawan kena limit 30 req/3 menit.
  if (!checkPaymentRateLimit(req.session.userId)) {
    return res.json({ success: true, status: 'pending', rateLimited: true });
  }
  // Cegah race condition: jika transaksi sedang diproses, kembalikan pending
  if (processingOrders.has(refId)) {
    return res.json({ success: true, status: 'pending' });
  }
  processingOrders.add(refId);
  try {
    const transactions = readDB('transactions.json');
    const transaction = transactions.find(t => t.id === refId);
    if (!transaction) return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
    // FIX KEAMANAN — IDOR (audit 22 Agu 2026): endpoint ini sebelumnya HANYA
    // cek requireAuth (harus login), TAPI TIDAK PERNAH memverifikasi bahwa
    // transaksi ini benar milik user yang sedang login. Akibatnya: siapapun
    // yang tahu/menebak refId (UUID transaksi) bisa memanggil endpoint ini
    // dan mengambil KEY CHEAT milik transaksi orang lain secara gratis --
    // padahal refId bisa saja bocor lewat cara tidak sengaja (mis. customer
    // share link invoice ke grup chat sebagai bukti pembelian, screenshot,
    // dll). Admin dikecualikan karena memang berwenang mengecek status
    // transaksi siapapun untuk keperluan support.
    if (!req.session.isAdmin && transaction.userId !== req.session.userId) {
      return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
    }
    if (transaction.status === 'done') {
      if (transaction.type === 'reseller') return res.json({ success: true, status: 'done', type: 'reseller' });
      if (transaction.type === 'deposit') {
        const u = readDB('users.json').find(u => u.id === transaction.userId);
        return res.json({ success: true, status: 'done', type: 'deposit', balance: u?.balance || 0 });
      }
      return res.json({ success: true, status: 'done', key: transaction.key, code: transaction.code });
    }

    // Static QRIS: tunggu konfirmasi manual admin
    if (transaction.isStatic) return res.json({ success: true, status: 'pending_static' });

    const settings = readDB('settings.json');
    let paid = false;
    // PENTING: selalu verifikasi ke gateway yang SAMA dengan yang dipakai
    // saat transaksi ini dibuat (transaction.paymentGateway), BUKAN
    // settings.apiGateway yang sedang aktif sekarang — supaya transaksi lama
    // tetap benar dicek walau admin sudah ganti gateway di panel.
    const gateway = transaction.paymentGateway || settings.apiGateway || 'pakasir';

    // GensPay TIDAK punya endpoint cek status manual (lihat catatan panjang
    // di checkPaymentStatusGenspay) -- satu-satunya sumber kebenaran soal
    // status transaksi GensPay adalah webhook (app.post('/webhook/genspay')).
    // Jangan panggil checkPaymentStatus untuk gateway ini sama sekali,
    // supaya tidak spam error ke log tiap kali browser polling. Balas
    // "pending" apa adanya -- kalau webhook sudah masuk & finalize,
    // transaction.status di database sudah 'done' duluan dan ke-tangkep
    // oleh pengecekan status di atas sebelum sampai sini.
    if (gateway === 'genspay') {
      return res.json({ success: true, status: 'pending' });
    }
    try {
      // PENTING: Pakasir mewajibkan parameter `amount` di /api/transactiondetail
      // adalah NOMINAL ASLI yang diminta saat transaksi dibuat (field `price`
      // kita), BUKAN `total_payment` (yang sudah ditambah fee Pakasir).
      // Sebelumnya kode ini salah kirim totalPayment, jadi setiap kali
      // Pakasir mengenakan fee (tergantung channel/bank pembayaran, mis.
      // saat dirutekan lewat "Zona ID"), query ke Pakasir gagal mencocokkan
      // transaksinya — hasilnya status selalu balik pending walau uang
      // sudah benar-benar masuk ke saldo Pakasir. Lihat dokumentasi resmi:
      // https://pakasir.com/p/docs
      const r = await checkPaymentStatus(transaction.orderId, transaction.price, settings, gateway);
      // Normalize status dari berbagai format response PakKasir
      const status = (r.transaction?.status || r.status || r.data?.status || '').toLowerCase();
      paid = ['completed','success','paid','settlement','capture','complete','authorize','accepted'].includes(status) || r.success === true;
      if (!paid && !['expired','canceled','cancelled',''].includes(status)) {
        // Status nggak match daftar di atas tapi juga bukan expired — log biar kelihatan di server log kalau Pakasir balikin status baru yang belum kita tangani
        console.warn(`[check-payment] Status tidak dikenali untuk order ${transaction.orderId}: "${status}" | raw response:`, JSON.stringify(r).slice(0, 300));
      }
      if (['expired','canceled','cancelled'].includes(status)) {
        transaction.status = 'expired';
        const txListExpired = await readFresh('transactions.json');
        const txIdxExpired = txListExpired.findIndex(t => t.id === refId);
        if (txIdxExpired !== -1) txListExpired[txIdxExpired] = transaction; else txListExpired.push(transaction);
        await writeDB('transactions.json', txListExpired);
        return res.json({ success: true, status: 'expired' });
      }
    } catch(e) {
      // Sebelumnya error di sini ditelan total tanpa jejak (komentar doang).
      // Sekarang dicatat ke log server supaya kalau status macet pending
      // terus, gampang ketahuan apakah penyebabnya error koneksi/API,
      // bukan cuma nebak-nebak.
      console.error(`[check-payment] Gagal cek status order ${transaction.orderId}:`, e.message);
    }

    if (paid) {
      // ── ANTI DOUBLE-PROCESSING (lintas-instance Vercel) ──
      // finalizeOrder() sendiri sudah re-fetch transaksi terbaru & idempotent
      // (return status 'already_done' kalau sudah diproses instance/caller
      // lain), jadi aman dipanggil langsung dari sini.
      const result = await finalizeOrder(refId, settings);
      if (result.status === 'not_found') return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
      if (result.type === 'reseller') return res.json({ success: true, status: 'done', type: 'reseller' });
      if (result.type === 'deposit') return res.json({ success: true, status: 'done', type: 'deposit', balance: result.balance });
      return res.json({ success: true, status: 'done', key: result.key, code: result.code, outOfStock: result.outOfStock });
    }

    res.json({ success: true, status: transaction.status });
  } catch (error) {
    console.error('[check-payment] error:', error.message);
    res.json({ success: false, message: error.message });
  } finally {
    processingOrders.delete(refId);
  }
});

// ══════════════════════════════════════════════════════════════════
// WEBHOOK GENSPAY — dipanggil server-to-server oleh GensPay begitu
// pembayaran QRIS sukses & dana masuk, TANPA bergantung pembeli membuka
// atau tetap membuka halaman pembayaran. Sebelumnya toko lama cuma
// mengandalkan polling client di /check-payment, jadi kalau pembeli
// tutup tab sebelum polling sempat nangkep status "paid", order nyangkut
// pending selamanya sampai admin approve manual.
//
// CARA AKTIFKAN: buka dashboard GensPay → pilih project → isi kolom
// "Webhook URL" dengan:
//   https://domainkamu.com/webhook/genspay
//
// 📖 Dokumentasi Integrasi: https://genspay.my.id/docs (Swagger API)
// Base URL API: https://genspay.my.id/api/v1
// ══════════════════════════════════════════════════════════════════
app.post('/webhook/genspay', async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const apiKey = (settings.genspay?.apiKey || process.env.GENSPAY_API_KEY || '').trim();
    const signatureHeader = req.headers['x-genspay-signature'];
    if (!apiKey || !signatureHeader) { logWebhook('genspay', { result: 'no_apikey_or_signature' }); return res.status(401).send('Unauthorized'); }

    // Signature = sha256(rawBody + apiKey). Pakai req.rawBody (string mentah,
    // lihat opsi `verify` di express.json() setup di atas) -- BUKAN
    // JSON.stringify(req.body) ulang, karena re-serialize objek yang sudah
    // di-parse tidak dijamin identik persis dengan raw body asli (urutan
    // key bisa berubah), jadi hash yang dihitung dari situ tidak akan
    // pernah match signature asli dari GensPay.
    if (!req.rawBody) { logWebhook('genspay', { result: 'no_raw_body' }); return res.status(401).send('Unauthorized: Raw body tidak tersedia'); }
    const computedSignature = crypto.createHash('sha256')
      .update(req.rawBody + apiKey)
      .digest('hex');

    // Perbandingan tahan timing-attack
    const sigA = Buffer.from(String(signatureHeader));
    const sigB = Buffer.from(computedSignature);
    if (sigA.length !== sigB.length || !crypto.timingSafeEqual(sigA, sigB)) {
      logWebhook('genspay', { result: 'invalid_signature', orderId: req.body?.data?.order_id || null });
      return res.status(401).send('Unauthorized: Invalid Signature');
    }

    // Sesuai dokumentasi resmi GensPay (genspay.my.id/docs bagian
    // "7. WEBHOOK NOTIFIKASI"): payload berbentuk
    // { event: "transaction.updated", data: { order_id, status, ... } },
    // dan status sukses SELALU dikirim sebagai string "SUCCESS" (huruf besar).
    const { event, data } = req.body || {};
    if (event !== 'transaction.updated' || !data?.order_id) { logWebhook('genspay', { result: 'event_not_matched', event, orderId: data?.order_id || null }); return res.status(200).send('OK'); }

    const orderId = data.order_id;
    const transactions = await readFresh('transactions.json');
    const transaction = transactions.find(t => t.orderId === orderId);
    if (!transaction) { logWebhook('genspay', { result: 'transaction_not_found', orderId }); return res.status(200).send('OK'); }
    if (transaction.status === 'done') { logWebhook('genspay', { result: 'already_done', orderId }); return res.status(200).send('OK'); }

    const status = (data.status || '').toUpperCase();
    const paid = status === 'SUCCESS';
    if (status === 'EXPIRED' || status === 'FAILED') {
      transaction.status = status.toLowerCase();
      transaction.gatewayStatus = status;
      transaction.gatewayUpdatedAt = new Date().toISOString();
      const freshList = await readFresh('transactions.json');
      const txIndex = freshList.findIndex(t => t.id === transaction.id);
      if (txIndex !== -1) freshList[txIndex] = transaction; else freshList.push(transaction);
      await writeDB('transactions.json', freshList);
      logWebhook('genspay', { result: 'transaction_closed', orderId, statusFromWebhook: status });
      return res.status(200).send('OK');
    }
    if (!paid) { logWebhook('genspay', { result: 'not_paid', orderId, statusFromWebhook: status || '(kosong)' }); return res.status(200).send('OK'); }

    if (processingOrders.has(transaction.id)) { logWebhook('genspay', { result: 'already_processing', orderId }); return res.status(200).send('OK'); }
    processingOrders.add(transaction.id);
    try {
      const result = await finalizeOrder(transaction.id, settings);
      logWebhook('genspay', { result: 'finalized', orderId, type: result.type, key: result.key ? '(terkirim)' : (result.outOfStock ? '(kosong/out-of-stock)' : '(n/a)') });
      res.status(200).send('OK');
    } finally {
      processingOrders.delete(transaction.id);
    }
  } catch (error) {
    console.error('[webhook/genspay] error:', error.message);
    logWebhook('genspay', { result: 'error', error: error.message });
    res.status(200).send('OK'); // tetap 200 biar GensPay tidak retry terus akibat error internal kita
  }
});

app.get('/invoice', async (req, res) => {
  if (!checkInvoiceRateLimit(req.ip)) {
    return res.render('pages/invoice', { transaction: null, error: 'Terlalu banyak pencarian. Coba lagi dalam 5 menit.' });
  }
  const { code } = req.query;
  if (code) {
    const transactions = readDB('transactions.json');
    const transaction = transactions.find(t => t.code === code.toUpperCase());
    let productChannelUrl = '';
    if (transaction && transaction.productId) {
      const products = await readFresh('products.json');
      const product = products.find(p => p.id === transaction.productId);
      productChannelUrl = product?.channelUrl || '';
    }
    return res.render('pages/invoice', { transaction: transaction || null, error: transaction ? null : 'Pesanan tidak ditemukan', productChannelUrl });
  }
  res.render('pages/invoice', { transaction: null, error: null, productChannelUrl: '' });
});

app.post('/invoice', async (req, res) => {
  if (!checkInvoiceRateLimit(req.ip)) {
    return res.render('pages/invoice', { transaction: null, error: 'Terlalu banyak pencarian. Coba lagi dalam 5 menit.' });
  }
  const { code } = req.body;
  const transactions = readDB('transactions.json');
  const transaction = transactions.find(t => t.code === code.toUpperCase());

  if (!transaction) {
    return res.render('pages/invoice', { transaction: null, error: 'Pesanan tidak ditemukan', productChannelUrl: '' });
  }

  let productChannelUrl = '';
  if (transaction.productId) {
    const products = await readFresh('products.json');
    const product = products.find(p => p.id === transaction.productId);
    productChannelUrl = product?.channelUrl || '';
  }

  res.render('pages/invoice', { transaction, error: null, productChannelUrl });
});

// Admin routes
// Heartbeat dari tab admin yang masih terbuka — requireAdmin di atasnya
// sudah otomatis menolak (sessionRevoked) kalau lock sudah diambil device
// lain, dan otomatis memperpanjang lastSeen kalau masih sah.
app.post('/admin/session/heartbeat', requireAdmin, (req, res) => {
  res.json({ success: true });
});

// ══════════════════════════════════════════════════════════════════
// BUG FIX (audit 19 Sep 2026): tombol "Export Database" / "Import Database"
// di admin.ejs (lihat <a href="/admin/export"> dan fetch('/admin/import'))
// SUDAH ADA di UI sejak lama, tapi endpoint server-nya TIDAK PERNAH dibuat
// -- klik Export selalu 404 ("ga bisa export, error"), dan Import pasti
// gagal juga karena fetch ke route yang tidak ada. Ini juga yang bikin
// Mul tidak bisa narik daftar lengkap key produk (mis. 49 key XREG) lewat
// fitur backup, karena satu-satunya jalan keluar (export per-produk lewat
// tombol "Export Keys" di halaman edit produk) beda dari tombol backup
// database penuh ini.
//
// Export: satu file JSON berisi SEMUA koleksi data (persis daftar
// DB_FILES di supabase.js) -- format ini SENGAJA dibuat identik dengan
// yang dibaca importDB() di admin.ejs, supaya file hasil export bisa
// langsung dipakai lagi lewat tombol Import tanpa diedit.
const EXPORTABLE_DB_FILES = ['users.json','products.json','transactions.json','testimonials.json','notifications.json','settings.json','keyspool.json','vouchers.json','admin-lock.json'];

app.get('/admin/export', requireAdmin, async (req, res) => {
  try {
    const dump = {};
    for (const file of EXPORTABLE_DB_FILES) {
      dump[file] = await readFresh(file);
    }
    const settings = dump['settings.json'] || {};
    const safeName = (settings.siteName || 'agha-nl').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="backup-${safeName || 'agha-nl'}-${stamp}.json"`);
    res.send(JSON.stringify(dump, null, 2));
  } catch (error) {
    console.error('[admin/export] error:', error.message);
    res.status(500).json({ success: false, message: 'Gagal export database: ' + error.message });
  }
});

// Import: hanya menerima key yang memang dikenal (EXPORTABLE_DB_FILES) --
// mencegah upload file JSON acak/berbahaya menimpa koleksi yang tidak
// seharusnya bisa ditulis dari sini. Ditulis satu per satu (bukan
// Promise.all) supaya kalau salah satu gagal di tengah jalan, pesan error
// jelas menyebut file mana yang bermasalah alih-alih database jadi
// campuran separuh lama-separuh baru tanpa penjelasan.
app.post('/admin/import', requireAdmin, async (req, res) => {
  try {
    const body = req.body || {};
    const incomingKeys = Object.keys(body).filter(k => EXPORTABLE_DB_FILES.includes(k));
    if (incomingKeys.length === 0) {
      return res.json({ success: false, message: 'File tidak berisi data yang dikenali (harus hasil export dari fitur ini).' });
    }
    for (const file of incomingKeys) {
      await writeDB(file, body[file]);
    }
    res.json({ success: true, message: `${incomingKeys.length} koleksi berhasil di-restore (${incomingKeys.join(', ')})` });
  } catch (error) {
    console.error('[admin/import] error:', error.message);
    res.json({ success: false, message: 'Gagal import database: ' + error.message });
  }
});


// Status koneksi Supabase, dipakai widget "Status Database" di Settings.
// BUG SEBELUMNYA: frontend sudah fetch('/admin/db-status') tapi route ini
// belum pernah didaftarkan → selalu 404 → ketangkep catch(e){} kosong di
// frontend → teks "Memeriksa koneksi..." nyangkut selamanya, padahal
// koneksi Supabase-nya sendiri sebenarnya baik-baik saja.
app.get('/admin/db-status', requireAdmin, async (req, res) => {
  try {
    const status = await db.getDbStatus();
    res.json(status);
  } catch (e) {
    res.json({ connected: false, errorMsg: e.message });
  }
});

// FIX (bug performa 23 Agu 2026, disesuaikan lagi 23 Agu 2026): endpoint
// sekali-jalan untuk migrasi gambar LAMA di Supabase Storage jadi WebP
// terkompres (lihat migrate-images-to-webp.js untuk detail lengkap kenapa
// ini perlu -- PageSpeed sebelumnya menunjukkan LCP puluhan detik &
// payload ~14MB, hampir semuanya gambar yang belum pernah dikompres).
//
// Awalnya dilindungi requireAdmin (perlu login dulu), tapi diminta diganti
// pakai SETUP_SECRET (pola sama dengan /agha-setup di atas) supaya
// bisa diakses tanpa perlu login admin sama sekali -- berguna kalau admin
// sedang lupa password atau mau migrasi sebelum akun admin siap.
// Akses: /admin/migrate-images?secret=SETUP_SECRET (dari env var Vercel).
// Set SETUP_SECRET di env Vercel dulu, akses URL-nya, lalu HAPUS
// SETUP_SECRET dari env Vercel setelah selesai (endpoint ini otomatis
// nonaktif total / 404 kalau SETUP_SECRET tidak di-set, jadi aman by
// default -- tidak akan kebuka ke publik selama env itu kosong).
// ══════════════════════════════════════════════════════════════════
// RAPIKAN KATEGORI PRODUK AGHA NL (one-off, diminta client 15 Sep 2026)
// Sesuai chat client jam 16.02-16.03: pindahin 10 produk spesifik ke
// kategori FF PROXY APKMOD / IOS [IPHONES PANEL / PC PANEL / ROOT ANDROID
// (kategori terakhir ini belum ada, otomatis dibikin), sisanya tetap di
// APK MOD NO ROOT (default). Kategori "GUILD GLORY BOT" yang nyasar di
// dashboard TIDAK disentuh -- client belum pernah nyebut ini di chat manapun.
// Dilindungi requireAdmin (bukan SETUP_SECRET) karena cuma dipakai sekali
// oleh admin yang udah login -- gak perlu setting env var tambahan,
// tinggal buka URL-nya pas lagi login admin. GET = preview (belum
// menyimpan apa-apa), POST (tombol di halaman preview) = beneran apply.
const AGHA_CATEGORY_FIX_PLAN = [
  { categoryLabel: 'FF PROXY APKMOD', productNames: ['Hg prime proxy', 'Pato team regedit proxy', 'DRIP PROXY', 'HG CHEATS PROXY APKMOD'] },
  { categoryLabel: 'IOS [IPHONES PANEL', productNames: ['Migul ios Pro', 'Migul ios lite', 'Fluriote mlbb ios', 'Gbox 1th'] },
  { categoryLabel: 'PC PANEL', productNames: ['BR MODS PC'] },
  { categoryLabel: 'ROOT ANDROID', productNames: ['RAPID CORE ROOT', 'Angry Mood root'] },
  // UPDATE (chat client 16 Sep 2026 jam 20.51): client kasih daftar EKSPLISIT
  // buat kategori ini (bukan "sisanya semua" seperti asumsi awal), dan minta
  // tab-nya diurutkan PALING PERTAMA setelah "Semua/All" -- ditangani lewat
  // AGHA_PRIORITY_CATEGORY_SLUG di bawah, bukan lewat urutan array ini.
  { categoryLabel: 'APK MOD NO ROOT', productNames: ['DRIP CLINT APK MOD', 'ABCD PANEL', 'DRIP WIRE', 'AIM HACK', 'SILENT CHEATS', 'HG APK MOD', 'XREG APK MOD', 'PATO ORANGE', 'PATO GREEN', 'PATO BLUE'] },
];
// Kategori yang harus tampil PALING PERTAMA di dashboard setelah "Semua/All"
// (client: "buat paling pertama setelah smua /all"). Ditaruh di index 0
// array settings.categories, karena urutan tab render di home.ejs ngikutin
// urutan array ini.
const AGHA_PRIORITY_CATEGORY_LABEL = 'APK MOD NO ROOT';
// Produk yang KETEMU di database tapi NAMANYA gak persis sama dengan yang
// client sebutin di chat manapun (baik chat kategori atau chat pricelist) --
// jadi statusnya AMBIGU, sengaja TIDAK diotak-atik, biar Mul konfirmasi dulu
// ke client baru masuk kategori mana.
const AGHA_AMBIGUOUS_PRODUCTS = ['DRIP CLINT ROOT'];
function aghaNormalize(s) { return String(s || '').toLowerCase().replace(/\s+/g, ' ').trim(); }
function aghaSlugify(label) { return label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, ''); }
async function aghaBuildCategoryFixPlan() {
  const settings = await readFresh('settings.json');
  const products = await readFresh('products.json');
  settings.categories = settings.categories || [];
  settings.categoryLabels = settings.categoryLabels || {};
  const newCategories = [], productUpdates = [], notFound = [];
  for (const item of AGHA_CATEGORY_FIX_PLAN) {
    let slug = settings.categories.find(s => aghaNormalize(settings.categoryLabels[s]) === aghaNormalize(item.categoryLabel));
    let isNew = false;
    if (!slug) { slug = aghaSlugify(item.categoryLabel); isNew = true; }
    if (isNew) newCategories.push({ slug, label: item.categoryLabel });
    for (const targetName of item.productNames) {
      const product = products.find(p => aghaNormalize(p.name) === aghaNormalize(targetName));
      if (!product) { notFound.push(targetName); continue; }
      productUpdates.push({ id: product.id, name: product.name, oldCategories: product.categories || [], newCategories: [slug], label: item.categoryLabel });
    }
  }
  const guildSlug = settings.categories.find(s => aghaNormalize(settings.categoryLabels[s] || s).includes('guild glory'));
  const guildCount = guildSlug ? products.filter(p => (p.categories || []).includes(guildSlug)).length : 0;

  // Reorder: kategori prioritas harus jadi INDEX 0 di array (tampil paling
  // pertama setelah tab "Semua/All" yang di-render terpisah di home.ejs).
  const priorityEntry = newCategories.find(c => c.label === AGHA_PRIORITY_CATEGORY_LABEL)
    || { slug: settings.categories.find(s => aghaNormalize(settings.categoryLabels[s]) === aghaNormalize(AGHA_PRIORITY_CATEGORY_LABEL)), label: AGHA_PRIORITY_CATEGORY_LABEL };
  const reorderNote = priorityEntry.slug ? `Kategori "${AGHA_PRIORITY_CATEGORY_LABEL}" akan dipindah jadi tab PALING PERTAMA (setelah Semua/All).` : null;

  // Produk yang ADA di database tapi namanya gak kesebut di manapun (baik
  // di rencana kategori ini maupun daftar produk yang pernah diproses) --
  // supaya kelihatan kalau ada yang "kececer" dan belum jelas kategorinya.
  const ambiguous = AGHA_AMBIGUOUS_PRODUCTS
    .map(name => products.find(p => aghaNormalize(p.name) === aghaNormalize(name)))
    .filter(Boolean)
    .map(p => ({ name: p.name, currentCategories: p.categories || [] }));

  return { settings, products, newCategories, productUpdates, notFound, guildSlug, guildCount, priorityEntry, reorderNote, ambiguous };
}
function aghaCategoryFixHtml({ newCategories, productUpdates, notFound, guildSlug, guildCount, reorderNote, ambiguous, applied }) {
  const rows = productUpdates.map(u => `
    <tr>
      <td style="padding:8px;border-bottom:1px solid #222;">${u.name}</td>
      <td style="padding:8px;border-bottom:1px solid #222;color:#888;">${u.oldCategories.join(', ') || '(default)'}</td>
      <td style="padding:8px;border-bottom:1px solid #222;color:#4ade80;">${u.label}</td>
    </tr>`).join('');
  const newCatRows = newCategories.map(c => `<li>${c.label} <span style="color:#666;">(slug: ${c.slug})</span></li>`).join('') || '<li style="color:#666;">(tidak ada, semua kategori target sudah ada)</li>';
  const notFoundHtml = notFound.length
    ? `<p style="color:#facc15;">⚠️ Produk tidak ketemu di database (cek nama persis di admin): ${notFound.join(', ')}</p>` : '';
  const guildHtml = guildSlug
    ? `<p style="color:#888;">Kategori "GUILD GLORY BOT" ketemu (${guildCount} produk di dalamnya) -- TIDAK disentuh sama sekali, cek manual ke client apakah ini perlu atau salah nyasar.</p>`
    : `<p style="color:#888;">Kategori "GUILD GLORY BOT" tidak ketemu (mungkin sudah dihapus manual).</p>`;
  const reorderHtml = reorderNote ? `<p style="color:#60a5fa;">↑ ${reorderNote}</p>` : '';
  const ambiguousHtml = ambiguous.length
    ? `<p style="color:#facc15;">⚠️ Produk berikut ADA di database tapi belum pernah disebut client di kategori manapun (dibiarkan apa adanya, cek manual): ${ambiguous.map(a => `${a.name} (sekarang: ${a.currentCategories.join(', ') || 'default'})`).join('; ')}</p>`
    : '';
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Rapikan Kategori AGHA NL</title>
  <style>body{background:#0a0a0a;color:#eee;font-family:sans-serif;max-width:720px;margin:40px auto;padding:0 16px;}
  h1{color:#dc2626;font-size:20px;} table{width:100%;border-collapse:collapse;margin:16px 0;font-size:13px;}
  th{text-align:left;padding:8px;color:#888;border-bottom:1px solid #333;}
  button{background:#dc2626;color:#fff;border:none;padding:12px 20px;border-radius:8px;font-weight:bold;cursor:pointer;font-size:14px;}
  a{color:#f87171;}</style></head><body>
  <h1>${applied ? '✅ Kategori berhasil dirapikan' : '🔍 Preview: Rapikan Kategori AGHA NL'}</h1>
  <h3>Kategori baru ${applied ? 'ditambahkan' : 'yang akan ditambahkan'}:</h3>
  <ul>${newCatRows}</ul>
  ${reorderHtml}
  <h3>Produk ${applied ? 'yang dipindah' : 'yang akan dipindah'}:</h3>
  <table><tr><th>Produk</th><th>Dari</th><th>Ke</th></tr>${rows}</table>
  ${notFoundHtml}
  ${ambiguousHtml}
  ${guildHtml}
  ${applied
    ? `<p style="margin-top:24px;"><a href="/">← Kembali ke beranda toko</a> untuk lihat hasilnya.</p>`
    : `<form method="POST"><button type="submit">Terapkan Perubahan Ini</button></form>
       <p style="color:#666;font-size:12px;margin-top:12px;">Belum ada yang disimpan. Klik tombol di atas kalau sudah yakin sesuai.</p>`
  }
  </body></html>`;
}
app.get('/admin/fix-categories-agha', requireAdmin, async (req, res) => {
  try {
    const plan = await aghaBuildCategoryFixPlan();
    res.send(aghaCategoryFixHtml({ ...plan, applied: false }));
  } catch (e) { res.status(500).send('Error: ' + e.message); }
});
app.post('/admin/fix-categories-agha', requireAdmin, async (req, res) => {
  try {
    const plan = await withProductsWriteLock(async () => {
      const plan = await aghaBuildCategoryFixPlan();
    plan.newCategories.forEach(c => { plan.settings.categories.push(c.slug); plan.settings.categoryLabels[c.slug] = c.label; });
    plan.productUpdates.forEach(u => {
      const p = plan.products.find(pr => pr.id === u.id);
      if (p) p.categories = u.newCategories;
    });
    // Reorder: kategori prioritas dipindah ke index 0 (tab pertama setelah Semua/All)
    if (plan.priorityEntry && plan.priorityEntry.slug) {
      const idx = plan.settings.categories.indexOf(plan.priorityEntry.slug);
      if (idx > 0) {
        plan.settings.categories.splice(idx, 1);
        plan.settings.categories.unshift(plan.priorityEntry.slug);
      }
    }
    if (plan.newCategories.length > 0 || plan.priorityEntry?.slug) await writeDB('settings.json', plan.settings);
    if (plan.productUpdates.length > 0) await writeDB('products.json', plan.products);
      return plan;
    });
    res.send(aghaCategoryFixHtml({ ...plan, applied: true }));
  } catch (e) { res.status(500).send('Error: ' + e.message); }
});

// ══════════════════════════════════════════════════════════════════
// IMPORT PRODUK CLIENT VIA URL ADMIN-ONLY
// Login admin -> buka URL khusus dengan price/days -> daftar produk client
// dibuat otomatis. Operasi idempotent: nama yang sudah ada dilewati.
const AGHA_CLIENT_PRODUCT_IMPORT_LIST = [
  'DRIP CLINT APK MOD',
  'ABCD PANEL',
  'DRIP WIRE',
  'AIM HACK',
  'SILENT CHEATS',
  'HG APK MOD',
  'XREG APK MOD',
  'PATO ORANGE',
  'PATO GREEN',
  'PATO BLUE'
];
const AGHA_CLIENT_PRODUCT_IMPORT_CATEGORY = 'APK MOD NO ROOT';

const importProductsNormalizeName = (value) => String(value || '')
  .normalize('NFKC')
  .toLowerCase()
  .replace(/[._|/\\-]+/g, ' ')
  .replace(/\s+/g, ' ')
  .trim();

const importProductsSlugify = (label) => importProductsNormalizeName(label).replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');

const importProductsParseMoney = (value) => {
  if (value === undefined || value === null || value === '') return NaN;
  const digits = String(value).replace(/[^\d]/g, '');
  return digits ? Number(digits) : NaN;
};

async function importAghaClientProducts({ price, days, unit = 'd' }) {
  const safePrice = importProductsParseMoney(price);
  const safeDays = Number(String(days ?? '').replace(/[^\d]/g, ''));
  const safeUnit = String(unit).toLowerCase() === 'h' ? 'h' : 'd';

  if (!Number.isFinite(safePrice) || safePrice < 1) {
    throw new Error('Harga wajib diisi. Gunakan ?price=50000');
  }
  if (!Number.isInteger(safeDays) || safeDays < 1) {
    throw new Error('Durasi wajib diisi. Gunakan ?days=30');
  }

  return withProductsWriteLock(async () => {
      const [productsRaw, settingsRaw] = await Promise.all([
        readFresh('products.json'),
        readFresh('settings.json')
      ]);
      const products = Array.isArray(productsRaw) ? productsRaw : [];
      const settings = settingsRaw && typeof settingsRaw === 'object' ? settingsRaw : {};

      settings.categories = Array.isArray(settings.categories) ? [...settings.categories] : [];
      settings.categoryLabels = settings.categoryLabels && typeof settings.categoryLabels === 'object'
        ? { ...settings.categoryLabels }
        : {};

      // PENTING: cari KATEGORI EXISTING berdasarkan label ATAU slug.
      // Jangan bikin kategori kedua hanya karena label/slug di data lama tidak persis sama.
      const targetNorm = importProductsNormalizeName(AGHA_CLIENT_PRODUCT_IMPORT_CATEGORY);
      const targetSlugCandidates = new Set([
        importProductsSlugify(AGHA_CLIENT_PRODUCT_IMPORT_CATEGORY),
        'apk-mod-no-root',
        'apkmodnoroot'
      ]);

      let categorySlug = settings.categories.find(slug =>
        importProductsNormalizeName(settings.categoryLabels[slug]) === targetNorm
      );
      if (!categorySlug) {
        categorySlug = settings.categories.find(slug =>
          targetSlugCandidates.has(importProductsNormalizeName(slug).replace(/\s+/g, '-'))
          || importProductsNormalizeName(slug).replace(/[^a-z0-9]+/g, '') === 'apkmodnoroot'
        );
      }
      // Fallback hanya kalau kategori memang benar-benar belum ada.
      if (!categorySlug) {
        categorySlug = importProductsSlugify(AGHA_CLIENT_PRODUCT_IMPORT_CATEGORY);
        settings.categories.unshift(categorySlug);
      }
      if (!settings.categories.includes(categorySlug)) settings.categories.unshift(categorySlug);
      settings.categoryLabels[categorySlug] = AGHA_CLIENT_PRODUCT_IMPORT_CATEGORY;

      const existingByName = new Map();
      for (const product of products) {
        const key = importProductsNormalizeName(product?.name);
        if (key && !existingByName.has(key)) existingByName.set(key, product);
      }

      const added = [];
      const updated = [];
      const skipped = [];

      for (const name of AGHA_CLIENT_PRODUCT_IMPORT_LIST) {
        const normalized = importProductsNormalizeName(name);
        const existing = existingByName.get(normalized);

        // BUG FIX UTAMA:
        // Produk yang SUDAH ADA tidak boleh sekadar di-skip. Pastikan produk
        // tersebut benar-benar punya kategori target. Kategori lain tetap dipertahankan.
        if (existing) {
          const currentCategories = Array.isArray(existing.categories)
            ? [...existing.categories]
            : (existing.category ? [existing.category] : []);

          // Normalisasi kategori target ke SLUG CANONICAL yang dipakai tombol filter
          // di home.ejs. Ini penting untuk produk lama yang menyimpan label
          // "APK MOD NO ROOT" langsung di field categories.
          const normalizedCategories = [];
          let targetFound = false;
          for (const category of currentCategories) {
            const categoryText = importProductsNormalizeName(category);
            const categoryLabel = importProductsNormalizeName(settings.categoryLabels[category]);
            const isTarget = categoryText === importProductsNormalizeName(categorySlug)
              || categoryLabel === targetNorm
              || categoryText.replace(/[^a-z0-9]+/g, '') === 'apkmodnoroot';

            if (isTarget) {
              targetFound = true;
              if (!normalizedCategories.includes(categorySlug)) normalizedCategories.push(categorySlug);
            } else if (!normalizedCategories.includes(category)) {
              normalizedCategories.push(category);
            }
          }

          // Selalu canonicalize kategori produk. Kategori lain tidak dihapus.
          if (!targetFound) normalizedCategories.push(categorySlug);
          const changed = JSON.stringify(currentCategories) !== JSON.stringify(normalizedCategories)
            || Object.prototype.hasOwnProperty.call(existing, 'category');

          if (changed) {
            existing.categories = normalizedCategories;
            // Field singular lama dapat membuat fallback frontend membaca nilai yang salah.
            if (Object.prototype.hasOwnProperty.call(existing, 'category')) delete existing.category;
            updated.push({
              id: existing.id,
              name: existing.name,
              action: targetFound ? 'kategori dinormalisasi' : 'kategori ditambahkan'
            });
          } else {
            skipped.push({ name, reason: 'sudah benar di kategori' });
          }
          continue;
        }

        const pricingOption = {
          days: safeDays,
          unit: safeUnit,
          price: safePrice,
          reseller_price: null,
          strike_price: null
        };

        const durationLabel = safeUnit === 'h' ? `${safeDays} JAM` : `${safeDays} HARI`;
        const product = {
          id: uuidv4(),
          name,
          categories: [categorySlug],
          description: '',
          image: '/images/placeholder.jpg',
          pricingOptions: [pricingOption],
          items: [{
            l: `${name.toUpperCase()} ${durationLabel}`,
            p: safePrice,
            reseller_price: null,
            strike_price: null
          }],
          status: 'active',
          keys: [],
          channelUrl: '',
          downloadUrl: '',
          fakeSold: null,
          sold: 0,
          createdAt: new Date().toISOString()
        };

        products.push(product);
        existingByName.set(normalized, product);
        added.push(product);
      }

      // Pastikan kategori target berada paling awal setelah SEMUA.
      const categoryIndex = settings.categories.indexOf(categorySlug);
      if (categoryIndex > 0) {
        settings.categories.splice(categoryIndex, 1);
        settings.categories.unshift(categorySlug);
      }

      // Satu write per sumber data.
      await writeDB('settings.json', settings);
      await writeDB('products.json', products);

      // Verifikasi source-of-truth setelah write. Jangan kasih status sukses
      // kalau data yang dibaca ulang belum benar-benar memuat kategori target.
      const [verifiedSettings, verifiedProductsRaw] = await Promise.all([
        readFresh('settings.json'),
        readFresh('products.json')
      ]);
      const verifiedProducts = Array.isArray(verifiedProductsRaw) ? verifiedProductsRaw : [];
      const verifiedCategorySlug = (verifiedSettings?.categories || []).find(slug =>
        importProductsNormalizeName(verifiedSettings?.categoryLabels?.[slug]) === targetNorm
        || String(slug) === String(categorySlug)
      );
      if (!verifiedCategorySlug) {
        throw new Error('Kategori APK MOD NO ROOT tidak terverifikasi setelah penyimpanan.');
      }
      const verifyMissing = AGHA_CLIENT_PRODUCT_IMPORT_LIST.filter(name => {
        const p = verifiedProducts.find(x => importProductsNormalizeName(x?.name) === importProductsNormalizeName(name));
        const cats = Array.isArray(p?.categories) ? p.categories : (p?.category ? [p.category] : []);
        return !p || !cats.includes(verifiedCategorySlug);
      });
      if (verifyMissing.length) {
        throw new Error('Verifikasi kategori gagal untuk: ' + verifyMissing.join(', '));
      }

      return {
        category: AGHA_CLIENT_PRODUCT_IMPORT_CATEGORY,
        categorySlug,
        price: safePrice,
        days: safeDays,
        unit: safeUnit,
        added: added.map(p => ({ id: p.id, name: p.name })),
        updated,
        skipped,
        totalRequested: AGHA_CLIENT_PRODUCT_IMPORT_LIST.length,
        totalChanged: added.length + updated.length
      };
  });
}

// URL AUTO-IMPORT:
// /admin/tools/import-client-apk?price=50000&days=30&unit=d
// WAJIB sedang login sebagai admin karena dilindungi requireAdmin.
// Refresh aman: produk yang sudah ada otomatis dilewati.
app.get('/admin/tools/import-client-apk', requireAdmin, async (req, res) => {
  try {
    const result = await importAghaClientProducts({
      price: req.query.price,
      days: req.query.days,
      unit: req.query.unit || 'd'
    });

    const addedHtml = result.added.length
      ? result.added.map(p => `<li>${p.name}</li>`).join('')
      : '<li>Tidak ada produk baru.</li>';
    const updatedHtml = result.updated.length
      ? `<h3>Produk existing yang diperbaiki kategorinya (${result.updated.length})</h3><ul>${result.updated.map(p => `<li>${p.name} — kategori ditambahkan</li>`).join('')}</ul>`
      : '';
    const skippedHtml = result.skipped.length
      ? `<p style="color:#a1a1aa;">Sudah benar di kategori: ${result.skipped.length} produk.</p>`
      : '';

    res.send(`<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Import Produk Client</title>
      <style>body{margin:0;background:#09090b;color:#f4f4f5;font-family:Arial,sans-serif}.wrap{max-width:720px;margin:48px auto;padding:24px}.card{border:1px solid #27272a;border-radius:14px;padding:22px;background:#111113}h1{font-size:22px;margin:0 0 8px;color:#4ade80}p{color:#a1a1aa}.meta{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:18px 0}.meta div{padding:12px;border:1px solid #27272a;border-radius:10px}.label{font-size:11px;color:#71717a;text-transform:uppercase}.value{margin-top:4px;font-weight:700}li{padding:4px 0}a{color:#60a5fa;text-decoration:none}</style></head>
      <body><main class="wrap"><section class="card"><h1>✅ Import produk berhasil</h1>
      <p>Endpoint ini hanya bisa dibuka setelah login admin.</p>
      <div class="meta"><div><div class="label">Kategori</div><div class="value">${result.category}</div></div><div><div class="label">Paket default</div><div class="value">${result.days}${result.unit === 'h' ? ' jam' : ' hari'} — Rp${result.price.toLocaleString('id-ID')}</div></div></div>
      <h3>Produk baru (${result.added.length})</h3><ul>${addedHtml}</ul>${updatedHtml}${skippedHtml}
      <p style="margin-top:22px;"><a href="/admin">← Kembali ke Admin</a></p></section></main></body></html>`);
  } catch (e) {
    res.status(400).send(`<!doctype html><html><body style="font-family:Arial;background:#09090b;color:#f4f4f5;padding:40px"><h2 style="color:#f87171">❌ Import gagal</h2><p>${String(e?.message || e).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}</p><p>Contoh URL: <code>/admin/tools/import-client-apk?price=50000&amp;days=30&amp;unit=d</code></p><p><a style="color:#60a5fa" href="/admin">← Kembali ke Admin</a></p></body></html>`);
  }
});

// ══════════════════════════════════════════════════════════════════
// REPAIR KATEGORI APK MOD NO ROOT (admin-only)
// Tidak membuat produk baru dan tidak mengubah harga/stok/mapping.
// Ini khusus memperbaiki membership kategori untuk 10 produk client yang
// sudah ada di database, lalu memverifikasi ulang hasilnya dari source of truth.
app.get('/admin/tools/repair-apk-no-root', requireAdmin, async (req, res) => {
  try {
    const [productsRaw, settingsRaw] = await Promise.all([
      readFresh('products.json'),
      readFresh('settings.json')
    ]);
    const products = Array.isArray(productsRaw) ? productsRaw : [];
    const settings = settingsRaw && typeof settingsRaw === 'object' ? settingsRaw : {};
    settings.categories = Array.isArray(settings.categories) ? [...settings.categories] : [];
    settings.categoryLabels = settings.categoryLabels && typeof settings.categoryLabels === 'object'
      ? { ...settings.categoryLabels } : {};

    const targetNorm = importProductsNormalizeName(AGHA_CLIENT_PRODUCT_IMPORT_CATEGORY);
    const targetCompact = 'apkmodnoroot';
    let categorySlug = settings.categories.find(slug =>
      importProductsNormalizeName(settings.categoryLabels[slug]) === targetNorm
    );
    if (!categorySlug) {
      categorySlug = settings.categories.find(slug =>
        importProductsNormalizeName(slug).replace(/[^a-z0-9]+/g, '') === targetCompact
      );
    }
    if (!categorySlug) {
      throw new Error('Kategori existing "APK MOD NO ROOT" tidak ditemukan di Settings.');
    }
    settings.categoryLabels[categorySlug] = AGHA_CLIENT_PRODUCT_IMPORT_CATEGORY;

    const changed = [];
    const notFound = [];
    for (const name of AGHA_CLIENT_PRODUCT_IMPORT_LIST) {
      const product = products.find(p => importProductsNormalizeName(p?.name) === importProductsNormalizeName(name));
      if (!product) { notFound.push(name); continue; }
      const current = Array.isArray(product.categories)
        ? [...product.categories]
        : (product.category ? [product.category] : []);
      const next = [];
      let foundTarget = false;
      for (const cat of current) {
        const compact = importProductsNormalizeName(cat).replace(/[^a-z0-9]+/g, '');
        const isTarget = String(cat) === String(categorySlug)
          || importProductsNormalizeName(settings.categoryLabels[cat]) === targetNorm
          || compact === targetCompact;
        if (isTarget) {
          foundTarget = true;
          if (!next.includes(categorySlug)) next.push(categorySlug);
        } else if (!next.includes(cat)) {
          next.push(cat);
        }
      }
      if (!foundTarget) next.push(categorySlug);
      const altered = JSON.stringify(current) !== JSON.stringify(next)
        || Object.prototype.hasOwnProperty.call(product, 'category');
      if (altered) {
        product.categories = next;
        if (Object.prototype.hasOwnProperty.call(product, 'category')) delete product.category;
        changed.push(name);
      }
    }

    const idx = settings.categories.indexOf(categorySlug);
    if (idx > 0) {
      settings.categories.splice(idx, 1);
      settings.categories.unshift(categorySlug);
    }
    await writeDB('settings.json', settings);
    await writeDB('products.json', products);

    const [verifiedSettings, verifiedProductsRaw] = await Promise.all([
      readFresh('settings.json'),
      readFresh('products.json')
    ]);
    const verifiedProducts = Array.isArray(verifiedProductsRaw) ? verifiedProductsRaw : [];
    const verifiedSlug = (verifiedSettings?.categories || []).find(slug =>
      String(slug) === String(categorySlug)
      && importProductsNormalizeName(verifiedSettings?.categoryLabels?.[slug]) === targetNorm
    );
    if (!verifiedSlug) throw new Error('Kategori target gagal diverifikasi setelah repair.');
    const verifyMissing = AGHA_CLIENT_PRODUCT_IMPORT_LIST.filter(name => {
      const p = verifiedProducts.find(x => importProductsNormalizeName(x?.name) === importProductsNormalizeName(name));
      const cats = Array.isArray(p?.categories) ? p.categories : [];
      return !p || !cats.includes(verifiedSlug);
    });
    if (verifyMissing.length) {
      throw new Error('Repair gagal diverifikasi untuk: ' + verifyMissing.join(', '));
    }

    const missingHtml = notFound.length
      ? `<p style="color:#facc15;">Tidak ditemukan di database: ${notFound.join(', ')}</p>`
      : '<p>Semua 10 nama client ditemukan di database.</p>';
    res.send(`<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Repair APK MOD NO ROOT</title><style>body{margin:0;background:#09090b;color:#f4f4f5;font-family:Arial,sans-serif}.wrap{max-width:720px;margin:48px auto;padding:24px}.card{border:1px solid #27272a;border-radius:14px;padding:22px;background:#111113}h1{font-size:22px;color:#4ade80}li{padding:4px 0}a{color:#60a5fa;text-decoration:none}</style></head><body><main class="wrap"><section class="card"><h1>✅ Kategori berhasil diperbaiki</h1><p>Target: <b>${AGHA_CLIENT_PRODUCT_IMPORT_CATEGORY}</b></p><p>Slug: <b>${categorySlug}</b></p><p>Produk yang diperbaiki: <b>${changed.length}</b></p>${missingHtml}<ul>${AGHA_CLIENT_PRODUCT_IMPORT_LIST.map(n => `<li>${n} — OK</li>`).join('')}</ul><p><a href="/admin">← Kembali ke Admin</a> &nbsp; <a href="/">Lihat Store</a></p></section></main></body></html>`);
  } catch (e) {
    res.status(400).send(`<!doctype html><html><body style="font-family:Arial;background:#09090b;color:#f4f4f5;padding:40px"><h2 style="color:#f87171">❌ Repair gagal</h2><p>${String(e?.message || e).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}</p><p><a style="color:#60a5fa" href="/admin">← Kembali ke Admin</a></p></body></html>`);
  }
});

// ══════════════════════════════════════════════════════════════════
// BERSIHKAN KATEGORI KOSONG/GAK DIPAKAI (one-off, diminta client 16 Sep 2026
// lewat video: kategori lain -- kayak PUBG Mobile dkk -- gak ada produknya
// sama sekali dan harus dihapus, sisain cuma yang tampil di dashboard).
// Beda dari /admin/fix-categories-agha (yang MEMINDAHKAN produk ke kategori
// baru): tool ini buat HAPUS kategori yang sudah gak kepake, dicek otomatis
// dari jumlah produk yang masih nempel di tiap kategori -- bukan tebak-tebakan
// nama. Kategori yang harus tetap ada (APK MOD NO ROOT, FF PROXY APKMOD,
// IOS [IPHONES PANEL, PC PANEL, ROOT ANDROID) otomatis TIDAK dicentang
// default, walau seharusnya semua sudah ada isinya. Kategori "GUILD GLORY
// BOT" sengaja dibiarkan mengikuti data asli (dicentang HANYA kalau memang
// 0 produk) karena client belum pernah menjelaskan kategori itu untuk apa.
const AGHA_KEEP_CATEGORY_LABELS = ['APK MOD NO ROOT', 'FF PROXY APKMOD', 'IOS [IPHONES PANEL', 'PC PANEL', 'ROOT ANDROID'];

app.get('/admin/cleanup-categories-agha', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const products = await readFresh('products.json');
    settings.categories = settings.categories || [];
    settings.categoryLabels = settings.categoryLabels || {};

    const rows = settings.categories.map(slug => {
      const label = settings.categoryLabels[slug] || slug;
      const count = products.filter(p => (p.categories || []).includes(slug)).length;
      const isProtected = AGHA_KEEP_CATEGORY_LABELS.some(l => aghaNormalize(l) === aghaNormalize(label));
      return { slug, label, count, isProtected, suggestDelete: count === 0 && !isProtected };
    });

    const rowsHtml = rows.map(r => `
      <tr>
        <td style="padding:8px;border-bottom:1px solid #222;">
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
            <input type="checkbox" name="deleteSlug" value="${r.slug}" ${r.suggestDelete ? 'checked' : ''}>
            <span>${r.label}</span>
          </label>
        </td>
        <td style="padding:8px;border-bottom:1px solid #222;color:#666;">${r.slug}</td>
        <td style="padding:8px;border-bottom:1px solid #222;color:${r.count === 0 ? '#f87171' : '#4ade80'};">${r.count} produk</td>
        <td style="padding:8px;border-bottom:1px solid #222;color:#666;">${r.isProtected ? '🔒 kategori inti, jangan dihapus' : (r.count === 0 ? '⚠️ kosong, aman dihapus' : '')}</td>
      </tr>`).join('');

    res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Bersihkan Kategori AGHA NL</title>
    <style>body{background:#0a0a0a;color:#eee;font-family:sans-serif;max-width:760px;margin:40px auto;padding:0 16px;}
    h1{color:#dc2626;font-size:20px;} table{width:100%;border-collapse:collapse;margin:16px 0;font-size:13px;}
    th{text-align:left;padding:8px;color:#888;border-bottom:1px solid #333;}
    button{background:#dc2626;color:#fff;border:none;padding:12px 20px;border-radius:8px;font-weight:bold;cursor:pointer;font-size:14px;}
    </style></head><body>
    <h1>🧹 Bersihkan Kategori yang Gak Kepake</h1>
    <p style="color:#888;font-size:13px;">Kategori dengan checkbox tercentang otomatis kepilih buat DIHAPUS (yang 0 produk & bukan kategori inti). Cek dulu manual sebelum submit -- kategori bertanda 🔒 sengaja TIDAK dicentang walau kebetulan 0 produk, biar gak kehapus gak sengaja.</p>
    <form method="POST">
      <table><tr><th>Kategori (centang = hapus)</th><th>Slug</th><th>Jumlah Produk</th><th>Catatan</th></tr>${rowsHtml}</table>
      <button type="submit" onclick="return confirm('Yakin hapus kategori yang dicentang? Produk di dalamnya TIDAK ikut terhapus, cuma label kategorinya yang dilepas.')">Hapus Kategori Terpilih</button>
    </form>
    </body></html>`);
  } catch (e) { res.status(500).send('Error: ' + e.message); }
});

app.post('/admin/cleanup-categories-agha', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const products = await readFresh('products.json');
    settings.categories = settings.categories || [];
    settings.categoryLabels = settings.categoryLabels || {};

    let toDelete = req.body.deleteSlug || [];
    if (!Array.isArray(toDelete)) toDelete = [toDelete];
    toDelete = toDelete.filter(Boolean);

    if (toDelete.length === 0) {
      return res.send('<p style="font-family:sans-serif;color:#facc15;">Gak ada kategori yang dicentang, tidak ada yang dihapus. <a href="/admin/cleanup-categories-agha" style="color:#f87171;">← Kembali</a></p>');
    }

    settings.categories = settings.categories.filter(s => !toDelete.includes(s));
    toDelete.forEach(s => delete settings.categoryLabels[s]);
    // Safety net: lepas slug yang dihapus dari categories array tiap produk juga,
    // jaga-jaga kalau ternyata ada produk yang masih nempel (harusnya sudah 0 dari preview).
    let productsTouched = 0;
    products.forEach(p => {
      if (Array.isArray(p.categories) && p.categories.some(c => toDelete.includes(c))) {
        p.categories = p.categories.filter(c => !toDelete.includes(c));
        productsTouched++;
      }
    });

    await writeDB('settings.json', settings);
    if (productsTouched > 0) await writeDB('products.json', products);

    res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Selesai</title>
    <style>body{background:#0a0a0a;color:#eee;font-family:sans-serif;max-width:600px;margin:40px auto;padding:0 16px;} a{color:#f87171;}</style>
    </head><body>
    <h1 style="color:#4ade80;">✅ Kategori berhasil dibersihkan</h1>
    <p>Dihapus: ${toDelete.join(', ')}</p>
    ${productsTouched > 0 ? `<p style="color:#facc15;">${productsTouched} produk ada yang masih nempel di kategori itu, sudah otomatis dilepas (produknya sendiri TIDAK dihapus).</p>` : ''}
    <p><a href="/">← Kembali ke beranda toko</a></p>
    </body></html>`);
  } catch (e) { res.status(500).send('Error: ' + e.message); }
});

app.get('/admin/migrate-images', async (req, res) => {
  const secret = process.env.SETUP_SECRET;
  if (!secret || req.query.secret !== secret) {
    return res.status(403).send('<pre>❌ Akses ditolak. Set SETUP_SECRET di env Vercel, lalu akses /admin/migrate-images?secret=SETUP_SECRET_KAMU</pre>');
  }

  const { runMigration, formatSummary } = require('./migrate-images-to-webp');
  const client = db.getClient();
  if (!client) {
    return res.status(500).send('<pre>Supabase belum terkonfigurasi (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY belum di-set di env Vercel).</pre>');
  }

  // Stream progress sebagai plain text yang keupdate live di browser,
  // supaya tidak terlihat "hang" selama proses (bisa makan waktu kalau
  // gambarnya banyak).
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.write('Memulai migrasi gambar ke WebP...\n\n');
  // Beberapa proxy/browser menahan buffer kecil sebelum flush pertama --
  // paksa flush kalau tersedia supaya baris ini langsung muncul.
  if (typeof res.flushHeaders === 'function') res.flushHeaders();

  try {
    // maxFiles dibatasi supaya tidak kena timeout Vercel kalau gambarnya
    // banyak -- aman karena idempotent, tinggal refresh URL ini beberapa
    // kali sampai ringkasan menunjukkan "Sisa belum diproses: 0".
    const summary = await runMigration(client, {
      onProgress: (line) => res.write(line + '\n'),
      maxFiles: 15
    });
    res.write('\n' + formatSummary(summary) + '\n');
    if (summary.remaining > 0) {
      res.write('\nMasih ada sisa -- refresh/buka lagi halaman ini untuk lanjutkan batch berikutnya.\n');
    } else {
      res.write('\nSelesai. Buka kembali homepage dan cek PageSpeed Insights untuk verifikasi.\n');
    }
    res.end();
  } catch (err) {
    res.write('\n❌ Migrasi berhenti karena error: ' + err.message + '\n');
    res.end();
  }
});

app.get('/admin', requireAdmin, async (req, res) => {
  // ── FIX: readFresh() bypass cache per-instance Vercel ──
  // Sebelumnya pakai readDB (cache lokal tiap instance), jadi setelah
  // tambah/edit produk di satu instance, refresh halaman bisa nyasar ke
  // instance lain yang cache-nya masih lama → produk kelihatan hilang/berubah.
  const [products, transactions, users, settings] = await Promise.all([
    readFresh('products.json'),
    readFresh('transactions.json'),
    readFresh('users.json'),
    readFresh('settings.json')
  ]);
  if (normalizeBanners(settings)) await writeDB('settings.json', settings);

  // PERFORMANCE: single-pass untuk stats + chart 7 hari, menggantikan
  // pola sebelumnya yang men-scan SELURUH transactions SEBANYAK 7 KALI
  // (sekali per hari) plus beberapa .filter()/.reduce() terpisah untuk
  // stats. Sekarang cukup 1 kali iterasi transactions, hasil akhir
  // (angka, urutan chart, format tanggal) identik dengan sebelumnya.
  const today = new Date();
  const dateKeys = [];
  const chartByDate = {};
  for (let i = 6; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().slice(0, 10);
    dateKeys.push(dateStr);
    chartByDate[dateStr] = {
      date: d.toLocaleDateString('id-ID', { weekday: 'short', day: 'numeric', month: 'short' }),
      count: 0,
      revenue: 0
    };
  }

  let pendingTransactions = 0, doneTransactions = 0, totalRevenue = 0;
  for (const t of transactions) {
    if (t.status === 'pending') pendingTransactions++;
    if (t.status === 'done') {
      doneTransactions++;
      totalRevenue += t.price;
      const dKey = t.createdAt && t.createdAt.slice(0, 10);
      if (dKey && chartByDate[dKey]) {
        chartByDate[dKey].count++;
        chartByDate[dKey].revenue += t.price;
      }
    }
  }

  let activeProducts = 0;
  for (const p of products) if (p.status === 'active') activeProducts++;
  let totalResellers = 0;
  for (const u of users) if (u.is_reseller) totalResellers++;

  const stats = {
    totalProducts: products.length,
    activeProducts,
    totalTransactions: transactions.length,
    pendingTransactions,
    doneTransactions,
    totalUsers: users.length,
    totalResellers,
    totalRevenue
  };

  const chartData = dateKeys.map(k => chartByDate[k]);

  // Audit stok admin: tampilkan stok yang sama dengan frontend publik, bukan
  // simbol "∞" atau raw keys.length. Satu angka stok hanya merepresentasikan
  // kapasitas paket terbesar yang tersedia; stok per durasi dihitung sendiri.
  const adminDsMode = settings.dripstore?.fulfillmentMode || 'live';
  let adminProviderSnapshot = null;
  if ((adminDsMode === 'live' || adminDsMode === 'hybrid') && settings.dripstore?.apiToken) {
    adminProviderSnapshot = getCachedDripstoreCatalogSnapshot(settings);
    if (!adminProviderSnapshot) {
      adminProviderSnapshot = await getDripstoreCatalogSnapshot(settings, { maxWaitMs: 4500 }).catch(() => null);
      if (!adminProviderSnapshot?.products) adminProviderSnapshot = getDisplayDripstoreSnapshot(settings) || adminProviderSnapshot;
    }
    warmDripstoreCatalog(settings);
  }
  const adminProducts = products.map(rawProduct => {
    const summary = buildProductStockSummary(rawProduct, settings, adminProviderSnapshot);
    return {
      ...rawProduct,
      pricingOptions: summary.product.pricingOptions,
      items: summary.product.items,
      _adminStockByOption: summary.stockByOption,
      _adminStockCount: summary.stockCount,
      _adminStockUnknown: summary.providerStockUnknown,
      _adminUsableKeyCount: summary.usableLocalKeyCount,
      _adminGenericKeyCount: summary.genericLocalKeyCount
    };
  });

  res.render('pages/admin', {
    layout: false,
    products: adminProducts,
    transactions: transactions.slice(-20).reverse(),
    users,
    settings,
    stats,
    chartData
  });
});

// Helper: parse pricingOptions
// FIX (fitur baru: key per-jam, diminta client 21 Agu 2026): pricingOptions
// sekarang punya field `unit` ('d' hari atau 'h' jam) selain `days` (dipakai
// sebagai `value` numerik durasi, nama field dipertahankan "days" demi
// backward-compat data produk lama yang sudah tersimpan -- HANYA readable
// sebagai angka durasi, satuannya ikut field unit terpisah).
function parsePricingOptions(days, prices, resellerPrices, units, strikePrices) {
  const da = Array.isArray(days) ? days : (days ? [days] : []);
  const pa = Array.isArray(prices) ? prices : (prices ? [prices] : []);
  const rpa = Array.isArray(resellerPrices) ? resellerPrices : (resellerPrices ? [resellerPrices] : []);
  const ua = Array.isArray(units) ? units : (units ? [units] : []);
  // FIX (diminta client 22 Agu 2026, referensi screenshot produk "SENJU"):
  // harga coret itu PER-OPSI DURASI (mis. paket 30 hari punya harga coret
  // sendiri beda dari paket 60 hari), BUKAN satu harga coret global untuk
  // seluruh produk seperti implementasi sebelumnya (product.strikePrice).
  const spa = Array.isArray(strikePrices) ? strikePrices : (strikePrices ? [strikePrices] : []);
  const opts = []; const seen = new Set();
  // FIX (bug dilaporkan client 14 Sep 2026, screenshot form "Harga Paket"):
  // sebagian keyboard HP (terutama Android) suka nyisipin titik pemisah
  // ribuan pas ngetik angka di field number (misal ketik "10000" tapi yang
  // kekirim/kesimpen jadi string "10.000"). parseInt("10.000") cuma baca
  // sampai ketemu titik dan hasilnya 10 -- 3 angka nol di belakang hilang
  // diam-diam. cleanNum() buang semua karakter selain digit dulu sebelum
  // di-parseInt, jadi "10.000" atau "10,000" tetap kebaca 10000 yang bener.
  const cleanNum = (v) => {
    if (v === undefined || v === null || v === '') return NaN;
    const digitsOnly = String(v).replace(/[^\d]/g, '');
    return digitsOnly === '' ? NaN : parseInt(digitsOnly, 10);
  };
  for (let i = 0; i < da.length; i++) {
    const d = cleanNum(da[i]), p = cleanNum(pa[i]);
    const unit = (ua[i] === 'h' ? 'h' : 'd'); // default 'd' kalau tidak diisi/tidak valid
    const seenKey = `${d}${unit}`;
    if (d > 0 && p >= 0 && !seen.has(seenKey)) {
      seen.add(seenKey);
      const rp = rpa[i] !== undefined && rpa[i] !== '' ? cleanNum(rpa[i]) : null;
      let sp = null;
      if (spa[i] !== undefined && spa[i] !== null && spa[i] !== '') {
        const parsed = cleanNum(spa[i]);
        if (!isNaN(parsed) && parsed > p) sp = parsed; // harga coret harus LEBIH BESAR dari harga jual, kalau tidak dianggap tidak valid (diabaikan)
      }
      opts.push({ days: d, unit, price: p, reseller_price: (rp !== null && !isNaN(rp) && rp >= 0) ? rp : null, strike_price: sp });
    }
  }
  // Urutkan: jam dulu (durasi lebih pendek umumnya), lalu hari, masing-masing ascending
  return opts.sort((a, b) => a.unit === b.unit ? a.days - b.days : (a.unit === 'h' ? -1 : 1));
}

// Label tampilan buat 1 opsi durasi, dipakai konsisten di seluruh app
// (nama item `items[].l`, tampilan buy.ejs, invoice, dll).
function formatDurationLabel(days, unit) {
  return unit === 'h' ? `${days} JAM` : `${days} HARI`;
}

// ══════════════════════════════════════════════════════════════════
// PARSE DESKRIPSI PRODUK (auto-format ringan, diminta client 22 Agu 2026
// -- referensi screenshot fixaonly.com: badge tagline, daftar fitur cheat,
// link Telegram). Admin tetap cukup ngetik di 1 textarea description biasa,
// TIDAK perlu form/field baru -- baris yang diawali "-" atau "•" otomatis
// jadi bullet list fitur, baris polos jadi paragraf. Ini dipakai HANYA
// untuk RENDER (halaman /buy/:id), data tersimpan tetap 1 string apa
// adanya di product.description.
function parseProductDescription(description) {
  if (!description || typeof description !== 'string') return { paragraphs: [], bullets: [] };
  const lines = description.split('\n').map(l => l.trim()).filter(l => l);
  const paragraphs = [];
  const bullets = [];
  for (const line of lines) {
    if (/^[-•*]\s+/.test(line)) bullets.push(line.replace(/^[-•*]\s+/, ''));
    else paragraphs.push(line);
  }
  return { paragraphs, bullets };
}

// Helper: validasi URL gambar (cegah XSS via javascript:/data: protocol)
const isValidImageUrl = (url) => {
  if (!url) return true;
  const lower = url.toLowerCase().trim();
  return !lower.startsWith('javascript:') && !lower.startsWith('data:') && !lower.startsWith('vbscript:');
};

app.post('/admin/product/add', requireAdmin, (req, res, next) => {
  upload.single('image')(req, res, err => {
    if (err) return res.json({ success: false, message: 'Upload error: ' + err.message });
    // FIX KEAMANAN (audit 22 Agu 2026): validasi magic bytes, lihat
    // requireValidImageMagicBytes untuk penjelasan lengkap kenapa ini perlu.
    if (req.file && !verifyImageMagicBytes(req.file.path)) {
      fs.unlink(req.file.path, () => {});
      return res.json({ success: false, message: 'File yang diupload bukan gambar asli (gagal validasi format file).' });
    }
    next();
  });
}, async (req, res) => {
  try {
    const {name,categories,description,imageUrl:imgUrl,pricingDays,pricingPrices,pricingResellerPrices,pricingUnits,pricingStrikePrices,keys,status,channelUrl,downloadUrl,fakeSold}=req.body;
    if(!name)return res.json({success:false,message:'Nama produk wajib diisi'});
    if(imgUrl && !isValidImageUrl(imgUrl)) return res.json({success:false,message:'URL gambar tidak valid'});
    if(channelUrl && !isValidImageUrl(channelUrl)) return res.json({success:false,message:'URL channel tidak valid'});
    if(downloadUrl && !isValidImageUrl(downloadUrl)) return res.json({success:false,message:'URL download tidak valid'});
    const products=await readFresh('products.json');
    const pricingOptions=parsePricingOptions(pricingDays,pricingPrices,pricingResellerPrices,pricingUnits,pricingStrikePrices);
    if(!pricingOptions.length)return res.json({success:false,message:'Tambahkan minimal 1 opsi harga'});
    const keyArray=keys?keys.split('\n').map(k=>k.trim()).filter(k=>k):[];
    let image = imgUrl?.trim() || '';
    if (req.file) {
      if (!isVercel) {
        image = `/uploads/products/${req.file.filename}`;
      } else {
        try {
          image = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype);
        } catch { image = imgUrl?.trim() || '/images/placeholder.jpg'; }
      }
    }
    if (!image) image = '/images/placeholder.jpg';
    // items.strike_price ikut dari pricingOptions (per-durasi, lihat parsePricingOptions)
    const items=pricingOptions.map(o=>({l:`${name.toUpperCase()} ${formatDurationLabel(o.days,o.unit)}`,p:o.price,reseller_price:o.reseller_price,strike_price:o.strike_price}));
    // Angka "terjual" palsu/manual (opsional, diminta client 21 Agu 2026) --
    // lihat komentar lengkap di /admin/product/:id. Harga coret SEKARANG
    // per-durasi (ada di dalam tiap pricingOptions/items, lihat di atas),
    // bukan lagi field tunggal per-produk.
    let fakeSoldVal = null;
    if (fakeSold !== undefined && fakeSold !== '' && fakeSold !== null) { const fs = parseInt(String(fakeSold).replace(/[^\d]/g,''), 10); if (!isNaN(fs) && fs >= 0) fakeSoldVal = fs; }
    // FIX (diminta client 22 Agu 2026): categories sekarang array (bisa
    // lebih dari 1 sekaligus), dari multer bisa berupa string tunggal
    // (kalau cuma 1 checkbox dicentang) atau array (kalau lebih dari 1) --
    // dinormalisasi jadi array selalu.
    const categoriesArray = categories ? (Array.isArray(categories) ? categories : [categories]) : [];
    const newProduct={id:uuidv4(),name,categories:categoriesArray,description:description||'',image,pricingOptions,items,status:status==='inactive'?'inactive':'active',keys:keyArray,channelUrl:channelUrl?.trim()||'',downloadUrl:downloadUrl?.trim()||'',fakeSold:fakeSoldVal,sold:0,createdAt:new Date().toISOString()};
    const savedProduct = await withProductsWriteLock(async () => {
      const freshProducts = await readFresh('products.json');
      freshProducts.push(newProduct);
      await writeDB('products.json', freshProducts);
      return newProduct;
    });
    res.json({success:true,product:savedProduct});
  }catch(error){res.json({success:false,message:error.message});}
});

app.post('/admin/product/edit/:id', requireAdmin, (req, res, next) => {
  upload.single('image')(req, res, err => {
    if (err) return res.json({ success: false, message: 'Upload error: ' + err.message });
    if (req.file && !verifyImageMagicBytes(req.file.path)) {
      fs.unlink(req.file.path, () => {});
      return res.json({ success: false, message: 'File yang diupload bukan gambar asli (gagal validasi format file).' });
    }
    next();
  });
}, async (req, res) => {
  try {
    const result = await withPersistentProductStockLock(req.params.id, async () => {
      const {name,categories,description,imageUrl:imgUrl,pricingDays,pricingPrices,pricingResellerPrices,pricingUnits,pricingStrikePrices,keys,keysMode,status,channelUrl,downloadUrl,fakeSold}=req.body;
      const products=await readFresh('products.json');
      const product=products.find(p=>p.id===req.params.id);
      if(!product) throw new Error('Produk tidak ditemukan');
      if(imgUrl && !isValidImageUrl(imgUrl)) throw new Error('URL gambar tidak valid');
      if(channelUrl && !isValidImageUrl(channelUrl)) throw new Error('URL channel tidak valid');
      if(downloadUrl && !isValidImageUrl(downloadUrl)) throw new Error('URL download tidak valid');
      if(name)product.name=name;
      if(categories!==undefined) product.categories = Array.isArray(categories) ? categories : (categories ? [categories] : []);
      if(description!==undefined)product.description=description;if(status)product.status=status;
      if(channelUrl!==undefined)product.channelUrl=channelUrl.trim();
      if(downloadUrl!==undefined)product.downloadUrl=downloadUrl.trim();
      if (fakeSold !== undefined) {
        if (fakeSold === '' || fakeSold === null) product.fakeSold = null;
        else { const fs = parseInt(String(fakeSold).replace(/[^\d]/g,''), 10); if (!isNaN(fs) && fs >= 0) product.fakeSold = fs; }
      }
      if (product.strikePrice !== undefined) delete product.strikePrice;
      if(pricingDays){
        const opts=parsePricingOptions(pricingDays,pricingPrices,pricingResellerPrices,pricingUnits,pricingStrikePrices);
        if(opts.length){
          const oldMap = new Map((product.pricingOptions || []).map(o => [
            `${Number(o.days)}${o.unit === 'h' ? 'h' : 'd'}`, String(o.dripstoreVariantId || '') || null
          ]));
          for (const o of opts) {
            const k = `${Number(o.days)}${o.unit === 'h' ? 'h' : 'd'}`;
            o.dripstoreVariantId = oldMap.get(k) || null;
          }
          product.pricingOptions=opts;
          product.items=opts.map(o=>({l:`${product.name.toUpperCase()} ${formatDurationLabel(o.days,o.unit)}`,p:o.price,reseller_price:o.reseller_price,strike_price:o.strike_price}));
        }
      }
      if(keys!==undefined&&keys!==null){
        const nk=normalizeUsableLocalKeys(String(keys).split('\n'));
        if (keysMode==='append') {
          product.keys=normalizeUsableLocalKeys([...(product.keys||[]), ...nk]);
        } else {
          // Replace tetap membuang placeholder lama dan duplikat identik.
          product.keys=nk;
        }
      }
      if (req.file) {
        if (!isVercel) product.image=`/uploads/products/${req.file.filename}`;
        else { try { product.image = await db.uploadImage(require('fs').readFileSync(req.file.path), req.file.originalname, req.file.mimetype); } catch {} }
      } else if(imgUrl?.trim()) product.image=imgUrl.trim();
      await writeDB('products.json',products);
      return product;
    });
    res.json({success:true,product:result});
  }catch(error){res.json({success:false,message:error.message});}
});

app.post('/admin/product/keys/:id', requireAdmin, async (req, res) => {
  try {
    const result = await withPersistentProductStockLock(req.params.id, async () => {
      const{keys,mode}=req.body;
      const products=await readFresh('products.json');
      const product=products.find(p=>p.id===req.params.id);
      if(!product) throw new Error('Produk tidak ditemukan');
      const nk=normalizeUsableLocalKeys(String(keys||'').split('\n'));
      if (mode === 'replace') {
        product.keys = nk;
      } else {
        product.keys = normalizeUsableLocalKeys([...(product.keys || []), ...nk]);
      }
      await writeDB('products.json',products);
      return { keyCount: product.keys.length, product };
    });
    res.json({success:true,keyCount:result.keyCount,product:result.product});
  }catch(e){res.json({success:false,message:e.message});}
});

app.post('/admin/product/delete/:id', requireAdmin, async (req, res) => {
  try {
    await withProductsWriteLock(async () => {
      let products = await readFresh('products.json');
      products = products.filter(p => p.id !== req.params.id);
      await writeDB('products.json', products);
    });
    res.json({ success: true, message: 'Produk berhasil dihapus' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/user/delete/:id', requireAdmin, async (req, res) => {
  try {
    let users = await readFresh('users.json');
    users = users.filter(u => u.id !== req.params.id);
    await writeDB('users.json', users);
    res.json({ success: true, message: 'User berhasil dihapus' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/transaction/delete/:id', requireAdmin, async (req, res) => {
  try {
    let transactions = await readFresh('transactions.json');
    transactions = transactions.filter(t => t.id !== req.params.id);
    await writeDB('transactions.json', transactions);
    res.json({ success: true, message: 'Transaksi berhasil dihapus' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/transaction/status/:id', requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const transactions = await readFresh('transactions.json');
    const trx = transactions.find(t => t.id === req.params.id);
    if (!trx) return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
    trx.status = status;
    trx.updatedBy = 'admin';
    trx.updatedAt = new Date().toISOString();
    await writeDB('transactions.json', transactions);
    res.json({ success: true, message: 'Status berhasil diubah' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/product/toggle/:id', requireAdmin, async (req, res) => {
  try {
    const products = await readFresh('products.json');
    const product = products.find(p => p.id === req.params.id);

    if (!product) {
      return res.json({ success: false, message: 'Produk tidak ditemukan' });
    }

    const nextStatus = await withProductsWriteLock(async () => {
      const freshProducts = await readFresh('products.json');
      const freshProduct = freshProducts.find(p => p.id === req.params.id);
      if (!freshProduct) return null;
      freshProduct.status = freshProduct.status === 'active' ? 'inactive' : 'active';
      await writeDB('products.json', freshProducts);
      return freshProduct.status;
    });
    if (!nextStatus) return res.json({ success: false, message: 'Produk tidak ditemukan' });
    res.json({ success: true, message: 'Status produk berhasil diubah', status: nextStatus });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/product/add-keys/:id', requireAdmin, async (req, res) => {
  try {
    const result = await withPersistentProductStockLock(req.params.id, async () => {
      const { keys } = req.body;
      const products = await readFresh('products.json');
      const product = products.find(p => p.id === req.params.id);
      if (!product) throw new Error('Produk tidak ditemukan');
      const newKeys = normalizeUsableLocalKeys(String(keys || '').split('\n'));
      const before = new Set(normalizeUsableLocalKeys(product.keys));
      const uniqueNew = newKeys.filter(k => !before.has(k));
      product.keys = normalizeUsableLocalKeys([...(product.keys || []), ...uniqueNew]);
      await writeDB('products.json', products);
      return { added: uniqueNew.length, keyCount: product.keys.length };
    });
    res.json({ success: true, message: `${result.added} key berhasil ditambahkan`, keyCount: result.keyCount });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/settings/update', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const { siteName, gamePanelName, about, marqueeText, whatsapp, telegram, email, downloadUrl, waChannel, adminUsername, categories, categoryLabels, logoUrl, logoTextUrl, fonnteToken, buyerGroupName, buyerGroupUrl, resellerGroupName, resellerGroupUrl, siteUrl, seoKeywords, paymentMethods } = req.body;

    if (siteName)      settings.siteName      = siteName;
    if (gamePanelName) settings.gamePanelName = gamePanelName;
    if (about !== undefined) settings.about   = about;
    if (marqueeText)   settings.marqueeText   = marqueeText;
    if (adminUsername) settings.adminUsername = adminUsername;
    if (logoUrl !== undefined) settings.logoUrl = logoUrl;
    if (logoTextUrl !== undefined) settings.logoTextUrl = logoTextUrl.trim();
    if (fonnteToken !== undefined) settings.fonnteToken = fonnteToken;
    if (buyerGroupName !== undefined) settings.buyerGroupName = buyerGroupName.trim();
    if (buyerGroupUrl !== undefined) settings.buyerGroupUrl = buyerGroupUrl.trim();
    if (resellerGroupName !== undefined) settings.resellerGroupName = resellerGroupName.trim();
    if (resellerGroupUrl !== undefined) settings.resellerGroupUrl = resellerGroupUrl.trim();
    // SEO (diminta client 22 Agu 2026): domain kanonik & keyword target,
    // dipakai di <link rel="canonical">, Open Graph, sitemap.xml, dll.
    if (siteUrl !== undefined) settings.siteUrl = siteUrl.trim().replace(/\/$/, '');
    if (seoKeywords !== undefined) settings.seoKeywords = seoKeywords.trim();
    // Logo metode pembayaran di footer (diminta client 22 Agu 2026) --
    // dikirim sebagai JSON string dari textarea/hidden-input, di-parse
    // dan divalidasi minimal (harus array, tiap entry harus punya logoUrl
    // yang bukan javascript:/data: URL berbahaya).
    if (paymentMethods !== undefined) {
      try {
        const parsed = JSON.parse(paymentMethods);
        if (Array.isArray(parsed)) {
          settings.paymentMethods = parsed.filter(pm => pm && typeof pm.logoUrl === 'string' && isValidImageUrl(pm.logoUrl)).map(pm => ({
            name: (pm.name || '').trim().slice(0, 50),
            logoUrl: pm.logoUrl.trim()
          }));
        }
      } catch { /* JSON tidak valid, diabaikan -- settings.paymentMethods lama dipertahankan */ }
    }

    settings.contact = settings.contact || {};
    if (whatsapp !== undefined) settings.contact.whatsapp = whatsapp;
    if (telegram !== undefined) settings.contact.telegram = telegram;
    if (email    !== undefined) settings.contact.email    = email;
    if (downloadUrl !== undefined) settings.contact.downloadUrl = downloadUrl.trim();
    if (waChannel !== undefined) settings.contact.waChannel = waChannel.trim();

    // Handle categories update from JSON string or array
    if (categories) {
      try {
        settings.categories = JSON.parse(categories);
      } catch(e) {
        if (Array.isArray(categories)) settings.categories = categories;
      }
    }
    if (categoryLabels) {
      try {
        settings.categoryLabels = JSON.parse(categoryLabels);
      } catch(e) {
        if (typeof categoryLabels === 'object') settings.categoryLabels = categoryLabels;
      }
    }

    await writeDB('settings.json', settings);
    res.json({ success: true, message: 'Pengaturan berhasil diupdate' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/settings/pakasir', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const { apiKey, project, mode, apiBaseUrl, qrisMode } = req.body;

    settings.pakasir = {
      apiKey: apiKey !== undefined ? apiKey : (settings.pakasir?.apiKey || ''),
      project: project !== undefined ? project : (settings.pakasir?.project || ''),
      mode: mode || settings.pakasir?.mode || 'production',
      apiBaseUrl: apiBaseUrl !== undefined ? apiBaseUrl : (settings.pakasir?.apiBaseUrl || 'api.pakasir.com')
    };
    settings.apiGateway = 'pakasir';

    if (qrisMode) settings.qrisMode = qrisMode;

    await writeDB('settings.json', settings);

    res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// ── GensPay Settings ──
// 📖 Dokumentasi Integrasi: https://genspay.my.id/docs (Swagger API)
// Base URL API: https://genspay.my.id/api/v1
app.post('/admin/settings/genspay', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const { apiKey, baseUrl, qrisMode } = req.body;

    settings.genspay = {
      apiKey: apiKey !== undefined ? apiKey : (settings.genspay?.apiKey || ''),
      baseUrl: baseUrl !== undefined ? baseUrl : (settings.genspay?.baseUrl || 'https://genspay.my.id/api/v1')
    };
    settings.apiGateway = 'genspay';

    if (qrisMode) settings.qrisMode = qrisMode;

    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// ── DripStore Settings (supplier stok key, BUKAN payment gateway) ──
app.post('/admin/settings/dripstore', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const { apiToken, baseUrl, fulfillmentMode, balanceGuardEnabled, autoRestockEnabled, lowStockThreshold, restockQty } = req.body;
    const savedMode = ['live','local','hybrid'].includes(fulfillmentMode) ? fulfillmentMode : (settings.dripstore?.fulfillmentMode || 'live');
    const requestedAutoRestock = autoRestockEnabled === 'on' || autoRestockEnabled === true;
    settings.dripstore = {
      apiToken: apiToken !== undefined ? apiToken.trim() : (settings.dripstore?.apiToken || ''),
      baseUrl: baseUrl !== undefined ? baseUrl.trim() : (settings.dripstore?.baseUrl || 'https://dripclientstore.shop/api/v1'),
      fulfillmentMode: savedMode,
      balanceGuardEnabled: balanceGuardEnabled === undefined ? (settings.dripstore?.balanceGuardEnabled !== false) : (balanceGuardEnabled === 'on' || balanceGuardEnabled === true),
      // Auto-restock hanya masuk akal di HYBRID karena LIVE sudah JIT provider
      // dan LOCAL tidak memakai provider. Mode lain selalu dipaksa OFF.
      autoRestockEnabled: savedMode === 'hybrid' ? requestedAutoRestock : false,
      lowStockThreshold: Number.isFinite(parseInt(lowStockThreshold, 10)) ? Math.max(0, parseInt(lowStockThreshold, 10)) : (settings.dripstore?.lowStockThreshold ?? 3),
      restockQty: Number.isFinite(parseInt(restockQty, 10)) && parseInt(restockQty, 10) > 0 ? parseInt(restockQty, 10) : (settings.dripstore?.restockQty ?? 10),
    };
    await writeDB('settings.json', settings);
    // Token/base URL provider berubah => snapshot provider lama harus dibuang.
    _invalidateDripstoreSnapshot({ full: true });

    // Saat Auto-Restock diaktifkan + token tersedia, sinkronkan
    // product -> variant DripStore. Stok rendah hanya membuat proposal pending.
    // Pengaturan provider tetap tersimpan walaupun API mapping sedang error.
    let autoMap = null;
    if (settings.dripstore.apiToken && settings.dripstore.autoRestockEnabled) {
      try {
        autoMap = await autoMapDripstoreProducts({ restockLowStock: false });
      } catch (e) {
        autoMap = { warning: e.message };
      }
    }
    res.json({ success: true, autoMap });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// Sinkronkan semua produk AGHA NL ke variant DripStore berdasarkan nama + durasi.
// Endpoint ini juga bisa dipanggil manual dari Settings kapan saja.
app.post('/admin/dripstore/auto-map', requireAdmin, async (req, res) => {
  try {
    // Mapping sengaja dipisah dari generate key agar request ini cepat dan aman
    // untuk Vercel/serverless. Restock dilakukan lewat /restock-one di bawah.
    const result = await autoMapDripstoreProducts({ restockLowStock: false });
    res.json({ success: true, ...result });
  } catch (e) {
    console.error('[dripstore auto-map]', e);
    res.json({ success: false, message: e.message });
  }
});

// Generate key untuk SATU target saja. Ini mencegah timeout kalau toko punya
// banyak produk/durasi yang stoknya sama-sama di bawah threshold.
app.post('/admin/dripstore/restock-one', requireAdmin, async (req, res) => {
  try {
    const result = await restockOneDripstoreTarget(req.body || {});
    res.json({ success: true, ...result });
  } catch (e) {
    console.error('[dripstore restock-one]', e);
    res.json({ success: false, message: e.message });
  }
});

// Status circuit breaker provider (buat admin lihat apakah lagi kena rate limit)
app.get('/admin/dripstore/status', requireAdmin, (req, res) => {
  res.set('Cache-Control', 'no-store, max-age=0');
  const brk = dripstoreBreakerState();
  res.json({ success: true, breaker: brk, total429: _dsBreaker.hits429, microCacheEntries: _dsMicroCache.size, failCooldownSec: Math.max(0, Math.ceil((_dripstoreFailUntil - Date.now()) / 1000)) });
});

// ══════════════════════════════════════════════════════════════════
// LIVE LOG VIEWER -- endpoint + persistensi (lihat komentar di bagian atas file)
// ══════════════════════════════════════════════════════════════════
const LOG_FILE = 'app_logs.json';
let _logPersistBase = null;   // riwayat tersimpan (dimuat SEKALI per instance)
let _logFlushing = false;

function _logDedupe(list) {
  const seen = new Set(); const out = [];
  for (const e of list) {
    if (!e || typeof e !== 'object') continue;
    const k = e.inst + ':' + e.id + ':' + e.t;
    if (seen.has(k)) continue; seen.add(k); out.push(e);
  }
  return out.sort((a, b) => a.t - b.t);
}

// Flush: hanya warn/error, dibatasi 1x/60 dtk, dan hanya jika ada entri penting baru.
// Baca DB cuma SEKALI per instance (untuk menggabung riwayat sebelum cold start),
// setelah itu murni tulis -> tidak menambah egress Supabase.
_logFlushImpl = async function () {
  if (_logFlushing) return;
  if (!_logDirtyImportant) return;
  _logFlushing = true; _logLastFlush = Date.now(); _logDirtyImportant = 0;
  try {
    if (_logPersistBase === null) {
      let prev = [];
      try { prev = await Promise.race([db.readFresh(LOG_FILE), new Promise(r => setTimeout(() => r([]), 2500))]); } catch (_) {}
      _logPersistBase = Array.isArray(prev) ? prev : [];
    }
    const mine = _logRing.filter(e => e.lv !== 'info').map(e => ({ ...e, msg: String(e.msg).slice(0, 500) }));
    _logPersistBase = _logDedupe(_logPersistBase.concat(mine)).slice(-LOG_PERSIST_MAX);
    await db.writeDB(LOG_FILE, _logPersistBase);
  } catch (_) {
    // jangan pernah console.* di sini (bisa memicu flush berulang)
  } finally { _logFlushing = false; }
};

function _logStatus(settings) {
  const brk = dripstoreBreakerState();
  let snap = { fresh: false, ageSec: null, lastGoodAgeSec: null, hasCatalog: false };
  try {
    if (_dripstoreCatalogCache) {
      snap.fresh = (Date.now() - _dripstoreCatalogCacheAt) < DRIPSTORE_CATALOG_CACHE_TTL;
      snap.ageSec = Math.round((Date.now() - _dripstoreCatalogCacheAt) / 1000);
    }
    const lg = _dsLastGood(settings);
    if (lg && lg.products) { snap.hasCatalog = true; snap.lastGoodAgeSec = Math.round((Date.now() - Number(lg.productsAt || 0)) / 1000); }
  } catch (_) {}
  const topCalls = Object.entries(_dsStats.byWho).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const topReq = Array.from(_reqCounts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 8);
  return {
    now: Date.now(), boot: _logBoot, inst: _logInstance, buffered: _logRing.length,
    breaker: { open: brk.open, retryAfterSec: brk.retryAfterSec, reason: brk.reason, total429: _dsBreaker.hits429 },
    failCooldownSec: Math.max(0, Math.ceil((_dripstoreFailUntil - Date.now()) / 1000)),
    snapshot: snap,
    provider: {
      sinceSec: Math.round((Date.now() - _dsStats.since) / 1000),
      calls: _dsStats.calls, ok: _dsStats.ok, rateLimited: _dsStats.rateLimited, err: _dsStats.err,
      last429AgeSec: _dsStats.last429At ? Math.round((Date.now() - _dsStats.last429At) / 1000) : null,
      byTrigger: topCalls, microCache: _dsMicroCache.size
    },
    gate: { enabled: SITE_CHALLENGE_ON, redirected: _gateStats.redirected, passed: _gateStats.passed, rejected: _gateStats.rejected },
    topRequests: topReq,
    env: {
      NODE_ENV: process.env.NODE_ENV || '-', vercel: !!process.env.VERCEL,
      SITE_CHALLENGE_set: String(process.env.SITE_CHALLENGE || '') || '-',
      turnstileKeys: !!(process.env.TURNSTILE_SITE_KEY && process.env.TURNSTILE_SECRET_KEY),
      CLOUDFLARE_PROXY: CLOUDFLARE_PROXY,
      supabase: !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY),
      sessionSecret: !!process.env.SESSION_SECRET,
      dripstoreToken: !!settings?.dripstore?.apiToken,
      fulfillmentMode: settings?.dripstore?.fulfillmentMode || 'live'
    }
  };
}

app.get('/admin/logs', requireAdmin, (req, res) => {
  res.set('Cache-Control', 'no-store, max-age=0');
  res.render('pages/admin-logs', { layout: false });
});

app.get('/admin/logs/data', requireAdmin, async (req, res) => {
  res.set('Cache-Control', 'no-store, max-age=0');
  const since = Math.max(0, parseInt(req.query.since, 10) || 0);
  const out = { success: true, entries: _logRing.filter(e => e.id > since), lastId: _logSeq };
  if (req.query.persisted === '1') {
    let saved = [];
    try { saved = await Promise.race([db.readFresh(LOG_FILE), new Promise(r => setTimeout(() => r(readDB(LOG_FILE)), 2500))]); } catch (_) { saved = readDB(LOG_FILE); }
    out.persisted = Array.isArray(saved) ? saved.slice(-LOG_PERSIST_MAX) : [];
  }
  out.status = _logStatus(readDB('settings.json'));
  res.json(out);
});

app.post('/admin/logs/clear', requireAdmin, async (req, res) => {
  res.set('Cache-Control', 'no-store, max-age=0');
  // Anti-CSRF: wajib JSON (browser lintas-situs tidak bisa kirim ini tanpa preflight)
  // dan Origin, kalau ada, harus sama dengan host kita.
  const origin = req.headers.origin;
  if (!req.is('application/json') || (origin && (() => { try { return new URL(origin).host !== req.get('host'); } catch { return true; } })())) {
    return res.status(403).json({ success: false, message: 'Ditolak' });
  }
  _logRing.length = 0; _logPersistBase = []; _logDirtyImportant = 0;
  try { await db.writeDB(LOG_FILE, []); } catch (_) {}
  pushLog('info', '[admin] log dibersihkan', { cat: 'app' });
  res.json({ success: true });
});

// Cek saldo DripStore langsung dari admin (buat preview sebelum restock manual)
app.get('/admin/dripstore/balance', requireAdmin, async (req, res) => {
  res.set('Cache-Control', 'no-store, max-age=0');
  try {
    const settings = await readFresh('settings.json');
    const resp = await dripstoreCall(settings, 'balance.php'); // GET: sudah auto-retry 1x utk error sementara
    res.json({ success: true, data: resp.data || resp });
  } catch (e) {
    // Provider gagal sesaat: tampilkan saldo terakhir yang berhasil dibaca
    // (ditandai jelas sebagai data lama) daripada error kosong.
    const settings = await readFresh('settings.json').catch(() => ({}));
    const last = getLastGoodDripstoreSnapshot(settings);
    if (last && last.balance !== null) {
      return res.json({ success: true, stale: true, ageSeconds: Math.round((last.ageMs || 0) / 1000), data: { balance: last.balance }, message: 'Provider tidak merespons: ini saldo terakhir yang berhasil dibaca (' + e.message + ')' });
    }
    res.json({ success: false, message: e.message });
  }
});

// FITUR BARU (audit 20 Sep 2026): dibuat karena berulang kali nama produk
// yang diketik manual di AGHA NL beda dengan nama ASLI di sistem DripStore
// (typo, urutan kata, kata tambahan seperti "VERSION"), dan sejauh ini
// satu-satunya cara mendeteksi itu adalah tebak-tebakan lewat Cek Kemampuan
// Saldo. Endpoint ini membongkar katalog mentah DripStore (products.php)
// dan mengembalikan nama produk + nama variant + ID variant PERSIS seperti
// tersimpan di sistem mereka, supaya admin bisa cari & kasih tau Claude
// nama yang benar untuk didaftarkan ke DRIPSTORE_PRODUCT_ALIASES.
app.get('/admin/dripstore/catalog-search', requireAdmin, async (req, res) => {
  try {
    const q = String(req.query.q || '').trim().toLowerCase();
    const settings = await readFresh('settings.json');
    const snapshot = await getDripstoreCatalogSnapshot(settings, { maxWaitMs: 9000 });
    if (!snapshot.products) {
      return res.json({ success: false, message: 'Katalog DripStore belum bisa dibaca (cek token API di Settings).' });
    }
    const items = _dsExtractProductItems(snapshot.products);
    const filtered = q ? items.filter(it => (it.productName + ' ' + it.variantName).toLowerCase().includes(q)) : items;
    // Group per productName biar gampang dibaca, bukan satu baris per variant durasi.
    const grouped = {};
    for (const it of filtered) {
      const key = it.productName || '(tanpa nama)';
      if (!grouped[key]) grouped[key] = [];
      grouped[key].push({ variantId: it.variantId, variantName: it.variantName, days: it.days, unit: it.unit });
    }
    res.json({ success: true, count: filtered.length, products: grouped });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Gagal cari katalog: ' + error.message });
  }
});


app.get('/admin/dripstore/availability', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    // Admin butuh angka akurat: paksa refresh dan tunggu lebih lama (bukan cache).
    const snapshot = await getDripstoreCatalogSnapshot(settings, { force: true, maxWaitMs: 9000 });
    if (!snapshot?.products || snapshot.balance == null) {
      return res.json({ success: false, message: 'Provider DripStore tidak merespons (timeout/error). Coba klik lagi beberapa detik lagi; tidak ada data yang diubah.' });
    }
    const balance = snapshot?.balance ?? null;
    const products = await readFresh('products.json');
    const rows = [];
    for (const raw of products) {
      const product = normalizeProductBuyOptions(raw);
      for (const opt of (product.pricingOptions || [])) {
        const resolved = findDripstoreVariantForOption(snapshot, product.name, opt);
        const localStock = getLocalOptionStock(product, opt);
        if (!resolved) {
          rows.push({ productId: product.id, productName: product.name, days: Number(opt.days), unit: opt.unit || 'd', variantId: null, cost: null, localStock, providerCapacity: null, totalStock: localStock, available: null });
          continue;
        }
        const cost = _dsFindVariantCost(snapshot.products, resolved.variantId);
        const balanceCents = _dsMoneyCents(balance);
        const costCents = _dsMoneyCents(cost);
        const capacity = balanceCents != null && costCents != null && costCents > 0 ? Math.max(0, Math.floor(balanceCents / costCents)) : null;
        rows.push({ productId: product.id, productName: product.name, days: Number(opt.days), unit: opt.unit || 'd', variantId: String(resolved.variantId), cost, localStock, providerCapacity: capacity, totalStock: localStock + (capacity || 0), available: capacity == null ? null : capacity > 0 });
      }
    }
    const counts = {
      available: rows.filter(x => x.available === true).length,
      unavailable: rows.filter(x => x.available === false).length,
      unknown: rows.filter(x => x.available === null).length
    };
    res.json({ success: true, balance, stale: !!snapshot.stale, rows, ...counts });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// Restock MANUAL 1 baris harga tertentu dari DripStore (tombol di admin-product-edit).
// Beda dari auto-restock: ini SELALU jalan kalau dipencet, gak peduli threshold stok.
app.post('/admin/product/:id/restock-dripstore', requireAdmin, async (req, res) => {
  try {
    const { days, unit, quantity } = req.body || {};
    const request = await createDripstoreRestockRequest({
      productId: req.params.id,
      days: Number(days),
      unit: unit === 'h' ? 'h' : 'd',
      quantity: Number(quantity),
      source: 'manual'
    });
    res.json({ success: true, request, requiresApproval: true });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// Daftar proposal restock. Tidak ada purchase di endpoint ini.
app.get('/admin/dripstore/restock-requests', requireAdmin, async (req, res) => {
  try {
    const all = await readFresh('dripstore_restock_requests.json').catch(() => []);
    const status = String(req.query.status || 'pending');
    const requests = status === 'all' ? all : all.filter(r => r.status === status);
    res.json({ success: true, requests: requests.slice(0, 100) });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// Purchase DripStore HANYA boleh terjadi lewat endpoint approval ini.
app.post('/admin/dripstore/restock-requests/:id/approve', requireAdmin, async (req, res) => {
  try {
    const adminName = req.session?.username || req.session?.userId || 'admin';
    const request = await approveDripstoreRestockRequest(String(req.params.id), adminName);
    res.json({ success: true, request });
  } catch (e) {
    console.error('[dripstore restock approve]', e);
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/dripstore/restock-requests/:id/reject', requireAdmin, async (req, res) => {
  try {
    const requests = await readFresh('dripstore_restock_requests.json').catch(() => []);
    const idx = requests.findIndex(r => r.id === String(req.params.id));
    if (idx === -1) return res.json({ success: false, message: 'Restock request tidak ditemukan' });
    if (requests[idx].status !== 'pending') return res.json({ success: false, message: `Request sudah ${requests[idx].status}` });
    requests[idx].status = 'rejected';
    requests[idx].rejectedAt = new Date().toISOString();
    requests[idx].rejectedBy = req.session?.username || req.session?.userId || 'admin';
    await writeDB('dripstore_restock_requests.json', requests.slice(0, 500));
    res.json({ success: true, request: requests[idx] });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/qris/test', requireAdmin, async (req, res) => {
  try {
    // gateway: 'pakasir' (default) atau 'genspay' — menentukan gateway mana yang dites
    const { apiKey, project, apiBaseUrl, gateway, baseUrl } = req.body;
    try {
      if (gateway === 'genspay') {
        const testSettings = { apiGateway: 'genspay', genspay: { apiKey, baseUrl: baseUrl || 'https://genspay.my.id/api/v1' } };
        await createQRISPayment('test-' + Date.now(), 1000, testSettings);
      } else {
        const hostname = apiBaseUrl || 'api.pakasir.com';
        const testSettings = { apiGateway: 'pakasir', pakasir: { apiKey, project, apiBaseUrl: hostname } };
        await createQRISPayment('test-' + Date.now(), 1000, testSettings);
      }
      res.json({ success: true });
    } catch (e) {
      res.json({ success: false, message: e.message });
    }
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/settings/password', requireAdmin, async (req, res) => {
  try {
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
      return res.json({ success: false, message: 'Password minimal 6 karakter' });
    }

    const settings = await readFresh('settings.json');
    settings.adminPassword = await bcrypt.hash(newPassword, 12);

    await writeDB('settings.json', settings);
    res.json({ success: true, message: 'Password admin berhasil diubah' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/settings/popular-products', requireAdmin, async (req, res) => {
  try {
    const { popularProductIds } = req.body;
    const settings = await readFresh('settings.json');
    settings.popularProductIds = Array.isArray(popularProductIds) ? popularProductIds : [];
    await writeDB('settings.json', settings);
    res.json({ success: true, popularProductIds: settings.popularProductIds });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/settings/reseller', requireAdmin, async (req, res) => {
  try {
    const { resellerEnabled, resellerPrice, resellerDiscount, resellerNote } = req.body;
    const settings = await readFresh('settings.json');
    settings.resellerEnabled = resellerEnabled === 'true' || resellerEnabled === true;
    if (resellerPrice !== undefined && resellerPrice !== '') {
      const price = parseInt(resellerPrice);
      if (isNaN(price) || price < 0) return res.json({ success: false, message: 'Harga reseller tidak valid' });
      settings.resellerPrice = price;
    }
    if (resellerDiscount !== undefined && resellerDiscount !== '') {
      const discount = parseInt(resellerDiscount);
      if (isNaN(discount) || discount < 0 || discount > 100) return res.json({ success: false, message: 'Diskon harus antara 0-100%' });
      settings.resellerDiscount = discount;
    }
    if (resellerNote !== undefined) settings.resellerNote = resellerNote;
    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// Minimal top up saldo — dipisah per role biar member biasa & reseller VIP
// bisa diatur beda (member biasa umumnya lebih kecil daripada reseller).
app.post('/admin/settings/wallet', requireAdmin, async (req, res) => {
  try {
    const { memberMinDeposit, resellerMinDeposit } = req.body;
    const settings = await readFresh('settings.json');
    if (memberMinDeposit !== undefined && memberMinDeposit !== '') {
      const minDep = parseInt(memberMinDeposit);
      if (isNaN(minDep) || minDep < 0) return res.json({ success: false, message: 'Minimal top up member tidak valid' });
      settings.memberMinDeposit = minDep;
    }
    if (resellerMinDeposit !== undefined && resellerMinDeposit !== '') {
      const minDep = parseInt(resellerMinDeposit);
      if (isNaN(minDep) || minDep < 0) return res.json({ success: false, message: 'Minimal top up reseller tidak valid' });
      settings.resellerMinDeposit = minDep;
    }
    await writeDB('settings.json', settings);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/user/toggle-reseller/:id', requireAdmin, async (req, res) => {
  try {
    const users = await readFresh('users.json');
    const user = users.find(u => u.id === req.params.id);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });
    user.is_reseller = !user.is_reseller;
    user.role = user.is_reseller ? 'reseller' : 'user';
    if (user.is_reseller) {
      user.reseller_since = user.reseller_since || new Date().toISOString();
      user.reseller_code = user.reseller_code || ('RSL-' + user.username.toUpperCase().slice(0, 4) + '-' + crypto.randomBytes(2).toString('hex').toUpperCase());
    }
    await writeDB('users.json', users);
    res.json({ success: true, is_reseller: user.is_reseller });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// Admin koreksi/tambah saldo wallet user secara manual (mis. transfer di luar QRIS)
app.post('/admin/user/adjust-balance/:id', requireAdmin, async (req, res) => {
  try {
    // FIX (bug 14 Sep 2026, sama kayak harga produk): bersihin karakter
    // non-digit dulu biar "50.000" tidak kebaca cuma 50. Nominal koreksi
    // saldo tetap boleh negatif (potong saldo), jadi tanda minus dipertahankan.
    const rawAmount = String(req.body.amount||'').trim();
    const isNegative = rawAmount.startsWith('-');
    const digitsOnly = rawAmount.replace(/[^\d]/g,'');
    const amount = digitsOnly === '' ? NaN : parseInt(digitsOnly, 10) * (isNegative ? -1 : 1);
    if (isNaN(amount) || amount === 0) return res.json({ success: false, message: 'Nominal tidak valid' });

    const users = await readFresh('users.json');
    const user = users.find(u => u.id === req.params.id);
    if (!user) return res.json({ success: false, message: 'User tidak ditemukan' });

    const newBalance = (user.balance || 0) + amount;
    if (newBalance < 0) return res.json({ success: false, message: 'Saldo tidak boleh minus' });
    user.balance = newBalance;
    await writeDB('users.json', users);

    const transactions = await readFresh('transactions.json');
    transactions.push({
      id: uuidv4(), orderId: `ADJ-${Date.now()}`, code: generateOrderCode(),
      userId: user.id, type: 'adjustment', productName: amount > 0 ? 'Penambahan Saldo (Admin)' : 'Pengurangan Saldo (Admin)',
      amount, price: Math.abs(amount), customerName: user.username, wa: user.wa,
      status: 'done', paidAt: new Date().toISOString(),
      createdAt: new Date().toISOString(), time: formatDate(), confirmedBy: 'admin'
    });
    await writeDB('transactions.json', transactions);

    res.json({ success: true, balance: user.balance });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});
app.post('/admin/transaction/confirm/:id', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const result = await finalizeOrder(req.params.id, settings);
    if (result.status === 'not_found') return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
    if (result.status === 'already_done') return res.json({ success: false, message: 'Transaksi sudah selesai' });
    if (result.status === 'already_processing') return res.json({ success: false, message: 'Transaksi sedang diproses di request lain. Tunggu sebentar.' });
    if (result.status !== 'done') return res.json({ success: false, message: 'Transaksi belum dapat diproses' });

    return res.json({
      success: true,
      type: result.type,
      key: result.key || null,
      code: result.code,
      outOfStock: !!result.outOfStock,
      balance: result.balance
    });
  } catch (e) {
    console.error('[admin/transaction/confirm]', e.message);
    return res.json({ success: false, message: e.message });
  }
});

// ══════════════════════════════════════════════════════════════════
// HALAMAN INFORMASI (Cara Beli, FAQ, Syarat & Ketentuan)
// diminta client 21 Agu 2026 -- sebelumnya semua link footer "Informasi"
// (Cara Beli/FAQ/Syarat) asal redirect ke /invoice, tidak jelas fungsinya.
// ══════════════════════════════════════════════════════════════════
app.get('/informasi', (req, res) => {
  const section = ['cara-beli', 'faq', 'syarat'].includes(req.query.tab) ? req.query.tab : 'cara-beli';
  res.render('pages/informasi', { activeTab: section });
});

// Leaderboard route
app.get('/leaderboard', (req, res) => {
  const settings = readDB('settings.json');

  // FIX (diminta client 26 Agu 2026): leaderboard publik sekarang HANYA
  // data transaksi asli -- fakeLeaderboard (entri buatan admin) tidak lagi
  // digabung ke sini supaya "Top Pembeli" selalu sesuai data pembeli real.
  // PERFORMANCE: pakai computeLeaderboard() yang efisien (Map lookup, bukan
  // .find() berulang) dan sudah di-cache 30 detik.
  const combinedLeaderboard = computeLeaderboard().map(e => ({
    userId: e.userId,
    username: e.username === 'User' ? 'Unknown' : e.username,
    totalTransactions: e.totalTransactions,
    totalSpent: e.totalSpent,
    photo: e.photo
  }));

  // Add rank
  combinedLeaderboard.forEach((item, index) => {
    item.rank = index + 1;
  });

  const user = getSessionUser(req);

  res.render('pages/leaderboard', {
    leaderboard: combinedLeaderboard,
    settings,
    user
  });
});

// API endpoints
app.get('/api/products', async (req, res) => {
  res.set('Cache-Control', 'public, max-age=60, stale-while-revalidate=300');
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan. Coba lagi nanti.' });
  // FIX (egress): endpoint publik paling sering dipanggil frontend -- ini
  // penyumbang terbesar cached egress karena dulu readFresh() menarik ulang
  // seluruh blob products dari Supabase di SETIAP request. readSmart pakai
  // cache ber-TTL sehingga data yang sama tidak ditransfer berulang.
  const products = (await readSmart('products.json'))
    .filter(p => p.status === 'active')
    // SECURITY: jangan kirim keys ke publik — keys hanya dikirim setelah pembayaran sukses.
    // stockCount di endpoint pencarian hanya merepresentasikan stok lokal yang
    // benar-benar dapat dipakai; provider stock dihitung di halaman katalog
    // /buy secara terpisah agar endpoint ini tidak memukul API supplier per request.
    .map(p => {
      const normalized = normalizeProductBuyOptions(p);
      const optionStocks = (normalized.pricingOptions || []).map(o => getLocalOptionStock(normalized, o));
      const localStock = optionStocks.length ? Math.max(...optionStocks, 0) : getLocalOptionStock(normalized, { days: null, unit: 'd' });
      const { keys, ...safe } = normalized;
      return { ...safe, stockCount: localStock };
    });
  res.json(products);
});

// ── Helper: validasi & hitung diskon voucher ──
const validateVoucher = async (code, price, userId) => {
  if (!code) return { valid: false, error: 'Kode kosong' };
  const vouchers = await readFresh('vouchers.json');
  const v = vouchers.find(v => v.code.toUpperCase() === code.trim().toUpperCase());
  if (!v) return { valid: false, error: 'Kode voucher tidak ditemukan' };
  if (!v.active) return { valid: false, error: 'Voucher tidak aktif' };
  if (v.expiresAt && new Date(v.expiresAt) < new Date()) return { valid: false, error: 'Voucher sudah kadaluarsa' };
  if (v.maxUses > 0 && v.usedCount >= v.maxUses) return { valid: false, error: 'Voucher sudah habis digunakan' };
  if (v.minPurchase > 0 && price < v.minPurchase) return { valid: false, error: `Minimal pembelian Rp ${v.minPurchase.toLocaleString('id-ID')}` };
  // Cegah reseller double-discount: kalau voucher punya flag excludeReseller,
  // tolak pemakaian oleh akun reseller (mereka sudah dapat diskon harga reseller).
  if (v.excludeReseller && userId) {
    const users = readDB('users.json');
    const u = users.find(u => u.id === userId);
    if (u?.is_reseller) return { valid: false, error: 'Voucher ini tidak berlaku untuk akun Reseller' };
  }
  if (v.perUserLimit > 0 && userId) {
    const userUses = (v.usages || []).filter(u => u.userId === userId).length;
    if (userUses >= v.perUserLimit) return { valid: false, error: 'Kamu sudah pernah memakai voucher ini' };
  }
  const discount = v.type === 'percent'
    ? Math.round(price * v.value / 100)
    : Math.min(v.value, price);
  const finalPrice = Math.max(price - discount, 0);
  return { valid: true, voucher: v, discount, finalPrice };
};

app.get('/api/stats', async (req, res) => {
  res.set('Cache-Control', 'public, max-age=60, stale-while-revalidate=300');
  const products = await readSmart('products.json');
  const testimonials = await readSmart('testimonials.json');
  const users = await readSmart('users.json');
  const active = products.filter(p => p.status === 'active');
  const totalSold = products.reduce((s, p) => s + (p.sold || 0), 0);
  const avgRating = testimonials.length
    ? (testimonials.reduce((s, t) => s + (t.rating || 0), 0) / testimonials.length).toFixed(1)
    : '0.0';
  res.json({
    totalSold,
    totalActiveProducts: active.length,
    totalUsers: users.length,
    avgRating: parseFloat(avgRating)
  });
});

// Cek voucher (user)
app.post('/api/voucher/check', requireAuth, async (req, res) => {
  // FIX KEAMANAN (audit 22 Agu 2026): endpoint ini sebelumnya TIDAK ada
  // rate limiting -- bisa disalahgunakan buat brute-force menebak kode
  // voucher yang valid (terutama kalau formatnya pendek/predictable).
  // Dibatasi per user (bukan per IP) karena endpoint ini requireAuth.
  if (!checkPaymentRateLimit(req.session.userId)) {
    return res.json({ valid: false, error: 'Terlalu banyak percobaan, coba lagi sebentar.' });
  }
  const { code, price } = req.body;
  if (!code || !price) return res.json({ valid: false, error: 'Data tidak lengkap' });
  const result = await validateVoucher(code, parseInt(price), req.session.userId);
  if (!result.valid) return res.json({ valid: false, error: result.error });
  res.json({
    valid: true,
    code: result.voucher.code,
    type: result.voucher.type,
    value: result.voucher.value,
    description: result.voucher.description || '',
    discount: result.discount,
    finalPrice: result.finalPrice
  });
});

app.get('/api/transactions', requireAdmin, (req, res) => {
  const transactions = readDB('transactions.json');
  res.json(transactions);
});

app.get('/api/testimonials', async (req, res) => {
  res.set('Cache-Control', 'public, max-age=60, stale-while-revalidate=300');
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan.' });
  const testimonials = await readSmart('testimonials.json');
  const users = await readSmart('users.json');
  const featured = req.query.featured === 'true';
  const verifiedOnly = req.query.verified === 'true';
  const productId = req.query.product;

  let filtered = testimonials;

  if (featured) {
    filtered = filtered.filter(t => t.featured && t.verified);
  } else if (verifiedOnly) {
    filtered = filtered.filter(t => t.verified);
  }

  if (productId) {
    filtered = filtered.filter(t => t.product === productId || t.productName === productId);
  }

  // Sort by date descending
  filtered.sort((a, b) => new Date(b.date) - new Date(a.date));

  // Attach user photo if available
  // PERFORMANCE: Map lookup dibangun sekali (O(1) per lookup), bukan
  // users.find() yang scan ulang seluruh array users untuk tiap testimonial.
  const userByUsername = buildUserLookupMaps(users).byUsername;
  filtered = filtered.map(t => {
    const u = userByUsername.get(t.username);
    return { ...t, photo: u?.photo || null };
  });

  // Pad with fake entries so page always looks alive
  const fakeTestimonials = [
    { id:'fake1', username:'Rizky F.',    name:'Rizky F.',    rating:5, text:'Mod FF-nya mantap, udah 3 bulan pakai dan aman-aman aja. Fitur lengkap dari ESP sampai fly hack. CS juga responsif banget!', product:'ff',         productName:'FREE FIRE MAX',      date:'2025-05-20', verified:true },
    { id:'fake2', username:'Andi S.',     name:'Andi S.',     rating:5, text:'ML mod-nya lengkap banget! Map hack, drone view, sampai skin all hero ada. Auto update jadi nggak perlu repot tiap update.', product:'ml',        productName:'MOBILE LEGENDS',    date:'2025-05-18', verified:true },
    { id:'fake3', username:'Dimas P.',    name:'Dimas P.',    rating:5, text:'Support fast response! Pas ada masalah langsung dibantu sampai beres. PUBG mod-nya juga smooth, nggak lag sama sekali.', product:'pubgm',     productName:'PUBG MOBILE',   date:'2025-05-15', verified:true },
    { id:'fake4', username:'farhan99',    name:'farhan',      rating:5, text:'Beli sertifikat anti-banned udah 2x dan alhamdulillah akun tetap aman. Worth it banget harganya segitu.', product:'sertifikat', productName:'SERTIFIKAT', date:'2025-05-10', verified:true },
    { id:'fake5', username:'gamer_mlbb',  name:'Wanda M.',    rating:4, text:'Produknya bagus, pengiriman key cepet banget. Cuma kadang agak lag di device lama tapi overall oke lah.', product:'ml',        productName:'MOBILE LEGENDS',    date:'2025-05-08', verified:true },
    { id:'fake6', username:'ACA XITERZ', name:'ACA',          rating:5, text:'Udah lama langganan di sini, belum pernah kecewa. Proses beli gampang, bayar QRIS langsung dapat key. Recommended!', product:'ff',       productName:'FREE FIRE MAX',      date:'2025-05-05', verified:true },
    { id:'fake7', username:'bintang_07',  name:'bintang',     rating:5, text:'Lifetime PUBGM worth it banget. Udah 6 bulan masih lancar jaya, fitur no recoil-nya mantul.', product:'pubgm',     productName:'PUBG MOBILE',   date:'2025-04-28', verified:true },
    { id:'fake8', username:'rizky_ff',    name:'Rizky',       rating:4, text:'Kalau FF mod-nya top. Pernah ada issue tapi langsung di-handle sama admin. Keep up the good work!', product:'ff',        productName:'FREE FIRE MAX',      date:'2025-04-20', verified:true },
    { id:'fake9', username:'keymaster',   name:'Kevin',       rating:5, text:'CODM mod anti-recoil smooth banget. Rank dari Silver langsung naik ke Platinum dalam seminggu haha.', product:'codm',     productName:'CODM',    date:'2025-04-15', verified:true },
    { id:'fake10',username:'abil',        name:'abil',        rating:5, text:'Ini toko mod menu terpercaya yang pernah aku coba. Transaksi aman, key langsung masuk, CS ramah.', product:'ff',        productName:'FREE FIRE MAX',      date:'2025-04-10', verified:true },
    { id:'fake11',username:'Hergi',       name:'Hergi',       rating:5, text:'Valorant ESP-nya akurat banget. Sudah 2 bulan pake dan belum ada masalah sama sekali. Pelayanan top!', product:'val',      productName:'VALORANT', date:'2025-04-05', verified:true },
    { id:'fake12',username:'rehan',       name:'rehan',       rating:5, text:'HOK mod-nya mantap, map hack dan skin unlock semua ada. Proses beli cepet dan key langsung terkirim.', product:'hok',     productName:'HOK',     date:'2025-03-28', verified:true },
    { id:'fake13',username:'Saell',       name:'Saell',       rating:5, text:'Beli Free Fire MAX bundle, prosesnya cepet banget! Cuma 2 menit key langsung masuk. Akun aman sampai sekarang.', product:'ff',         productName:'FREE FIRE MAX',      date:'2025-03-25', verified:true },
    { id:'fake14',username:'GamerKing99', name:'GamerKing99', rating:5, text:'MLBB mod-nya juara! Skin all hero gratis, map hack jalan mulus. Adminnya juga friendly, fast respon.', product:'ml',        productName:'MOBILE LEGENDS',    date:'2025-03-20', verified:true },
    { id:'fake15',username:'SkyyFire',    name:'SkyyFire',    rating:5, text:'PUBG mod smooth banget di HP kentang sekalipun. No lag, no crash. Harga juga affordable banget!', product:'pubgm',     productName:'PUBG MOBILE',   date:'2025-03-15', verified:true },
    { id:'fake16',username:'ShadowX',     name:'ShadowX',     rating:5, text:'Udah 4x beli di sini, selalu puas. Key original, legit, dan awet. Best store for mod menu!', product:'ff',        productName:'FREE FIRE MAX',      date:'2025-03-10', verified:true },
    { id:'fake17',username:'NightWolf',   name:'NightWolf',   rating:4, text:'PUBGM no recoil mantap, tapi kadang auto aim agak delay. Overall masih oke sih, worth the price.', product:'pubgm',     productName:'PUBG MOBILE',   date:'2025-03-05', verified:true },
    { id:'fake18',username:'LunarKing',   name:'LunarKing',   rating:5, text:'MLBB dron view works perfectly! Enemy location always visible. Rank naik terus dari season kemarin.', product:'ml',        productName:'MOBILE LEGENDS',    date:'2025-02-28', verified:true },
    { id:'fake19',username:'NeonVibes',   name:'NeonVibes',   rating:5, text:'FF aimbot-nya smooth, headshot mulus. UDAH 3 BULAN pakai dan belum pernah kena ban. Mantap!', product:'ff',        productName:'FREE FIRE MAX',      date:'2025-02-20', verified:true },
    { id:'fake20',username:'StormRider',  name:'StormRider',  rating:4, text:'Produk bagus, cuma pengiriman key agak lama pas weekend. Tapi overall puas, CS-nya ramah.', product:'pubgm',     productName:'PUBG MOBILE',   date:'2025-02-15', verified:true },
    { id:'fake21',username:'GhostByte',   name:'GhostByte',   rating:5, text:'FF wallhack jernih, bisa lihat musuh tembus dinding. Gameplay jadi lebih seru dan menang terus!', product:'ff',        productName:'FREE FIRE MAX',      date:'2025-02-10', verified:true },
    { id:'fake22',username:'CyberRush',   name:'CyberRush',   rating:5, text:'MLBB skin all hero unlocked, effect skill keliatan keren banget! Teman-teman pada kaget.', product:'ml',        productName:'MOBILE LEGENDS',    date:'2025-02-05', verified:true },
    { id:'fake23',username:'AlphaGod',    name:'AlphaGod',    rating:5, text:'PUBG mod versi terbaru udah support map Livik juga. Smooth, nggak ada glitch. Top banget!', product:'pubgm',     productName:'PUBG MOBILE',   date:'2025-01-28', verified:true },
    { id:'fake24',username:'IronPhoenix', name:'IronPhoenix', rating:5, text:'FF mod ini yang paling stabil dari semua yang pernah aku coba. Langganan bulanan, worth it!', product:'ff',        productName:'FREE FIRE MAX',      date:'2025-01-20', verified:true },
    { id:'fake25',username:'TurboAce',    name:'TurboAce',    rating:4, text:'MLBB drone view bagus, tapi agak boros battery. Overall recommend buat yang mau rank push.', product:'ml',        productName:'MOBILE LEGENDS',    date:'2025-01-15', verified:true },
    { id:'fake26',username:'NovaStar',    name:'NovaStar',    rating:5, text:'FF ESP wallhack akurat, bisa lihat posisi semua musuh. Combo sama aimbot auto winner!', product:'ff',        productName:'FREE FIRE MAX',      date:'2025-01-10', verified:true },
    { id:'fake27',username:'DragonByte',  name:'DragonByte',  rating:5, text:'PUBG no recoil + auto headshot combo mantap! Rank naik dari Gold ke Diamond dalam 2 minggu.', product:'pubgm',     productName:'PUBG MOBILE',   date:'2025-01-05', verified:true },
    { id:'fake28',username:'MegaBoss',    name:'MegaBoss',    rating:5, text:'Beli mod menu di sini gampang banget, bayar pakai QRIS langsung dapat key. Nggak ribet!', product:'ff',        productName:'FREE FIRE MAX',      date:'2024-12-28', verified:true },
    { id:'fake29',username:'PulseWave',   name:'PulseWave',   rating:4, text:'MLBB mod oke, tapi perlu update manual tiap patch baru. Harusnya auto update sih.', product:'ml',        productName:'MOBILE LEGENDS',    date:'2024-12-20', verified:true },
    { id:'fake30',username:'HyperCore',   name:'HyperCore',   rating:5, text:'PUBG speed hack works! Movement jadi cepat, musuh nggak bisa ngejar. Asik banget!', product:'pubgm',     productName:'PUBG MOBILE',   date:'2024-12-15', verified:true },
  ];

  // Filter fake by product if requested
  let finalFake = fakeTestimonials;
  if (productId) {
    finalFake = fakeTestimonials.filter(f => f.product === productId || f.productName === productId);
  }

  // Only add fake entries that don't duplicate real usernames
  const realUsernames = new Set(filtered.map(t => (t.username||'').toLowerCase()));
  const paddedFake = finalFake.filter(f => !realUsernames.has((f.username||'').toLowerCase()));

  // Merge: real first, then fake (capped so total stays reasonable)
  const maxDisplay = 30;
  const combined = [...filtered, ...paddedFake].slice(0, maxDisplay);

  res.json(combined);
});

app.post('/api/testimonials', requireAuth, async (req, res) => {
  try {
    // FIX (audit 22 Agu 2026): sebelumnya tidak ada rate limit maupun cek
    // duplikat -- user yang sudah beli bisa spam testimoni berkali-kali
    // untuk produk yang sama, membanjiri list dan merusak kredibilitas
    // rating (bukan celah keamanan data, tapi integritas data publik).
    if (!checkApiRateLimit(req.ip, 10, 60000)) {
      return res.json({ success: false, message: 'Terlalu banyak permintaan, coba lagi sebentar.' });
    }
    const { productId, productName, rating, text } = req.body;
    if (!productId || !rating || !text) return res.json({ success: false, message: 'Data tidak lengkap' });
    const ratingNum = parseInt(rating);
    if (ratingNum < 1 || ratingNum > 5) return res.json({ success: false, message: 'Rating tidak valid' });
    if (!text.trim()) return res.json({ success: false, message: 'Ulasan tidak boleh kosong' });
    if (text.trim().length > 500) return res.json({ success: false, message: 'Ulasan maksimal 500 karakter' });

    // Hanya user yang sudah membeli (transaksi sukses/done) produk ini yang boleh kirim testimoni
    const transactions = readDB('transactions.json');
    const hasPurchased = transactions.some(t =>
      t.userId === req.session.userId &&
      t.productId === productId &&
      t.status === 'done'
    );
    if (!hasPurchased) {
      return res.json({ success: false, message: 'Hanya pembeli produk ini yang bisa memberikan rating/testimoni' });
    }

    // Cegah spam: satu user cuma boleh kasih 1 testimoni per produk.
    const testimonials = readDB('testimonials.json');
    const alreadyReviewed = testimonials.some(t => t.userId === req.session.userId && t.product === productId);
    if (alreadyReviewed) {
      return res.json({ success: false, message: 'Kamu sudah memberikan ulasan untuk produk ini' });
    }

    const users = readDB('users.json');
    const user = users.find(u => u.id === req.session.userId);

    testimonials.unshift({
      id: uuidv4(),
      userId: req.session.userId,
      product: productId,
      productName: productName || '',
      username: user?.username || 'Pengguna',
      rating: ratingNum,
      text: text.trim(),
      date: new Date().toISOString(),
      verified: true,
      featured: false
    });

    await writeDB('testimonials.json', testimonials);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/testimonial/add', requireAdmin, async (req, res) => {
  try {
    if (!req.body.name || !req.body.text) {
      return res.json({ success: false, message: 'Nama dan isi testimoni wajib diisi' });
    }
    const { name, username, rating, text, product, verified, featured } = req.body;
    const testimonials = await readFresh('testimonials.json');

    // FIX (bug 24 Agu 2026): `product` sekarang berisi ID produk (dari
    // dropdown di form admin, bukan lagi text bebas -- lihat catatan
    // lengkap di admin.ejs dekat <select name="product">). productName
    // ikut diisi supaya konsisten dengan struktur testimoni ASLI dari
    // pembeli (lihat POST /api/testimonials di atas) dan tetap match
    // dengan kondisi t.productName === productId di endpoint GET, kalau
    // ada pemanggil lama yang masih mengandalkan itu.
    const productsAll = readDB('products.json');
    const matchedProduct = product ? productsAll.find(p => p.id === product) : null;

    const newTestimonial = {
      id: `testi-${Date.now()}`,
      name,
      username: username || null,
      rating: parseInt(rating) || 5,
      text,
      product: product || null,
      productName: matchedProduct ? matchedProduct.name : '',
      date: new Date().toISOString(),
      verified: verified === true || verified === 'true',
      featured: featured === true || featured === 'true'
    };

    testimonials.push(newTestimonial);
    await writeDB('testimonials.json', testimonials);

    res.json({ success: true, message: 'Testimoni berhasil ditambahkan' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/testimonial/delete/:id', requireAdmin, async (req, res) => {
  try {
    let testimonials = await readFresh('testimonials.json');
    testimonials = testimonials.filter(t => t.id !== req.params.id);
    await writeDB('testimonials.json', testimonials);
    res.json({ success: true, message: 'Testimoni berhasil dihapus' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/testimonial/toggle-featured/:id', requireAdmin, async (req, res) => {
  try {
    const testimonials = await readFresh('testimonials.json');
    const testi = testimonials.find(t => t.id === req.params.id);
    if (!testi) return res.json({ success: false, message: 'Testimoni tidak ditemukan' });

    testi.featured = !testi.featured;
    await writeDB('testimonials.json', testimonials);
    res.json({ success: true, message: 'Status featured berhasil diubah' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

app.post('/admin/testimonial/toggle-verified/:id', requireAdmin, async (req, res) => {
  try {
    const testimonials = await readFresh('testimonials.json');
    const testi = testimonials.find(t => t.id === req.params.id);
    if (!testi) return res.json({ success: false, message: 'Testimoni tidak ditemukan' });

    testi.verified = !testi.verified;
    await writeDB('testimonials.json', testimonials);
    res.json({ success: true, message: testi.verified ? 'Testimoni berhasil diverifikasi' : 'Verifikasi dicabut' });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
});

// ── FAKE LEADERBOARD (admin bisa tambah entri palsu biar leaderboard & notif ramai) ──
app.get('/admin/leaderboard/list', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    res.json({ success: true, entries: settings.fakeLeaderboard || [] });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/leaderboard/add', requireAdmin, async (req, res) => {
  try {
    const { username, totalTransactions, totalSpent } = req.body;
    if (!username || !username.trim()) return res.json({ success: false, message: 'Nama wajib diisi' });
    const trx = parseInt(totalTransactions);
    const spent = parseInt(totalSpent);
    if (isNaN(trx) || trx < 0) return res.json({ success: false, message: 'Jumlah transaksi tidak valid' });
    if (isNaN(spent) || spent < 0) return res.json({ success: false, message: 'Total belanja tidak valid' });

    const settings = await readFresh('settings.json');
    settings.fakeLeaderboard = settings.fakeLeaderboard || [];
    settings.fakeLeaderboard.push({
      id: `fake-${Date.now()}`,
      username: username.trim(),
      totalTransactions: trx,
      totalSpent: spent,
      photo: null,
      createdAt: new Date().toISOString()
    });
    await writeDB('settings.json', settings);
    res.json({ success: true, message: 'Entri leaderboard palsu ditambahkan' });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/leaderboard/delete/:id', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    settings.fakeLeaderboard = (settings.fakeLeaderboard || []).filter(f => f.id !== req.params.id);
    await writeDB('settings.json', settings);
    res.json({ success: true, message: 'Entri leaderboard palsu dihapus' });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.get('/api/notifications', (req, res) => {
  res.set('Cache-Control', 'public, max-age=60, stale-while-revalidate=300');
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan.' });
  const notifs = readDB('notifications.json').slice(0, 20);
  // SECURITY: anonimkan nama pembeli — hanya tampilkan initial agar tidak bocor daftar username asli
  const anonymize = (name = '') => {
    if (!name) return '***';
    return name[0] + '*'.repeat(Math.max(name.length - 1, 2));
  };
  const enriched = notifs.map(({ id, type, productName, price, timeStr, buyerName }) => ({
    id, type, productName, price, timeStr,
    buyerName: anonymize(buyerName),
    buyerPhoto: null
  }));
  res.json(enriched);
});

app.get('/api/leaderboard', (req, res) => {
  const entries = computeLeaderboard();
  res.json({ success: true, data: entries.slice(0, 10) });
});

// ═══════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════════════════════

// Admin Product Edit Page
app.get('/admin/product-edit', requireAdmin, async (req, res) => {
  const [products, settings] = await Promise.all([readFresh('products.json'), readFresh('settings.json')]);
  const productId = req.query.id;
  const product = productId ? products.find(p => p.id === productId) : null;
  res.render('pages/admin-product-edit', { product, products, settings });
});

// Admin Theme Settings Page
app.get('/admin/theme-settings', requireAdmin, async (req, res) => {
  const settings = await readFresh('settings.json');
  res.render('pages/admin-theme', { settings });
});

// Admin Product Management
app.get('/admin/products', requireAdmin, async (req, res) => {
  const products = await readFresh('products.json');
  res.json({ success: true, data: products });
});

// Admin Get Single Product
app.get('/admin/product/:id', requireAdmin, async (req, res) => {
  const products = await readFresh('products.json');
  const product = products.find(p => p.id === req.params.id);
  if (!product) return res.json({ success: false, message: 'Produk tidak ditemukan' });
  res.json({ success: true, data: product });
});

// Admin Update Product (image, status, keys)
app.post('/admin/product/:id', requireAdmin, async (req, res) => {
  try {
    const result = await withPersistentProductStockLock(req.params.id, async () => {
      const { items, name, bannerUrl, status, keys, keysMode, categories, channelUrl, downloadUrl, fakeSold, description, videoUrl, compatibility, featureList } = req.body;
      const products = await readFresh('products.json');
      const productIndex = products.findIndex(p => p.id === req.params.id);
      if (productIndex === -1) throw new Error('Produk tidak ditemukan');
      const p = products[productIndex];

      // BUG FIX (audit 20 Sep 2026): sebelumnya field `name` tidak pernah
      // dibaca/disimpan di sini sama sekali, jadi nama produk memang tidak
      // bisa diubah dari admin panel (lihat juga fix di admin-product-edit.ejs
      // yang baru menambahkan kolom inputnya).
      if (typeof name === 'string' && name.trim()) p.name = name.trim();

      if (bannerUrl && bannerUrl.trim()) { p.image = bannerUrl.trim(); p.bannerUrl = bannerUrl.trim(); }
      if (status) p.status = status;
      if (Array.isArray(categories)) p.categories = categories;
      if (description !== undefined) p.description = description;
      if (videoUrl !== undefined) {
        if (videoUrl && !isValidImageUrl(videoUrl)) throw new Error('URL video tidak valid');
        p.videoUrl = videoUrl.trim();
      }
      if (compatibility !== undefined) p.compatibility = compatibility.trim();
      if (featureList !== undefined) p.featureList = String(featureList).split('\n').map(f => f.trim()).filter(f => f);
      if (channelUrl !== undefined) {
        if (channelUrl && !isValidImageUrl(channelUrl)) throw new Error('URL channel tidak valid');
        p.channelUrl = channelUrl.trim();
      }
      if (downloadUrl !== undefined) {
        if (downloadUrl && !isValidImageUrl(downloadUrl)) throw new Error('URL download tidak valid');
        p.downloadUrl = downloadUrl.trim();
      }
      if (fakeSold !== undefined) {
        if (fakeSold === '' || fakeSold === null) p.fakeSold = null;
        else { const fs = parseInt(String(fakeSold).replace(/[^\d]/g,''), 10); if (!isNaN(fs) && fs >= 0) p.fakeSold = fs; }
      }
      if (p.strikePrice !== undefined) delete p.strikePrice;

      const { pricingOptions } = req.body;
      if (Array.isArray(pricingOptions) && pricingOptions.length > 0) {
        const seenDays = new Set();
        const validOpts = [];
        const cleanNum = (v) => {
          if (v === undefined || v === null || v === '') return NaN;
          if (typeof v === 'number') return v;
          const digitsOnly = String(v).replace(/[^\d]/g, '');
          return digitsOnly === '' ? NaN : parseInt(digitsOnly, 10);
        };
        for (const o of pricingOptions) {
          const days = cleanNum(o.days), price = cleanNum(o.price), unit = (o.unit === 'h' ? 'h' : 'd');
          const seenKey = `${days}${unit}`;
          if (!(days > 0) || isNaN(price) || price < 0 || seenDays.has(seenKey)) continue;
          seenDays.add(seenKey);
          let resellerPrice = null;
          if (o.reseller_price !== undefined && o.reseller_price !== null && o.reseller_price !== '') {
            const rp = cleanNum(o.reseller_price); if (!isNaN(rp) && rp >= 0) resellerPrice = rp;
          }
          let strikePriceVal = null;
          if (o.strike_price !== undefined && o.strike_price !== null && o.strike_price !== '') {
            const sp = cleanNum(o.strike_price); if (!isNaN(sp) && sp > price) strikePriceVal = sp;
          }
          validOpts.push({ days, unit, price, reseller_price: resellerPrice, strike_price: strikePriceVal,
            dripstoreVariantId: (o.dripstoreVariantId || '').toString().trim() || null });
        }
        if (validOpts.length > 0) {
          validOpts.sort((a, b) => a.unit === b.unit ? a.days - b.days : (a.unit === 'h' ? -1 : 1));
          p.pricingOptions = validOpts;
          p.items = validOpts.map(o => ({ l: `${(p.name||'PRODUK').toUpperCase()} ${formatDurationLabel(o.days, o.unit)}`, p: o.price, reseller_price: o.reseller_price, strike_price: o.strike_price }));
        }
      }

      if (keys !== undefined && keys !== null) {
        const newKeys = normalizeUsableLocalKeys(String(keys).split('\n'));
        if (newKeys.length > 0) {
          if (keysMode === 'replace') p.keys = newKeys;
          else p.keys = normalizeUsableLocalKeys([...(p.keys || []), ...newKeys]);
        }
      }

      await writeDB('products.json', products);
      return p;
    });
    res.json({ success: true, message: 'Produk berhasil diupdate', data: result });
  } catch (error) {
    res.json({ success: false, message: 'Error: ' + error.message });
  }
});

// Admin Upload Banner — di Vercel upload ke Supabase Storage, lokal ke filesystem
app.post('/admin/upload-banner', requireAdmin, multer({ storage: multer.memoryStorage(), fileFilter }).single('banner'), requireValidImageMagicBytesBuffer, async (req, res) => {
  try {
    if (!req.file) return res.json({ success: false, message: 'Tidak ada file diupload' });

    if (isVercel) {
      // Vercel: upload ke Supabase Storage
      try {
        const url = await db.uploadImage(req.file.buffer, req.file.originalname, req.file.mimetype);
        return res.json({ success: true, bannerUrl: url });
      } catch (e) {
        return res.json({ success: false, message: e.message });
      }
    }

    // Lokal: simpan di filesystem
    const bannersDir = path.join(__dirname, 'public', 'uploads', 'banners');
    if (!fs.existsSync(bannersDir)) fs.mkdirSync(bannersDir, { recursive: true });
    const filename = `${Date.now()}-${uuidv4()}${path.extname(req.file.originalname)}`;
    fs.writeFileSync(path.join(bannersDir, filename), req.file.buffer);
    res.json({ success: true, bannerUrl: `/uploads/banners/${filename}` });
  } catch (error) {
    res.json({ success: false, message: 'Error: ' + error.message });
  }
});

// Admin Get Theme Settings
app.get('/admin/theme', requireAdmin, async (req, res) => {
  const settings = await readFresh('settings.json');
  res.json({ success: true, data: settings.theme || {} });
});

// Admin Update Theme Settings
app.post('/admin/theme', requireAdmin, async (req, res) => {
  try {
    const { primaryColor, secondaryColor, accentColor, backgroundColor, cardBackground, borderColor, glowColor } = req.body;
    const settings = await readFresh('settings.json');

    // FIX KEAMANAN (audit 22 Agu 2026): sebelumnya warna tema disimpan
    // MENTAH tanpa validasi format sama sekali, padahal nilai ini di-render
    // langsung di dalam <style> block (bukan attribute HTML biasa) di
    // layout.ejs -- kalau isinya bukan hex color valid (mis. mengandung
    // "; } body { ... } /*"), itu bisa BREAK OUT dari CSS declaration dan
    // inject CSS arbitrary (CSS injection). Endpoint ini memang di belakang
    // requireAdmin, tapi validasi input tetap wajib sebagai defense-in-depth
    // -- jangan percaya input attacker meski sudah "admin", karena skenario
    // realistis: akun admin dikompromis, atau ada bug privilege-escalation
    // lain di kemudian hari yang bisa mengeksploitasi endpoint ini.
    const isValidHexColor = (v) => typeof v === 'string' && /^#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$/.test(v.trim());
    const isValidCssColorValue = (v) => typeof v === 'string' && /^(#[0-9a-fA-F]{3,8}|rgba?\([0-9.,\s%]+\))$/.test(v.trim());

    const prevTheme = settings.theme || {};
    const newTheme = {
      primaryColor: isValidHexColor(primaryColor) ? primaryColor.trim() : (prevTheme.primaryColor || '#7b2cbf'),
      secondaryColor: isValidHexColor(secondaryColor) ? secondaryColor.trim() : (prevTheme.secondaryColor || '#9d4edd'),
      accentColor: isValidHexColor(accentColor) ? accentColor.trim() : (prevTheme.accentColor || '#c77dff'),
      backgroundColor: isValidHexColor(backgroundColor) ? backgroundColor.trim() : (prevTheme.backgroundColor || '#0a0a0a'),
      cardBackground: isValidHexColor(cardBackground) ? cardBackground.trim() : (prevTheme.cardBackground || '#151520'),
      // borderColor/glowColor historis diisi dalam format rgba(...), bukan hex -- validasi terpisah yang menerima keduanya.
      borderColor: isValidCssColorValue(borderColor) ? borderColor.trim() : (prevTheme.borderColor || 'rgba(157,78,221,.15)'),
      glowColor: isValidCssColorValue(glowColor) ? glowColor.trim() : (prevTheme.glowColor || 'rgba(157, 78, 221, 0.1)'),
    };
    // Kalau ADA field yang dikirim tapi tidak lolos validasi, kasih tau
    // dengan jelas alih-alih diam-diam pakai fallback -- supaya admin tahu
    // input yang dia masukkan salah format, bukan sekedar "kelihatannya
    // tidak tersimpan".
    const rejected = [];
    if (primaryColor !== undefined && !isValidHexColor(primaryColor)) rejected.push('Warna Utama');
    if (secondaryColor !== undefined && !isValidHexColor(secondaryColor)) rejected.push('Warna Sekunder');
    if (accentColor !== undefined && !isValidHexColor(accentColor)) rejected.push('Warna Aksen');
    if (backgroundColor !== undefined && !isValidHexColor(backgroundColor)) rejected.push('Background');
    if (cardBackground !== undefined && !isValidHexColor(cardBackground)) rejected.push('Card Background');
    if (rejected.length > 0) {
      return res.json({ success: false, message: `Format warna tidak valid (harus hex, contoh #dc2626): ${rejected.join(', ')}` });
    }

    settings.theme = newTheme;
    await writeDB('settings.json', settings);
    res.json({ success: true, message: 'Tema berhasil diupdate', data: settings.theme });
  } catch (error) {
    res.json({ success: false, message: 'Error: ' + error.message });
  }
});

// ═══════════════════════════════════════════════════════════
// KEY POOL SYSTEM — Format: CODE - X Hari
// ═══════════════════════════════════════════════════════════

// User: halaman aktifkan key
app.get('/activate-key', requireAuth, (req, res) => {
  const user = getSessionUser(req);
  const settings = readDB('settings.json');
  res.render('pages/activate-key', { user, settings, result: null, error: null, code: '' });
});

app.post('/activate-key', requireAuth, async (req, res) => {
  const user = getSessionUser(req);
  const settings = readDB('settings.json');
  // FIX KEAMANAN (audit 22 Agu 2026): endpoint ini sebelumnya TIDAK ada
  // rate limiting sama sekali -- ini titik PALING BERISIKO untuk brute-force
  // di seluruh aplikasi, karena kode key diisi BEBAS oleh admin (bisa saja
  // pendek/predictable, mis. serial number produk fisik) dan endpoint ini
  // langsung memberi hak pakai produk premium ke siapapun yang menebak kode
  // yang benar -- beda dari voucher yang "cuma" diskon, ini bisa mencuri
  // hak milik produk utuh. Dibatasi ketat per user.
  if (!checkPaymentRateLimit(req.session.userId)) {
    return res.render('pages/activate-key', { user, settings, result: null, error: 'Terlalu banyak percobaan, coba lagi sebentar.', code: '' });
  }
  const code = (req.body.code || '').trim().toUpperCase();

  if (!code) return res.render('pages/activate-key', { user, settings, result: null, error: 'Masukkan kode key terlebih dahulu', code: '' });

  const keyspool = readDB('keyspool.json');
  const key = keyspool.find(k => k.code.toUpperCase() === code);

  if (!key) return res.render('pages/activate-key', { user, settings, result: null, error: 'Key tidak ditemukan atau tidak valid', code });
  if (key.used) return res.render('pages/activate-key', { user, settings, result: null, error: 'Key sudah pernah digunakan', code });

  key.used = true;
  key.usedBy = user.id;
  key.usedByUsername = user.username;
  key.usedAt = new Date().toISOString();
  await writeDB('keyspool.json', keyspool);

  res.render('pages/activate-key', {
    user, settings, code,
    result: { code: key.code, duration: key.duration, label: key.label || `${key.duration} Hari`, note: key.note || '' },
    error: null
  });
});

// Admin: lihat semua key pool
app.get('/admin/keyspool', requireAdmin, async (req, res) => {
  res.json({ success: true, data: await readFresh('keyspool.json') });
});

// Admin: tambah key baru
app.post('/admin/keyspool/add', requireAdmin, async (req, res) => {
  try {
    const { code, duration, label, note } = req.body;
    if (!code || !duration) return res.json({ success: false, message: 'Kode dan durasi wajib diisi' });
    const d = parseInt(duration);
    if (isNaN(d) || d <= 0) return res.json({ success: false, message: 'Durasi tidak valid (harus > 0 hari)' });
    const keyspool = await readFresh('keyspool.json');
    if (keyspool.find(k => k.code.toUpperCase() === code.trim().toUpperCase())) {
      return res.json({ success: false, message: 'Kode key sudah ada' });
    }
    keyspool.push({
      id: uuidv4(),
      code: code.trim().toUpperCase(),
      duration: d,
      label: label?.trim() || `${d} Hari`,
      used: false, usedBy: null, usedByUsername: null, usedAt: null,
      note: note?.trim() || '',
      createdAt: new Date().toISOString()
    });
    await writeDB('keyspool.json', keyspool);
    res.json({ success: true, data: keyspool });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// Admin: generate key otomatis (bulk)
app.post('/admin/keyspool/generate', requireAdmin, async (req, res) => {
  try {
    const { count, duration, prefix, label } = req.body;
    const n = Math.min(parseInt(count) || 1, 100);
    const d = parseInt(duration);
    if (isNaN(d) || d <= 0) return res.json({ success: false, message: 'Durasi tidak valid' });
    const keyspool = await readFresh('keyspool.json');
    const pref = (prefix || 'KEY').toUpperCase();
    const added = [];
    for (let i = 0; i < n; i++) {
      const code = `${pref}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
      keyspool.push({
        id: uuidv4(), code, duration: d,
        label: label?.trim() || `${d} Hari`,
        used: false, usedBy: null, usedByUsername: null, usedAt: null,
        note: '', createdAt: new Date().toISOString()
      });
      added.push(code);
    }
    await writeDB('keyspool.json', keyspool);
    res.json({ success: true, generated: added.length, codes: added, data: keyspool });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// Admin: hapus key
app.post('/admin/keyspool/delete/:id', requireAdmin, async (req, res) => {
  try {
    let keyspool = await readFresh('keyspool.json');
    keyspool = keyspool.filter(k => k.id !== req.params.id);
    await writeDB('keyspool.json', keyspool);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

// ═══════════════════════════════════════════════════════════
// VOUCHER SYSTEM
// ═══════════════════════════════════════════════════════════

app.get('/admin/vouchers', requireAdmin, async (req, res) => {
  res.json({ success: true, data: await readFresh('vouchers.json') });
});

app.post('/admin/vouchers/add', requireAdmin, async (req, res) => {
  try {
    const { code, type, value, minPurchase, maxUses, perUserLimit, expiresAt, description, excludeReseller } = req.body;
    if (!code || !type || value === undefined) return res.json({ success: false, message: 'Kode, tipe, dan nilai wajib diisi' });
    const val = parseFloat(value);
    if (isNaN(val) || val <= 0) return res.json({ success: false, message: 'Nilai voucher tidak valid' });
    if (type === 'percent' && val > 100) return res.json({ success: false, message: 'Persentase diskon maksimal 100%' });
    const vouchers = await readFresh('vouchers.json');
    if (vouchers.find(v => v.code.toUpperCase() === code.trim().toUpperCase())) {
      return res.json({ success: false, message: 'Kode voucher sudah ada' });
    }
    const newV = {
      id: uuidv4(),
      code: code.trim().toUpperCase(),
      type,
      value: val,
      minPurchase: parseInt(minPurchase) || 0,
      maxUses: parseInt(maxUses) || 0,
      perUserLimit: parseInt(perUserLimit) || 1,
      expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
      description: description?.trim() || '',
      excludeReseller: excludeReseller === true || excludeReseller === 'true',
      active: true,
      usedCount: 0,
      usages: [],
      createdAt: new Date().toISOString()
    };
    vouchers.push(newV);
    await writeDB('vouchers.json', vouchers);
    res.json({ success: true, data: vouchers });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/vouchers/toggle/:id', requireAdmin, async (req, res) => {
  try {
    const vouchers = await readFresh('vouchers.json');
    const v = vouchers.find(v => v.id === req.params.id);
    if (!v) return res.json({ success: false, message: 'Voucher tidak ditemukan' });
    v.active = !v.active;
    await writeDB('vouchers.json', vouchers);
    res.json({ success: true, active: v.active });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

app.post('/admin/vouchers/delete/:id', requireAdmin, async (req, res) => {
  try {
    let vouchers = await readFresh('vouchers.json');
    vouchers = vouchers.filter(v => v.id !== req.params.id);
    await writeDB('vouchers.json', vouchers);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});
