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

// LIVE LOG VIEWER (admin) -- supaya log asli bisa dilihat dari web tanpa buka Vercel.
// Cara kerja:
const LOG_MAX = 600;
const LOG_PERSIST_MAX = 1500;
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
const _dsStats = { since: Date.now(), calls: {}, byWho: {}, ok: 0, rateLimited: 0, err: 0, timeout: 0, last429At: 0, pendingRetryCount: 0 };
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
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// Production warning tapi JANGAN exit — Vercel kadat lambat inject env
if (process.env.NODE_ENV === 'production' && !process.env.SESSION_SECRET) {
  console.warn('⚠️  SESSION_SECRET belum di-set! Pakai secret acak sementara (reset tiap restart server).');
  console.warn('⚠️  WAJIB set SESSION_SECRET di environment variables untuk keamanan & session yang stabil.');
}

// Load DB module AFTER dotenv so env vars are available
const db = require('./supabase');

const app = express();

// KOMPRESI RESPONS (4 Okt 2026) -- sebelumnya TIDAK ADA. Tiap HTML (home/buy/admin
// 100-300KB mentah) dan JSON dikirim function -> CDN Vercel tanpa kompresi, dan itu yang
// dihitung sebagai "Fast Origin Transfer" (limit Hobby 10GB). Gzip memperkecil HTML/JSON
// sekitar 5-8x. Gambar (webp/jpg) otomatis dilewati oleh filter bawaan.
try {
  // Di Vercel respons sudah di-compress CDN (gzip/brotli); compress di dalam fungsi hanya memakan Active CPU.
  if (!process.env.VERCEL) {
    const compression = require('compression');
    app.use(compression({ threshold: 1024 }));
  }
} catch (e) {
  console.warn('[compression] modul belum terpasang, jalankan npm install:', e.message);
}
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

// Validasi kekuatan password (dipakai di /api/auth/register dan
// /register, dua-duanya harus konsisten). Sebelumnya TIDAK ADA validasi
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

// RATE LIMIT KHUSUS PEMBAYARAN (kebijakan wajib GensPay per 15 Agustus 2026)
// GensPay memblokir IP yang melakukan polling/generate QRIS berlebihan
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

// SISTEM KEY DENGAN DURASI (per-hari & per-jam)
// Format key di stok (product.keys, array of string):
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
  try { paymentAudit.record('webhook.' + gateway + '.result', { orderId: entry?.orderId || null, ...entry }); } catch (_) {}
  if (webhookLog.length > 30) webhookLog.length = 30;
  // Sambungkan ke Log Live (/admin/logs) supaya kejadian webhook (termasuk yang
  // gagal/ditolak) kelihatan di sana juga, bukan cuma di webhookLog yang tidak
  // pernah diekspos endpoint mana pun (bug lama -- data ini terkumpul tapi tidak
  // pernah bisa dibaca admin).
  try {
    const lv = /invalid_signature|no_apikey|no_raw_body|^error$/.test(entry?.result || '') ? 'warn' : 'info';
    pushLog(lv, `[webhook/${gateway}] ${entry?.result || '?'} orderId=${entry?.orderId || '-'}${entry?.error ? ' error=' + entry.error : ''}`, { cat: 'payment' });
  } catch (_) {}
}



// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('layout', 'layout');
app.set('trust proxy', 1);

// REAL CLIENT IP di belakang Cloudflare
// Kalau domain diproxy Cloudflare (awan oranye), req.ip = IP edge Cloudflare,
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
  if (/\.(?:css|js|mjs|map|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf|mp4|webm)$/i.test(p) || p.startsWith('/uploads/') || p.startsWith('/media/') || p.startsWith('/admin/logs')) return next();
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


// MEDIA PROXY (4 Okt 2026) -- sumber utama "Cached Egress" Supabase jebol.
// Semua gambar (produk, banner, avatar, QRIS) disimpan di Supabase Storage dan
const _mkMediaBase = (envName) => {
  const u = (process.env[envName] || '').trim().replace(/\/+$/, '');
  return u ? `${u}/storage/v1/object/public/product-images/` : null;
};
const _mediaBase = _mkMediaBase('SUPABASE_URL');
// Opsional: URL project Supabase LAMA (setelah migrasi). Gambar lama masih
// menunjuk ke sana; proxy mencoba project baru dulu, lalu project lama.
const _legacyMediaBase = _mkMediaBase('LEGACY_SUPABASE_URL');
const _mediaBases = [_mediaBase, _legacyMediaBase].filter(Boolean);
if (_mediaBase) {
  const _origSend = express.response.send;
  express.response.send = function (body) {
    if (typeof body === 'string') {
      for (const b of _mediaBases) if (body.includes(b)) body = body.split(b).join('/media/');
    }
    return _origSend.call(this, body);
  };
  app.get('/media/:file', async (req, res) => {
    const f = String(req.params.file || '');
    if (!/^[A-Za-z0-9._-]{1,200}$/.test(f)) return res.status(400).end();
    try {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 8000);
      let r = null;
      try {
        for (const b of _mediaBases) {
          r = await fetch(b + encodeURIComponent(f), { signal: ctl.signal }).catch(() => null);
          if (r && r.ok) break;
        }
      } finally { clearTimeout(t); }
      if (!r) { res.set('Cache-Control', 'public, max-age=30'); return res.status(502).end(); }
      const ct = r.headers.get('content-type') || '';
      if (!r.ok || !/^image\//i.test(ct)) {
        res.set('Cache-Control', 'public, max-age=30');
        return res.status(r.status === 404 ? 404 : 502).end();
      }
      let buf = Buffer.from(await r.arrayBuffer());
      let outType = ct;
      // Resize on-the-fly (whitelist lebar) -> webp kecil. Hasil di-cache CDN 1 tahun
      // per (file, lebar), jadi sharp jalan sekali per ukuran. Gagal -> file asli.
      const w = parseInt(req.query.w, 10);
      if (IMG_WIDTHS.includes(w) && !/gif|svg/i.test(ct)) {
        try {
          buf = await require('sharp')(buf, { failOn: 'none' }).rotate().resize({ width: w, withoutEnlargement: true }).webp({ quality: 78 }).toBuffer();
          outType = 'image/webp';
        } catch (_) { /* pakai file asli */ }
      }
      res.set({
        'Content-Type': outType,
        'Cache-Control': 'public, max-age=31536000, s-maxage=31536000, immutable',
        'X-Content-Type-Options': 'nosniff'
      });
      res.end(buf);
    } catch (e) {
      res.set('Cache-Control', 'public, max-age=30');
      res.status(502).end();
    }
  });
}

// ── CDN CACHE GUARD ──
// Header s-maxage otomatis dibatalkan (private, no-store) kalau response bawa
// Set-Cookie atau statusnya bukan 200 (429/302/404/5xx tidak boleh tersimpan di CDN).
app.use((req, res, next) => {
  const _wh = res.writeHead;
  res.writeHead = function (...a) {
    try {
      const cc = String(res.getHeader('Cache-Control') || '');
      if (/s-maxage/.test(cc) && (res.statusCode !== 200 || res.getHeader('Set-Cookie'))) {
        res.setHeader('Cache-Control', 'private, no-store');
      }
    } catch (_) {}
    return _wh.apply(this, a);
  };
  next();
});

// Helper EJS: versi kecil gambar lewat proxy /media (webp, di-cache CDN 1 tahun).
// Gambar non-/media (mis. file lokal saat development) dikembalikan apa adanya.
const IMG_WIDTHS = [96, 160, 240, 320, 480, 640, 960, 1280];
app.use((req, res, next) => {
  res.locals.imgW = (u, w) => {
    u = String(u || '');
    return (u.startsWith('/media/') && !u.includes('?') && IMG_WIDTHS.includes(w)) ? u + '?w=' + w : u;
  };
  next();
});

// Versi aset statis (cache-busting): commit Vercel kalau ada, else waktu start.
const ASSET_V = String(process.env.VERCEL_GIT_COMMIT_SHA || Date.now()).slice(0, 8);
app.use(expressLayouts);
// `verify` di sini nyimpen raw body string ke req.rawBody -- dibutuhkan
// khusus buat verifikasi signature webhook GensPay (lihat app.post('/webhook/genspay')),
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

// GOOGLE OAUTH LOGIN (opsional, diminta client 21 Agu 2026 -- "daftar
// bisa pilih menggunakan login akun ggl (optional)")
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
    state: true,
  }, async (accessToken, refreshToken, profile, done) => {
    // NOTE: fungsi ini HANYA mencocokkan/membuat user, TIDAK menyentuh
    // req.session -- itu dilakukan manual di route callback (lihat di
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

// SITE CHALLENGE GATE -- halaman pengecekan fullscreen (mirip "Checking your
// browser" Cloudflare) untuk pengunjung baru. Pakai Cloudflare Turnstile
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
const GATE_BYPASS_PREFIX = ['/webhook/', '/auth/google', '/uploads/', '/media/', '/track', '/auditor', '/cron/', '/css/', '/js/', '/img/', '/images/', '/fonts/', '/assets/', '/cf-check'];
const GATE_BYPASS_EXACT = new Set(['/robots.txt', '/sitemap.xml', '/favicon.ico', '/manifest.json', '/sw.js', '/health', '/ads.txt']);
// Crawler mesin pencari/preview link yang sah. UA bisa dipalsukan, tapi risikonya
// cuma "lolos gate" (bukan bypass auth) -- gate ini lapisan anti-bot, bukan auth.
const GATE_GOOD_BOTS = /(googlebot|adsbot-google|mediapartners-google|bingbot|duckduckbot|yandexbot|baiduspider|facebookexternalhit|twitterbot|whatsapp|telegrambot|slackbot|linkedinbot|applebot)/i;

app.use((req, res, next) => {
  if (!SITE_CHALLENGE_ON) return next();
  if (GATE_BYPASS_EXACT.has(req.path)) return next();
  if (GATE_BYPASS_PREFIX.some(p => req.path.startsWith(p))) return next();
  if (/\.(?:css|js|mjs|map|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf|mp4|webm|txt|xml|json)$/i.test(req.path)) return next();
  // UA "Googlebot" gampang dipalsukan -> jangan jadi karpet merah ke API/admin/order.
  // Crawler sah cuma butuh baca halaman publik (GET), bukan endpoint dinamis.
  if (GATE_GOOD_BOTS.test(req.headers['user-agent'] || '')
      && (req.method === 'GET' || req.method === 'HEAD')
      && !/^\/(api|admin|check-payment|order|buy-|topup|dashboard|auth)\b/i.test(req.path)) return next();
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
  // Petunjuk status login untuk UI (cookie 'agu', BUKAN untuk keamanan)
  // Dengan ini HTML publik (beranda, informasi) tidak lagi berbeda per pengunjung, jadi aman
  try {
    const hasSess = !!(req.session?.userId || req.session?.isAdmin);
    const m = /(?:^|;\s*)agu=([^;]*)/.exec(req.headers.cookie || '');
    const sec = (req.headers['x-forwarded-proto'] === 'https' || req.secure) ? '; Secure' : '';
    if (hasSess && (res.locals.user || res.locals.isAdmin)) {
      const u = res.locals.user;
      const enc = encodeURIComponent(JSON.stringify({ n: String((u && u.username) || 'admin').slice(0, 40), a: res.locals.isAdmin ? 1 : 0, r: (u && u.is_reseller) ? 1 : 0, p: (u && u.photo) ? String(u.photo).slice(0, 200) : '' }));
      if (!m || m[1] !== enc) res.append('Set-Cookie', `agu=${enc}; Path=/; Max-Age=2592000; SameSite=Lax${sec}`);
    } else if (m) {
      res.append('Set-Cookie', `agu=; Path=/; Max-Age=0; SameSite=Lax${sec}`);
    }
  } catch (_) {}
  res.locals.googleOAuthEnabled = GOOGLE_OAUTH_ENABLED;
  res.locals.assetV = ASSET_V;
  res.locals.currentPath = req.path;
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

// FIX KEAMANAN (audit 22 Agu 2026): validasi MAGIC BYTES untuk file
// upload gambar. Multer fileFilter yang lama HANYA cek `file.mimetype`
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
// bungkus: setelah menulis transactions.json, buang micro-cache baca segar supaya /invoice & /track langsung melihat perubahan
const writeDB = async (filename, data, opts) => {
  const r = await db.writeDB(filename, data, opts);
  if (filename === 'transactions.json' && typeof _txMicro !== 'undefined') _txMicro.at = 0;
  return r;
};
const readFresh = db.readFresh;

// Riwayat pembayaran permanen + halaman /admin/payment-history (bukti banding payment gateway)
const paymentAudit = require('./payment-audit');
const wijayapay = require('./wijayapay');
paymentAudit.init({ readFresh: (f) => db.readFresh(f), writeDB: (f, d) => db.writeDB(f, d) });

// Banner lama (seed default "Open Reseller") tersimpan tanpa field `id` dan
// pakai key `url` bukan `imageUrl` — akibatnya tombol "Hapus"/"Toggle" di
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

// Baca transactions.json yang SEGAR (maks 4 detik basi) -- readDB/readSmart bisa basi sampai 60 dtk
// atau selamanya di instance lain, sehingga pembeli melihat "pending" padahal admin sudah konfirmasi.
let _txMicro = { at: 0, data: null, p: null };
async function readTxFresh(maxAgeMs = 4000) {
  if (_txMicro.data && Date.now() - _txMicro.at < maxAgeMs) return _txMicro.data;
  if (_txMicro.p) return _txMicro.p;
  _txMicro.p = readFresh('transactions.json')
    .then(d => { _txMicro = { at: Date.now(), data: d, p: null }; return d; })
    .catch(e => { _txMicro.p = null; throw e; });
  return _txMicro.p;
}


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
    wijayapay: { codeMerchant: '', apiKey: '' },
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

  // MIGRASI PRODUK LAMA ke sistem kategori baru (diminta client 22 Agu
  // 2026: gabung "platform" Android/iOS/PC hardcode jadi 1 sistem
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

  // Single-Device Admin Lock
  // Mencegah 2 orang (mis: web dev + client) login admin bersamaan di
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
const normalizeOrderCode = (v) => String(v == null ? '' : v).trim().toUpperCase().replace(/\s+/g, '').replace(/[–—−]/g, '-').slice(0, 40);
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
const _pkLastCheck = new Map();
const createQRISPaymentPakasir = (orderId, amount, settings) => {
  // API v2 (v1 /transactioncreate dihentikan Pakasir pada 20 Okt 2026):
  // POST /api/v2/create-transaction/{slug}/{order_id}, header X-Api-Key, body { method, amount }.
  // Bersifat find-or-create: panggilan ulang dengan order_id & body sama mengembalikan transaksi yang sama.
  // Rate limit 2 request/detik. Respons membawa txn_id yang dipakai untuk cek status v2.
  return new Promise((resolve, reject) => {
    const apiKey = settings.pakasir?.apiKey?.trim() || '';
    const slug = settings.pakasir?.project?.trim() || '';
    if (!apiKey || !slug) return reject(new Error('API Key atau Slug project Pakasir belum dikonfigurasi'));

    const body = JSON.stringify({ method: 'qris', amount: parseInt(amount, 10) });
    const req = https.request({
      hostname: 'app.pakasir.com', port: 443,
      path: `/api/v2/create-transaction/${encodeURIComponent(slug)}/${encodeURIComponent(orderId)}`, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Api-Key': apiKey, 'Content-Length': Buffer.byteLength(body) },
      timeout: 15000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const r = JSON.parse(data);
          const qr = r.qr_string || r.payment?.payment_number || r.payment_number || r.data?.qr_string;
          if (res.statusCode === 429) return reject(_dsTransientError('Pakasir rate limit (2 request/detik), coba lagi sebentar'));
          if (!qr) return reject(new Error(r.message || r.error || `Pakasir error ${res.statusCode}: ${data.slice(0, 100)}`));
          resolve({ qr_string: qr, total_payment: r.total_payment || amount, expired_at: r.expired_at || null, txn_id: r.txn_id || null, fee: r.fee || 0 });
        } catch (e) { reject(new Error(`Gagal parse response Pakasir (HTTP ${res.statusCode})`)); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('Pakasir timeout')); });
    req.on('error', e => reject(_dsTransientError('Network error: ' + e.message)));
    req.write(body); req.end();
  });
};

// GensPay API (genspay.my.id)
// 📖 Dokumentasi Integrasi: https://genspay.my.id/docs
const _createQRISPaymentGenspayRaw = (orderId, amount, settings) => {
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
    req.on('error', e => reject(_dsTransientError('Network error: ' + e.message)));
    req.write(body); req.end();
  });
};

// Bungkus panggilan create GensPay: setiap request keluar (sukses/gagal, durasi) dicatat permanen
// supaya bisa dijadikan bukti saat banding. API key TIDAK ikut tercatat.
const createQRISPaymentGenspay = async (orderId, amount, settings) => {
  const t0 = Date.now();
  try {
    const r = await _createQRISPaymentGenspayRaw(orderId, amount, settings);
    paymentAudit.record('genspay.create', { orderId, amount, ok: true, durationMs: Date.now() - t0, totalPayment: r.total_payment, expiredAt: r.expired_at });
    return r;
  } catch (e) {
    paymentAudit.record('genspay.create', { orderId, amount, ok: false, durationMs: Date.now() - t0, error: e.message });
    throw e;
  }
};


// ── WijayaPay (gateway.wijayapay.com) ──
// ref_id = orderId kita sendiri; status dicek lewat GET /api/get-status + webhook /webhook/wijayapay.
const createQRISPaymentWijayapay = async (orderId, amount, settings) => {
  const t0 = Date.now();
  try {
    const r = await wijayapay.createTransaction(settings, orderId, amount);
    paymentAudit.record('wijayapay.create', { orderId, amount, ok: true, durationMs: Date.now() - t0, totalPayment: r.total_payment, expiredAt: r.expired_at });
    return r;
  } catch (e) {
    paymentAudit.record('wijayapay.create', { orderId, amount, ok: false, durationMs: Date.now() - t0, error: e.message });
    throw e;
  }
};

// DRIP STORE RESELLER API (dripclientstore.shop) — supplier key/stok
// buat produk-produk mod-menu (dokumentasi dari client library resmi
function _dsTransientError(message) {
  const err = new Error(message);
  err.transient = true;
  return err;
}

// CIRCUIT BREAKER + COALESCING + MICRO-CACHE (fix limit "Daily request limit reached")
// AKAR MASALAH (audit 23 Sep 2026): begitu provider balas 429, kode lama tetap
const _dsBreaker = { openUntil: 0, reason: '', hits429: 0 };
const _dsInflight = new Map();   // key -> Promise (coalescing GET identik)
const _dsMicroCache = new Map(); // key -> { at, ttl, value }
// HEMAT API (9 Okt 2026): cache per-instance diperpanjang. Vercel menjalankan banyak
// instance paralel & cold start, jadi TTL pendek (20 dtk / 8 dtk) berarti panggilan ke
const DS_MICRO_TTL = { 'products.php': 10 * 60 * 1000, 'balance.php': 60 * 1000 }; // ms
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

async function dripstoreCall(settings, endpoint, params = {}, method = 'GET', _retried = false, opts = {}) {
  const isGet = String(method).toUpperCase() === 'GET';

  if (isGet) {
    // Breaker terbuka: fail-fast, JANGAN sentuh provider.
    if (dripstoreBreakerState().open) throw _dsBreakerError();

    const cacheKey = endpoint + '?' + new URLSearchParams(params).toString() + '|' + _getDripstoreCatalogSignature(settings);
    const ttl = DS_MICRO_TTL[endpoint] || 0;
    if (ttl) {
      const hit = _dsMicroCache.get(cacheKey);
      const maxAge = (opts && Number.isFinite(opts.maxAgeMs)) ? Math.min(opts.maxAgeMs, ttl) : ttl;
      if (hit && (Date.now() - hit.at) < maxAge) return hit.value;
    }
    // Coalescing: request GET identik yang sedang terbang dibagi hasilnya.
    if (_dsInflight.has(cacheKey)) return _dsInflight.get(cacheKey);

    const p = (async () => {
      try {
        let value;
        try {
          value = await _dripstoreCallOnce(settings, endpoint, params, method, _retried);
        } catch (e) {
          if (!e?.transient || _retried || dripstoreBreakerState().open) throw e;
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
    if (rl) { _dsStats.rateLimited++; _dsStats.last429At = Date.now(); }
    else { _dsStats.err++; if (/timeout/i.test((e && e.message) || '')) _dsStats.timeout++; }
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
      headers, timeout: isGet ? 8000 : 20000
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
    req.on('timeout', () => { req.destroy(); reject(_dsTransientError('DripStore timeout (' + (isGet ? 8 : 20) + ' detik)')); });
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
  // RIWAYAT (jangan diulang lagi tanpa bukti serupa):
  // 1) Awalnya ada alias 'xreg apk mod' -> 'aim hack' dengan asumsi "XREG di AGHA NL
  'xreg apk mod': ['xreg android ios', 'xreg android+ ios'],

  // Typo/casing mismatch that exists between the AGHA product name and
  // DripStore catalog; use an explicit alias instead of broad fuzzy matching.
  'drip clint apk mod': ['drip client apk mod'],
  // BUG FIX (audit 20 Sep 2026, dikoreksi setelah cari langsung ke katalog
  // DripStore lewat /admin/dripstore/catalog-search): nama yang dikasih
  'hg save apk mod': ['hg cheat safe version mod'],
  'hg safe apk mod': ['hg cheat safe version mod']
};

// ALIAS STRICT (dipakai untuk produk yang namanya di toko BEDA dari nama asli di DripStore)
// Beda dari DRIPSTORE_PRODUCT_ALIASES di atas: pencocokan alias strict TIDAK dua arah.
const DRIPSTORE_STRICT_ALIASES = {
  // Nama di DripStore: HG CHEAT SAFE SERVER  (sumber: chat client 24 Sep 2026)
  'hg apk mod global rank': ['hg cheat safe server'],
  'hg apk mod global': ['hg cheat safe server'],
  // Nama di DripStore: HG CHEAT BRUTAL  (sumber: chat client 24-25 Sep 2026)
  // Nama produk asli di web ternyata "HG APK MOD CR (COSTUM ROOM ONLY)" -- ada kata
  'hg apk mod cr costum room only': ['hg cheat brutal'],
  'hg apk mod cr custom room only': ['hg cheat brutal'],
  'hg apk mod cr costum room': ['hg cheat brutal'],
  'hg apk mod cr custom room': ['hg cheat brutal'],
  'hg apk mod cr': ['hg cheat brutal']
};

function _dsStrictAliasCandidates(localName) {
  return (DRIPSTORE_STRICT_ALIASES[_dsNormalizeName(localName)] || []).map(_dsNormalizeName).filter(Boolean);
}
function _dsStrictAliasMatch(candidates, supplierName) {
  const b = _dsNormalizeName(supplierName);
  if (!b) return false;
  const padded = ' ' + b + ' ';
  return candidates.some(a => b === a || padded.includes(' ' + a + ' '));
}
// "Exact" untuk urutan prioritas: sama dengan nama lokal, ATAU sama persis dengan alias strict.
function _dsIsExactNameMatch(localName, supplierName) {
  const sup = _dsNormalizeName(supplierName);
  if (!sup) return false;
  return sup === _dsNormalizeName(localName) || _dsStrictAliasCandidates(localName).includes(sup);
}

function _dsProviderNameCandidates(localName) {
  const normalized = _dsNormalizeName(localName);
  const aliases = DRIPSTORE_PRODUCT_ALIASES[normalized] || [];
  return [String(localName || ''), ...aliases];
}

function _dsNameMatchWithAliases(localName, supplierName) {
  const strict = _dsStrictAliasCandidates(localName);
  if (strict.length) return _dsStrictAliasMatch(strict, supplierName);
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
          const xe = _dsIsExactNameMatch(product.name, x.productName) ? 1 : 0;
          const ye = _dsIsExactNameMatch(product.name, y.productName) ? 1 : 0;
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
    const currentVariantId = resolveDripstoreVariantForOption(providerProducts, normalized.name, opt);
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

async function getDripstoreBalanceValue(settings, opts = {}) {
  const resp = await dripstoreCall(settings, 'balance.php', {}, 'GET', false, opts);
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
// FIX (egress Supabase, audit 29 Sep 2026): TTL ini SEBELUMNYA 30000 (30 detik).
// Dampaknya: file snapshot katalog DripStore (dripstore_snapshot.json) ditulis
// Stok produk DripStore di web = FLOOR(saldo DripStore / harga modal varian). Jadi angka stok ikut naik/turun
// setiap saldo berubah (top up / penjualan). TTL snapshot dipendekkan ke 2 menit supaya stok tidak telat lama
// setelah top up; biaya API tetap kecil karena products.php (katalog+harga, jarang berubah) di-cache 10 menit
// dan balance.php di-cache 60 dtk per instance (lihat DS_MICRO_TTL).
const DRIPSTORE_CATALOG_CACHE_TTL = 2 * 60 * 1000;
const DRIPSTORE_CATALOG_TIMEOUT_MS = 4500;
const DRIPSTORE_SNAPSHOT_FILE = 'dripstore_snapshot.json';
const DRIPSTORE_STALE_BALANCE_MAX_MS = 10 * 60 * 1000;   // saldo basi maks 10 menit utk tampilan
const DRIPSTORE_STALE_PRODUCTS_MAX_MS = 60 * 60 * 1000;  // katalog/harga jarang berubah
const DRIPSTORE_STALE_DISPLAY_MAX_MS = 7 * 24 * 60 * 60 * 1000; // 6 Okt 2026: 24 jam -> 7 hari. Lewat 24 jam tanpa snapshot, SELURUH toko jadi "Cek stok" dan tidak bisa dibeli walau checkout memverifikasi ulang. // katalog basi maks 24 jam khusus utk tampilan stok

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
  // HEMAT (9 Okt 2026): dulu di sini snapshot persisten DITULIS ULANG ke Supabase setiap
  // ada penjualan (egress + CPU per sale). Cukup tandai instance ini; akurasi pembelian
  // tidak bergantung pada snapshot (guard fulfillment selalu pakai saldo <=5 dtk).
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
let _dripstoreLastWarmAttempt = 0;
const DRIPSTORE_WARM_MIN_GAP_MS = 5000;
function warmDripstoreCatalog(settings) {
  if (!settings?.dripstore?.apiToken) return;
  if (_dripstoreCatalogInflight) return;
  // Jangan pernah 'warm' saat provider sedang dibatasi / baru gagal, dan jangan
  // warm kalau cache masih segar. Sebelumnya dipanggil di SETIAP page load.
  if (dripstoreBreakerState().open || Date.now() < _dripstoreFailUntil) return;
  if (getCachedDripstoreCatalogSnapshot(settings)) return;
  // Throttle independen dari _dripstoreFailUntil (yang baru terisi SETELAH satu
  // percobaan gagal). Tanpa ini, banyak pengunjung yang datang bersamaan sebelum
  // cooldown resmi aktif bisa memicu beberapa percobaan warm sekaligus.
  const now = Date.now();
  if (now - _dripstoreLastWarmAttempt < DRIPSTORE_WARM_MIN_GAP_MS) return;
  _dripstoreLastWarmAttempt = now;
  getDripstoreCatalogSnapshot(settings).catch(() => {});
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
      const ae = _dsIsExactNameMatch(productName, a.productName) ? 1 : 0;
      const be = _dsIsExactNameMatch(productName, b.productName) ? 1 : 0;
      return be - ae || String(b.productName).length - String(a.productName).length;
    });
    return matches[0].variantId;
  }
  // Katalog provider berhasil dibaca tetapi pasangan product+durasi tidak ada.
  // Jangan menggunakan ID lama karena bisa menunjuk ke variant yang sudah
  // berubah; false-positive stock lebih berbahaya daripada status unknown.
  return null;
}

// Pilih Variant ID provider untuk satu opsi durasi.
// PRIORITAS: mapping eksplisit (opt.dripstoreVariantId) selama ID itu MASIH ada & punya harga di katalog
function resolveDripstoreVariantForOption(productsResp, productName, opt) {
  const mapped = String(opt?.dripstoreVariantId || '').trim();
  if (mapped && productsResp) {
    const cost = _dsFindVariantCost(productsResp, mapped);
    if (cost !== null) return mapped;
  }
  return resolveDripstoreVariantFromCatalog(productsResp, productName, opt);
}

function findDripstoreVariantForOption(snapshot, productName, opt) {
  if (!snapshot?.products || !productName || !opt) return null;

  // Prefer the explicitly auto-mapped Variant ID, but NEVER trust it blindly:
  // the current provider catalog must still contain that ID and its current
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
    // Saldo WAJIB segar (<=5 dtk) karena ini guard tepat sebelum generate_key (uang keluar).
    [balance, productsResp] = await Promise.all([
      getDripstoreBalanceValue(settings, { maxAgeMs: 5000 }),
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
  const variantId = resolveDripstoreVariantForOption(productsResp, productName, opt);
  if (!variantId) return { ok: false, variantMissing: true, reason: 'Variant DripStore untuk produk + durasi ini tidak ditemukan' };
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
    // PERF (5 Okt 2026): sebelumnya SELALU memanggil products.php live (katalog 170+ varian,
    // 1-8 dtk, kena timeout/limit) tiap Konfirmasi Bayar. Katalog terakhir yang <10 menit
    // dipakai dulu; pencocokan tetap berdasar nama+durasi, jadi hasilnya sama. Kalau tidak
    // ketemu di snapshot, baru ambil live.
    let recent = null;
    try {
      const lgp = _dsLastGood(settings);
      if (lgp && lgp.products && (Date.now() - Number(lgp.productsAt || 0)) < 10 * 60 * 1000) recent = lgp.products;
    } catch (_) {}
    if (recent && resolveDripstoreVariantForOption(recent, product.name, opt)) providerProducts = recent;
    else providerProducts = await dripstoreCall(settings, 'products.php');
  }
  const currentVariantId = resolveDripstoreVariantForOption(providerProducts, product.name, opt);
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
const _dripstoreRestockLocks = new Set();

// Auto-restock: dipanggil (fire-and-forget, TIDAK di-await di alur
// pembelian) tiap kali 1 key berhasil terjual. Kalau stok durasi itu
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
// settings.apiGateway: 'pakasir' (default) | 'genspay' | 'wijayapay'
// Semua call site lama tetap manggil createQRISPayment(orderId, amount, settings)
// apa adanya -- dispatcher ini yang nentuin ke gateway mana request-nya pergi.
const createQRISPayment = (orderId, amount, settings) => {
  const gateway = settings.apiGateway || 'pakasir';
  if (gateway === 'genspay') return createQRISPaymentGenspay(orderId, amount, settings);
  if (gateway === 'wijayapay') return createQRISPaymentWijayapay(orderId, amount, settings);
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

const checkPaymentStatusPakasirV1 = (orderId, amount, settings) => {
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

// API v2: GET /api/v2/transaction-status/{slug}/{txn_id}. Status: pending | completed | canceled.
// Rate limit: 1 panggilan per 4 detik PER transaksi (webhook adalah jalur utama, ini cadangan).
const checkPaymentStatusPakasirV2 = (txnId, settings) => {
  return new Promise((resolve, reject) => {
    const apiKey = settings.pakasir?.apiKey?.trim() || '';
    const slug = settings.pakasir?.project?.trim() || '';
    if (!apiKey || !slug) return reject(new Error('API Key atau Slug project Pakasir belum dikonfigurasi'));
    const req = https.request({
      hostname: 'app.pakasir.com', port: 443,
      path: `/api/v2/transaction-status/${encodeURIComponent(slug)}/${encodeURIComponent(txnId)}`, method: 'GET',
      headers: { 'X-Api-Key': apiKey }, timeout: 10000
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        if (res.statusCode === 429) return reject(new Error('Pakasir status rate limit'));
        try { resolve(JSON.parse(data)); } catch (e) { reject(new Error(`Gagal parse response status (HTTP ${res.statusCode})`)); }
      });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('Pakasir status timeout')); });
    req.on('error', e => reject(new Error('Network error: ' + e.message)));
    req.end();
  });
};

// Order yang dibuat SEBELUM migrasi v2 tidak punya txn_id -> pakai v1 (hanya berfungsi sampai 20 Okt 2026).
const checkPaymentStatusPakasir = (orderId, amount, settings, txnId) => {
  if (txnId) return checkPaymentStatusPakasirV2(txnId, settings);
  return checkPaymentStatusPakasirV1(orderId, amount, settings);
};

// PENTING: dokumentasi resmi GensPay (genspay.my.id/docs) TIDAK menyediakan
// endpoint GET untuk cek status transaksi -- GensPay sepenuhnya mengandalkan
const checkPaymentStatusGenspay = (orderId, amount, settings) => {
  return Promise.reject(new Error(
    'GensPay tidak menyediakan endpoint cek status manual -- status transaksi HANYA dikirim via webhook. ' +
    'Pastikan Webhook URL sudah didaftarkan di dashboard GensPay (Settings project).'
  ));
};

// Dispatcher, sama polanya seperti createQRISPayment di atas.
const checkPaymentStatus = (orderId, amount, settings, gatewayOverride, txnId) => {
  const gateway = gatewayOverride || settings.apiGateway || 'pakasir';
  if (gateway === 'genspay') return checkPaymentStatusGenspay(orderId, amount, settings);
  if (gateway === 'wijayapay') return wijayapay.checkStatus(settings, orderId);
  return checkPaymentStatusPakasir(orderId, amount, settings, txnId);
};


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
      { loc: '/login', priority: '0.3', changefreq: 'yearly' },
      { loc: '/register', priority: '0.3', changefreq: 'yearly' },
    ];

    // Halaman produk dinamis -- ini yang paling penting untuk SEO produk
    // spesifik (mis. "topup mod ff [nama produk]" bisa nemu halaman ini
    // langsung dari Google).
    // Halaman /buy/:id sudah diganti bottom-sheet di beranda (redirect) -> tidak ikut sitemap.
    const productUrls = [];

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
  // Route publik dengan traffic tertinggi: pakai readSmart (cache ber-TTL),
  // BUKAN readFresh, supaya tiap pengunjung tidak menarik ulang seluruh blob
  // products.json dari Supabase.
  const products = (await readSmart('products.json')).filter(p => p.status === 'active');

  // Ulasan pembeli (gaya ThanHub)
  // Semua testimoni tampil: dari pembeli asli (otomatis verified, lihat
  const _relTime = (iso) => {
    const t = Date.parse(iso);
    if (!Number.isFinite(t)) return '';
    const min = Math.floor(Math.max(0, Date.now() - t) / 60000), hr = Math.floor(min / 60), day = Math.floor(hr / 24);
    if (min < 1) return 'Baru saja';
    if (min < 60) return min + ' menit lalu';
    if (hr < 24) return hr + ' jam lalu';
    if (day === 1) return 'Kemarin';
    if (day < 7) return day + ' hari lalu';
    if (day < 30) return Math.floor(day / 7) + ' minggu lalu';
    if (day < 365) return Math.floor(day / 30) + ' bulan lalu';
    return Math.floor(day / 365) + ' tahun lalu';
  };
  const allTestimonials = readDB('testimonials.json')
    .filter(t => t && t.text)
    .sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));
  const reviewCount = allTestimonials.length;
  const avgRating = reviewCount
    ? (allTestimonials.reduce((sum, t) => sum + (Number(t.rating) || 0), 0) / reviewCount).toFixed(1)
    : '5.0';
  const testimonialsForHome = allTestimonials.slice(0, 12).map(t => ({
    id: t.id,
    name: t.name || t.username || 'Pembeli',
    rating: Number(t.rating) || 5,
    text: t.text,
    productName: t.productName || '',
    verified: !!t.verified,
    time: _relTime(t.date)
  }));
  const totalSold = products.reduce((s, p) => s + (p.sold || 0), 0);
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
    // STALE-WHILE-REVALIDATE: kalau tidak ada cache SEGAR, coba dulu katalog BASI
    // (bisa umur berjam-jam, lihat DRIPSTORE_STALE_DISPLAY_MAX_MS) -- itu tidak
    if (!homeProviderSnapshot) homeProviderSnapshot = getDisplayDripstoreSnapshot(settings);
    if (!homeProviderSnapshot) {
      homeProviderSnapshot = await getDripstoreCatalogSnapshot(settings, { maxWaitMs: 3500 }).catch(() => null);
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

  // HTML beranda sama untuk semua pengunjung (status login diisi JS dari cookie 'agu') ->
  // cache CDN 60 dtk + stale-while-revalidate. Dinonaktifkan kalau SITE_CHALLENGE aktif
  // (gerbang verifikasi tidak boleh dilewati lewat cache).
  if (!SITE_CHALLENGE_ON) res.set('Cache-Control', 'public, max-age=0, s-maxage=60, stale-while-revalidate=120');
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
    banners: (Array.isArray(settings.banners) ? settings.banners : []).filter(b => b && b.active !== false),
    storeMaintenance: !!settings.storeMaintenance,
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || null,
    testimonialsForHome,
    avgRating,
    reviewCount,
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

// API JSON untuk LOGIN/REGISTER via POPUP (diminta client 22 Agu 2026:
// "login daftar nya tuh di pop up dahsbord bkn di halaman beda")
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
  res.render('pages/reseller', { settings, user });
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
        const r = await createQRISPayment(orderId, price, settings); _mark('gateway');
        qrString = r.qr_string;
        var providerTxnId = r.txn_id || null;
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
      providerTxnId: providerTxnId || undefined,
      status: 'pending', key: null,
      ip: clientIp, ua: clientUa,
      createdAt: new Date().toISOString(), time: formatDate()
    });
    await writeDB('transactions.json', transactions);
    await paymentAudit.record('order.created', { orderId, refId, gateway: settings.apiGateway || 'pakasir', amount: price, totalPayment, userId: req.session.userId, ip: clientIp, ua: clientUa, product: product.name, static: isStatic });

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
        var providerTxnId = r.txn_id || null;
        // total_payment dari Pakasir = amount + fee mereka (kalau ada). Ini
        // CUMA buat ditampilkan ke user biar nominal yang ditampilkan sama
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
      providerTxnId: providerTxnId || undefined,
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

    const products = await productsP; _mark('db_read');
    const rawProduct = products.find(p => p.id === productId);
    const product = rawProduct ? normalizeProductBuyOptions(rawProduct) : null;
    if (!product || product.status !== 'active') return res.json({ success: false, message: 'Produk tidak ditemukan' });
    if (rawProduct?.maintenance || (res.locals.settings && res.locals.settings.storeMaintenance)) {
      return res.json({ success: false, message: 'Produk sedang maintenance. Silakan coba lagi nanti.' });
    }

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
  res.set('Cache-Control', 'public, max-age=60, s-maxage=120, stale-while-revalidate=300');
  // FIX (loading lambat): sebelumnya pakai readFresh -- artinya SETIAP kali
  // ada yang buka homepage, server nunggu round-trip penuh ke Supabase dulu
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
app.get('/buy/:id', (req, res) => {
  res.set('Cache-Control', 'public, max-age=300, s-maxage=3600');
  res.redirect(301, '/?buy=' + encodeURIComponent(String(req.params.id || '').slice(0, 80)));
});

// Public catalog stock refresh: SATU request untuk seluruh kartu katalog.
// Ini mencegah homepage harus memanggil /api/products/:id/stock satu per satu.
// Provider tetap hanya dipanggil sekali lewat snapshot cache TTL pendek.
app.get('/api/catalog/stock', async (req, res) => {
  if (!checkApiRateLimit(req.ip)) return res.status(429).json({ success: false, message: 'Terlalu banyak permintaan. Coba lagi nanti.' });
  try {
    res.set('Cache-Control', 'public, max-age=0, s-maxage=15, stale-while-revalidate=30');
    const rawProducts = (await readSmart('products.json')).filter(p => p.status === 'active');
    // FIX (egress, audit 29 Sep 2026): settings.json jarang berubah dalam hitungan
    // detik -- readSmart (cache 60 dtk) cukup, konsisten dengan products.json di
    // atas, dan endpoint ini dipanggil otomatis oleh SETIAP load homepage.
    const settings = await readSmart('settings.json');
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
    res.set('Cache-Control', 'public, max-age=0, s-maxage=15, stale-while-revalidate=30');
    // FIX (egress, audit 29 Sep 2026): dulu readFresh('products.json') DAN
    // readFresh('settings.json') di sini -- endpoint ini dipanggil otomatis oleh
    const rawProducts = await readSmart('products.json');
    const raw = rawProducts.find(p => String(p.id) === String(req.params.id) && p.status === 'active');
    if (!raw) return res.status(404).json({ success: false, message: 'Produk tidak ditemukan' });
    const settings = await readSmart('settings.json');
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
app.post('/create-order', async (req, res) => {
  try {
    const { productId, duration, durationUnit, customerName, wa, voucherCode } = req.body;

    // ── KECEPATAN (9 Okt 2026): tiap readFresh = 1 round-trip ke Supabase (dulu berurutan:
    // users -> products -> transactions ...). Pembacaan yang tidak saling bergantung sekarang
    // dijalankan PARALEL sejak awal, jadi total waktu = yang terlama, bukan jumlahnya.
    // Server-Timing di respons menunjukkan durasi tiap tahap (DevTools > Network > Timing).
    const _t0 = Date.now(), _marks = [];
    const _mark = (n) => _marks.push(`${n};dur=${Date.now() - _t0}`);
    const productsP = readFresh('products.json'); productsP.catch(() => {});
    const preTxP = readFresh('transactions.json'); preTxP.catch(() => {});
    const usersP = !req.session?.userId ? readFresh('users.json') : null; if (usersP) usersP.catch(() => {});

    // Guest checkout: kalau belum ada session user sama sekali, buat akun
    // guest baru dari nama+WA yang diisi di form. Kalau nomor WA yang sama
    // pernah dipakai guest sebelumnya, pakai ulang akun itu (supaya riwayat
    // pembelian nyambung meski tanpa password/login eksplisit).
    if (!req.session?.userId) {
      if (!customerName || !customerName.trim() || !wa || !wa.trim()) {
        return res.json({ success: false, message: 'Nama dan nomor WhatsApp wajib diisi' });
      }
      const users = await usersP;
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
    if (rawProduct?.maintenance || (res.locals.settings && res.locals.settings.storeMaintenance)) {
      return res.json({ success: false, message: 'Produk sedang maintenance. Silakan coba lagi nanti.' });
    }

    // Stok lokal tidak wajib untuk durasi yang sudah di-map ke DripStore:
    // key dibeli live dari provider setelah pembayaran dikonfirmasi.
    const hasDripstoreMappedOption = (product.pricingOptions || []).some(o => o?.dripstoreVariantId);

    // Support pricingOptions (deem style: {days,unit,price}) dan items (lama: {l,p})
    // FIX (fitur key per-jam, diminta client 21 Agu 2026): sebelumnya durasi
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
            // Hanya tampilkan angka saldo/kebutuhan kalau memang dua-duanya terbaca. Kalau penyebabnya
            // variant belum ke-mapping / saldo tak terbaca, tampilkan alasan sebenarnya (bukan "$?").
            console.warn('[checkout] pre-flight provider gagal:', JSON.stringify({ product: product.name, days: selectedDays, unit: selectedUnit, reason: av.reason, balance: av.balance, required: av.required, variantId: av.variantId }));
            if (av.balance != null && av.required != null) {
              return res.json({ success: false, message: `Stok variant ini belum tersedia. Saldo provider $${Number(av.balance).toFixed(2)}, kebutuhan $${Number(av.required).toFixed(2)}.` });
            }
            return res.json({ success: false, message: `Stok variant ini belum bisa diproses: ${av.reason || 'data provider tidak lengkap'}. Hubungi CS.` });
          }
        } catch (e) {
          return res.json({ success: false, message: 'Tidak bisa memverifikasi stok provider sebelum checkout: ' + e.message });
        }
      }
    }

    const clientIp = String(req.ip || req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    const clientUa = String(req.headers['user-agent'] || '').slice(0, 160);

    // CEGAH QRIS SIA-SIA (akar masalah banyak "pending" & suspend GensPay)
    // Sebelumnya cek "pesanan pending duplikat" baru dilakukan SETELAH createQRISPayment() dipanggil, jadi
    {
      const preTx = await preTxP; _mark('pre_checks');
      const nowMs = Date.now(), WINDOW = 30 * 60 * 1000;
      const live = (Array.isArray(preTx) ? preTx : []).filter(t => t.status === 'pending' && (nowMs - Date.parse(t.createdAt)) < WINDOW);
      const dup = live.find(t => t.userId === req.session.userId && t.productId === productId);
      const dyn = live.filter(t => !t.isStatic);
      const pendingByUser = dyn.filter(t => t.userId === req.session.userId).length;
      const pendingByIp = clientIp ? dyn.filter(t => t.ip === clientIp).length : 0;
      if (dup) {
        paymentAudit.record('order.blocked_duplicate', { orderId: dup.orderId, userId: req.session.userId, ip: clientIp, reason: 'pending_same_product' });
        return res.json({ success: false, message: 'Kamu masih memiliki pesanan pending untuk produk ini. Selesaikan pembayaran atau tunggu 30 menit.' });
      }
      if (pendingByUser >= 3 || pendingByIp >= 5) {
        paymentAudit.record('order.blocked_duplicate', { userId: req.session.userId, ip: clientIp, reason: 'too_many_pending', pendingByUser, pendingByIp });
        return res.json({ success: false, message: 'Kamu masih punya beberapa pesanan yang belum dibayar. Selesaikan pembayaran atau tunggu 30 menit sebelum membuat pesanan baru.' });
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
        var providerTxnId = r.txn_id || null;
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
      providerTxnId: providerTxnId || undefined,
      status: 'pending', key: null,
      createdAt: new Date().toISOString(), time: formatDate()
    });
    // Tulis transaksi + catat voucher PARALEL (dulu berurutan: 2-3 round-trip tambahan).
    const _writes = [writeDB('transactions.json', transactions)];
    if (appliedVoucher) {
      _writes.push((async () => {
        const vouchers = await readFresh('vouchers.json');
        const v = vouchers.find(v => v.id === appliedVoucher.id);
        if (v) {
          v.usedCount = (v.usedCount || 0) + 1;
          v.usages = v.usages || [];
          v.usages.push({ userId: req.session.userId, usedAt: new Date().toISOString(), orderId: refId });
          await writeDB('vouchers.json', vouchers);
        }
      })());
    }
    await Promise.all(_writes); _mark('db_write');
    res.set('Server-Timing', _marks.join(', ') + `, total;dur=${Date.now() - _t0}`);

    res.json({ success: true, refId, orderId, qrString, orderCode, isStatic, totalPayment, expiredAt,
      voucherDiscount: voucherDiscount || undefined,
      qrisStaticImage: isStatic ? settings.qrisStaticImage : null });
  } catch (error) {
    console.error('[create-order] error:', error.message);
    res.json({ success: false, message: 'Terjadi kesalahan: ' + error.message });
  }
});

// finalizeOrder — tandai transaksi lunas & proses sesuai tipenya
// (reseller upgrade / top up saldo / kirim key produk). Diekstrak dari
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

async function releaseProductFulfillmentClaim(refId) {
  const claimKey = `fulfillment-claim:${String(refId)}`;
  const client = db.getClient();
  try {
    if (!client) { _localFulfillmentClaims.delete(claimKey); return; }
    await client.from('keyvalue_store').delete().eq('key', claimKey);
  } catch (e) {
    console.error('[fulfillment] gagal melepas klaim', refId, e.message);
  }
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
  if (!key && !outOfStock && shouldTryLocalFirst && product) {
    const localResult = await consumeLocalProductKey(product.id, transaction.selectedDays, transaction.selectedUnit || 'd');
    products = localResult.products || products;
    product = products.find(p => p.id === transaction.productId) || product;
    if (localResult.key) {
      key = localResult.key;
      localInventoryCommitted = !!localResult.committed;
    }
  }

  let pendingRetry = false;
  if (!key && !outOfStock && (fulfillmentMode === 'live' || fulfillmentMode === 'hybrid')) {
    const liveProvider = await fulfillProductFromDripstore(transaction, settings).catch(e => ({ error: e }));
    if (liveProvider && !liveProvider.error) {
      key = liveProvider.key; keySource = liveProvider.source;
      providerTransactionId = liveProvider.providerTransactionId; providerVariantId = liveProvider.variantId;
    } else if (liveProvider?.error) {
      const err = liveProvider.error;
      // Transient (timeout/network/5xx/rate-limit): PROVIDER-nya yang lelet/limit,
      // bukan stoknya yang kosong. Jangan vonis "stok habis" -- itu memicu WA "proses
      // manual" padahal beberapa detik lagi provider biasanya sudah pulih.
      const isTransient = !!(err?.transient || err?.rateLimited);
      if (isTransient) {
        pendingRetry = true;
        _dsStats.pendingRetryCount++;
        console.warn('[DripStore hybrid fulfillment] transient, akan dicoba lagi:', transaction.code, err.message);
      } else {
        console.error('[DripStore hybrid fulfillment]', transaction.code, err.message);
        outOfStock = true;
      }
    }
  }

  if (pendingRetry) {
    // Uang sudah dikonfirmasi masuk, TAPI belum difulfill. JANGAN tandai 'done' (nanti
    // dianggap outOfStock permanen). Lepas klaim supaya panggilan check-payment
    // berikutnya (polling client, biasanya tiap beberapa detik) boleh mencoba lagi.
    if (!transaction.type || transaction.type === 'product') await releaseProductFulfillmentClaim(refId);
    return { status: 'pending_retry', type: 'product', code: transaction.code };
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
  // PERF (5 Okt 2026): qrString (payload QRIS) = ~29% ukuran transactions.json dan hanya
  // dipakai saat pembeli sedang membayar. Setelah tidak pending, buang -- tiap konfirmasi
  // jadi mengunduh/mengunggah file yang jauh lebih kecil (sebelumnya ~900KB x3 per konfirmasi).
  for (const t of txListFinal) { if (t && t.status !== 'pending' && t.qrString !== undefined) delete t.qrString; }
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

// ── HALAMAN PEMBAYARAN (ThanHub: /order/pay) ──
// Tampil QRIS (dinamis dari gateway / statis dari admin), total, cara bayar, countdown, dan
// polling status yang hemat (lihat views/pages/pay.ejs). Hanya pemilik order / admin.
app.get('/pay/:refId', async (req, res) => {
  res.set('Cache-Control', 'private, no-store');
  try {
    if (!req.session?.userId && !req.session?.isAdmin) return res.redirect('/login?redirect=' + encodeURIComponent(req.originalUrl));
    const all = await readFresh('transactions.json');
    const tx = (Array.isArray(all) ? all : []).find(t => t.id === req.params.refId);
    if (!tx || (!req.session.isAdmin && tx.userId !== req.session.userId)) return res.redirect('/');
    const settings = res.locals.settings || readDB('settings.json');
    let expiresAtMs = Date.parse(String(tx.expiredAt || '').replace(' ', 'T'));
    if (!Number.isFinite(expiresAtMs)) expiresAtMs = Date.parse(tx.createdAt) + 30 * 60 * 1000;
    const fee = Math.max(0, Number(tx.totalPayment || 0) - Number(tx.price || 0));
    let channelUrl = '';
    if (tx.productId) { try { const pr = (await readSmart('products.json')).find(x => x.id === tx.productId); channelUrl = String(pr?.channelUrl || pr?.downloadUrl || ''); } catch (_) {} }
    const csWa = String(settings?.contact?.csWhatsapp || settings?.contact?.whatsapp || '').replace(/\D/g, '');
    res.render('pages/pay', {
      csWa,
      channelUrl: /^https?:\/\//i.test(channelUrl) ? channelUrl : '',
      tx: {
        id: tx.id, orderId: tx.orderId, code: tx.code, type: tx.type || 'product', status: tx.status,
        productName: tx.productName || '', duration: tx.duration || '', price: Number(tx.price || 0),
        totalPayment: Number(tx.totalPayment || tx.price || 0), fee, isStatic: !!tx.isStatic,
        qrString: tx.isStatic ? null : (tx.qrString || null), voucherCode: tx.voucherCode || null,
        key: tx.status === 'done' ? (tx.key || null) : null, expiresAtMs
      },
      staticQris: settings.qrisStaticImage || null
    });
  } catch (e) {
    console.error('[pay] error:', e.message);
    res.redirect('/');
  }
});

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
    if (gateway === 'genspay') {
      return res.json({ success: true, status: 'pending' });
    }
    try {
      // PENTING: Pakasir mewajibkan parameter `amount` di /api/transactiondetail
      // adalah NOMINAL ASLI yang diminta saat transaksi dibuat (field `price`
      const _pkNow = Date.now();
      if (_pkLastCheck.get(transaction.id) && _pkNow - _pkLastCheck.get(transaction.id) < 4500) {
        return res.json({ success: true, status: 'pending' });
      }
      _pkLastCheck.set(transaction.id, _pkNow);
      if (_pkLastCheck.size > 2000) { for (const k of [..._pkLastCheck.keys()].slice(0, 1000)) _pkLastCheck.delete(k); }
      const r = await checkPaymentStatus(transaction.orderId, transaction.price, settings, gateway, transaction.providerTxnId);
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
      if (result.status === 'pending_retry' || result.status === 'already_processing') {
        // Uang sudah masuk, provider lagi lelet/limit -- client tetap polling normal,
        // percobaan fulfillment berikutnya terjadi otomatis di panggilan check-payment ini juga.
        return res.json({ success: true, status: 'pending' });
      }
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

// WEBHOOK GENSPAY — dipanggil server-to-server oleh GensPay begitu
// pembayaran QRIS sukses & dana masuk, TANPA bergantung pembeli membuka
app.post('/webhook/genspay', async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const apiKey = (settings.genspay?.apiKey || process.env.GENSPAY_API_KEY || '').trim();
    const signatureHeader = req.headers['x-genspay-signature'];
    paymentAudit.record('webhook.genspay.received', { ip: req.ip, ua: req.headers['user-agent'], contentType: req.headers['content-type'], signaturePresent: !!signatureHeader, rawBody: req.rawBody ? req.rawBody.toString().slice(0, 800) : null });
    if (!apiKey || !signatureHeader) { logWebhook('genspay', { result: 'no_apikey_or_signature' }); return res.status(401).send('Unauthorized'); }

    // Signature = sha256(rawBody + apiKey). Pakai req.rawBody (string mentah,
    // lihat opsi `verify` di express.json() setup di atas) -- BUKAN
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
    if (!transaction) {
      // PENTING: GensPay memanggil webhook segera setelah pembayaran sukses
      // dalam kondisi Supabase lelet/race jarang, ada kemungkinan webhook ini
      logWebhook('genspay', { result: 'transaction_not_found', orderId });
      return res.status(503).send('Transaction not found yet, please retry');
    }
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

    if (processingOrders.has(transaction.id)) {
      // Request lain (mis. retry GensPay yang datang sangat cepat, atau polling
      // client) sedang memproses order yang sama detik ini juga. Balas 200 di
      logWebhook('genspay', { result: 'already_processing', orderId });
      return res.status(200).send('OK');
    }
    processingOrders.add(transaction.id);
    try {
      const result = await finalizeOrder(transaction.id, settings);
      if (result.status === 'pending_retry') {
        // Fulfillment gagal transient (provider DripStore timeout/limit). Order
        // TETAP 'pending' di database (lihat finalizeOrder), TAPI dari sudut
        logWebhook('genspay', { result: 'finalized_pending_retry', orderId, note: 'provider lelet, fulfillment akan dicoba ulang saat polling/konfirmasi manual' });
        return res.status(200).send('OK');
      }
      const fulfillNote = result.key ? '(terkirim)' : (result.outOfStock ? '(kosong/out-of-stock)' : '(n/a)');
      logWebhook('genspay', { result: 'finalized', orderId, type: result.type, key: fulfillNote });
      res.status(200).send('OK');
    } finally {
      processingOrders.delete(transaction.id);
    }
  } catch (error) {
    // Error internal TAK TERDUGA (bug, exception yang tidak ditangani cabang
    // manapun di atas) -- ini KEMUNGKINAN BESAR transient (mis. Supabase drop
    console.error('[webhook/genspay] error:', error.message);
    logWebhook('genspay', { result: 'error', error: error.message });
    res.status(500).send('Internal error, please retry');
  }
});



// WEBHOOK WIJAYAPAY (docs.wijayapay.com) — dikirim saat pembayaran lunas.
// URL: https://domainkamu.com/webhook/wijayapay   (dikirim juga per-transaksi
app.post('/webhook/wijayapay', async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const payload = req.body || {};
    const refId = payload.data && payload.data.ref_id ? String(payload.data.ref_id) : '';
    const sigOk = wijayapay.verifyWebhookSignature(settings, refId, req.headers['x-signature']);
    paymentAudit.record('webhook.wijayapay.received', { ip: req.ip, ua: req.headers['user-agent'], orderId: refId || null, sigOk, ipWhitelisted: wijayapay.isWhitelistedIp(req.ip), status: payload.status || null });
    if (!sigOk) { logWebhook('wijayapay', { result: 'invalid_signature', orderId: refId || null, ip: req.ip }); return res.status(401).json({ status: false, message: 'Invalid signature' }); }
    if (String(payload.status || '').toLowerCase().trim() !== 'paid') { logWebhook('wijayapay', { result: 'not_paid', orderId: refId, statusFromWebhook: payload.status || '(kosong)' }); return res.status(200).json({ status: true }); }

    const transactions = await readFresh('transactions.json');
    const transaction = transactions.find(t => t.orderId === refId);
    if (!transaction) {
      logWebhook('wijayapay', { result: 'transaction_not_found', orderId: refId });
      return res.status(503).json({ status: false, message: 'Transaction not found yet, please retry' });
    }
    if (transaction.status === 'done') { logWebhook('wijayapay', { result: 'already_done', orderId: refId }); return res.status(200).json({ status: true }); }
    if (transaction.paymentGateway && transaction.paymentGateway !== 'wijayapay') { logWebhook('wijayapay', { result: 'gateway_mismatch', orderId: refId, gateway: transaction.paymentGateway }); return res.status(200).json({ status: true }); }

    // Cross-check nominal terhadap database KITA (total_dibayar = nominal + fee kalau fee ditanggung pembeli).
    const paid = Number(payload.data.total_dibayar);
    const expected = Number(transaction.totalPayment || transaction.price);
    if (Number.isFinite(paid) && expected && Math.abs(paid - expected) > 1) {
      logWebhook('wijayapay', { result: 'amount_mismatch', orderId: refId, expected, got: paid });
      return res.status(200).json({ status: true });
    }

    if (processingOrders.has(transaction.id)) { logWebhook('wijayapay', { result: 'already_processing', orderId: refId }); return res.status(200).json({ status: true }); }
    processingOrders.add(transaction.id);
    try {
      const result = await finalizeOrder(transaction.id, settings);
      if (result.status === 'pending_retry') {
        logWebhook('wijayapay', { result: 'finalized_pending_retry', orderId: refId, note: 'provider lelet, fulfillment dicoba ulang saat polling/rekonsiliasi' });
      } else {
        logWebhook('wijayapay', { result: 'finalized', orderId: refId, type: result.type, key: result.key ? '(terkirim)' : (result.outOfStock ? '(kosong/out-of-stock)' : '(n/a)') });
      }
      return res.status(200).json({ status: true });
    } finally {
      processingOrders.delete(transaction.id);
    }
  } catch (error) {
    console.error('[webhook/wijayapay] error:', error.message);
    logWebhook('wijayapay', { result: 'error', error: error.message });
    // 200 + status:true supaya WijayaPay tidak retry terus karena bug internal; status tetap terkoreksi lewat polling/rekonsiliasi.
    res.status(200).json({ status: true });
  }
});

// WEBHOOK PAKASIR (API v2) -- dikirim Pakasir (HTTP POST) saat transaksi BERHASIL.
// CARA AKTIFKAN: dashboard Pakasir > detail proyek > isi "Webhook URL":
app.post('/webhook/pakasir', async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const secret = (settings.pakasir?.webhookSecret || process.env.PAKASIR_WEBHOOK_SECRET || '').trim();
    const hdr = String(req.headers['x-secret'] || '');
    paymentAudit.record('webhook.pakasir.received', { ip: req.ip, ua: req.headers['user-agent'], secretPresent: !!hdr, orderId: req.body?.order_id || null, txnId: req.body?.txn_id || null, status: req.body?.status || null });
    if (!secret || !hdr) { logWebhook('pakasir', { result: 'no_secret_configured_or_header' }); return res.status(401).send('Unauthorized'); }
    const a = Buffer.from(hdr), b = Buffer.from(secret);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) { logWebhook('pakasir', { result: 'invalid_secret', orderId: req.body?.order_id || null }); return res.status(401).send('Unauthorized'); }

    const { txn_id, order_id, amount, status, is_sandbox } = req.body || {};
    if (!order_id) { logWebhook('pakasir', { result: 'no_order_id' }); return res.status(200).send('OK'); }
    // Transaksi sandbox (simulasi) tidak boleh memicu pengiriman key di mode produksi.
    if (is_sandbox === true && (settings.pakasir?.mode || 'production') !== 'sandbox') { logWebhook('pakasir', { result: 'sandbox_ignored', orderId: order_id }); return res.status(200).send('OK'); }
    if (String(status || '').toLowerCase() !== 'completed') { logWebhook('pakasir', { result: 'not_completed', orderId: order_id, statusFromWebhook: status || '(kosong)' }); return res.status(200).send('OK'); }

    const transactions = await readFresh('transactions.json');
    const transaction = transactions.find(t => t.orderId === order_id) || (txn_id ? transactions.find(t => t.providerTxnId === txn_id) : null);
    if (!transaction) {
      // Sama seperti GensPay: balas 5xx supaya dicoba ulang, jangan 200 (order bisa nyangkut pending selamanya).
      logWebhook('pakasir', { result: 'transaction_not_found', orderId: order_id });
      return res.status(503).send('Transaction not found yet, please retry');
    }
    if (transaction.status === 'done') { logWebhook('pakasir', { result: 'already_done', orderId: order_id }); return res.status(200).send('OK'); }
    // Validasi nominal terhadap database KITA sebelum menandai lunas (amount = nominal asli, bukan total + fee).
    if (Number(amount) !== Number(transaction.price)) {
      logWebhook('pakasir', { result: 'amount_mismatch', orderId: order_id, expected: transaction.price, got: amount });
      return res.status(200).send('OK');
    }
    if (transaction.paymentGateway && transaction.paymentGateway !== 'pakasir') { logWebhook('pakasir', { result: 'gateway_mismatch', orderId: order_id, gateway: transaction.paymentGateway }); return res.status(200).send('OK'); }

    if (processingOrders.has(transaction.id)) { logWebhook('pakasir', { result: 'already_processing', orderId: order_id }); return res.status(200).send('OK'); }
    processingOrders.add(transaction.id);
    try {
      const result = await finalizeOrder(transaction.id, settings);
      if (result.status === 'pending_retry') {
        logWebhook('pakasir', { result: 'finalized_pending_retry', orderId: order_id, note: 'provider lelet, fulfillment dicoba ulang saat polling/konfirmasi manual' });
        return res.status(200).send('OK');
      }
      logWebhook('pakasir', { result: 'finalized', orderId: order_id, type: result.type, key: result.key ? '(terkirim)' : (result.outOfStock ? '(kosong/out-of-stock)' : '(n/a)') });
      res.status(200).send('OK');
    } finally {
      processingOrders.delete(transaction.id);
    }
  } catch (error) {
    console.error('[webhook/pakasir] error:', error.message);
    logWebhook('pakasir', { result: 'error', error: error.message });
    res.status(500).send('Internal error, please retry');
  }
});

// TRACKING PESANAN PUBLIK (4 Okt 2026) -- diminta tim payment gateway untuk audit.
// /track?q=KODE1,KODE2,...  -> status tiap pesanan (kode FX-XXXX-XXXX ATAU order id FX-17xxxxxxxxx).
function _trackLabel(t) {
  if (t.status === 'done') {
    if (t.keySource === 'manual_admin') return { text: 'Selesai - diproses manual oleh admin (key dikirim via WhatsApp)', tone: 'warn' };
    return { text: 'Selesai - key terkirim otomatis oleh sistem', tone: 'ok' };
  }
  if (t.status === 'pending') return { text: 'Menunggu pembayaran / belum diproses', tone: 'pending' };
  if (t.status === 'expired') return { text: 'Kedaluwarsa - tidak ada pembayaran terkonfirmasi, tidak ada key terkirim', tone: 'bad' };
  if (t.status === 'failed') return { text: 'Gagal / dibatalkan oleh gateway - tidak ada key terkirim', tone: 'bad' };
  return { text: String(t.status || '-'), tone: 'pending' };
}

// AKUN AUDITOR READ-ONLY (4 Okt 2026) -- untuk tim payment gateway.
// Login TERPISAH dari admin (session.auditor), tidak menyentuh single-device admin lock.
const _net = require('net');
const AUDITOR_FILE = 'auditor.json';
const _auditorFails = new Map();
const _normIp = ip => { let x = String(ip || '').trim().toLowerCase(); if (x.startsWith('::ffff:')) x = x.slice(7); return x; };
async function _auditorCfg() {
  try { const c = await readFresh(AUDITOR_FILE); return (c && typeof c === 'object' && !Array.isArray(c)) ? c : {}; } catch (_) { return {}; }
}
function _auditorReady(c) { return !!(c && c.enabled && c.username && c.passwordHash && c.allowedIp); }
function _auditorHeaders(res) { res.set({ 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow', 'X-Frame-Options': 'DENY' }); }
function _auditorBlocked(ip) {
  const f = _auditorFails.get(ip);
  return f && f.count >= 5 && Date.now() - f.first < 15 * 60 * 1000;
}
function _auditorFail(ip) {
  const f = _auditorFails.get(ip);
  if (!f || Date.now() - f.first > 15 * 60 * 1000) _auditorFails.set(ip, { count: 1, first: Date.now() });
  else f.count++;
}
async function auditorGuard(req, res, next) {
  _auditorHeaders(res);
  const cfg = await _auditorCfg();
  if (!_auditorReady(cfg)) return res.status(404).send('Not found');
  const ip = _normIp(req.ip);
  if (ip !== _normIp(cfg.allowedIp)) {
    return res.status(403).render('pages/auditor', { layout: false, mode: 'blocked', ip, error: null, data: null });
  }
  req.auditorCfg = cfg;
  next();
}
function _auditorAuthed(req) {
  const a = req.session && req.session.auditor;
  return !!(a && a.ip === _normIp(req.ip) && a.v === req.auditorCfg.updatedAt);
}
const _maskWa = wa => { const d = String(wa || '').replace(/\D/g, ''); return d.length >= 7 ? d.slice(0, 4) + '***' + d.slice(-3) : (d ? '***' : '-'); };
const _jktFmt = iso => iso ? new Date(iso).toLocaleString('id-ID', { timeZone: 'Asia/Jakarta', hour12: false }) + ' WIB' : '-';
async function _auditorRows(q) {
  const all = await readFresh('transactions.json');
  const status = String(q.status || 'all');
  const term = String(q.q || '').toUpperCase().split(/[\s,;]+/).map(x => x.trim()).filter(Boolean).slice(0, 100);
  const from = q.from ? Date.parse(q.from) : null;
  const to = q.to ? Date.parse(q.to) + 86400000 : null;
  const rows = (Array.isArray(all) ? all : []).filter(t => {
    if (!t) return false;
    if (status !== 'all' && t.status !== status) return false;
    const c = Date.parse(t.createdAt || '');
    if (from && !(c >= from)) return false;
    if (to && !(c < to)) return false;
    if (term.length && !term.some(x => String(t.code || '').toUpperCase() === x || String(t.orderId || '').toUpperCase() === x || String(t.id || '').toUpperCase() === x)) return false;
    return true;
  }).sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
  const summary = { total: 0, done: 0, pending: 0, expired: 0, failed: 0, doneRevenue: 0, doneManual: 0 };
  for (const t of (Array.isArray(all) ? all : [])) {
    if (!t) continue; summary.total++;
    if (summary[t.status] !== undefined) summary[t.status]++;
    if (t.status === 'done') { summary.doneRevenue += Number(t.price) || 0; if (t.keySource === 'manual_admin') summary.doneManual++; }
  }
  const view = t => {
    const lb = _trackLabel(t);
    return {
      code: t.code || '-', orderId: t.orderId || '-', product: t.productName || '-',
      duration: t.selectedDays ? `${t.selectedDays} ${t.selectedUnit === 'h' ? 'jam' : 'hari'}` : '-',
      price: Number(t.price) || 0, status: t.status, label: lb.text, tone: lb.tone,
      created: _jktFmt(t.createdAt), createdIso: t.createdAt || '', paid: _jktFmt(t.paidAt), paidIso: t.paidAt || '',
      keySent: t.status === 'done' && !!t.key, by: t.status === 'done' ? (t.keySource === 'manual_admin' ? 'manual admin' : 'otomatis') : '-',
      note: t.keySource === 'manual_admin' ? String(t.manualNote || '').slice(0, 200) : '', wa: _maskWa(t.wa)
    };
  };
  return { rows, summary, view };
}

app.get('/auditor', auditorGuard, async (req, res) => {
  if (!_auditorAuthed(req)) return res.render('pages/auditor', { layout: false, mode: 'login', ip: _normIp(req.ip), error: null, data: null });
  try {
    const { rows, summary, view } = await _auditorRows(req.query);
    const per = 100, page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pages = Math.max(1, Math.ceil(rows.length / per));
    res.render('pages/auditor', {
      layout: false, mode: 'list', ip: _normIp(req.ip), error: null,
      data: { items: rows.slice((page - 1) * per, page * per).map(view), total: rows.length, page, pages, summary, f: { status: String(req.query.status || 'all'), q: String(req.query.q || ''), from: String(req.query.from || ''), to: String(req.query.to || '') } }
    });
  } catch (e) {
    res.status(500).render('pages/auditor', { layout: false, mode: 'login', ip: _normIp(req.ip), error: 'Gagal memuat data, coba lagi.', data: null });
  }
});
app.post('/auditor/login', auditorGuard, express.urlencoded({ extended: false, limit: '4kb' }), async (req, res) => {
  const ip = _normIp(req.ip);
  const fail = msg => res.status(401).render('pages/auditor', { layout: false, mode: 'login', ip, error: msg, data: null });
  if (_auditorBlocked(ip)) return fail('Terlalu banyak percobaan. Coba lagi 15 menit.');
  const cfg = req.auditorCfg;
  const u = String(req.body?.username || '').trim().toLowerCase();
  const p = String(req.body?.password || '');
  const userOk = u.length === String(cfg.username).length && require('crypto').timingSafeEqual(Buffer.from(u), Buffer.from(String(cfg.username)));
  const passOk = await bcrypt.compare(p.slice(0, 200), cfg.passwordHash).catch(() => false);
  if (!(userOk && passOk)) { _auditorFail(ip); return fail('Username atau password salah.'); }
  _auditorFails.delete(ip);
  req.session.auditor = { ip, v: cfg.updatedAt, at: Date.now() };
  try { paymentAudit.record('auditor.login', { ip }); } catch (_) {}
  res.redirect('/auditor');
});
app.post('/auditor/logout', auditorGuard, (req, res) => { if (req.session) req.session.auditor = null; res.redirect('/auditor'); });
app.get('/auditor/export.csv', auditorGuard, async (req, res) => {
  if (!_auditorAuthed(req)) return res.status(401).send('Login dulu');
  const { rows, view } = await _auditorRows(req.query);
  const cell = v => { let x = String(v ?? ''); if (/^[=+\-@]/.test(x)) x = "'" + x; return `"${x.replace(/"/g, '""')}"`; };
  const head = ['kode', 'order_id', 'produk', 'durasi', 'harga', 'status', 'dibuat_WIB', 'dibuat_ISO', 'dibayar_WIB', 'dibayar_ISO', 'key_terkirim', 'diproses_oleh', 'catatan_manual', 'wa_masked'];
  const lines = [head.join(',')].concat(rows.map(t => { const v = view(t); return [v.code, v.orderId, v.product, v.duration, v.price, v.status, v.created, v.createdIso, v.paid, v.paidIso, v.keySent ? 'ya' : 'tidak', v.by, v.note, v.wa].map(cell).join(','); }));
  res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="audit-transaksi.csv"' });
  res.send('\ufeff' + lines.join('\r\n'));
});

// ── Admin: kelola akun auditor ──
app.get('/admin/auditor/config', requireAdmin, async (req, res) => {
  const c = await _auditorCfg();
  res.json({ success: true, enabled: !!c.enabled, username: c.username || '', allowedIp: c.allowedIp || '', hasPassword: !!c.passwordHash, updatedAt: c.updatedAt || null, yourIp: _normIp(req.ip) });
});
app.post('/admin/auditor/save', requireAdmin, async (req, res) => {
  try {
    const old = await _auditorCfg();
    const enabled = req.body?.enabled === true || req.body?.enabled === 'true' || req.body?.enabled === 'on';
    const username = String(req.body?.username || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const allowedIp = _normIp(req.body?.allowedIp);
    if (!/^[a-z0-9_.-]{3,32}$/.test(username)) return res.json({ success: false, message: 'Username 3-32 karakter (huruf kecil, angka, titik, strip, underscore)' });
    if (allowedIp && !_net.isIP(allowedIp)) return res.json({ success: false, message: 'Format IP tidak valid (contoh 103.10.20.30)' });
    if (enabled && !allowedIp) return res.json({ success: false, message: 'Isi IP yang diizinkan dulu. Auditor tanpa batasan IP tidak diperbolehkan.' });
    let passwordHash = old.passwordHash;
    if (password) {
      if (password.length < 10) return res.json({ success: false, message: 'Password minimal 10 karakter' });
      passwordHash = await bcrypt.hash(password, 10);
    }
    if (enabled && !passwordHash) return res.json({ success: false, message: 'Isi password dulu' });
    await writeDB(AUDITOR_FILE, { enabled, username, passwordHash, allowedIp, updatedAt: new Date().toISOString() });
    try { paymentAudit.record('auditor.config_saved', { enabled, username, allowedIp, passwordChanged: !!password, by: 'admin' }); } catch (_) {}
    res.json({ success: true });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.get('/track', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const raw = String(req.query.q || req.query.code || '').slice(0, 6000);
  if (!raw.trim()) return res.render('pages/track', { q: '', results: null, missing: [], error: null });
  if (!checkInvoiceRateLimit(req.ip)) {
    return res.render('pages/track', { q: raw, results: null, missing: [], error: 'Terlalu banyak pencarian. Coba lagi dalam 5 menit.' });
  }
  try {
    const terms = [...new Set(raw.split(/[\s,;]+/).map(x => x.trim().toUpperCase()).filter(Boolean))].slice(0, 100);
    const all = await readTxFresh();
    const byCode = new Map(), byOrder = new Map();
    for (const t of (Array.isArray(all) ? all : [])) {
      if (t.code) byCode.set(String(t.code).toUpperCase(), t);
      if (t.orderId) byOrder.set(String(t.orderId).toUpperCase(), t);
      if (t.id) byOrder.set(String(t.id).toUpperCase(), t);
    }
    const fmt = iso => iso ? new Date(iso).toLocaleString('id-ID', { timeZone: 'Asia/Jakarta', hour12: false }) + ' WIB' : '-';
    const results = [], missing = [];
    for (const term of terms) {
      const t = byCode.get(term) || byOrder.get(term);
      if (!t) { missing.push(term); continue; }
      const lb = _trackLabel(t);
      results.push({
        code: t.code, orderId: t.orderId || null, product: t.productName || '-',
        duration: t.selectedDays ? `${t.selectedDays} ${t.selectedUnit === 'h' ? 'jam' : 'hari'}` : '-',
        price: Number(t.price) || 0, status: t.status, label: lb.text, tone: lb.tone,
        created: fmt(t.createdAt), paid: t.paidAt ? fmt(t.paidAt) : '-',
        keySent: t.status === 'done' && !!t.key
      });
    }
    res.render('pages/track', { q: raw, results, missing, error: null });
  } catch (e) {
    console.error('[track]', e.message);
    res.render('pages/track', { q: raw, results: null, missing: [], error: 'Gagal memuat data, coba lagi sebentar.' });
  }
});

app.get('/invoice', async (req, res) => {
  if (!checkInvoiceRateLimit(req.ip)) {
    return res.render('pages/invoice', { transaction: null, error: 'Terlalu banyak pencarian. Coba lagi dalam 5 menit.' });
  }
  const code = normalizeOrderCode(req.query.code);
  if (code) {
    const transactions = await readTxFresh();
    const transaction = transactions.find(t => t.code === code);
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
  const code = normalizeOrderCode(req.body && req.body.code);
  const transactions = await readTxFresh();
  const transaction = code ? transactions.find(t => t.code === code) : null;

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

// BUG FIX (audit 19 Sep 2026): tombol "Export Database" / "Import Database"
// di admin.ejs (lihat <a href="/admin/export"> dan fetch('/admin/import'))
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

// Import: hanya menerima key yang memang dikenal (EXPORTABLE_DB_FILES)
// mencegah upload file JSON acak/berbahaya menimpa koleksi yang tidak
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
app.get('/admin/db-status', requireAdmin, async (req, res) => {
  try {
    const status = await db.getDbStatus();
    res.json(status);
  } catch (e) {
    res.json({ connected: false, errorMsg: e.message });
  }
});
// Riwayat transaksi LENGKAP untuk tab Transaksi admin (paginasi + filter di server).
// Sebelumnya /admin cuma mengirim 20 transaksi terakhir ke halaman, jadi riwayat
// lama (sejak awal toko jalan) tidak kelihatan sama sekali di panel.
app.get('/admin/transactions/page', requireAdmin, async (req, res) => {
  res.set('Cache-Control', 'no-store, max-age=0');
  try {
    const all = await readTxFresh(2000);
    const status = String(req.query.status || 'all');
    const q = String(req.query.q || '').toLowerCase().trim();
    const from = req.query.from ? Date.parse(req.query.from) : null;
    const to = req.query.to ? Date.parse(req.query.to) + 86400000 : null;
    const rows = (Array.isArray(all) ? all : []).filter(t => {
      if (!t) return false;
      if (status !== 'all' && t.status !== status) return false;
      const c = Date.parse(t.createdAt || '');
      if (from && !(c >= from)) return false;
      if (to && !(c < to)) return false;
      if (q && ![t.orderId, t.code, t.customerName, t.wa, t.productName, t.id].join(' ').toLowerCase().includes(q)) return false;
      return true;
    }).sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
    const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 50));
    const items = rows.slice(offset, offset + limit).map(t => ({
      id: t.id, code: t.code, type: t.type || null, productName: t.productName, status: t.status,
      outOfStock: !!t.outOfStock, customerName: t.customerName, wa: t.wa, price: Number(t.price) || 0,
      time: t.time, createdAt: t.createdAt, paidAt: t.paidAt || null, key: t.key || null,
      selectedDays: t.selectedDays || null, selectedUnit: t.selectedUnit || null, orderId: t.orderId || null
    }));
    res.json({ success: true, total: rows.length, offset, items, hasMore: offset + items.length < rows.length });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
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
    if (!adminProviderSnapshot) adminProviderSnapshot = getDisplayDripstoreSnapshot(settings);
    if (!adminProviderSnapshot) {
      adminProviderSnapshot = await getDripstoreCatalogSnapshot(settings, { maxWaitMs: 4500 }).catch(() => null);
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

// PARSE DESKRIPSI PRODUK (auto-format ringan, diminta client 22 Agu 2026
// referensi screenshot fixaonly.com: badge tagline, daftar fitur cheat,
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
    await writeDB('transactions.json', transactions, { deletedIds: [req.params.id] });
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
    await writeDB('transactions.json', transactions, { trusted: true });
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

// ── MAINTENANCE (ala ThanHub: kartu menampilkan 'Maintenance' + tombol nonaktif) ──
// Per produk: product.maintenance. Seluruh toko: settings.storeMaintenance.
// Penegakan ada di server (create-order & wallet/buy), jadi langsung berlaku walau HTML beranda masih ter-cache CDN.
app.post('/admin/product/maintenance/:id', requireAdmin, async (req, res) => {
  try {
    const next = await withProductsWriteLock(async () => {
      const list = await readFresh('products.json');
      const pr = list.find(x => x.id === req.params.id);
      if (!pr) return null;
      pr.maintenance = !pr.maintenance;
      await writeDB('products.json', list);
      return pr.maintenance;
    });
    if (next === null) return res.json({ success: false, message: 'Produk tidak ditemukan' });
    res.json({ success: true, maintenance: next, message: next ? 'Produk masuk mode maintenance' : 'Maintenance produk dimatikan' });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/settings/store-maintenance', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    settings.storeMaintenance = !settings.storeMaintenance;
    await writeDB('settings.json', settings);
    res.json({ success: true, storeMaintenance: settings.storeMaintenance, message: settings.storeMaintenance ? 'Mode maintenance TOKO aktif' : 'Mode maintenance TOKO dimatikan' });
  } catch (e) { res.json({ success: false, message: e.message }); }
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
    const { siteName, gamePanelName, about, marqueeText, whatsapp, telegram, instagram, csWhatsapp, email, downloadUrl, waChannel, adminUsername, categories, categoryLabels, logoUrl, logoTextUrl, fonnteToken, buyerGroupName, buyerGroupUrl, resellerGroupName, resellerGroupUrl, siteUrl, seoKeywords, paymentMethods } = req.body;

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
    if (csWhatsapp !== undefined) settings.contact.csWhatsapp = String(csWhatsapp).replace(/[^0-9]/g, '').slice(0, 20);
    if (instagram !== undefined) settings.contact.instagram = String(instagram).trim().slice(0, 200);

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
    const { apiKey, project, mode, apiBaseUrl, qrisMode, webhookSecret } = req.body;

    settings.pakasir = {
      apiKey: apiKey !== undefined ? apiKey : (settings.pakasir?.apiKey || ''),
      project: project !== undefined ? project : (settings.pakasir?.project || ''),
      mode: mode || settings.pakasir?.mode || 'production',
      apiBaseUrl: apiBaseUrl !== undefined ? apiBaseUrl : (settings.pakasir?.apiBaseUrl || 'api.pakasir.com'),
      webhookSecret: webhookSecret !== undefined ? String(webhookSecret).trim() : (settings.pakasir?.webhookSecret || '')
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

// ── WijayaPay Settings (docs.wijayapay.com) ──
app.post('/admin/settings/wijayapay', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const { codeMerchant, apiKey, qrisMode } = req.body;
    settings.wijayapay = {
      codeMerchant: codeMerchant !== undefined ? String(codeMerchant).trim().slice(0, 80) : (settings.wijayapay?.codeMerchant || ''),
      // API key yang disensor di form ("••••") tidak boleh menimpa key asli
      apiKey: (apiKey && !/^[•*]+/.test(String(apiKey))) ? String(apiKey).trim().slice(0, 200) : (settings.wijayapay?.apiKey || '')
    };
    settings.apiGateway = 'wijayapay';
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


// AUDIT PEMBAYARAN PENDING (25 Sep 2026): client melapor "kebanyakan pending,
// gak otomatis" untuk gateway GensPay. GensPay TIDAK punya endpoint cek status
paymentAudit.mount(app, requireAdmin);

app.get('/admin/audit/pending-payments', requireAdmin, async (req, res) => {
  res.set('Cache-Control', 'no-store, max-age=0');
  try {
    const minAgeMinutes = Math.max(1, parseInt(req.query.minAgeMinutes, 10) || 10);
    const cutoff = Date.now() - minAgeMinutes * 60 * 1000;
    const transactions = await readFresh('transactions.json');
    const stuck = (Array.isArray(transactions) ? transactions : []).filter(t => {
      if (!t || t.status !== 'pending') return false;
      const gateway = t.paymentGateway || 'pakasir';
      if (gateway !== 'genspay') return false; // Pakasir punya endpoint cek status, tidak masuk kategori "tidak ada jalan lain"
      const created = Date.parse(t.createdAt || '');
      return Number.isFinite(created) && created < cutoff;
    }).map(t => ({
      id: t.id, code: t.code, orderId: t.orderId, type: t.type, productName: t.productName || null,
      customerName: t.customerName || null, wa: t.wa || null, userId: t.userId || null,
      price: t.price, createdAt: t.createdAt,
      ageMinutes: Math.round((Date.now() - Date.parse(t.createdAt)) / 60000)
    })).sort((a, b) => b.ageMinutes - a.ageMinutes);
    res.json({
      success: true,
      minAgeMinutes,
      totalStuck: stuck.length,
      note: stuck.length
        ? 'Transaksi di bawah masih berstatus pending lebih dari ' + minAgeMinutes + ' menit lewat GensPay (yang tidak punya endpoint cek status manual). Cek dashboard GensPay atau minta bukti bayar ke pembeli SEBELUM klik Konfirmasi Manual -- jangan asumsikan otomatis lunas.'
        : 'Tidak ada transaksi GensPay yang pending lebih dari ' + minAgeMinutes + ' menit saat ini.',
      stuck
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
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
      calls: _dsStats.calls, ok: _dsStats.ok, rateLimited: _dsStats.rateLimited, err: _dsStats.err, timeout: _dsStats.timeout,
      last429AgeSec: _dsStats.last429At ? Math.round((Date.now() - _dsStats.last429At) / 1000) : null,
      byTrigger: topCalls, microCache: _dsMicroCache.size, pendingRetryOrders: _dsStats.pendingRetryCount
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


// IMPORT VARIAN / PRODUK DARI DRIPSTORE + HARGA OTOMATIS (margin persen)
// (diminta client 4 Okt 2026)
const DS_DEFAULT_USD_RATE = 18000;
function _dsImportPrefs(settings, body = {}, currency = null) {
  const saved = settings.dripstoreImport || {};
  const num = (v, d) => { if (v === undefined || v === null || String(v).trim() === '') return d; const n = Number(String(v).replace(',', '.')); return Number.isFinite(n) ? n : d; };
  const defaultKurs = String(currency || '').toUpperCase() === 'USD' ? DS_DEFAULT_USD_RATE : 1;
  const kurs = Math.max(0, num(body.kurs, num(saved.kurs, defaultKurs))) || 1;
  const margin = Math.max(0, Math.min(1000, num(body.marginPercent, num(saved.marginPercent, 10))));
  const resRaw = body.resellerMarginPercent ?? saved.resellerMarginPercent;
  const resellerMargin = (resRaw === undefined || resRaw === null || resRaw === '') ? null : Math.max(0, Math.min(1000, num(resRaw, 0)));
  const roundDefault = kurs > 1 ? 500 : 1;
  const roundTo = Math.max(1, Math.floor(num(body.roundTo, num(saved.roundTo, roundDefault))));
  return { kurs, marginPercent: margin, resellerMarginPercent: resellerMargin, roundTo };
}

function _dsSellPrice(cost, pct, prefs) {
  if (cost === null || cost === undefined || !Number.isFinite(Number(cost))) return null;
  const raw = Number(cost) * prefs.kurs * (1 + pct / 100);
  const r = prefs.roundTo;
  return Math.max(0, Math.ceil(raw / r - 1e-9) * r);
}

function _dsVariantCost(raw) {
  const v = _dsFirst(raw || {}, ['unit_price','unitPrice','price','cost','cost_price','costPrice','price_usd','priceUsd','unitPriceUsd','unit_price_usd','cost_usd','costUsd','unit_cost','unitCost','reseller_price','resellerPrice','selling_price','sellingPrice','p']);
  return _dsParseMoney(v);
}

// Kelompokkan hasil ekstraksi provider per nama produk, buang durasi dobel.
function _dsGroupSupplier(items) {
  const groups = new Map();
  for (const it of items) {
    const name = String(it.productName || '').trim();
    if (!name) continue;
    if (!groups.has(name)) groups.set(name, { name, variants: [], dupes: 0, raw: it.raw });
    const g = groups.get(name);
    // Provider kadang kirim kelipatan 24 jam (24h/48h/168h) untuk varian "1/2/7 hari".
    // Samakan ke hari supaya cocok dengan varian toko dan tidak jadi varian dobel.
    let vDays = it.days, vUnit = it.unit;
    if (vUnit === 'h' && vDays >= 24 && vDays % 24 === 0) { vDays = vDays / 24; vUnit = 'd'; }
    const key = `${vDays}${vUnit}`;
    const cost = _dsVariantCost(it.raw);
    const ex = g.variants.find(v => `${v.days}${v.unit}` === key);
    if (ex) {
      g.dupes++;
      // durasi dobel di satu produk: simpan yang lebih murah
      if (cost !== null && (ex.cost === null || cost < ex.cost)) { ex.variantId = it.variantId; ex.cost = cost; ex.variantName = it.variantName; }
      continue;
    }
    g.variants.push({ variantId: it.variantId, variantName: it.variantName, days: vDays, unit: vUnit, cost });
  }
  const sortVar = (a, b) => (a.unit === b.unit ? a.days - b.days : (a.unit === 'h' ? -1 : 1));
  groups.forEach(g => g.variants.sort(sortVar));
  return [...groups.values()];
}

function _dsFindLocalProduct(products, group) {
  const ids = new Set(group.variants.map(v => String(v.variantId)));
  // 1) tautan variantId yang sudah ada = bukti paling kuat
  let hit = products.find(p => (p.pricingOptions || []).some(o => o.dripstoreVariantId && ids.has(String(o.dripstoreVariantId))));
  if (hit) return hit;
  // 2) nama sama persis / alias strict
  hit = products.find(p => _dsIsExactNameMatch(p.name, group.name));
  if (hit) return hit;
  // 3) pencocokan nama biasa (sama seperti auto-map)
  return products.find(p => _dsNameMatchWithAliases(p.name, group.name)) || null;
}

function _dsBuildImportPlan(products, groups, prefs, opts) {
  const plan = { newProducts: [], addVariants: [], updatePrices: [], noCost: 0, dupes: 0 };
  for (const g of groups) {
    plan.dupes += g.dupes;
    const local = _dsFindLocalProduct(products, g);
    const mkOpt = (v) => {
      const price = _dsSellPrice(v.cost, prefs.marginPercent, prefs);
      const rp = prefs.resellerMarginPercent === null ? null : _dsSellPrice(v.cost, prefs.resellerMarginPercent, prefs);
      return { days: v.days, unit: v.unit, price, reseller_price: rp, strike_price: null, dripstoreVariantId: String(v.variantId), _cost: v.cost };
    };
    if (!local) {
      if (opts.mode !== 'all') continue;
      const options = g.variants.map(mkOpt).filter(o => { if (o.price === null) { plan.noCost++; return false; } return true; });
      if (options.length) plan.newProducts.push({ name: g.name, raw: g.raw, options });
      continue;
    }
    const have = new Map((local.pricingOptions || []).map(o => [`${Number(o.days)}${o.unit === 'h' ? 'h' : 'd'}`, o]));
    const add = [];
    for (const v of g.variants) {
      const o = have.get(`${v.days}${v.unit}`);
      if (!o) {
        const no = mkOpt(v);
        if (no.price === null) { plan.noCost++; continue; }
        add.push(no);
      } else if (opts.updateExisting && String(o.dripstoreVariantId || '') === String(v.variantId)) {
        const np = _dsSellPrice(v.cost, prefs.marginPercent, prefs);
        if (np !== null && Number(o.price) !== np) plan.updatePrices.push({ productId: local.id, productName: local.name, days: v.days, unit: v.unit, from: Number(o.price), to: np, resellerTo: prefs.resellerMarginPercent === null ? undefined : _dsSellPrice(v.cost, prefs.resellerMarginPercent, prefs) });
      }
    }
    if (add.length) plan.addVariants.push({ productId: local.id, productName: local.name, options: add });
  }
  return plan;
}

async function _dsLoadSupplierGroups(force = false) {
  const settings = await readFresh('settings.json');
  if (!settings.dripstore?.apiToken) throw new Error('API Token DripStore belum dikonfigurasi di Settings');
  const resp = await dripstoreCall(settings, 'products.php');
  const items = _dsExtractProductItems(resp);
  if (!items.length) throw new Error('Daftar produk DripStore kosong / format products.php belum dikenali.');
  const currency = String(_dsFirst(items[0].raw || {}, ['currency', 'currency_code', 'cur']) || '').toUpperCase() || null;
  return { settings, groups: _dsGroupSupplier(items), rawCount: items.length, currency };
}

// Pengaman: harga provider USD tapi kurs kecil => harga jual jadi Rp1-an. Tolak.
function _dsCheckKurs(currency, prefs) {
  if (String(currency || '').toUpperCase() === 'USD' && prefs.kurs < 1000) {
    throw new Error(`Harga provider dalam USD. Isi kurs ke Rupiah (mis. ${DS_DEFAULT_USD_RATE}), bukan ${prefs.kurs}.`);
  }
}

// PREVIEW: tidak mengubah apa pun, cuma menghitung apa yang AKAN terjadi.
app.post('/admin/dripstore/import-preview', requireAdmin, async (req, res) => {
  try {
    const { settings, groups, rawCount, currency } = await _dsLoadSupplierGroups();
    const prefs = _dsImportPrefs(settings, req.body, currency);
    _dsCheckKurs(currency, prefs);
    const mode = req.body?.mode === 'all' ? 'all' : 'variants';
    const updateExisting = req.body?.updateExisting === true || req.body?.updateExisting === 'true' || req.body?.updateExisting === 'on';
    const products = await readFresh('products.json');
    const plan = _dsBuildImportPlan(products, groups, prefs, { mode, updateExisting });
    const strip = o => ({ days: o.days, unit: o.unit, cost: o._cost, price: o.price, reseller_price: o.reseller_price });
    res.json({
      success: true, prefs, currency, mode, supplierVariants: rawCount, supplierProducts: groups.length,
      newProducts: plan.newProducts.map(p => ({ name: p.name, options: p.options.map(strip) })),
      addVariants: plan.addVariants.map(p => ({ productName: p.productName, options: p.options.map(strip) })),
      updatePrices: plan.updatePrices.slice(0, 200),
      skippedNoCost: plan.noCost, skippedDupes: plan.dupes
    });
  } catch (e) {
    console.error('[dripstore import-preview]', e);
    res.json({ success: false, message: e.message });
  }
});

// EKSEKUSI: tulis ke products.json lewat single-writer lock.
app.post('/admin/dripstore/import', requireAdmin, async (req, res) => {
  try {
    const { settings, groups, currency } = await _dsLoadSupplierGroups();
    const prefs = _dsImportPrefs(settings, req.body, currency);
    _dsCheckKurs(currency, prefs);
    const mode = req.body?.mode === 'all' ? 'all' : 'variants';
    const updateExisting = req.body?.updateExisting === true || req.body?.updateExisting === 'true' || req.body?.updateExisting === 'on';
    const newStatus = req.body?.newStatus === 'active' ? 'active' : 'inactive';

    const result = await withProductsWriteLock(async () => {
      const products = await readFresh('products.json');
      const plan = _dsBuildImportPlan(products, groups, prefs, { mode, updateExisting });
      const sortOpts = (a, b) => (a.unit === b.unit ? a.days - b.days : (a.unit === 'h' ? -1 : 1));
      const clean = o => { const { _cost, ...rest } = o; return rest; };
      const rebuildItems = (p) => {
        p.pricingOptions.sort(sortOpts);
        p.items = p.pricingOptions.map(o => ({ l: `${String(p.name).toUpperCase()} ${formatDurationLabel(o.days, o.unit)}`, p: o.price, reseller_price: o.reseller_price ?? null, strike_price: o.strike_price ?? null }));
      };
      let addedVariants = 0, createdProducts = 0, updatedPrices = 0;

      for (const a of plan.addVariants) {
        const p = products.find(x => x.id === a.productId);
        if (!p) continue;
        p.pricingOptions = Array.isArray(p.pricingOptions) ? p.pricingOptions : [];
        for (const o of a.options) { p.pricingOptions.push(clean(o)); addedVariants++; }
        rebuildItems(p);
      }
      for (const u of plan.updatePrices) {
        const p = products.find(x => x.id === u.productId);
        const o = p && p.pricingOptions.find(x => Number(x.days) === u.days && (x.unit === 'h' ? 'h' : 'd') === u.unit);
        if (!o) continue;
        o.price = u.to;
        if (u.resellerTo !== undefined) o.reseller_price = u.resellerTo;
        if (o.strike_price != null && Number(o.strike_price) <= o.price) o.strike_price = null;
        rebuildItems(p);
        updatedPrices++;
      }
      for (const np of plan.newProducts) {
        const raw = np.raw || {};
        let image = String(_dsFirst(raw, ['image', 'image_url', 'imageUrl', 'thumbnail', 'logo', 'icon']) || '').trim();
        if (!image || !isValidImageUrl(image)) image = '/images/placeholder.jpg';
        const descRaw = _dsFirst(raw, ['description', 'desc', 'details']);
        const prod = {
          id: uuidv4(), name: np.name, categories: [],
          description: typeof descRaw === 'string' ? descRaw.slice(0, 4000) : '',
          image, pricingOptions: np.options.map(clean), items: [], status: newStatus,
          keys: [], channelUrl: '', downloadUrl: '', fakeSold: null, sold: 0,
          createdAt: new Date().toISOString(), importedFrom: 'dripstore'
        };
        rebuildItems(prod);
        products.push(prod);
        createdProducts++;
      }
      if (addedVariants || createdProducts || updatedPrices) await writeDB('products.json', products);
      return { addedVariants, createdProducts, updatedPrices, skippedNoCost: plan.noCost, skippedDupes: plan.dupes };
    });

    // simpan preferensi margin/kurs buat dipakai lagi
    const st = await readFresh('settings.json');
    st.dripstoreImport = prefs;
    await writeDB('settings.json', st);
    res.json({ success: true, ...result, newStatus });
  } catch (e) {
    console.error('[dripstore import]', e);
    res.json({ success: false, message: e.message });
  }
});


// Samakan dripstoreVariantId tersimpan di tiap opsi harga dengan hasil resolve dari katalog provider
// (nama produk + durasi). Menemukan ID salah seperti opsi "HG APK MOD CR" yang menyimpan ID varian XREG
// (163/166/172) -- ID itu dipakai untuk cek stok/ketersediaan, jadi stok yang tampil bisa milik produk lain.
// dryRun=true hanya menampilkan perbedaan.
app.post('/admin/dripstore/repair-variants', requireAdmin, async (req, res) => {
  try {
    const dryRun = !(req.body?.dryRun === false || req.body?.dryRun === 'false');
    const settings = await readFresh('settings.json');
    if (!settings.dripstore?.apiToken) return res.json({ success: false, message: 'API Token DripStore belum dikonfigurasi' });
    const resp = await dripstoreCall(settings, 'products.php');
    const items = _dsExtractProductItems(resp);
    const nameById = new Map(items.map(i => [String(i.variantId), `${i.productName} / ${i.variantName}`]));
    const compute = products => {
      const diffs = [];
      for (const p of products) {
        for (const o of (p.pricingOptions || [])) {
          const id = resolveDripstoreVariantForOption(resp, p.name, { days: o.days, unit: o.unit === 'h' ? 'h' : 'd' });
          if (!id) continue;
          const cur = o.dripstoreVariantId ? String(o.dripstoreVariantId) : '';
          if (cur !== String(id)) diffs.push({ productId: p.id, product: p.name, days: o.days, unit: o.unit === 'h' ? 'h' : 'd', from: cur || null, fromName: cur ? (nameById.get(cur) || '?') : null, to: String(id), toName: nameById.get(String(id)) || '?' });
        }
      }
      return diffs;
    };
    if (dryRun) {
      const diffs = compute(await readFresh('products.json'));
      return res.json({ success: true, dryRun: true, count: diffs.length, diffs: diffs.slice(0, 200) });
    }
    const result = await withProductsWriteLock(async () => {
      const products = await readFresh('products.json');
      const diffs = compute(products);
      for (const d of diffs) {
        const p = products.find(x => x.id === d.productId);
        const o = p && p.pricingOptions.find(x => Number(x.days) === Number(d.days) && (x.unit === 'h' ? 'h' : 'd') === d.unit);
        if (o) o.dripstoreVariantId = d.to;
      }
      if (diffs.length) await writeDB('products.json', products);
      return diffs.length;
    });
    res.json({ success: true, dryRun: false, fixed: result });
  } catch (e) { res.json({ success: false, message: e.message }); }
});


// Diagnosa cepat koneksi DripStore: kenapa tombol jadi "Cek stok"? Menampilkan umur snapshot, status breaker,
// dan hasil panggilan LIVE products.php (waktu + error asli).
// Paksa ambil ulang saldo+katalog DripStore sekarang (dipakai setelah top up saldo supaya stok di web langsung naik).
app.post('/admin/dripstore/refresh', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    _dsMicroCache.clear();
    _invalidateDripstoreSnapshot();
    const snap = await getDripstoreCatalogSnapshot(settings, { force: true, maxWaitMs: 9000 });
    const bal = snap && snap.balance !== undefined ? snap.balance : null;
    if (bal === null) return res.json({ success: false, message: 'Gagal mengambil saldo DripStore (cek token/koneksi). Stok di web memakai data terakhir yang valid.' });
    res.json({ success: true, balance: bal, message: 'Saldo DripStore: ' + bal + '. Stok web diperbarui; tampilan pembeli menyusul ±1-2 menit (cache halaman).' });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.get('/admin/dripstore/health', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const out = { success: true, tokenConfigured: !!settings.dripstore?.apiToken, baseUrl: settings.dripstore?.baseUrl || 'https://dripclientstore.shop/api/v1', fulfillmentMode: settings.dripstore?.fulfillmentMode || 'live' };
    const brk = dripstoreBreakerState();
    out.breaker = { open: !!brk.open, retryAfterSec: brk.retryAfterSec || 0 };
    const lg = _dsLastGood(settings);
    out.snapshotAgeMin = lg && lg.productsAt ? Math.round((Date.now() - Number(lg.productsAt)) / 60000) : null;
    out.snapshotItems = lg && lg.products ? _dsExtractProductItems(lg.products).length : 0;
    if (!out.tokenConfigured) { out.probe = { ok: false, error: 'API Token DripStore belum diisi' }; return res.json(out); }
    const t0 = Date.now();
    try {
      const resp = await dripstoreCall(settings, 'products.php');
      out.probe = { ok: true, ms: Date.now() - t0, items: _dsExtractProductItems(resp).length };
    } catch (e) { out.probe = { ok: false, ms: Date.now() - t0, error: String(e.message || e).slice(0, 300), transient: !!e.transient }; }
    res.json(out);
  } catch (e) { res.json({ success: false, message: e.message }); }
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
      if (gateway === 'wijayapay') {
        // Test koneksi ringan (GET get-payment), TIDAK membuat transaksi.
        const saved = await readFresh('settings.json');
        const cm = (req.body.codeMerchant || saved.wijayapay?.codeMerchant || '').trim();
        const key = (apiKey && !/^[•*]+/.test(String(apiKey))) ? String(apiKey).trim() : (saved.wijayapay?.apiKey || '');
        const t = await wijayapay.testConnection(cm, key);
        return res.json(t);
      }
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

// Tandai transaksi PENDING sebagai selesai TANPA fulfillment (tidak beli key ke DripStore,
// tidak kirim apa pun). Dipakai kalau admin sudah mengirim key ke pembeli lewat WA.
// Jejaknya jujur: keySource 'manual_admin', ada catatan wajib + waktu, dan TIDAK mengisi
// paidAt (supaya tidak terbaca sebagai konfirmasi pembayaran dari gateway).


// VALIDASI PENDING OTOMATIS (6 Okt 2026)
// Order dinamis yang pending berjam-jam/berhari-hari diperiksa ulang:
async function reconcilePendingOrders({ maxItems = 40, minAgeMin = 3, deadlineMs = 45000 } = {}) {
  const t0 = Date.now();
  const settings = await readFresh('settings.json');
  const all = await readFresh('transactions.json');
  let events = []; try { events = await readFresh('payment_events.json'); } catch (_) {}
  const hook = new Set();
  for (const e of (Array.isArray(events) ? events : [])) if (e && e.orderId && /^webhook\./.test(e.type || '')) hook.add(e.orderId);
  const now = Date.now();
  const cands = (Array.isArray(all) ? all : []).filter(t => t && t.status === 'pending' && !t.isStatic && (now - Date.parse(t.createdAt || 0)) >= minAgeMin * 60000)
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  const sum = { candidates: cands.length, checked: 0, finalized: 0, retry: 0, expired: 0, stillPending: 0, needsReview: 0, errors: 0, deadlineHit: false };
  const toExpire = [];
  const PAID = ['completed', 'paid', 'success', 'settlement', 'berhasil'];
  const DEAD = ['canceled', 'cancelled', 'expired', 'failed'];
  for (const t of cands) {
    if (Date.now() - t0 > deadlineMs || sum.checked >= maxItems) { sum.deadlineHit = Date.now() - t0 > deadlineMs; break; }
    const ageH = (now - Date.parse(t.createdAt)) / 3600000;
    const gateway = t.paymentGateway || settings.apiGateway || 'pakasir';
    if (gateway === 'genspay') {
      if (hook.has(t.orderId)) { sum.needsReview++; continue; }
      if (ageH > 24) toExpire.push([t, 'Ditutup otomatis: >24 jam, tidak ada notifikasi pembayaran dari GensPay']); else sum.stillPending++;
      continue;
    }
    sum.checked++;
    try {
      const r = await checkPaymentStatus(t.orderId, t.price, settings, gateway, t.providerTxnId);
      const st = String(r?.transaction?.status || r?.status || '').toLowerCase();
      if (PAID.includes(st)) {
        if (processingOrders.has(t.id)) { sum.stillPending++; continue; }
        processingOrders.add(t.id);
        try {
          const f = await finalizeOrder(t.id, settings);
          if (f.status === 'pending_retry') sum.retry++; else sum.finalized++;
          try { paymentAudit.record('order.reconciled_paid', { orderId: t.orderId, gateway, viaStatusApi: true }); } catch (_) {}
        } finally { processingOrders.delete(t.id); }
      } else if (DEAD.includes(st)) {
        toExpire.push([t, `Ditutup otomatis: ${gateway} melaporkan status ${st}`]);
      } else if (ageH > 26) {
        toExpire.push([t, 'Ditutup otomatis: >26 jam masih pending di Pakasir (dibatalkan otomatis oleh Pakasir setelah 24 jam)']);
      } else sum.stillPending++;
    } catch (e) { sum.errors++; }
    await new Promise(r => setTimeout(r, 700));
  }
  if (toExpire.length) {
    await withProductsWriteLock(async () => {
      const list = await readFresh('transactions.json');
      const ids = new Map(toExpire.map(([t, note]) => [t.id, note]));
      let n = 0;
      for (const t of list) {
        if (t && ids.has(t.id) && t.status === 'pending') { t.status = 'expired'; t.closedBy = 'system'; t.closedAt = new Date().toISOString(); t.closeNote = ids.get(t.id); delete t.qrString; n++; }
      }
      if (n) await writeDB('transactions.json', list);
      sum.expired = n;
    });
    try { paymentAudit.record('order.reconcile_expired', { count: sum.expired }); } catch (_) {}
  }
  return sum;
}
app.get('/cron/reconcile', async (req, res) => {
  const secret = process.env.CRON_SECRET || '';
  if (!secret || req.headers.authorization !== `Bearer ${secret}`) return res.status(401).json({ success: false, message: 'Unauthorized' });
  try { res.json({ success: true, ...(await reconcilePendingOrders({ maxItems: 60, deadlineMs: 50000 })) }); }
  catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.post('/admin/transactions/reconcile', requireAdmin, async (req, res) => {
  try { res.json({ success: true, ...(await reconcilePendingOrders({ maxItems: 25, deadlineMs: 40000 })) }); }
  catch (e) { res.json({ success: false, message: e.message }); }
});

// Tutup order PENDING yang jelas tidak dibayar. TIDAK mengubah apa pun jadi "done", tidak
// beli key ke DripStore, tidak kirim key. Order yang punya bukti bayar (ada event webhook
// dari gateway untuk orderId-nya) otomatis DILEWATI. dryRun=1 hanya menghitung.
app.post('/admin/transactions/close-stale-pending', requireAdmin, async (req, res) => {
  try {
    const hours = Math.max(1, Number(req.body?.olderThanHours) || 24);
    const dryRun = req.body?.dryRun === true || req.body?.dryRun === 'true' || req.body?.dryRun === 1 || req.body?.dryRun === '1';
    const cutoff = Date.now() - hours * 3600 * 1000;
    let events = [];
    try { events = await readFresh('payment_events.json'); } catch (_) {}
    const paidSignal = new Set();
    for (const e of (Array.isArray(events) ? events : [])) {
      if (!e || !e.orderId || !/^webhook\./.test(e.type || '')) continue;
      // webhook yang ditolak karena transaksi tidak ditemukan bukan bukti bayar utk order ini
      paidSignal.add(e.orderId);
    }
    const out = await withProductsWriteLock(async () => {
      const list = await readFresh('transactions.json');
      const toClose = [], kept = [];
      for (const t of list) {
        if (t.status !== 'pending') continue;
        if (t.type && t.type !== 'product') { kept.push({ code: t.code, why: 'bukan order produk' }); continue; }
        if (t.isStatic) { kept.push({ code: t.code, why: 'QRIS statis (konfirmasi manual)' }); continue; }
        const created = Date.parse(t.createdAt || '');
        if (!(created < cutoff)) { kept.push({ code: t.code, why: 'belum melewati batas waktu' }); continue; }
        if (paidSignal.has(t.orderId)) { kept.push({ code: t.code, why: 'ada event dari gateway, cek manual' }); continue; }
        toClose.push(t);
      }
      if (!dryRun && toClose.length) {
        const now = new Date().toISOString();
        for (const t of toClose) {
          t.status = 'expired';
          t.closedBy = 'admin';
          t.closedAt = now;
          t.closeNote = 'Ditutup admin: tidak ada bukti pembayaran dari gateway (tidak ada webhook), tidak ada key terkirim';
          delete t.qrString;
        }
        await writeDB('transactions.json', list);
        paymentAudit.record('order.bulk_closed_unpaid', { count: toClose.length, olderThanHours: hours, by: 'admin' });
      }
      return { closed: toClose.length, kept: kept.length, keptReasons: kept.slice(0, 50), sample: toClose.slice(0, 10).map(t => ({ code: t.code, product: t.productName, price: t.price, createdAt: t.createdAt })) };
    });
    res.json({ success: true, dryRun, olderThanHours: hours, ...out });
  } catch (e) { res.json({ success: false, message: e.message }); }
});

app.post('/admin/transaction/manual-done/:id', requireAdmin, async (req, res) => {
  try {
    const note = String(req.body?.note || '').trim().slice(0, 300);
    if (note.length < 3) return res.json({ success: false, message: 'Isi catatan singkat (mis. "key sudah dikirim via WA 3/10").' });
    const list = await readFresh('transactions.json');
    const tx = list.find(t => t.id === req.params.id);
    if (!tx) return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
    if (tx.status === 'done') return res.json({ success: false, message: 'Transaksi sudah selesai' });
    if (tx.status !== 'pending') return res.json({ success: false, message: 'Hanya transaksi Pending yang bisa ditandai' });
    tx.status = 'done';
    tx.keySource = 'manual_admin';
    tx.manualNote = note;
    tx.manualResolvedAt = new Date().toISOString();
    delete tx.qrString;
    tx.confirmedBy = 'admin';
    await writeDB('transactions.json', list);
    paymentAudit.record('order.manual_resolved', { orderId: tx.orderId || tx.id, note, by: 'admin' });
    res.json({ success: true });
  } catch (e) { res.json({ success: false, message: e.message }); }
});
app.post('/admin/transaction/confirm/:id', requireAdmin, async (req, res) => {
  try {
    const settings = await readFresh('settings.json');
    const result = await finalizeOrder(req.params.id, settings);
    paymentAudit.record('order.manual_confirm', { orderId: req.params.id, result: result.status, type: result.type || null, by: 'admin' });
    if (result.status === 'not_found') return res.json({ success: false, message: 'Transaksi tidak ditemukan' });
    if (result.status === 'already_done') return res.json({ success: false, message: 'Transaksi sudah selesai' });
    if (result.status === 'already_processing') return res.json({ success: false, message: 'Transaksi sedang diproses di request lain. Tunggu sebentar.' });
    if (result.status === 'pending_retry') return res.json({ success: false, retry: true, message: 'DripStore lagi lambat/limit (timeout). Key belum dikirim & saldo DripStore belum terpotong. Coba lagi 1-2 menit. Kalau key sudah dikirim lewat WA, pakai tombol "Tandai Diproses".' });
    if (result.status !== 'done') return res.json({ success: false, message: 'Transaksi belum dapat diproses (status: ' + result.status + ')' });

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

// HALAMAN INFORMASI (Cara Beli, FAQ, Syarat & Ketentuan)
// diminta client 21 Agu 2026 -- sebelumnya semua link footer "Informasi"
app.get('/informasi', (req, res) => {
  const section = ['cara-beli', 'faq', 'syarat'].includes(req.query.tab) ? req.query.tab : 'cara-beli';
  if (!SITE_CHALLENGE_ON) res.set('Cache-Control', 'public, max-age=0, s-maxage=300, stale-while-revalidate=3600');
  res.render('pages/informasi', { activeTab: section });
});


// API endpoints
app.get('/api/products', async (req, res) => {
  res.set('Cache-Control', 'public, max-age=60, s-maxage=60, stale-while-revalidate=300');
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
  res.set('Cache-Control', 'public, max-age=60, s-maxage=60, stale-while-revalidate=300');
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
  res.set('Cache-Control', 'private, no-store');
  const transactions = readDB('transactions.json');
  res.json(transactions);
});

app.get('/api/testimonials', async (req, res) => {
  // (admin-only: tidak boleh di-cache CDN)
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

  // Hanya testimoni nyata (pembeli) + yang ditambah admin; tidak ada lagi
  // entri palsu hardcode.
  res.json(filtered.slice(0, 30));
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
    const { name, username, rating, text, product, verified, featured, date: customDate } = req.body;
    const testimonials = await readFresh('testimonials.json');

    // FIX (bug 24 Agu 2026): `product` sekarang berisi ID produk (dari
    // dropdown di form admin, bukan lagi text bebas -- lihat catatan
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
      date: (customDate && !isNaN(Date.parse(customDate)) && Date.parse(customDate) <= Date.now()) ? new Date(customDate).toISOString() : new Date().toISOString(),
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




app.get('/api/notifications', (req, res) => {
  res.set('Cache-Control', 'public, max-age=60, s-maxage=60, stale-while-revalidate=300');
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

// AUTO GAMBAR PRODUK DENGAN GEMINI (4 Okt 2026)
// Admin upload banyak gambar -> /admin/ai-images/match (1 gambar per request, supaya

const _aiImgHits = new Map();

function _geminiModels() {
  const list = String(process.env.GEMINI_MODELS || process.env.GEMINI_MODEL || 'gemini-3.1-flash-lite,gemini-2.5-flash')
    .split(',').map(x => x.trim()).filter(Boolean);
  return [...new Set(list)];
}




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
