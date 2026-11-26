/**
 * AutoGopay — klien API QRIS GoPay (https://autogopay.site/docs).
 *
 * Base URL : https://v1-gateway.autogopay.site
 *   POST /qris/generate   buat QRIS dinamis  { amount }                  -> data.{transaction_id, order_id, amount, qr_string}
 *   POST /qris/status     cek status         { transaction_id }          -> data.status (settlement = lunas)
 *   POST /qris/cancel     batalkan pending   { transaction_id }
 * Auth     : Authorization: Bearer <API_KEY>
 * Webhook  : POST ke URL Callback di dashboard AutoGopay, header X-Signature = HMAC-SHA256(rawBody, secret = API key) hex.
 *
 * Catatan penting:
 *  - URL Callback TIDAK dikirim per transaksi; owner wajib mengisinya SEKALI di dashboard AutoGopay.
 *  - "success: true" di level atas hanya berarti request berhasil, BUKAN lunas. Lunas = status settlement.
 *  - Kredensial disimpan di settings.autogopay = { apiKey } (Admin -> QRIS) atau env AUTOGOPAY_API_KEY.
 *  - Modul ini hanya memakai https bawaan Node (tanpa dependency baru).
 */
const https = require('https');
const crypto = require('crypto');

const HOST = 'v1-gateway.autogopay.site';

function getConfig(settings) {
  const a = (settings && settings.autogopay) || {};
  return { apiKey: cleanKey(a.apiKey || process.env.AUTOGOPAY_API_KEY || '') };
}
function isConfigured(settings) { return !!getConfig(settings).apiKey; }

// Buang spasi/newline/kutip dan awalan "Bearer " yang sering ikut tersalin dari kotak "Header" di dashboard.
function cleanKey(v) {
  return String(v || '').trim().replace(/^["']+|["']+$/g, '').replace(/^authorization\s*:\s*/i, '').replace(/^bearer\s+/i, '').trim();
}

/**
 * Validasi bentuk API key SEBELUM disimpan / dites. Mengembalikan { ok, key, message }.
 * Pesan ditulis untuk owner awam: apa yang salah dan apa yang harus dilakukan.
 */
function validateApiKeyFormat(raw) {
  const original = String(raw || '').trim();
  if (!original) return { ok: false, key: '', message: 'API key masih kosong. Salin dari dashboard AutoGopay > Dokumentasi > Autentikasi > baris "API key" (Tampilkan > Salin).' };
  if (/\s/.test(cleanKey(original))) return { ok: false, key: '', message: 'API key mengandung spasi / baris baru. Salin HANYA nilai key-nya (satu baris, diawali agp_), bukan seluruh kotak.' };
  const key = cleanKey(original);
  if (/^https?:\/\//i.test(key)) return { ok: false, key: '', message: 'Yang tertempel adalah URL, bukan API key. API key diawali agp_ (dashboard > Dokumentasi > Autentikasi).' };
  if (/^(content-type|x-api-key|header)/i.test(key)) return { ok: false, key: '', message: 'Yang tertempel adalah isi kotak "Header", bukan API key. Salin dari baris "API key" (Tampilkan > Salin).' };
  if (!/^agp_/i.test(key)) return { ok: false, key, message: 'API key AutoGopay biasanya diawali "agp_". Pastikan kamu menyalin dari baris "API key", bukan dari kotak lain.' };
  if (key.length < 20) return { ok: false, key, message: 'API key terlalu pendek, kemungkinan tidak tersalin utuh. Salin ulang lewat tombol Salin di dashboard.' };
  if (!/^[A-Za-z0-9_\-.]+$/.test(key)) return { ok: false, key, message: 'API key berisi karakter yang tidak lazim. Salin ulang lewat tombol Salin di dashboard.' };
  return { ok: true, key, message: 'Format API key benar.' };
}

// APP_URL sering salah tempel (mis. "https://https//www.http://domain"). Dibersihkan + divalidasi di sini.
function normalizeAppUrl(raw) {
  let u = String(raw || '').trim();
  if (!u) return '';
  const m = u.match(/(https?:\/\/)(?!.*https?:\/\/)(.+)$/i); // ambil http(s):// TERAKHIR
  if (m) u = m[1] + m[2];
  u = u.replace(/^(https?:)\/+/i, '$1//').replace(/\/+$/, '');
  return u;
}
function getAppUrl() {
  const raw = process.env.APP_URL || (process.env.VERCEL_PROJECT_PRODUCTION_URL ? 'https://' + process.env.VERCEL_PROJECT_PRODUCTION_URL : '');
  return normalizeAppUrl(raw);
}
function checkAppUrl() {
  const raw = String(process.env.APP_URL || '').trim();
  const url = getAppUrl();
  if (!url) return { ok: false, url: '', message: 'Env APP_URL belum diisi di Vercel. Isi dengan domain toko (contoh https://namatoko.com) lalu Redeploy.' };
  let p; try { p = new URL(url); } catch (_) { return { ok: false, url, message: 'APP_URL tidak valid: "' + raw + '". Isi satu URL saja, contoh https://namatoko.com' }; }
  if (p.protocol !== 'https:') return { ok: false, url, message: 'APP_URL harus HTTPS (AutoGopay hanya menerima Callback HTTPS). Sekarang: ' + url };
  if (!p.hostname.includes('.') || /^(localhost|127\.|10\.|192\.168\.)/.test(p.hostname)) return { ok: false, url, message: 'APP_URL mengarah ke alamat lokal (' + p.hostname + '). Pakai domain publik toko.' };
  if (raw && raw.replace(/\/+$/, '') !== url) return { ok: true, warn: true, url, message: 'APP_URL di Vercel salah tempel ("' + raw + '"), tapi otomatis dibersihkan jadi ' + url + '. Sebaiknya benahi di Vercel.' };
  return { ok: true, url, message: 'APP_URL benar: ' + url };
}
function callbackUrl() { const u = getAppUrl(); return u ? u + '/webhook/autogopay' : ''; }

function request(method, path, { body, apiKey, timeout = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = https.request({
      hostname: HOST, port: 443, path, method,
      headers: Object.assign({ Accept: 'application/json', Authorization: 'Bearer ' + apiKey }, payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
      timeout
    }, (res) => {
      let data = '';
      res.on('data', c => { data += c; if (data.length > 200000) req.destroy(new Error('Response terlalu besar')); });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (_) { /* biarkan null */ }
        resolve({ http: res.statusCode, json, text: data });
      });
    });
    req.on('timeout', () => req.destroy(new Error('AutoGopay timeout (tidak menjawab dalam ' + (timeout / 1000) + ' detik)')));
    req.on('error', (e) => reject(new Error('AutoGopay network error: ' + e.message)));
    if (payload) req.write(payload);
    req.end();
  });
}

// Terjemahan error HTTP -> kalimat yang bisa langsung ditindaklanjuti owner.
function explainHttp(r) {
  const apiMsg = r && r.json && (r.json.message || r.json.error || (r.json.data && r.json.data.message));
  if (r.http === 401) return 'API key ditolak (HTTP 401): key salah / sudah diganti di dashboard AutoGopay. Salin ulang dari Dokumentasi > Autentikasi.';
  if (r.http === 403) return 'Ditolak (HTTP 403): fitur Whitelist IP di dashboard AutoGopay masih aktif (IP Vercel selalu berubah) atau yang tersalin kotak "Header". Matikan Whitelist IP, dan pastikan yang dipakai nilai API key (agp_...).';
  if (r.http === 429) return 'Terlalu banyak request ke AutoGopay (HTTP 429). Tunggu 1 menit lalu coba lagi.';
  if (r.http >= 500) return 'Server AutoGopay sedang bermasalah (HTTP ' + r.http + '). Coba lagi beberapa menit lagi.';
  return (apiMsg ? String(apiMsg) : 'AutoGopay merespons tidak sesuai dugaan') + ' (HTTP ' + r.http + ')';
}

/**
 * Test koneksi TANPA membuat transaksi: panggil /qris/status dengan transaction_id palsu.
 *  - 401 / 403  -> key salah / IP diblok
 *  - lainnya    -> key DITERIMA (transaksi palsu wajar "tidak ditemukan")
 * Hasil berupa checklist { checks:[{ok,label,detail}], success }.
 */
async function testConnection(apiKeyInput) {
  const checks = [];
  const fmt = validateApiKeyFormat(apiKeyInput);
  checks.push({ ok: fmt.ok, label: 'Format API key', detail: fmt.message });
  if (!fmt.ok) return { success: false, checks, message: fmt.message };

  let reachable = false, authOk = false, authMsg = '';
  try {
    const r = await request('POST', '/qris/status', { apiKey: fmt.key, body: { transaction_id: 'cek-koneksi-' + Date.now() }, timeout: 10000 });
    reachable = true;
    if (r.http === 401 || r.http === 403 || r.http === 429 || r.http >= 500) { authMsg = explainHttp(r); }
    else { authOk = true; authMsg = 'API key diterima oleh AutoGopay.'; }
  } catch (e) { authMsg = e.message; }
  checks.push({ ok: reachable, label: 'Server AutoGopay terjangkau', detail: reachable ? 'v1-gateway.autogopay.site merespons.' : authMsg });
  if (reachable) checks.push({ ok: authOk, label: 'API key valid', detail: authMsg });

  const app = checkAppUrl();
  checks.push({ ok: app.ok, warn: !!app.warn, label: 'APP_URL (domain toko)', detail: app.message });
  const cb = callbackUrl();
  checks.push({ ok: !!cb && app.ok, warn: true, label: 'URL Callback yang harus diisi di dashboard AutoGopay', detail: cb ? cb + '  (isi PERSIS ini, wajib HTTPS, tanpa redirect. Tes ini tidak bisa memastikan kamu sudah mengisinya.)' : 'Belum bisa dihitung karena APP_URL belum benar.' });

  const success = reachable && authOk && app.ok;
  return {
    success, checks, callbackUrl: cb,
    message: success
      ? 'Siap dipakai: API key valid dan APP_URL benar. Langkah terakhir: pastikan URL Callback di dashboard AutoGopay sudah diisi (lihat kotak Webhook URL di bawah).'
      : 'Belum siap: perbaiki poin yang bertanda silang di bawah.'
  };
}

/**
 * Buat QRIS. Bentuk balikan sama dengan gateway lain di server.js:
 * { qr_string, total_payment, expired_at, txn_id }.
 */
async function createTransaction(settings, orderId, amount) {
  const cfg = getConfig(settings);
  if (!cfg.apiKey) throw new Error('API key AutoGopay belum diisi (Admin > QRIS > AutoGopay).');
  const nominal = Math.round(Number(amount));
  if (!Number.isFinite(nominal) || nominal <= 0) throw new Error('Nominal tidak valid untuk AutoGopay: ' + amount);
  const r = await request('POST', '/qris/generate', { apiKey: cfg.apiKey, body: { amount: nominal } });
  const b = r.json, d = b && b.data;
  if (r.http < 200 || r.http >= 300 || !b || b.success === false || !d || !(d.qr_string || d.qris_string) || !d.transaction_id) {
    throw new Error(r.http >= 400 || !b ? explainHttp(r) : ((b && b.message) || 'AutoGopay tidak mengembalikan QR (respons: ' + String(r.text).slice(0, 150) + ')'));
  }
  return {
    qr_string: d.qr_string || d.qris_string,
    // Nominal yang WAJIB dibayar pembeli menurut AutoGopay (bisa memuat kode unik); dipakai untuk validasi webhook.
    total_payment: Number(d.amount) || nominal,
    expired_at: d.expired_at || d.expired || new Date(Date.now() + 15 * 60 * 1000).toISOString(),
    txn_id: String(d.transaction_id),
    gateway_order_id: d.order_id ? String(d.order_id) : null
  };
}

// Samakan status AutoGopay ke kosakata yang dipahami server.js (paid / expired / canceled / failed / pending).
function normalizeStatus(s) {
  const v = String(s || '').toLowerCase().trim();
  if (['settlement', 'settled', 'success', 'paid', 'completed', 'capture'].includes(v)) return 'settlement';
  if (['expire', 'expired', 'timeout'].includes(v)) return 'expired';
  if (['cancel', 'canceled', 'cancelled'].includes(v)) return 'canceled';
  if (['deny', 'denied', 'failure', 'failed'].includes(v)) return 'failed';
  return v || 'pending';
}

/**
 * Cek status by transaction_id. SENGAJA hanya mengembalikan { status } (tanpa `success`) karena pemanggil
 * di server.js menganggap r.success === true berarti lunas.
 */
async function checkStatus(settings, transactionId) {
  const cfg = getConfig(settings);
  if (!cfg.apiKey) throw new Error('API key AutoGopay belum diisi');
  if (!transactionId) throw new Error('transaction_id AutoGopay tidak ada di transaksi ini');
  const r = await request('POST', '/qris/status', { apiKey: cfg.apiKey, body: { transaction_id: String(transactionId) }, timeout: 8000 });
  if (r.http === 401 || r.http === 403) throw new Error(explainHttp(r));
  if (!r.json) throw new Error('AutoGopay /qris/status: response tidak valid (HTTP ' + r.http + ')');
  const d = r.json.data || r.json.transaction || {};
  const pick = (...c) => c.find(x => typeof x === 'string' && x.trim());
  // r.json.status === 'success' di level atas = request berhasil (bukan lunas) -> diabaikan.
  const raw = pick(d.transaction_status, d.status, r.json.transaction_status);
  return { status: normalizeStatus(raw), amount: Number(d.amount) || null };
}

function verifyWebhookSignature(settings, rawBody, signatureHeader) {
  const cfg = getConfig(settings);
  if (!cfg.apiKey || !signatureHeader || typeof rawBody !== 'string' || !rawBody) return false;
  const sig = String(signatureHeader).trim().replace(/^sha256=/i, '').toLowerCase();
  const mine = crypto.createHmac('sha256', cfg.apiKey).update(rawBody).digest('hex');
  const a = Buffer.from(mine), b = Buffer.from(sig);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

module.exports = { isConfigured, getConfig, cleanKey, validateApiKeyFormat, normalizeAppUrl, getAppUrl, checkAppUrl, callbackUrl, testConnection, createTransaction, checkStatus, normalizeStatus, verifyWebhookSignature };
