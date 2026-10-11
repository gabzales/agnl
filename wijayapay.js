/**
 * WijayaPay — klien API (docs.wijayapay.com). Sama dengan implementasi di ThanHubStore,
 * ditulis ulang memakai modul https bawaan Node (tanpa dependency baru).
 *
 * Base URL : https://gateway.wijayapay.com
 *   GET  /api/get-payment        daftar channel aktif (dipakai Test Koneksi, tidak membuat transaksi)
 *   POST /api/transaction/create buat transaksi QRIS (ref_id = orderId kita sendiri)
 *   GET  /api/get-status         status: pending | paid | expired
 *
 * X-Signature (request & webhook) = md5(code_merchant + api_key + ref_id)  — rumus resmi
 * WijayaPay. MD5 relatif lemah, jadi webhook juga dicek nominalnya terhadap database kita
 * dan IP pengirim dicatat (whitelist resmi: 45.158.126.118).
 *
 * Kredensial disimpan di settings.wijayapay = { codeMerchant, apiKey } (Admin → QRIS).
 */
const https = require('https');
const crypto = require('crypto');

const HOST = 'gateway.wijayapay.com';
const WEBHOOK_IP_WHITELIST = ['45.158.126.118'];

function getConfig(settings) {
  const w = (settings && settings.wijayapay) || {};
  return {
    codeMerchant: String(w.codeMerchant || process.env.WIJAYAPAY_CODE_MERCHANT || '').trim(),
    apiKey: String(w.apiKey || process.env.WIJAYAPAY_API_KEY || '').trim()
  };
}

function isConfigured(settings) {
  const c = getConfig(settings);
  return !!(c.codeMerchant && c.apiKey);
}

function computeSignature(refId, cfg) {
  return crypto.createHash('md5').update(`${cfg.codeMerchant}${cfg.apiKey}${refId}`).digest('hex');
}

function request(method, path, { query, body, headers, timeout = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    const qs = query ? '?' + new URLSearchParams(query).toString() : '';
    const payload = body ? JSON.stringify(body) : null;
    const req = https.request({
      hostname: HOST, port: 443, path: path + qs, method,
      headers: Object.assign({ Accept: 'application/json' }, payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}, headers || {}),
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
    req.on('timeout', () => req.destroy(new Error('WijayaPay timeout')));
    req.on('error', (e) => reject(new Error('WijayaPay network error: ' + e.message)));
    if (payload) req.write(payload);
    req.end();
  });
}

/** Test koneksi ringan (tidak membuat transaksi). */
async function testConnection(codeMerchant, apiKey) {
  if (!codeMerchant || !apiKey) return { success: false, message: 'Code Merchant / API Key WijayaPay belum diisi.' };
  try {
    const r = await request('GET', '/api/get-payment', { query: { code_merchant: codeMerchant, api_key: apiKey }, timeout: 10000 });
    const b = r.json;
    if (b && b.success && Array.isArray(b.data)) {
      const active = b.data.filter(c => c.status === 'active');
      const qris = active.find(c => c.code === 'QRIS');
      return {
        success: true,
        qrisActive: !!qris,
        message: `Koneksi OK! ${active.length} channel aktif.` + (qris ? ' Channel QRIS aktif.' : ' ⚠️ Channel QRIS BELUM aktif di akun ini — aktifkan dulu di dashboard WijayaPay.')
      };
    }
    return { success: false, message: (b && b.message) || `WijayaPay merespons tidak sesuai dugaan (HTTP ${r.http}).` };
  } catch (e) {
    return { success: false, message: e.message };
  }
}

/**
 * Buat transaksi QRIS. orderId dipakai LANGSUNG sebagai ref_id.
 * Mengembalikan bentuk yang sama dengan createQRISPayment* lain di server.js.
 */
async function createTransaction(settings, orderId, amount) {
  const cfg = getConfig(settings);
  if (!cfg.codeMerchant || !cfg.apiKey) throw new Error('Code Merchant / API Key WijayaPay belum dikonfigurasi');
  const refId = String(orderId);
  const appUrl = String(process.env.APP_URL || (process.env.VERCEL_PROJECT_PRODUCTION_URL ? 'https://' + process.env.VERCEL_PROJECT_PRODUCTION_URL : '')).trim().replace(/\/+$/, '');
  const callbackUrl = /^https?:\/\//i.test(appUrl) ? `${appUrl}/webhook/wijayapay` : null;
  const r = await request('POST', '/api/transaction/create', {
    headers: { 'X-Signature': computeSignature(refId, cfg) },
    body: Object.assign({ code_merchant: cfg.codeMerchant, api_key: cfg.apiKey, ref_id: refId, code_payment: 'QRIS', nominal: Math.round(Number(amount)) }, callbackUrl ? { callback_url: callbackUrl } : {})
  });
  const b = r.json, d = b && b.data;
  if (!b || !b.success || !d || !d.qr_string) {
    throw new Error((b && b.message) || `WijayaPay error (HTTP ${r.http}): ${String(r.text).slice(0, 150)}`);
  }
  return {
    qr_string: d.qr_string,
    // total_bayar = nominal yang wajib dibayar pembeli (bisa > amount kalau fee dibebankan ke pembeli)
    total_payment: Number(d.total_bayar) || amount,
    expired_at: d.expired || null,
    txn_id: d.trx_reference || null
  };
}

/**
 * Cek status by ref_id. SENGAJA tidak memakai field `success` di hasil: pemanggil di server.js
 * menganggap `r.success === true` berarti lunas (perilaku Pakasir), jadi hanya `status` yang dikembalikan.
 */
async function checkStatus(settings, orderId) {
  const cfg = getConfig(settings);
  if (!cfg.codeMerchant || !cfg.apiKey) throw new Error('Code Merchant / API Key WijayaPay belum dikonfigurasi');
  const r = await request('GET', '/api/get-status', { query: { code_merchant: cfg.codeMerchant, api_key: cfg.apiKey, ref_id: String(orderId) }, timeout: 8000 });
  if (!r.json) throw new Error(`WijayaPay get-status: response tidak valid (HTTP ${r.http})`);
  const status = String(r.json.status_pembayaran || 'pending').toLowerCase().trim();
  return { status };
}

function verifyWebhookSignature(settings, refId, signatureHeader) {
  const cfg = getConfig(settings);
  if (!cfg.codeMerchant || !cfg.apiKey || !signatureHeader || !refId) return false;
  const a = Buffer.from(computeSignature(String(refId), cfg)), b = Buffer.from(String(signatureHeader));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function isWhitelistedIp(ip) {
  return WEBHOOK_IP_WHITELIST.includes(String(ip || '').replace(/^::ffff:/, ''));
}

module.exports = { isConfigured, testConnection, createTransaction, checkStatus, verifyWebhookSignature, isWhitelistedIp, getConfig };
