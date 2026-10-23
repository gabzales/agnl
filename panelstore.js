'use strict';
/**
 * Provider tambahan: panelstore.shop (API reseller v1), dipakai bersama DripStore & Bantibhaiya.
 *   POST JSON ke /api/v1/index.php:
 *     { key, action: "order", pid, quantity, custom_notes }
 *   Sukses : { status: "success", license_key, message }
 *   Gagal  : { status: "error",   message }
 * Per durasi produk disimpan: opt.psProductId (PID di panelstore, diisi di Edit Produk).
 * API tidak punya cek stok, jadi "tersedia" = terpetakan + kunci terisi + tidak sedang
 * ditandai habis (10 menit setelah pembelian gagal karena stok/saldo).
 * Kunci dibaca dari settings.panelstore {apiKey, url}; fallback env PANELSTORE_*.
 * JANGAN hardcode API key di sini.
 */
const DEFAULT_URL = 'https://www.panelstore.shop/api/v1/index.php';
const DOWN_MS = 10 * 60000;
const VIRTUAL_STOCK = 20; // stok "maya" yang ditampilkan ke pembeli bila provider tersedia

let cfg = {};
function setConfig(c) { cfg = c && typeof c === 'object' ? c : {}; }
const apiKey = () => String(cfg.apiKey || process.env.PANELSTORE_API_KEY || '').trim();
const url = () => String(cfg.url || process.env.PANELSTORE_URL || DEFAULT_URL).trim() || DEFAULT_URL;
const configured = () => !!apiKey();

const mapping = (opt) => {
  const pid = String(opt?.psProductId ?? '').trim();
  return pid ? { pid } : null;
};

const down = new Map(); // pid -> { until, msg }
function markDown(opt, msg) { const m = mapping(opt); if (m) down.set(m.pid, { until: Date.now() + DOWN_MS, msg: String(msg || '').slice(0, 120) }); }
function clearDown(opt) { const m = mapping(opt); if (m) down.delete(m.pid); }
function downInfo(opt) {
  const m = mapping(opt); if (!m) return null;
  const d = down.get(m.pid);
  if (d && d.until > Date.now()) return d;
  if (d) down.delete(m.pid);
  return null;
}

/** Alasan opsi ini TIDAK bisa dipakai lewat Panelstore sekarang (null = bisa). */
function why(opt) {
  if (!configured()) return 'API Key Panelstore belum diisi';
  if (!mapping(opt)) return 'belum dipetakan ke Panelstore (PID kosong)';
  const d = downInfo(opt);
  if (d) return `ditandai habis sampai ${new Date(d.until).toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Jakarta' })} WIB (${d.msg || 'stok'})`;
  return null;
}
const usable = (opt) => why(opt) === null;
const isStockError = (msg) => /stock|stok|habis|out of|insufficient|saldo|balance|not available|unavailable|sold/i.test(String(msg || ''));

const firstStr = (v) => (typeof v === 'string' && v.trim() ? v.trim() : null);
function collectKeys(j) {
  const out = [];
  const take = (v) => {
    if (typeof v === 'string') { if (v.trim()) out.push(v.trim()); }
    else if (Array.isArray(v)) v.forEach(take);
    else if (v && typeof v === 'object') take(v.license_key ?? v.key ?? v.license ?? v.serial ?? null);
  };
  const d = j && j.data && typeof j.data === 'object' ? j.data : {};
  for (const src of [j, d]) for (const k of ['license_key', 'license_keys', 'keys', 'key', 'license', 'licenses', 'serial']) if (src[k] !== undefined && !out.length) take(src[k]);
  return out;
}
const isSuccess = (j) => j.success === true || j.status === true || /^(success|ok|1|true)$/i.test(String(j.status ?? ''));
const isFailure = (j) => !!j.error || j.success === false || j.status === false || /^(error|fail|failed|0|false)$/i.test(String(j.status ?? ''));

async function post(payload, timeoutMs) {
  const res = await fetch(url(), {
    method: 'POST', signal: AbortSignal.timeout(timeoutMs),
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ key: apiKey(), ...payload }),
  });
  return { res, text: (await res.text()).trim() };
}

/**
 * Beli SATU key. Dipanggil hanya setelah pembayaran terkonfirmasi.
 * @param {object} opt   opsi harga produk (butuh opt.psProductId)
 * @param {string} note  dikirim sebagai custom_notes (mis. order ID) supaya bisa dilacak di panel provider
 * @returns {{key, tx}}
 */
async function buy(opt, note = '') {
  const m = mapping(opt);
  if (!m) throw Object.assign(new Error('Durasi ini belum dipetakan ke Panelstore'), { ps: true });
  if (!configured()) throw Object.assign(new Error('API Key Panelstore belum diisi'), { ps: true });
  let res, text;
  try { ({ res, text } = await post({ action: 'order', pid: /^\d+$/.test(m.pid) ? Number(m.pid) : m.pid, quantity: 1, custom_notes: String(note || '').slice(0, 120) }, 25000)); }
  catch (e) { throw Object.assign(new Error('Koneksi Panelstore gagal: ' + (e.name === 'TimeoutError' ? 'timeout' : e.message)), { ps: true, transient: true }); }

  const fail = (msg, extra) => { throw Object.assign(new Error(msg), { ps: true }, extra); };
  if (text.startsWith('<') || /Just a moment|cf-browser-verification/i.test(text)) fail('Panelstore memblokir request (Cloudflare / IP server belum diizinkan?)', { auth: true });
  if (res.status === 429) fail('Rate limit Panelstore', { rateLimited: true, transient: true });
  if (res.status === 401 || res.status === 403) fail('Panelstore menolak kunci/IP (HTTP ' + res.status + ')', { auth: true });
  let j; try { j = JSON.parse(text); } catch { fail(`Respons Panelstore bukan JSON (HTTP ${res.status})`, { transient: res.status >= 500 }); }
  if (!j || typeof j !== 'object') fail('Respons Panelstore tidak valid');
  if (isFailure(j)) { const msg = j.error || j.message || j.msg || 'gagal'; fail('Panelstore: ' + String(msg).slice(0, 160), { stock: isStockError(msg) }); }
  if (res.status >= 500) fail(`Panelstore error ${res.status}`, { transient: true });

  const tx = firstStr(j.transaction_id) || firstStr(j.order_id) || firstStr(j.id) || firstStr(j.data && (j.data.transaction_id || j.data.order_id || j.data.id)) || null;
  const keys = collectKeys(j);
  if (keys.length) return { key: keys.join('\n'), tx };
  // Sukses jelas tapi bentuk key tidak dikenali: serahkan respons mentah (jangan beli ulang / key hilang).
  if (isSuccess(j)) return { key: text.slice(0, 2000), tx };
  fail('Respons beli Panelstore tidak dikenali: ' + text.slice(0, 120));
}

/** Tes kunci TANPA membeli (produk fiktif PID 0). @returns {{ok, note}} */
async function check() {
  if (!configured()) return { ok: false, note: 'API Key belum diisi' };
  let res, text;
  try { ({ res, text } = await post({ action: 'order', pid: 0, quantity: 1, custom_notes: 'key-check' }, 15000)); }
  catch (e) { return { ok: false, note: 'Koneksi gagal: ' + e.message }; }
  if (text.startsWith('<') || /Just a moment/i.test(text)) return { ok: false, note: 'Cloudflare memblokir server (IP belum diizinkan?)' };
  if (res.status === 401 || res.status === 403) return { ok: false, note: 'Kunci/IP ditolak (HTTP ' + res.status + ')' };
  let j; try { j = JSON.parse(text); } catch { return { ok: false, note: 'Respons bukan JSON (HTTP ' + res.status + '): ' + text.slice(0, 80) }; }
  const msg = String(j.error || j.message || j.msg || '').slice(0, 120);
  if (/api[ _-]?key|token|auth|unauthori|credential|forbidden|invalid key|ip not|not allowed/i.test(msg) && !/product|pid/i.test(msg)) return { ok: false, note: msg };
  if (isSuccess(j)) return { ok: false, note: 'Respons tak terduga (sukses untuk produk fiktif): ' + text.slice(0, 80) };
  return { ok: true, note: 'kunci diterima' + (msg ? ' (produk uji ditolak: "' + msg + '")' : '') };
}

module.exports = { setConfig, configured, mapping, usable, why, buy, check, markDown, clearDown, isStockError, VIRTUAL_STOCK };
