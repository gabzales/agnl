'use strict';
/**
 * Provider tambahan: bantibhaiya.to (reseller_v1.php), dipakai bersama DripStore.
 *   POST form-urlencoded: api_key, action=buy, product_id (PID), duration ("1 Day"), quantity
 *   Header: x-master-key
 * Per durasi produk disimpan: opt.bhProductId + opt.bhDuration (diisi di Edit Produk).
 * API tidak punya cek stok, jadi "tersedia" = terpetakan + kunci terisi + tidak sedang
 * ditandai habis (10 menit setelah pembelian gagal karena stok).
 * Kunci dibaca dari settings.bantibhaiya {apiKey, masterKey, url}; fallback env BANTIBHAIYA_*.
 */
const DEFAULT_URL = 'https://bantibhaiya.to/api/reseller_v1.php';
const DOWN_MS = 10 * 60000;
const VIRTUAL_STOCK = 20; // stok "maya" yang ditampilkan ke pembeli bila provider tersedia
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

let cfg = {};
function setConfig(c) { cfg = c && typeof c === 'object' ? c : {}; }
const apiKey = () => String(cfg.apiKey || process.env.BANTIBHAIYA_API_KEY || '').trim();
const masterKey = () => String(cfg.masterKey || process.env.BANTIBHAIYA_MASTER_KEY || '').trim();
const url = () => String(cfg.url || process.env.BANTIBHAIYA_URL || DEFAULT_URL).trim() || DEFAULT_URL;
const configured = () => !!(apiKey() && masterKey());

const mapping = (opt) => {
  const pid = String(opt?.bhProductId ?? '').trim(), dur = String(opt?.bhDuration ?? '').trim();
  return pid && dur ? { pid, dur } : null;
};

const down = new Map(); // `${pid}|${dur}` -> { until, msg }
const dkey = (m) => m.pid + '|' + m.dur;
function markDown(opt, msg) { const m = mapping(opt); if (m) down.set(dkey(m), { until: Date.now() + DOWN_MS, msg: String(msg || '').slice(0, 120) }); }
function clearDown(opt) { const m = mapping(opt); if (m) down.delete(dkey(m)); }
function downInfo(opt) {
  const m = mapping(opt); if (!m) return null;
  const d = down.get(dkey(m));
  if (d && d.until > Date.now()) return d;
  if (d) down.delete(dkey(m));
  return null;
}

/** Alasan opsi ini TIDAK bisa dipakai lewat Bantibhaiya sekarang (null = bisa). */
function why(opt) {
  if (!configured()) return 'API Key / Master Key Bantibhaiya belum diisi';
  if (!mapping(opt)) return 'belum dipetakan ke Bantibhaiya (PID + durasi kosong)';
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
    else if (v && typeof v === 'object') take(v.key ?? v.license ?? v.license_key ?? v.serial ?? null);
  };
  const d = j && j.data && typeof j.data === 'object' ? j.data : {};
  for (const src of [j, d]) for (const k of ['key', 'keys', 'license', 'licenses', 'license_key', 'serial', 'result']) if (src[k] !== undefined && !out.length) take(src[k]);
  return out;
}
const isSuccess = (j) => j.success === true || j.status === true || /^(success|ok|1|true)$/i.test(String(j.status ?? ''));
const isFailure = (j) => !!j.error || j.success === false || j.status === false || /^(error|fail|failed|0|false)$/i.test(String(j.status ?? ''));

async function post(params, timeoutMs) {
  const res = await fetch(url(), {
    method: 'POST', signal: AbortSignal.timeout(timeoutMs),
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'x-master-key': masterKey(), Accept: 'application/json', 'User-Agent': UA },
    body: new URLSearchParams({ api_key: apiKey(), ...params }).toString(),
  });
  return { res, text: (await res.text()).trim() };
}

/** Beli SATU key. Dipanggil hanya setelah pembayaran terkonfirmasi. @returns {{key, tx}} */
async function buy(opt) {
  const m = mapping(opt);
  if (!m) throw Object.assign(new Error('Durasi ini belum dipetakan ke Bantibhaiya'), { bh: true });
  if (!configured()) throw Object.assign(new Error('Kunci Bantibhaiya belum diisi'), { bh: true });
  let res, text;
  try { ({ res, text } = await post({ action: 'buy', product_id: m.pid, duration: m.dur, quantity: '1' }, 25000)); }
  catch (e) { throw Object.assign(new Error('Koneksi Bantibhaiya gagal: ' + (e.name === 'TimeoutError' ? 'timeout' : e.message)), { bh: true, transient: true }); }

  const fail = (msg, extra) => { throw Object.assign(new Error(msg), { bh: true }, extra); };
  if (text.startsWith('<') || /Just a moment|cf-browser-verification/i.test(text)) fail('Cloudflare Bantibhaiya memblokir request (IP server belum diizinkan?)', { auth: true });
  if (res.status === 429) fail('Rate limit Bantibhaiya', { rateLimited: true, transient: true });
  if (res.status === 401 || res.status === 403) fail('Bantibhaiya menolak kunci/IP (HTTP ' + res.status + ')', { auth: true });
  let j; try { j = JSON.parse(text); } catch { fail(`Respons Bantibhaiya bukan JSON (HTTP ${res.status})`, { transient: res.status >= 500 }); }
  if (!j || typeof j !== 'object') fail('Respons Bantibhaiya tidak valid');
  if (isFailure(j)) { const msg = j.error || j.message || j.msg || 'gagal'; fail('Bantibhaiya: ' + String(msg).slice(0, 160), { stock: isStockError(msg) }); }
  if (res.status >= 500) fail(`Bantibhaiya error ${res.status}`, { transient: true });

  const tx = firstStr(j.transaction_id) || firstStr(j.order_id) || firstStr(j.id) || firstStr(j.data && (j.data.transaction_id || j.data.order_id || j.data.id)) || null;
  const keys = collectKeys(j);
  if (keys.length) return { key: keys.join('\n'), tx };
  // Sukses jelas tapi bentuk key tidak dikenali: serahkan respons mentah (jangan beli ulang / key hilang).
  if (isSuccess(j)) return { key: text.slice(0, 2000), tx };
  fail('Respons beli Bantibhaiya tidak dikenali: ' + text.slice(0, 120));
}

/** Tes kunci TANPA membeli (produk fiktif PID 0). @returns {{ok, note}} */
async function check() {
  if (!configured()) return { ok: false, note: 'API Key / Master Key belum diisi' };
  let res, text;
  try { ({ res, text } = await post({ action: 'buy', product_id: '0', duration: '1 Day', quantity: '1' }, 15000)); }
  catch (e) { return { ok: false, note: 'Koneksi gagal: ' + e.message }; }
  if (text.startsWith('<') || /Just a moment/i.test(text)) return { ok: false, note: 'Cloudflare memblokir server (IP belum diizinkan?)' };
  if (res.status === 401 || res.status === 403) return { ok: false, note: 'Kunci/IP ditolak (HTTP ' + res.status + ')' };
  let j; try { j = JSON.parse(text); } catch { return { ok: false, note: 'Respons bukan JSON (HTTP ' + res.status + '): ' + text.slice(0, 80) }; }
  const msg = String(j.error || j.message || j.msg || '').slice(0, 120);
  if (/api[ _-]?key|master|token|auth|unauthori|credential|forbidden|ip not|not allowed/i.test(msg) && !/product|pid/i.test(msg)) return { ok: false, note: msg };
  if (isSuccess(j)) return { ok: false, note: 'Respons tak terduga (sukses untuk produk fiktif): ' + text.slice(0, 80) };
  return { ok: true, note: 'kunci diterima' + (msg ? ' (produk uji ditolak: "' + msg + '")' : '') };
}

module.exports = { setConfig, configured, mapping, usable, why, buy, check, markDown, clearDown, isStockError, VIRTUAL_STOCK };
