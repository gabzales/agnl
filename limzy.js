'use strict';
/**
 * Provider tambahan (khusus AGNL): limzyyxit.my.id Reseller API.
 *   POST form-data {BASE}/generate_key.php  : api_key, days (1 | 3 | 7 | 30)
 *   POST form-data {BASE}/reset_hwid.php    : api_key, key
 *     reset sukses: {"status":"success","message":"Hardware identifier has been reset successfully.","key":"USERNAME"}
 * Per durasi produk disimpan: opt.lzDays (1/3/7/30, diisi di Edit Produk). Kosong = tidak dipakai.
 * API tidak punya cek stok => "tersedia" = terpetakan + API key terisi + tidak sedang ditandai habis.
 * Kunci dibaca dari settings.limzy {apiKey, baseUrl}; fallback env LIMZY_API_KEY / LIMZY_BASE_URL.
 * JANGAN hardcode API key di sini.
 */
const DEFAULT_URL = 'https://limzyyxit.my.id/api';
const DOWN_MS = 10 * 60000;
const VIRTUAL_STOCK = 20;
const ALLOWED_DAYS = [1, 3, 7, 30];

let cfg = {};
function setConfig(c) { cfg = c && typeof c === 'object' ? c : {}; }
const apiKey = () => String(cfg.apiKey || process.env.LIMZY_API_KEY || '').trim();
const base = () => (String(cfg.baseUrl || process.env.LIMZY_BASE_URL || DEFAULT_URL).trim() || DEFAULT_URL).replace(/\/+$/, '');
const configured = () => !!apiKey();

const mapping = (opt) => {
  const d = Number(String(opt?.lzDays ?? '').trim());
  return ALLOWED_DAYS.includes(d) ? { days: d } : null;
};

const down = new Map();
function markDown(opt, msg) { const m = mapping(opt); if (m) down.set(m.days, { until: Date.now() + DOWN_MS, msg: String(msg || '').slice(0, 120) }); }
function clearDown(opt) { const m = mapping(opt); if (m) down.delete(m.days); }
function clearAllDown() { down.clear(); }
function downInfo(opt) {
  const m = mapping(opt); if (!m) return null;
  const d = down.get(m.days);
  if (d && d.until > Date.now()) return d;
  if (d) down.delete(m.days);
  return null;
}

function why(opt) {
  if (!configured()) return 'API Key Limzy belum diisi';
  if (!mapping(opt)) return 'belum dipetakan ke Limzy (hari 1/3/7/30 kosong)';
  const d = downInfo(opt);
  if (d) return `ditandai habis sampai ${new Date(d.until).toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Jakarta' })} WIB (${d.msg || 'stok'})`;
  return null;
}
const usable = (opt) => why(opt) === null;
const isStockError = (msg) => /stock|stok|habis|out of|insufficient|saldo|balance|credit|kredit|not available|unavailable|sold|limit/i.test(String(msg || ''));

function collectKeys(j) {
  const out = [];
  const take = (v) => {
    if (typeof v === 'string') { if (v.trim()) out.push(v.trim()); }
    else if (Array.isArray(v)) v.forEach(take);
    else if (v && typeof v === 'object') take(v.key ?? v.license_key ?? v.license ?? v.serial ?? null);
  };
  const d = j && j.data && typeof j.data === 'object' ? j.data : {};
  for (const src of [j, d]) for (const k of ['key', 'keys', 'license_key', 'license_keys', 'license', 'licenses', 'serial']) if (src[k] !== undefined && !out.length) take(src[k]);
  return out;
}
const isSuccess = (j) => j.success === true || j.status === true || /^(success|ok|1|true)$/i.test(String(j.status ?? ''));
const isFailure = (j) => !!j.error || j.success === false || j.status === false || /^(error|fail|failed|0|false)$/i.test(String(j.status ?? ''));

async function post(path, fields, timeoutMs) {
  const fd = new FormData();
  fd.append('api_key', apiKey());
  for (const [k, v] of Object.entries(fields || {})) fd.append(k, String(v));
  const res = await fetch(`${base()}/${path}`, { method: 'POST', body: fd, signal: AbortSignal.timeout(timeoutMs), headers: { Accept: 'application/json' } });
  return { res, text: (await res.text()).trim() };
}

/** Beli SATU key (dipanggil hanya setelah pembayaran lunas). @returns {{key, tx}} */
async function buy(opt, note = '') {
  const m = mapping(opt);
  if (!m) throw Object.assign(new Error('Durasi ini belum dipetakan ke Limzy'), { lz: true });
  if (!configured()) throw Object.assign(new Error('API Key Limzy belum diisi'), { lz: true });
  let res, text;
  try { ({ res, text } = await post('generate_key.php', { days: m.days }, 25000)); }
  catch (e) { throw Object.assign(new Error('Koneksi Limzy gagal: ' + (e.name === 'TimeoutError' ? 'timeout' : e.message)), { lz: true, transient: true }); }

  const fail = (msg, extra) => { throw Object.assign(new Error(msg), { lz: true }, extra); };
  if (text.startsWith('<') || /Just a moment|cf-browser-verification/i.test(text)) fail('Limzy memblokir request (Cloudflare / IP server?)', { auth: true });
  if (res.status === 429) fail('Rate limit Limzy', { rateLimited: true, transient: true });
  if (res.status === 401 || res.status === 403) fail('Limzy menolak kunci/IP (HTTP ' + res.status + ')', { auth: true });
  let j; try { j = JSON.parse(text); } catch { fail(`Respons Limzy bukan JSON (HTTP ${res.status})`, { transient: res.status >= 500 }); }
  if (!j || typeof j !== 'object') fail('Respons Limzy tidak valid');
  if (isFailure(j)) { const msg = j.error || j.message || j.msg || 'gagal'; fail('Limzy: ' + String(msg).slice(0, 160), { stock: isStockError(msg) }); }
  if (res.status >= 500) fail(`Limzy error ${res.status}`, { transient: true });

  const keys = collectKeys(j);
  if (keys.length) return { key: keys.join('\n'), tx: null };
  // Sukses jelas tapi bentuk key tidak dikenali: serahkan respons mentah (jangan beli ulang / key hilang).
  if (isSuccess(j)) return { key: text.slice(0, 2000), tx: null };
  fail('Respons beli Limzy tidak dikenali: ' + text.slice(0, 120));
}

/** Reset HWID sebuah key (reset_hwid.php). @returns {{ok, message, key}} */
async function resetHwid(key) {
  if (!configured()) return { ok: false, message: 'API Key Limzy belum diisi' };
  let res, text;
  try { ({ res, text } = await post('reset_hwid.php', { key: String(key || '').trim() }, 20000)); }
  catch (e) { return { ok: false, message: 'Koneksi gagal: ' + e.message }; }
  let j; try { j = JSON.parse(text); } catch { return { ok: false, message: 'Respons bukan JSON (HTTP ' + res.status + ')' }; }
  return { ok: /^success$/i.test(String(j.status || '')), message: String(j.message || j.error || '').slice(0, 160), key: j.key || null };
}

/** Tes API key TANPA membuat key: memanggil reset_hwid dengan key fiktif. @returns {{ok, note}} */
async function check() {
  if (!configured()) return { ok: false, note: 'API Key belum diisi' };
  let res, text;
  try { ({ res, text } = await post('reset_hwid.php', { key: 'key-check-nonexistent' }, 15000)); }
  catch (e) { return { ok: false, note: 'Koneksi gagal: ' + e.message }; }
  if (text.startsWith('<') || /Just a moment/i.test(text)) return { ok: false, note: 'Cloudflare memblokir server (IP belum diizinkan?)' };
  if (res.status === 401 || res.status === 403) return { ok: false, note: 'Kunci/IP ditolak (HTTP ' + res.status + ')' };
  let j; try { j = JSON.parse(text); } catch { return { ok: false, note: 'Respons bukan JSON (HTTP ' + res.status + '): ' + text.slice(0, 80) }; }
  const msg = String(j.error || j.message || j.msg || '').slice(0, 120);
  if (/api[ _-]?key|token|auth|unauthori|credential|forbidden|invalid key|ip not|not allowed/i.test(msg) && !/license|key (not|tidak)|not found/i.test(msg)) return { ok: false, note: msg };
  return { ok: true, note: 'kunci diterima' + (msg ? ' (respons uji: "' + msg + '")' : '') };
}

module.exports = { setConfig, configured, mapping, usable, why, buy, check, resetHwid, markDown, clearDown, clearAllDown, isStockError, VIRTUAL_STOCK };
