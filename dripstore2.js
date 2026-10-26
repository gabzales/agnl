'use strict';
/**
 * Provider tambahan: DripStore WEB 2 (dripclientofficial.shop) — API reseller yang sama bentuknya
 * dengan DripStore utama tapi domain + token sendiri (saldo terpisah).
 *   Header : X-API-Token  (wajib; juga tanda "API call tepercaya" bagi Cloudflare)
 *   Beli   : POST {base}/generate_key.php  (form-urlencoded: variant_id, quantity)
 *   Saldo  : GET  {base}/balance.php
 * Per durasi produk disimpan: opt.ds2VariantId (diisi di Edit Produk).
 * Tidak ada cek stok per varian di sini, jadi "tersedia" = terpetakan + token terisi + tidak sedang
 * ditandai habis (10 menit setelah pembelian gagal karena stok/saldo).
 * Aturan dari dokumentasi resmi toko (dripstore-client.js):
 *   - 5xx origin dibungkus HTTP 200 {success:false, code, error} -> yang berkode "server/origin/timeout/..." dianggap
 *     SEMENTARA (order mungkin sudah tercatat), bukan gagal biasa.
 *   - Varian Bala Mod (is_balamod) mode "v1" butuh Android ID pembeli -> TIDAK didukung, ditolak SEBELUM membeli
 *     (tidak ada saldo terpotong). Mode "both" selalu dikirim api_version=v2 (key langsung, tanpa Android ID).
 *     Salah api_version = key salah jenis yang tidak bisa diaktifkan pembeli, jadi dicek dulu lewat products.php.
 *   - Batas server: 60 req/menit per IP, 429 + Retry-After; 423 = batas reset key.
 * Token dibaca dari settings.dripstore2 {apiToken, baseUrl}; fallback env DRIPSTORE2_*.
 * JANGAN hardcode token di sini.
 */
const DEFAULT_URL = 'https://dripclientofficial.shop/api/v1';
const DOWN_MS = 10 * 60000;
const VIRTUAL_STOCK = 20;

let cfg = {};
function setConfig(c) {
  const n = c && typeof c === 'object' ? c : {};
  if (n.apiToken !== cfg.apiToken || n.baseUrl !== cfg.baseUrl) variantCache = { at: 0, byId: new Map() };
  cfg = n;
}
const token = () => String(cfg.apiToken || process.env.DRIPSTORE2_API_TOKEN || '').trim();
const baseUrl = () => (String(cfg.baseUrl || process.env.DRIPSTORE2_URL || DEFAULT_URL).trim() || DEFAULT_URL).replace(/\/+$/, '');
const configured = () => !!token();

const mapping = (opt) => {
  const variantId = String(opt?.ds2VariantId ?? '').trim();
  return variantId ? { variantId } : null;
};

const down = new Map(); // variantId -> { until, msg }
function markDown(opt, msg) { const m = mapping(opt); if (m) down.set(m.variantId, { until: Date.now() + DOWN_MS, msg: String(msg || '').slice(0, 120) }); }
function clearDown(opt) { const m = mapping(opt); if (m) down.delete(m.variantId); }
/** Hapus semua tanda "habis" (dipanggil saat admin menyimpan/mengetes DripStore Web 2, mis. setelah saldo/stok diisi). */
function clearAllDown() { down.clear(); }
function downInfo(opt) {
  const m = mapping(opt); if (!m) return null;
  const d = down.get(m.variantId);
  if (d && d.until > Date.now()) return d;
  if (d) down.delete(m.variantId);
  return null;
}

// Cache info varian dari products.php (10 menit). Hanya dipakai untuk deteksi Bala Mod; kegagalan baca = abaikan.
const VARIANT_TTL = 10 * 60000;
let variantCache = { at: 0, byId: new Map() };
function variantMode(info) { return info && info.balamod ? String(info.mode || '').toLowerCase() : ''; }
const needsAndroidId = (info) => variantMode(info) === 'v1';
function cachedVariant(id) { return Date.now() - variantCache.at < VARIANT_TTL ? variantCache.byId.get(String(id)) : undefined; }

async function loadVariants(force = false) {
  if (!force && Date.now() - variantCache.at < VARIANT_TTL) return variantCache.byId;
  const { res, text } = await api('products.php', 'GET', null, 12000);
  if (res.status !== 200 || text.startsWith('<')) throw new Error('products.php tidak terbaca');
  const j = JSON.parse(text);
  const list = (j.data && j.data.products) || j.products || [];
  const byId = new Map();
  for (const p of list) for (const v of (p.variants || [])) {
    byId.set(String(v.id), { balamod: !!v.is_balamod, mode: v.is_balamod ? (v.api_version_mode || '') : '', name: [p.name, v.name].filter(Boolean).join(' / ') });
  }
  variantCache = { at: Date.now(), byId };
  return byId;
}

/** Alasan opsi ini TIDAK bisa dipakai lewat DripStore Web 2 sekarang (null = bisa). */
function why(opt) {
  if (!configured()) return 'API Token DripStore Web 2 belum diisi';
  if (!mapping(opt)) return 'belum dipetakan ke DripStore Web 2 (Variant ID kosong)';
  if (needsAndroidId(cachedVariant(mapping(opt).variantId))) return 'varian Bala Mod v1 butuh Android ID pembeli (tidak didukung, jangan dipetakan)';
  const d = downInfo(opt);
  if (d) return `ditandai habis sampai ${new Date(d.until).toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit', timeZone: 'Asia/Jakarta' })} WIB (${d.msg || 'stok'})`;
  return null;
}
const usable = (opt) => why(opt) === null;
const isStockError = (msg) => /stock|stok|habis|out of|insufficient|saldo|balance|not available|unavailable|sold/i.test(String(msg || ''));

// Bentuk response generate_key.php sama dengan DripStore utama (lihat extractDripstoreKeys di server.js).
function extractKeys(resp) {
  const candidates = [
    resp?.data?.keys, resp?.keys, resp?.data?.key_list, resp?.key_list,
    (typeof resp?.data?.key === 'string' ? [resp.data.key] : null),
    (typeof resp?.key === 'string' ? [resp.key] : null),
    (Array.isArray(resp?.data) ? resp.data : null),
  ];
  for (const c of candidates) {
    if (Array.isArray(c) && c.length > 0) {
      const out = c.map(k => (typeof k === 'string' ? k : (k?.key || k?.license_key || ''))).map(k => String(k).trim()).filter(Boolean);
      if (out.length) return out;
    }
  }
  return [];
}

/** Request ke API. Cloudflare challenge (HTML) dilaporkan jelas — artinya IP server belum di-allowlist toko. */
async function api(path, method, form, timeoutMs) {
  const headers = { 'X-API-Token': token(), Accept: 'application/json' };
  const opt = { method, signal: AbortSignal.timeout(timeoutMs), headers };
  if (form) { headers['Content-Type'] = 'application/x-www-form-urlencoded'; opt.body = new URLSearchParams(form).toString(); }
  const res = await fetch(baseUrl() + '/' + path.replace(/^\/+/, ''), opt);
  return { res, text: (await res.text()).trim() };
}

/** Beli SATU key. Dipanggil hanya setelah pembayaran terkonfirmasi. @returns {{key, tx}} */
async function buy(opt) {
  const m = mapping(opt);
  if (!m) throw Object.assign(new Error('Durasi ini belum dipetakan ke DripStore Web 2'), { ds2: true });
  if (!configured()) throw Object.assign(new Error('API Token DripStore Web 2 belum diisi'), { ds2: true });
  // Cek jenis varian dulu (Bala Mod). Gagal baca products.php -> lanjut saja, server tetap memvalidasi.
  const body = { variant_id: m.variantId, quantity: 1 };
  try {
    const info = (await loadVariants()).get(String(m.variantId));
    if (needsAndroidId(info)) throw Object.assign(new Error('DripStore Web 2: varian Bala Mod v1 butuh Android ID pembeli — tidak didukung, tidak ada saldo terpotong'), { ds2: true, unsupported: true });
    if (variantMode(info) === 'both') body.api_version = 'v2'; // key langsung, tanpa Android ID
  } catch (e) { if (e.unsupported) throw e; }
  let res, text;
  try { ({ res, text } = await api('generate_key.php', 'POST', body, 25000)); }
  catch (e) { throw Object.assign(new Error('Koneksi DripStore Web 2 gagal: ' + (e.name === 'TimeoutError' ? 'timeout' : e.message)), { ds2: true, transient: true }); }

  const fail = (msg, extra) => { throw Object.assign(new Error(msg), { ds2: true }, extra); };
  if (text.startsWith('<') || /Just a moment|cf-browser-verification/i.test(text)) fail('Cloudflare DripStore Web 2 memblokir request (IP server belum di-allowlist toko)', { auth: true });
  if (res.status === 429) fail('Rate limit DripStore Web 2', { rateLimited: true, transient: true });
  let j; try { j = JSON.parse(text); } catch { fail(`Respons DripStore Web 2 bukan JSON (HTTP ${res.status})`, { transient: res.status >= 500 }); }
  if (!j || typeof j !== 'object') fail('Respons DripStore Web 2 tidak valid');
  if (res.status === 401) fail('DripStore Web 2: ' + String(j.error || 'token tidak valid / dicabut').slice(0, 120), { auth: true });
  if (res.status === 403) fail('DripStore Web 2: ' + String(j.error || 'akses ditolak (IP server diblokir?)').slice(0, 120), { auth: true });
  if (res.status === 423) fail('DripStore Web 2: ' + String(j.error || 'batas reset key tercapai').slice(0, 120));
  if (res.status >= 500) fail(`DripStore Web 2 error ${res.status}`, { transient: true });
  if (j.success === false || j.error) {
    const msg = j.error || j.message || 'gagal';
    // 5xx origin dibungkus HTTP 200 {success:false, code}: order MUNGKIN sudah tercatat -> perlakukan sementara.
    const wrapped5xx = /5\d\d|origin|upstream|internal|server|timeout|gateway|unavailable/i.test(String(j.code || ''));
    fail('DripStore Web 2: ' + String(msg).slice(0, 160) + (j.code ? ` [${String(j.code).slice(0, 40)}]` : ''), { stock: !wrapped5xx && isStockError(msg), transient: wrapped5xx });
  }

  const tx = j?.data?.transaction_id || j?.data?.transactionId || j?.transaction_id || j?.transactionId || j?.data?.purchase_id || j?.purchase_id || null;
  const keys = extractKeys(j);
  if (keys.length) return { key: keys.join('\n'), tx: tx ? String(tx) : null };
  // Sukses tapi bentuk key tidak dikenali: serahkan respons mentah (jangan beli ulang / key hilang).
  if (j.success === true) return { key: text.slice(0, 2000), tx: tx ? String(tx) : null };
  fail('Respons beli DripStore Web 2 tidak dikenali: ' + text.slice(0, 120));
}

/** Tes token TANPA membeli: baca saldo (balance.php, GET). @returns {{ok, note, balance?}} */
async function check() {
  if (!configured()) return { ok: false, note: 'API Token belum diisi' };
  let res, text;
  try { ({ res, text } = await api('balance.php', 'GET', null, 15000)); }
  catch (e) { return { ok: false, note: 'Koneksi gagal: ' + e.message }; }
  if (text.startsWith('<') || /Just a moment|cf-browser-verification/i.test(text)) return { ok: false, note: 'Cloudflare memblokir server ini — IP server belum di-allowlist toko (token sendiri tidak salah)' };
  if (res.status === 401 || res.status === 403) return { ok: false, note: 'Token/IP ditolak (HTTP ' + res.status + ')' };
  let j; try { j = JSON.parse(text); } catch { return { ok: false, note: 'Respons bukan JSON (HTTP ' + res.status + '): ' + text.slice(0, 80) }; }
  if (j.success === false || j.error) return { ok: false, note: String(j.error || j.message || 'gagal').slice(0, 120) };
  const bal = j?.data?.balance ?? j?.balance ?? null;
  let extra = '';
  try { // hangatkan cache varian & hitung varian yang butuh Android ID (Bala Mod v1)
    const v = await loadVariants(true);
    const v1 = [...v.values()].filter(needsAndroidId).length;
    extra = ` — ${v.size} varian` + (v1 ? `, ${v1} varian Bala Mod v1 (butuh Android ID, jangan dipetakan)` : '');
  } catch { /* opsional */ }
  clearAllDown(); // token & saldo terbaca normal: lepas semua tanda "habis" sementara
  return { ok: true, balance: bal, note: 'token valid' + (bal !== null && bal !== undefined ? ` — saldo ${bal}` : '') + extra };
}

/** Katalog lengkap DripStore Web 2 (products.php) dalam bentuk datar — dipakai alat "Katalog" di admin. */
let lastCatalog = { raw: null, text: '', status: 0 };
const lastCatalogInfo = () => lastCatalog;
async function catalog() {
  if (!configured()) throw new Error('API Token DripStore Web 2 belum diisi');
  const { res, text } = await api('products.php', 'GET', null, 15000);
  lastCatalog = { raw: null, text: text.slice(0, 1500), status: res.status };
  if (text.startsWith('<') || /Just a moment|cf-browser-verification/i.test(text)) throw new Error('Cloudflare memblokir server ini (IP server belum di-allowlist toko)');
  if (res.status === 401 || res.status === 403) throw new Error('Token/IP ditolak (HTTP ' + res.status + ')');
  let j; try { j = JSON.parse(text); } catch { throw new Error('products.php bukan JSON (HTTP ' + res.status + '): ' + text.slice(0, 80)); }
  if (j && (j.success === false || j.error)) throw new Error(String(j.error || j.message || 'gagal').slice(0, 140));
  lastCatalog.raw = j;
  const arr = (...c) => c.find(Array.isArray);
  const d = (j && j.data) || {};
  const list = arr(d.products, j.products, d.items, j.items, d.data, d.result, j.result, d.catalog, j.catalog, d, j.data) || [];
  const num = (...a) => { for (const x of a) if (x !== undefined && x !== null && x !== '' && !isNaN(Number(x))) return Number(x); return null; };
  const out = [];
  const push = (p, v) => out.push({
    productId: p && p.id != null ? String(p.id) : '',
    productName: String((p && (p.name || p.title || p.product_name)) || v.product_name || v.product || ''),
    variantId: String(v.id ?? v.variant_id),
    variantName: String(v.name || v.title || v.variant_name || v.label || v.duration || ''),
    price: num(v.price, v.reseller_price, v.cost, v.harga),
    stock: num(v.stock, v.available_stock, v.stock_count, v.available, v.quantity),
    balamod: !!v.is_balamod,
    mode: v.is_balamod ? String(v.api_version_mode || '') : ''
  });
  for (const p of list) {
    if (!p || typeof p !== 'object') continue;
    const vs = arr(p.variants, p.options, p.plans, p.packages, p.items, p.durations);
    if (vs) { for (const v of vs) if (v && (v.id != null || v.variant_id != null)) push(p, v); }
    else if (p.id != null || p.variant_id != null) push(null, p); // item sudah berupa varian
  }
  return out;
}

module.exports = { catalog, lastCatalogInfo, setConfig, configured, mapping, usable, why, buy, check, markDown, clearDown, clearAllDown, isStockError, VIRTUAL_STOCK };
