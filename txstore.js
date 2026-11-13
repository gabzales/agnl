// txstore.js — transaksi disimpan SATU BARIS PER TRANSAKSI (key 'tx:<id>') di tabel keyvalue_store.
//
// KENAPA (12 Nov 2026): dulu semua transaksi = satu blob JSON `transactions.json` (4,5 MB / 6.900+ transaksi,
// tumbuh ±75 KB/hari). Tiap order/polling/webhook membaca blob penuh (+ menulis balik penuh) -> egress Supabase
// habis 3x dan CPU Vercel boros (parse/stringify 4,5 MB tiap request). Sekarang jalur panas hanya menyentuh
// SATU baris (±700 byte); daftar/statistik admin memakai query terfilter, bukan blob.
//
// Kompatibilitas: baris lama `transactions.json` (kalau masih berisi data) otomatis dipindah ke baris tx:<id>
// saat pertama dipakai (salinan cadangan disimpan di key `backup:transactions-premigrasi-*`).

const TABLE = 'keyvalue_store';
const PREFIX = 'tx:';
const PAGE = 1000; // batas baris per request PostgREST (db-max-rows Supabase default 1000)

const TX_RANK = { pending: 1, failed: 2, expired: 2, done: 3 };
const txRank = (t) => TX_RANK[t && t.status] || 0;
const keyOf = (id) => PREFIX + id;
const strip = (t) => { if (t && t.status !== 'pending' && t.qrString !== undefined) delete t.qrString; return t; };
// teks aman untuk filter PostgREST (buang pemisah/wildcard yang bisa merusak sintaks or=())
const safeQ = (s) => String(s || '').replace(/[,()*%\\"'`:;]/g, ' ').trim().slice(0, 80);

// Gabungkan satu transaksi masuk dengan yang sudah ada di database (aturan sama dengan mergeTransactions lama):
//  - status tidak boleh mundur (done > failed/expired > pending) kecuali opts.trusted (aksi admin eksplisit)
//  - field penting yang hilang di data masuk diisi dari database
function mergeOne(remote, incoming, opts = {}) {
  if (!remote || opts.trusted) return strip(incoming);
  if (txRank(remote) > txRank(incoming)) return strip(remote);
  const m = { ...incoming };
  for (const k of ['key', 'paidAt', 'keySource', 'providerTransactionId', 'providerVariantId', 'qrString']) {
    if ((m[k] === undefined || m[k] === null) && remote[k] != null) m[k] = remote[k];
  }
  return strip(m);
}

function createTxStore({ getClient, readLocalBackup, writeLocalBackup }) {
  const warnedAt = {};
  const warnOnce = (k, msg) => { const n = Date.now(); if (!warnedAt[k] || n - warnedAt[k] > 3600000) { warnedAt[k] = n; console.warn(msg); } };

  // ── mode lokal (tanpa Supabase, hanya untuk dev) ──
  let _local = null;
  const localMap = () => {
    if (!_local) {
      _local = new Map();
      const arr = readLocalBackup('transactions.json');
      if (Array.isArray(arr)) for (const t of arr) if (t && t.id) _local.set(t.id, t);
    }
    return _local;
  };
  const localFlush = () => { try { writeLocalBackup('transactions.json', [...localMap().values()]); } catch (_) {} };
  const localList = () => [...localMap().values()].sort((a, b) => String(a.createdAt || '').localeCompare(String(b.createdAt || '')));

  // ── migrasi blob lama ──
  let _readyP = null;
  function ready() {
    if (!_readyP) {
      _readyP = migrateLegacyBlob().catch((e) => { _readyP = null; console.error('[tx] migrasi/cek transactions.json gagal:', e.message); throw e; });
    }
    return _readyP;
  }
  async function migrateLegacyBlob() {
    const client = getClient();
    if (!client) return;
    // cek murah: ambil elemen pertama saja (bukan seluruh blob)
    const { data: probe, error } = await client.from(TABLE).select('first:value->0').eq('key', 'transactions.json').maybeSingle();
    if (error) throw new Error(error.message);
    if (!probe || !probe.first) return; // tidak ada baris / array kosong -> sudah bermigrasi
    console.log('[tx] memindahkan transactions.json (blob) ke baris per transaksi ...');
    const { data: row, error: e2 } = await client.from(TABLE).select('value').eq('key', 'transactions.json').single();
    if (e2) throw new Error(e2.message);
    const arr = Array.isArray(row && row.value) ? row.value : [];
    if (!arr.length) return;
    const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 12);
    const { error: eb } = await client.from(TABLE).upsert({ key: `backup:transactions-premigrasi-${stamp}.json`, value: arr }, { onConflict: 'key' });
    if (eb) throw new Error('gagal membuat cadangan sebelum migrasi: ' + eb.message);
    // blob lama bisa memuat id ganda (bug race lama): pertahankan yang statusnya paling maju / paling lengkap
    const best = new Map();
    for (const t of arr) {
      if (!t || !t.id) continue;
      const cur = best.get(t.id);
      if (!cur || txRank(t) > txRank(cur) || (txRank(t) === txRank(cur) && JSON.stringify(t).length > JSON.stringify(cur).length)) best.set(t.id, t);
    }
    const rows = [...best.values()].map((t) => ({ key: keyOf(t.id), value: strip(t) }));
    for (let i = 0; i < rows.length; i += 300) {
      // ignoreDuplicates: baris tx:<id> yang sudah ada (lebih baru) tidak ditimpa
      const { error: eu } = await client.from(TABLE).upsert(rows.slice(i, i + 300), { onConflict: 'key', ignoreDuplicates: true });
      if (eu) throw new Error('migrasi batch gagal: ' + eu.message);
    }
    const { error: ec } = await client.from(TABLE).update({ value: [] }).eq('key', 'transactions.json');
    if (ec) throw new Error('gagal mengosongkan blob lama: ' + ec.message);
    console.log(`[tx] migrasi selesai: ${rows.length} transaksi dipindah (${arr.length - rows.length} duplikat/entri tanpa id dibuang; cadangan: backup:transactions-premigrasi-${stamp}.json)`);
  }

  // ── helper query ──
  const base = (client, cols = 'value') => client.from(TABLE).select(cols).like('key', PREFIX + '%');
  const vals = (data) => (data || []).map((r) => r.value).filter(Boolean);
  const fail = (what, error) => { throw new Error(`[tx] ${what}: ${error.message || error}`); };
  async function withRetry(fn) {
    try { return await fn(); } catch (e) { await new Promise((r) => setTimeout(r, 250)); return fn(); }
  }

  // ── baca satu / beberapa baris ──
  async function get(id) {
    if (!id) return null;
    const client = getClient();
    if (!client) return localMap().get(id) || null;
    await ready();
    return withRetry(async () => {
      const { data, error } = await client.from(TABLE).select('value').eq('key', keyOf(id)).maybeSingle();
      if (error) fail('get', error);
      return data ? data.value : null;
    });
  }
  async function find(field, value) {
    if (!value) return null;
    const client = getClient();
    if (!client) return localList().find((t) => t[field] === value) || null;
    await ready();
    return withRetry(async () => {
      const { data, error } = await base(client).eq(`value->>${field}`, String(value)).order('key', { ascending: false }).limit(1);
      if (error) fail('find ' + field, error);
      return vals(data)[0] || null;
    });
  }
  // Untuk /track: cocokkan banyak kode/orderId/id sekaligus. Hasil: { byCode:Map, byOrder:Map } (kunci HURUF BESAR).
  async function lookupTerms(terms) {
    const byCode = new Map(), byOrder = new Map();
    const clean = [...new Set((terms || []).map((x) => String(x).trim().toUpperCase()).filter((x) => /^[A-Z0-9][A-Z0-9_-]{2,60}$/.test(x)))].slice(0, 100);
    if (!clean.length) return { byCode, byOrder };
    const client = getClient();
    let rows = [];
    if (!client) {
      const set = new Set(clean);
      rows = localList().filter((t) => set.has(String(t.code || '').toUpperCase()) || set.has(String(t.orderId || '').toUpperCase()) || set.has(String(t.id || '').toUpperCase()));
    } else {
      await ready();
      const ids = clean.filter((x) => /^[0-9A-F-]{36}$/.test(x)).map((x) => keyOf(x.toLowerCase()));
      const q = await withRetry(() => Promise.all([
        base(client).in('value->>code', clean).limit(200),
        base(client).in('value->>orderId', clean).limit(200),
        ids.length ? client.from(TABLE).select('value').in('key', ids).limit(200) : Promise.resolve({ data: [] }),
      ]));
      for (const r of q) { if (r.error) fail('lookup', r.error); rows.push(...vals(r.data)); }
    }
    for (const t of rows) {
      if (t.code) byCode.set(String(t.code).toUpperCase(), t);
      if (t.orderId) byOrder.set(String(t.orderId).toUpperCase(), t);
      if (t.id) byOrder.set(String(t.id).toUpperCase(), t);
    }
    return { byCode, byOrder };
  }

  const invalidate = () => { _all.at = 0; };

  // ── tulis ──
  async function create(tx) {
    if (!tx || !tx.id) throw new Error('[tx] create: transaksi tanpa id');
    strip(tx);
    const client = getClient();
    if (!client) { localMap().set(tx.id, tx); localFlush(); return tx; }
    await ready();
    const { error } = await client.from(TABLE).insert({ key: keyOf(tx.id), value: tx });
    if (error) {
      if (error.code === '23505' || /duplicate key|unique constraint/i.test(error.message || '')) return save(tx);
      fail('create', error);
    }
    return tx;
  }
  // Simpan (gabung dengan isi database; lihat mergeOne). Optimistic concurrency lewat updated_at.
  async function save(tx, opts = {}) {
    if (!tx || !tx.id) throw new Error('[tx] save: transaksi tanpa id');
    const client = getClient();
    if (!client) { const cur = localMap().get(tx.id); const out = mergeOne(cur, tx, opts); localMap().set(tx.id, out); localFlush(); return out; }
    await ready();
    const key = keyOf(tx.id);
    for (let attempt = 1; attempt <= 10; attempt++) {
      if (attempt > 1) await new Promise((r) => setTimeout(r, 15 + Math.random() * 45 * attempt)); // jeda acak: penulis yang bertabrakan tidak bentrok lagi bersamaan
      const { data: row, error } = await client.from(TABLE).select('value,updated_at').eq('key', key).maybeSingle();
      if (error) fail('save/read', error);
      if (!row) {
        const out = strip(tx);
        const { error: ei } = await client.from(TABLE).insert({ key, value: out });
        if (!ei) return out;
        if (ei.code === '23505' || /duplicate key|unique constraint/i.test(ei.message || '')) continue; // keduluan instance lain -> baca ulang
        fail('save/insert', ei);
      }
      if (!opts.trusted && txRank(row.value) > txRank(tx)) return strip(row.value); // status di database lebih maju: data masuk basi, tidak perlu menulis
      const out = mergeOne(row.value, tx, opts);
      if (JSON.stringify(out) === JSON.stringify(row.value)) return out; // tidak ada perubahan -> hemat tulis
      const q = client.from(TABLE).update({ value: out }).eq('key', key);
      const { data: upd, error: eu } = await (row.updated_at ? q.eq('updated_at', row.updated_at) : q).select('key');
      if (eu) fail('save/update', eu);
      if (upd && upd.length) return out;
      // 0 baris ter-update = baris berubah di antara baca & tulis -> ulangi dengan data terbaru
    }
    throw new Error('[tx] save: konflik tulis berulang untuk ' + tx.id);
  }
  async function del(ids) {
    const list = [...new Set((ids || []).filter(Boolean))];
    if (!list.length) return 0;
    const client = getClient();
    if (!client) { for (const id of list) localMap().delete(id); localFlush(); return list.length; }
    await ready();
    for (let i = 0; i < list.length; i += 100) {
      const { error } = await client.from(TABLE).delete().in('key', list.slice(i, i + 100).map(keyOf));
      if (error) fail('delete', error);
    }
    return list.length;
  }

  // ── daftar terfilter ──
  async function byUser(userId) {
    // Ringkasan dashboard pelanggan: angka total (kolom ringan) + 20 transaksi terbaru + 15 mutasi saldo terbaru
    const empty = { stats: { totalOrders: 0, successOrders: 0, pendingOrders: 0, totalSpent: 0 }, recent: [], wallet: [] };
    if (!userId) return empty;
    const client = getClient();
    let mine;
    if (!client) mine = localList().filter((t) => t.userId === userId);
    if (mine) {
      const sorted = [...mine].sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
      const done = mine.filter((t) => t.status === 'done');
      return { stats: { totalOrders: mine.length, successOrders: done.length, pendingOrders: mine.filter((t) => t.status === 'pending').length, totalSpent: done.reduce((s, t) => s + (t.price || 0), 0) },
        recent: sorted.slice(0, 20), wallet: sorted.filter((t) => t.type === 'deposit' || t.type === 'adjustment').slice(0, 15) };
    }
    await ready();
    const f = (q) => q.eq('value->>userId', userId).order('value->>createdAt', { ascending: false });
    // kolom ringan dibaca per 1000 baris (batas PostgREST Supabase), supaya akun dengan >1000 order tetap terhitung benar
    const lightAll = async () => {
      const out = [];
      for (let from = 0; from < 50000; from += PAGE) {
        const { data, error } = await client.from(TABLE).select('s:value->>status,p:value->>price').like('key', PREFIX + '%').eq('value->>userId', userId).order('key').range(from, from + PAGE - 1);
        if (error) return { error };
        out.push(...(data || []));
        if (!data || data.length < PAGE) break;
      }
      return { data: out };
    };
    const [light, recent, wallet] = await withRetry(() => Promise.all([
      lightAll(),
      f(base(client)).limit(20),
      f(base(client)).in('value->>type', ['deposit', 'adjustment']).limit(15),
    ]));
    for (const r of [light, recent, wallet]) if (r.error) fail('byUser', r.error);
    const rows = light.data || [];
    let successOrders = 0, pendingOrders = 0, totalSpent = 0;
    for (const r of rows) { if (r.s === 'done') { successOrders++; totalSpent += Number(r.p) || 0; } else if (r.s === 'pending') pendingOrders++; }
    return { stats: { totalOrders: rows.length, successOrders, pendingOrders, totalSpent }, recent: vals(recent.data), wallet: vals(wallet.data) };
  }
  // Pending: opsional batas umur (ms) -> olderThanMs = hanya yang sudah lebih tua; newerThanMs = hanya yang lebih baru
  async function pending({ olderThanMs = 0, newerThanMs = 0, limit = 1000 } = {}) {
    const now = Date.now();
    const client = getClient();
    const keep = (t) => { const c = Date.parse(t.createdAt || 0); return (!olderThanMs || now - c >= olderThanMs) && (!newerThanMs || now - c < newerThanMs); };
    if (!client) return localList().filter((t) => t.status === 'pending' && keep(t)).reverse().slice(0, limit);
    await ready();
    let q = base(client).eq('value->>status', 'pending');
    if (olderThanMs) q = q.lte('value->>createdAt', new Date(now - olderThanMs).toISOString());
    if (newerThanMs) q = q.gte('value->>createdAt', new Date(now - newerThanMs).toISOString());
    const { data, error } = await withRetry(() => q.order('value->>createdAt', { ascending: false }).limit(limit));
    if (error) fail('pending', error);
    return vals(data);
  }
  // Pending milik satu user dalam jendela waktu (cek pesanan ganda saat checkout)
  async function pendingForUser(userId, windowMs, ip) {
    const client = getClient();
    const now = Date.now();
    if (!client) return localList().filter((t) => t.status === 'pending' && now - Date.parse(t.createdAt) < windowMs && (t.userId === userId || (ip && t.ip === ip)));
    await ready();
    const since = new Date(now - windowMs).toISOString();
    const mk = () => base(client).eq('value->>status', 'pending').gte('value->>createdAt', since).limit(50);
    const [u, p] = await withRetry(() => Promise.all([
      userId ? mk().eq('value->>userId', userId) : Promise.resolve({ data: [] }),
      ip ? mk().eq('value->>ip', ip) : Promise.resolve({ data: [] }),
    ]));
    if (u.error) fail('pendingForUser', u.error);
    if (p.error) fail('pendingForUser', p.error);
    const seen = new Map();
    for (const t of [...vals(u.data), ...vals(p.data)]) seen.set(t.id, t);
    return [...seen.values()];
  }
  async function recent(n = 20) {
    const client = getClient();
    if (!client) return localList().reverse().slice(0, n);
    await ready();
    const { data, error } = await withRetry(() => base(client).order('value->>createdAt', { ascending: false }).limit(n));
    if (error) fail('recent', error);
    return vals(data);
  }
  // Pesanan sudah dibayar tapi key belum terkirim (outOfStock) sejak sinceMs
  async function undelivered(sinceMs) {
    const client = getClient();
    const since = new Date(Date.now() - sinceMs).toISOString();
    const okRow = (t) => t && t.status === 'done' && t.outOfStock && !t.key && !t.manualResolved && (!t.type || t.type === 'product') && (new Date(t.paidAt || t.createdAt || 0).getTime() || 0) >= Date.now() - sinceMs;
    if (!client) return localList().filter(okRow);
    await ready();
    const { data, error } = await withRetry(() => base(client).eq('value->>status', 'done').eq('value->>outOfStock', 'true')
      .or(`value->>paidAt.gte.${since},value->>createdAt.gte.${since}`).limit(500));
    if (error) fail('undelivered', error);
    return vals(data).filter(okRow);
  }
  // Daftar admin: filter status/tanggal/teks + paginasi di database. -> { total, items }
  async function query({ status = 'all', q = '', from = null, to = null, offset = 0, limit = 50 } = {}) {
    const client = getClient();
    const term = safeQ(q).toLowerCase();
    if (!client) {
      const rows = localList().reverse().filter((t) => {
        if (status !== 'all' && t.status !== status) return false;
        const c = Date.parse(t.createdAt || '');
        if (from && !(c >= from)) return false;
        if (to && !(c < to)) return false;
        if (term && ![t.orderId, t.code, t.customerName, t.wa, t.productName, t.id].join(' ').toLowerCase().includes(term)) return false;
        return true;
      });
      return { total: rows.length, items: rows.slice(offset, offset + limit) };
    }
    await ready();
    let qq = client.from(TABLE).select('value', { count: 'exact' }).like('key', PREFIX + '%');
    if (status !== 'all') qq = qq.eq('value->>status', status);
    if (from) qq = qq.gte('value->>createdAt', new Date(from).toISOString());
    if (to) qq = qq.lt('value->>createdAt', new Date(to).toISOString());
    if (term) {
      const p = `*${term}*`;
      qq = qq.or(['orderId', 'code', 'customerName', 'wa', 'productName'].map((f) => `value->>${f}.ilike.${p}`).concat(`key.ilike.${PREFIX}${p}`).join(','));
    }
    const { data, error, count } = await withRetry(() => qq.order('value->>createdAt', { ascending: false }).range(offset, offset + limit - 1));
    if (error) fail('query', error);
    return { total: count == null ? (data || []).length : count, items: vals(data) };
  }
  // Statistik admin: total/pending/done/omzet + per-hari (chart). RPC tx_stats (lihat supabase-hemat.sql); fallback kolom ringan.
  async function stats(days = 8) {
    const client = getClient();
    const dayKey = (t) => String(t.createdAt || '').slice(0, 10);
    const fromRows = (rows) => {
      const out = { total: rows.length, pending: 0, done: 0, revenue: 0, daily: {} };
      const cut = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
      for (const r of rows) {
        if (r.status === 'pending') out.pending++;
        if (r.status === 'done') {
          out.done++; const p = Number(r.price) || 0; out.revenue += p;
          const d = dayKey(r);
          if (d && d >= cut) { const o = out.daily[d] || (out.daily[d] = { count: 0, revenue: 0 }); o.count++; o.revenue += p; }
        }
      }
      return out;
    };
    if (!client) return fromRows(localList());
    await ready();
    const rpc = await client.rpc('tx_stats', { p_days: days });
    if (!rpc.error && rpc.data) return rpc.data;
    warnOnce('stats-rpc', '[tx] RPC tx_stats belum ada -> pakai kolom ringan. Jalankan supabase-hemat.sql di SQL Editor Supabase.');
    const rows = [];
    for (let from = 0; from < 200000; from += PAGE) {
      const { data, error } = await client.from(TABLE).select('status:value->>status,price:value->>price,createdAt:value->>createdAt').like('key', PREFIX + '%').order('key').range(from, from + PAGE - 1);
      if (error) fail('stats', error);
      rows.push(...(data || []));
      if (!data || data.length < PAGE) break;
    }
    return fromRows(rows);
  }
  // id transaksi yang layak dibuang (pending lama / expired-failed lama) -> untuk pembersihan harian
  async function staleIds(pendMs, deadMs) {
    const client = getClient();
    const now = Date.now();
    const staticMul = (t) => (t.isStatic ? 4 : 1);
    if (!client) {
      return localList().filter((t) => { const a = now - (Date.parse(t.createdAt || t.paidAt || 0) || now); return (t.status === 'pending' && a > pendMs * staticMul(t)) || ((t.status === 'expired' || t.status === 'failed') && a > deadMs); }).map((t) => t.id);
    }
    await ready();
    const lim = (ms) => new Date(now - ms).toISOString();
    const [p, d] = await withRetry(() => Promise.all([
      client.from(TABLE).select('id:value->>id,st:value->>isStatic,c:value->>createdAt').like('key', PREFIX + '%').eq('value->>status', 'pending').lte('value->>createdAt', lim(pendMs)).limit(1000),
      client.from(TABLE).select('id:value->>id').like('key', PREFIX + '%').in('value->>status', ['expired', 'failed']).lte('value->>createdAt', lim(deadMs)).limit(1000),
    ]));
    if (p.error) fail('staleIds', p.error);
    if (d.error) fail('staleIds', d.error);
    const ids = [];
    for (const r of p.data || []) if (r.id && (now - Date.parse(r.c) > pendMs * (r.st === 'true' ? 4 : 1))) ids.push(r.id);
    for (const r of d.data || []) if (r.id) ids.push(r.id);
    return ids;
  }
  // Status beberapa transaksi sekaligus: Map id -> status (baris tidak ada = tidak masuk map)
  async function statusOf(ids) {
    const out = new Map();
    const client = getClient();
    if (!client) { for (const id of ids) { const t = localMap().get(id); if (t) out.set(id, t.status); } return out; }
    await ready();
    for (let i = 0; i < ids.length; i += 100) {
      const { data, error } = await client.from(TABLE).select('id:value->>id,s:value->>status').in('key', ids.slice(i, i + 100).map(keyOf));
      if (error) fail('statusOf', error);
      for (const r of data || []) out.set(r.id, r.s);
    }
    return out;
  }

  // Apakah user pernah membeli produk ini (status done)? -> boolean (untuk izin testimoni)
  async function hasPurchased(userId, productId) {
    if (!userId || !productId) return false;
    const client = getClient();
    if (!client) return localList().some((t) => t.userId === userId && t.productId === productId && t.status === 'done');
    await ready();
    const { data, error } = await withRetry(() => base(client, 'key').eq('value->>userId', userId).eq('value->>productId', productId).eq('value->>status', 'done').limit(1));
    if (error) fail('hasPurchased', error);
    return (data || []).length > 0;
  }
  // Restore/import massal (menimpa): upsert per 300 baris, tanpa membaca satu per satu
  async function importAll(list) {
    const rows = [];
    const seen = new Set();
    for (const t of (Array.isArray(list) ? list : [])) { if (t && t.id && !seen.has(t.id)) { seen.add(t.id); rows.push({ key: keyOf(t.id), value: strip(t) }); } }
    const client = getClient();
    if (!client) { for (const r of rows) localMap().set(r.value.id, r.value); localFlush(); return rows.length; }
    await ready();
    for (let i = 0; i < rows.length; i += 300) {
      const { error } = await client.from(TABLE).upsert(rows.slice(i, i + 300), { onConflict: 'key' });
      if (error) fail('importAll', error);
    }
    invalidate();
    return rows.length;
  }

  // ── daftar LENGKAP (jalur langka: export/backup/laporan; di-cache supaya tidak diunduh berulang) ──
  const _all = { at: 0, list: null, snap: null, p: null };
  async function all({ maxAgeMs = 60000 } = {}) {
    if (_all.list && Date.now() - _all.at < maxAgeMs) return _all.list;
    if (_all.p) return _all.p;
    _all.p = (async () => {
      const client = getClient();
      let list;
      if (!client) list = localList();
      else {
        await ready();
        list = [];
        for (let from = 0; from < 500000; from += PAGE) {
          const { data, error } = await client.from(TABLE).select('value').like('key', PREFIX + '%').order('key').range(from, from + PAGE - 1);
          if (error) fail('all', error);
          list.push(...vals(data));
          if (!data || data.length < PAGE) break;
        }
        list.sort((a, b) => String(a.createdAt || '').localeCompare(String(b.createdAt || '')));
      }
      _all.list = list; _all.snap = new Map(list.map((t) => [t.id, JSON.stringify(t)])); _all.at = Date.now();
      return list;
    })();
    try { return await _all.p; } finally { _all.p = null; }
  }
  // writeDB('transactions.json', list) gaya lama: hanya baris yang BERUBAH/baru yang ditulis; hapus hanya opts.deletedIds
  async function writeList(list, opts = {}) {
    warnOnce('legacy-write', '[tx] writeDB(transactions.json) gaya lama dipakai — pastikan ini jalur jarang (admin), bukan jalur pembeli.');
    const snap = _all.snap || new Map();
    const deleted = new Set(opts.deletedIds || []);
    if (deleted.size) await del([...deleted]);
    const changed = (Array.isArray(list) ? list : []).filter((t) => t && t.id && !deleted.has(t.id) && snap.get(t.id) !== JSON.stringify(t));
    for (let i = 0; i < changed.length; i += 6) {
      const outs = await Promise.all(changed.slice(i, i + 6).map((t) => save(t, opts)));
      outs.forEach((o, j) => { if (o && o.id) snap.set(o.id, JSON.stringify(o)); });
    }
    if (_all.list) _all.snap = snap;
    return changed.length;
  }
  function cachedAllOrEmpty() { warnOnce('legacy-readdb', '[tx] readDB(transactions.json) sinkron sudah tidak berisi seluruh transaksi — pakai db.tx*()'); return _all.list || []; }

  return { ready, get, find, lookupTerms, create, save, del, hasPurchased, importAll, byUser, pending, pendingForUser, recent, undelivered, query, stats, staleIds, statusOf, all, writeList, invalidate, cachedAllOrEmpty, mergeOne };
}

module.exports = { createTxStore, mergeOne, txRank, safeQ };
