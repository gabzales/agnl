#!/usr/bin/env node
/**
 * BACKUP Supabase: data (tabel keyvalue_store) + SEMUA gambar/file di Storage.
 *
 * Pakai (dari folder project, butuh SUPABASE_URL & SUPABASE_SERVICE_ROLE_KEY di .env atau env):
 *   node tools/backup-supabase.js                 -> data + gambar ke folder ./backup
 *   node tools/backup-supabase.js --only=storage  -> gambar saja
 *   node tools/backup-supabase.js --only=db       -> data saja
 *   node tools/backup-supabase.js --out=D:/bk     -> folder tujuan lain
 *   node tools/backup-supabase.js --include-claims   (ikutkan baris fulfillment-claim:*, default dilewati)
 *
 * Aman dijalankan ulang: file gambar yang sudah terunduh (ukuran sama) dilewati.
 * Hasil: backup/db/keyvalue_store.json, backup/db/<koleksi>.json, backup/storage/<bucket>/<file>, backup/manifest.json
 */
try { require('dotenv').config(); } catch (_) {}
const fs = require('fs');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const arg = (n, d) => { const a = process.argv.find(x => x === `--${n}` || x.startsWith(`--${n}=`)); return a ? (a.includes('=') ? a.split('=').slice(1).join('=') : true) : d; };
const OUT = path.resolve(String(arg('out', 'backup')));
const ONLY = arg('only', 'all');
const INCLUDE_CLAIMS = !!arg('include-claims', false);
const URL_ = (process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
if (!URL_ || !KEY) { console.error('✗ SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY belum di-set (isi di .env atau environment).'); process.exit(1); }
const client = createClient(URL_, KEY, { auth: { persistSession: false } });
const mb = (n) => (n / 1048576).toFixed(2) + ' MB';
const mkdir = (d) => fs.mkdirSync(d, { recursive: true });
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function withRetry(fn, label) {
  let last;
  for (let i = 0; i < 4; i++) {
    try { return await fn(); } catch (e) { last = e; await sleep(600 * (i + 1)); }
  }
  throw new Error(`${label}: ${last && last.message || last}`);
}

async function backupDb(manifest) {
  console.log('\n[1/2] Data (keyvalue_store)…');
  mkdir(path.join(OUT, 'db'));
  const PAGE = 500, rows = [];
  for (let from = 0; from < 500000; from += PAGE) {
    let q = client.from('keyvalue_store').select('key, value, updated_at').order('key', { ascending: true }).range(from, from + PAGE - 1);
    if (!INCLUDE_CLAIMS) q = q.not('key', 'like', 'fulfillment-claim:%');
    const { data, error } = await withRetry(async () => { const r = await q; if (r.error) throw new Error(r.error.message); return r; }, 'baca keyvalue_store');
    if (!data || !data.length) break;
    rows.push(...data);
    process.stdout.write(`  ${rows.length} baris\r`);
    if (data.length < PAGE) break;
  }
  fs.writeFileSync(path.join(OUT, 'db', 'keyvalue_store.json'), JSON.stringify(rows));
  let bytes = 0;
  for (const r of rows) {
    const safe = String(r.key).replace(/[^a-zA-Z0-9._-]/g, '_');
    const txt = JSON.stringify(r.value, null, 1);
    bytes += Buffer.byteLength(txt);
    if (!/^fulfillment-claim_/.test(safe)) fs.writeFileSync(path.join(OUT, 'db', safe.endsWith('.json') ? safe : safe + '.json'), txt);
  }
  manifest.tables = { keyvalue_store: { rows: rows.length, bytes } };
  console.log(`  ✓ ${rows.length} baris (${mb(bytes)})`);
}

async function listAll(bucket, prefix = '') {
  const files = [];
  const LIMIT = 100;
  for (let offset = 0; ; offset += LIMIT) {
    const { data, error } = await withRetry(async () => {
      const r = await client.storage.from(bucket).list(prefix, { limit: LIMIT, offset, sortBy: { column: 'name', order: 'asc' } });
      if (r.error) throw new Error(r.error.message); return r;
    }, `list ${bucket}/${prefix}`);
    if (!data || !data.length) break;
    for (const it of data) {
      const full = prefix ? `${prefix}/${it.name}` : it.name;
      if (it.id === null || it.id === undefined) files.push(...await listAll(bucket, full)); // folder
      else files.push({ path: full, size: (it.metadata && it.metadata.size) || 0 });
    }
    if (data.length < LIMIT) break;
  }
  return files;
}

async function backupStorage(manifest) {
  console.log('\n[2/2] Gambar / file Storage…');
  const { data: buckets, error } = await client.storage.listBuckets();
  if (error) throw new Error('listBuckets: ' + error.message);
  manifest.buckets = {};
  for (const b of buckets) {
    const files = await listAll(b.name);
    const dir = path.join(OUT, 'storage', b.name);
    mkdir(dir);
    let done = 0, skipped = 0, bytes = 0, failed = [];
    const queue = files.slice();
    const worker = async () => {
      while (queue.length) {
        const f = queue.shift();
        const dest = path.join(dir, f.path);
        try {
          if (fs.existsSync(dest) && (!f.size || fs.statSync(dest).size === f.size)) { skipped++; bytes += fs.statSync(dest).size; continue; }
          const { data, error: dErr } = await withRetry(async () => { const r = await client.storage.from(b.name).download(f.path); if (r.error) throw new Error(r.error.message); return r; }, `unduh ${f.path}`);
          const buf = Buffer.from(await data.arrayBuffer());
          mkdir(path.dirname(dest));
          fs.writeFileSync(dest, buf);
          done++; bytes += buf.length;
        } catch (e) { failed.push(`${f.path}: ${e.message}`); }
        process.stdout.write(`  ${b.name}: ${done + skipped}/${files.length}\r`);
      }
    };
    await Promise.all([worker(), worker(), worker(), worker()]);
    manifest.buckets[b.name] = { public: !!b.public, files: files.length, downloaded: done, skipped, bytes, failed };
    console.log(`  ✓ bucket "${b.name}": ${files.length} file (${mb(bytes)})${failed.length ? ` — ${failed.length} GAGAL` : ''}`);
    failed.slice(0, 10).forEach(x => console.log('    ✗ ' + x));
  }
}

(async () => {
  mkdir(OUT);
  const manifest = { createdAt: new Date().toISOString(), projectUrl: URL_ };
  try {
    if (ONLY === 'all' || ONLY === 'db') await backupDb(manifest);
    if (ONLY === 'all' || ONLY === 'storage') await backupStorage(manifest);
  } catch (e) {
    console.error('\n✗ Backup berhenti: ' + e.message);
    console.error('  Jika project Supabase sedang dibatasi (quota habis), API bisa menolak. Pakai cadangan manual:');
    console.error('  Dashboard → Table Editor → keyvalue_store → Export data → SQL, dan Storage → unduh file per bucket.');
    fs.writeFileSync(path.join(OUT, 'manifest.json'), JSON.stringify(manifest, null, 2));
    process.exit(1);
  }
  fs.writeFileSync(path.join(OUT, 'manifest.json'), JSON.stringify(manifest, null, 2));
  console.log('\n✅ Selesai. Folder: ' + OUT);
  const failed = Object.values(manifest.buckets || {}).reduce((a, b) => a + b.failed.length, 0);
  if (failed) { console.log(`⚠ ${failed} file gagal diunduh — jalankan ulang perintah yang sama untuk mencoba lagi.`); process.exit(2); }
})();
