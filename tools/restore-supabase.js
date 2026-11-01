#!/usr/bin/env node
/**
 * RESTORE hasil backup ke project Supabase (mis. project baru yang masih gratis & belum kena limit).
 *
 * Langkah:
 *  1) Buat project Supabase baru → SQL Editor → jalankan isi supabase-schema.sql (membuat tabel keyvalue_store).
 *  2) Isi SUPABASE_URL & SUPABASE_SERVICE_ROLE_KEY di .env dengan milik project BARU.
 *  3) node tools/restore-supabase.js            (membaca ./backup; atau --from=D:/bk)
 *       --only=db | --only=storage   (pilih salah satu)
 *       --dry-run                    (hanya menampilkan rencana)
 *  4) Ganti env yang sama di Vercel (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY) lalu redeploy.
 *
 * URL gambar absolut di dalam data (https://PROYEK-LAMA.supabase.co/storage/...) otomatis diganti ke URL project baru.
 */
try { require('dotenv').config(); } catch (_) {}
const fs = require('fs');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const arg = (n, d) => { const a = process.argv.find(x => x === `--${n}` || x.startsWith(`--${n}=`)); return a ? (a.includes('=') ? a.split('=').slice(1).join('=') : true) : d; };
const FROM = path.resolve(String(arg('from', 'backup')));
const ONLY = arg('only', 'all');
const DRY = !!arg('dry-run', false);
const NEW_URL = (process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
if (!NEW_URL || !KEY) { console.error('✗ SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY (project BARU) belum di-set.'); process.exit(1); }
if (!fs.existsSync(path.join(FROM, 'manifest.json'))) { console.error('✗ Folder backup tidak ditemukan / tanpa manifest.json: ' + FROM); process.exit(1); }
const manifest = JSON.parse(fs.readFileSync(path.join(FROM, 'manifest.json'), 'utf8'));
const OLD_URL = String(manifest.projectUrl || '').replace(/\/+$/, '');
const client = createClient(NEW_URL, KEY, { auth: { persistSession: false } });
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const MIME = { '.webp': 'image/webp', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.svg': 'image/svg+xml', '.mp4': 'video/mp4', '.apk': 'application/vnd.android.package-archive', '.pdf': 'application/pdf', '.json': 'application/json', '.txt': 'text/plain' };

// Tipe asli dari isi file (hasil pemulihan dari CDN berformat webp walau namanya .png/.jpg)
function sniffType(b) {
  if (b.length > 12 && b.slice(0, 4).toString() === 'RIFF' && b.slice(8, 12).toString() === 'WEBP') return 'image/webp';
  if (b[0] === 0x89 && b[1] === 0x50) return 'image/png';
  if (b[0] === 0xFF && b[1] === 0xD8) return 'image/jpeg';
  if (b.slice(0, 3).toString() === 'GIF') return 'image/gif';
  return null;
}
async function retry(fn, label) { let last; for (let i = 0; i < 4; i++) { try { return await fn(); } catch (e) { last = e; await sleep(600 * (i + 1)); } } throw new Error(`${label}: ${last && last.message || last}`); }
function walk(dir, base = '') { const out = []; if (!fs.existsSync(dir)) return out; for (const n of fs.readdirSync(dir)) { const p = path.join(dir, n); const rel = base ? `${base}/${n}` : n; fs.statSync(p).isDirectory() ? out.push(...walk(p, rel)) : out.push(rel); } return out; }

async function restoreStorage() {
  console.log('\n[1/2] Storage…');
  const root = path.join(FROM, 'storage');
  for (const bucket of fs.existsSync(root) ? fs.readdirSync(root) : []) {
    const files = walk(path.join(root, bucket));
    const meta = (manifest.buckets || {})[bucket] || {};
    console.log(`  bucket "${bucket}": ${files.length} file${DRY ? ' (dry-run)' : ''}`);
    if (DRY) continue;
    const { error: cErr } = await client.storage.createBucket(bucket, { public: meta.public !== false });
    if (cErr && !/already exists|duplicate/i.test(cErr.message || '')) throw new Error(`buat bucket ${bucket}: ${cErr.message}`);
    let ok = 0; const failed = []; const q = files.slice();
    const worker = async () => { while (q.length) { const f = q.shift(); try {
      const buf = fs.readFileSync(path.join(root, bucket, f));
      await retry(async () => { const r = await client.storage.from(bucket).upload(f, buf, { upsert: true, contentType: sniffType(buf) || MIME[path.extname(f).toLowerCase()] || 'application/octet-stream', cacheControl: '31536000' }); if (r.error) throw new Error(r.error.message); }, `unggah ${f}`);
      ok++; } catch (e) { failed.push(`${f}: ${e.message}`); } process.stdout.write(`  ${bucket}: ${ok}/${files.length}\r`); } };
    await Promise.all([worker(), worker(), worker(), worker()]);
    console.log(`  ✓ ${ok}/${files.length} terunggah${failed.length ? ` — ${failed.length} GAGAL` : ''}`);
    failed.slice(0, 10).forEach(x => console.log('    ✗ ' + x));
  }
}

async function restoreDb() {
  console.log('\n[2/2] Data…');
  const rows = JSON.parse(fs.readFileSync(path.join(FROM, 'db', 'keyvalue_store.json'), 'utf8'));
  console.log(`  ${rows.length} baris${DRY ? ' (dry-run)' : ''}${OLD_URL && OLD_URL !== NEW_URL ? `; URL gambar ${OLD_URL} → ${NEW_URL}` : ''}`);
  if (DRY) return;
  const rewrite = (v) => (OLD_URL && OLD_URL !== NEW_URL) ? JSON.parse(JSON.stringify(v).split(OLD_URL).join(NEW_URL)) : v;
  const BATCH = 50; let ok = 0;
  for (let i = 0; i < rows.length; i += BATCH) {
    const chunk = rows.slice(i, i + BATCH).map(r => ({ key: r.key, value: rewrite(r.value) }));
    await retry(async () => { const r = await client.from('keyvalue_store').upsert(chunk, { onConflict: 'key' }); if (r.error) throw new Error(r.error.message); }, 'tulis keyvalue_store');
    ok += chunk.length; process.stdout.write(`  ${ok}/${rows.length}\r`);
  }
  console.log(`  ✓ ${ok} baris dipulihkan`);
}

(async () => {
  try {
    if (ONLY === 'all' || ONLY === 'storage') await restoreStorage();
    if (ONLY === 'all' || ONLY === 'db') await restoreDb();
    console.log('\n✅ Restore selesai. Ganti SUPABASE_URL & SUPABASE_SERVICE_ROLE_KEY di Vercel ke project baru, lalu redeploy.');
  } catch (e) { console.error('\n✗ Restore berhenti: ' + e.message); process.exit(1); }
})();
