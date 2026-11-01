#!/usr/bin/env node
/**
 * Ubah hasil "Export table as CSV" dari Supabase (Table Editor → keyvalue_store → Export data → CSV)
 * menjadi folder backup yang bisa dipulihkan dengan tools/restore-supabase.js.
 * Dipakai saat API/Storage project lama sudah mati dan hanya dashboard (Table Editor) yang masih bisa dibuka.
 *
 *   node tools/csv-to-backup.js keyvalue_store.csv [--out=backup-recovered]
 *
 * Hasil: <out>/db/keyvalue_store.json  (+ manifest.json berisi URL project lama, dipakai untuk mengganti URL gambar)
 */
const fs = require('fs');
const path = require('path');

const file = process.argv.slice(2).find(a => !a.startsWith('--'));
const outArg = process.argv.find(a => a.startsWith('--out='));
const OUT = path.resolve(outArg ? outArg.slice(6) : 'backup-recovered');
if (!file || !fs.existsSync(file)) { console.error('Pemakaian: node tools/csv-to-backup.js <file.csv> [--out=folder]'); process.exit(1); }

// Parser CSV RFC-4180 (kutip ganda, "" sebagai escape, newline di dalam kutip)
function parseCsv(text) {
  if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
  const rows = []; let row = [], f = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; }
      else f += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(f); f = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(f); f = ''; if (row.length > 1 || row[0] !== '') rows.push(row); row = []; }
    else f += c;
  }
  if (f !== '' || row.length) { row.push(f); rows.push(row); }
  return rows;
}

const rows = parseCsv(fs.readFileSync(file, 'utf8'));
if (!rows.length) { console.error('✗ CSV kosong'); process.exit(1); }
const head = rows[0].map(h => h.trim().toLowerCase());
const ki = head.indexOf('key'), vi = head.indexOf('value');
if (ki < 0 || vi < 0) { console.error('✗ Kolom "key" dan "value" tidak ditemukan di baris pertama CSV. Header: ' + rows[0].join(' | ')); process.exit(1); }

const out = []; const bad = []; let claims = 0;
for (const r of rows.slice(1)) {
  const key = r[ki]; if (!key) continue;
  if (key.startsWith('fulfillment-claim:')) { claims++; continue; }
  try { out.push({ key, value: JSON.parse(r[vi]) }); }
  catch (e) { bad.push(key); }
}
fs.mkdirSync(path.join(OUT, 'db'), { recursive: true });
fs.writeFileSync(path.join(OUT, 'db', 'keyvalue_store.json'), JSON.stringify(out));

// deteksi URL project lama dari URL gambar yang tersimpan di data
const txt = JSON.stringify(out);
const m = txt.match(/https:\/\/([a-z0-9]+)\.supabase\.co\/storage\/v1\/object\/public\//i);
const mfPath = path.join(OUT, 'manifest.json');
const mf = fs.existsSync(mfPath) ? JSON.parse(fs.readFileSync(mfPath, 'utf8')) : { createdAt: new Date().toISOString(), buckets: {} };
if (m) mf.projectUrl = `https://${m[1]}.supabase.co`;
mf.tables = { keyvalue_store: { rows: out.length } };
fs.writeFileSync(mfPath, JSON.stringify(mf, null, 2));

console.log(`✓ ${out.length} koleksi dibaca${claims ? `, ${claims} baris klaim dilewati` : ''}`);
if (bad.length) console.log(`⚠ ${bad.length} baris gagal dibaca (JSON rusak): ${bad.slice(0, 5).join(', ')}`);
console.log(m ? `✓ URL project lama terdeteksi: ${mf.projectUrl}` : '⚠ URL gambar Supabase tidak ditemukan di data (mungkin tidak ada gambar yang tersimpan).');
console.log('Folder: ' + OUT);
