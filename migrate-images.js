// Salin SEMUA gambar dari Supabase Storage project LAMA ke project BARU, otomatis.
// Nama file dipertahankan, jadi URL lama tetap jalan lewat /media/ (lihat LEGACY_SUPABASE_URL)
// tanpa edit data apa pun. Aman dijalankan berulang (file yang sudah ada dilewati).
//
// Pakai:  node migrate-images.js export.json
// .env  :  NEW_SUPABASE_URL, NEW_SUPABASE_SERVICE_ROLE_KEY  (sama seperti migrate-supabase.js)
// Catatan: selama project lama masih RESTRICTED, download akan gagal (script akan bilang).
//          Jalankan lagi setelah restrict kebuka (reset 14 Okt / upgrade Pro).
require('dotenv').config();
const fs = require('fs');
const { createClient } = require('@supabase/supabase-js');

const BUCKET = 'product-images';
const RE = /https:\/\/([a-z0-9]+)\.supabase\.co\/storage\/v1\/object\/public\/product-images\/([^"'\s\\)]+)/g;

(async () => {
  const file = process.argv[2] || 'export.json';
  const url = (process.env.NEW_SUPABASE_URL || '').trim().replace(/\/+$/, '');
  const key = (process.env.NEW_SUPABASE_SERVICE_ROLE_KEY || '').trim();
  if (!url || !key) throw new Error('Set NEW_SUPABASE_URL dan NEW_SUPABASE_SERVICE_ROLE_KEY di .env');
  const newRef = url.replace('https://', '').split('.')[0];

  // 1) kumpulkan semua URL gambar storage dari data (kecuali log/claim yang bukan gambar toko)
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  const skip = k => k.startsWith('fulfillment-claim') || ['payment_events.json', 'dripstore_snapshot.json', 'app_logs.json'].includes(k);
  const found = new Map(); // filename -> oldBase
  for (const [k, v] of Object.entries(data)) {
    if (skip(k)) continue;
    const s = JSON.stringify(v);
    let m; RE.lastIndex = 0;
    while ((m = RE.exec(s))) {
      if (m[1] === newRef) continue;
      found.set(decodeURIComponent(m[2]), `https://${m[1]}.supabase.co/storage/v1/object/public/${BUCKET}/`);
    }
  }
  const files = [...found.entries()];
  console.log(`Ditemukan ${files.length} file gambar unik.`);
  if (!files.length) return;

  const sb = createClient(url, key, { auth: { persistSession: false } });
  // file yang sudah ada di bucket baru -> dilewati
  const existing = new Set();
  for (let off = 0; ; off += 1000) {
    const { data: list, error } = await sb.storage.from(BUCKET).list('', { limit: 1000, offset: off });
    if (error) throw new Error('Bucket product-images belum ada / key salah: ' + error.message + ' (jalankan supabase-schema.sql lengkap dulu)');
    list.forEach(f => existing.add(f.name));
    if (list.length < 1000) break;
  }

  let ok = 0, skipped = 0, failed = 0, blocked = 0;
  for (const [name, base] of files) {
    if (existing.has(name)) { skipped++; continue; }
    try {
      const r = await fetch(base + encodeURIComponent(name));
      if (!r.ok) {
        const t = (await r.text().catch(() => '')).slice(0, 120);
        if (r.status === 402 || r.status === 403 || r.status === 429 || /restrict|quota|disabled/i.test(t)) blocked++;
        console.log(`  GAGAL ${r.status} ${name} ${t}`); failed++; continue;
      }
      const buf = Buffer.from(await r.arrayBuffer());
      const ct = r.headers.get('content-type') || 'image/webp';
      const { error } = await sb.storage.from(BUCKET).upload(name, buf, { contentType: ct, cacheControl: '31536000', upsert: true });
      if (error) { console.log(`  GAGAL upload ${name}: ${error.message}`); failed++; continue; }
      ok++; console.log(`  ok ${name} (${Math.round(buf.length / 1024)}KB)`);
    } catch (e) { console.log(`  GAGAL ${name}: ${e.message}`); failed++; }
  }
  console.log(`\nSelesai: ${ok} disalin, ${skipped} sudah ada, ${failed} gagal.`);
  if (blocked) console.log('Project lama masih membatasi akses storage. Jalankan ulang script ini setelah restrict kebuka (aman, yang sudah ada dilewati).');
})().catch(e => { console.error('GAGAL:', e.message); process.exit(1); });
