// Pindah data keyvalue_store ke project Supabase BARU (org/akun baru).
//
// 1) Di project LAMA: Dashboard -> SQL Editor, jalankan:
//      select jsonb_object_agg(key, value) from keyvalue_store;
//    Copy hasil kolom (klik cell -> copy) ke file export.json di folder ini.
//    (Kalau SQL Editor ikut dibatasi, pakai Table Editor -> keyvalue_store ->
//     Export CSV, lalu kabari untuk converter-nya.)
// 2) Di project BARU: jalankan supabase-schema.sql di SQL Editor.
// 3) Isi env lokal: NEW_SUPABASE_URL & NEW_SUPABASE_SERVICE_ROLE_KEY, lalu:
//      node migrate-supabase.js export.json
// 4) Ganti SUPABASE_URL & SUPABASE_SERVICE_ROLE_KEY di env Vercel, redeploy.
require('dotenv').config();
const fs = require('fs');
const { createClient } = require('@supabase/supabase-js');

(async () => {
  const file = process.argv[2] || 'export.json';
  const url = (process.env.NEW_SUPABASE_URL || '').trim();
  const key = (process.env.NEW_SUPABASE_SERVICE_ROLE_KEY || '').trim();
  if (!url || !key) throw new Error('Set NEW_SUPABASE_URL dan NEW_SUPABASE_SERVICE_ROLE_KEY dulu');
  let raw = fs.readFileSync(file, 'utf8').trim();
  let data = JSON.parse(raw);
  if (Array.isArray(data)) data = data[0]?.jsonb_object_agg || data[0] || {};
  const rows = Object.entries(data).map(([k, v]) => ({ key: k, value: v }));
  if (!rows.length) throw new Error('export.json kosong / format tidak dikenali');
  const sb = createClient(url, key, { auth: { persistSession: false } });
  // Cek tabel ada dulu (kasih pesan jelas kalau supabase-schema.sql belum dijalankan)
  const probe = await sb.from('keyvalue_store').select('key', { head: true, count: 'exact' });
  if (probe.error) throw new Error('Tabel keyvalue_store belum ada / key salah: ' + (probe.error.message || probe.error.code) + ' -> jalankan supabase-schema.sql dulu di SQL Editor project baru');
  const BATCH = 50;
  for (let i = 0; i < rows.length; i += BATCH) {
    const chunk = rows.slice(i, i + BATCH);
    const { error } = await sb.from('keyvalue_store').upsert(chunk, { onConflict: 'key' });
    if (error) throw new Error(`batch ${i}-${i + chunk.length}: ${error.message}`);
    console.log(`  ${Math.min(i + BATCH, rows.length)}/${rows.length}`);
  }
  const { count, error: cErr } = await sb.from('keyvalue_store').select('key', { head: true, count: 'exact' });
  if (cErr) throw new Error(cErr.message);
  console.log(`OK: ${rows.length} baris dikirim, di database sekarang ada ${count} baris (harus ${rows.length}).`);
})().catch(e => { console.error('GAGAL:', e.message); process.exit(1); });
