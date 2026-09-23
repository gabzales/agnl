// migrate-images-to-webp.js
//
// Migrasi SEKALI JALAN untuk fix bug performa 23 Agu 2026 (PageSpeed:
// LCP puluhan detik di mobile, payload halaman ~14MB, hampir semuanya
// gambar). uploadImage() di supabase.js sudah dibenahi supaya upload
// BARU otomatis dikompres jadi WebP -- tapi itu tidak menyentuh gambar
// yang SUDAH terlanjur ada di Supabase Storage sebelum fix itu
// di-deploy. Modul ini yang mengurus gambar-gambar lama itu:
//
//   1. List semua file di bucket "product-images"
//   2. Download tiap file, resize maks 1600px + convert ke WebP kualitas 80
//      (GIF dilewati apa adanya supaya animasi tidak hilang, dan file yang
//      sudah .webp dilewati juga -- tidak ada gunanya dikompres ulang)
//   3. Upload versi baru dengan nama file sama tapi ekstensi .webp
//   4. Cari & ganti SEMUA referensi ke URL lama -> URL baru, di
//      products.json, users.json, settings.json (dicari rekursif, jadi
//      tidak perlu tahu persis nama field di tiap tempat)
//   5. Hapus file LAMA dari Storage setelah referensinya berhasil diganti
//      semua (supaya tidak menyimpan 2x kapasitas storage sia-sia)
//
// DUA CARA MENJALANKAN:
//
//   A) Dari terminal lokal (butuh .env berisi SUPABASE_URL dan
//      SUPABASE_SERVICE_ROLE_KEY):
//         node migrate-images-to-webp.js
//
//   B) Lewat browser, tanpa perlu .env / login admin sama sekali --
//      server.js sudah dipasangi route yang memanggil modul ini memakai
//      env yang SUDAH ADA di Vercel (SUPABASE_URL/SUPABASE_SERVICE_ROLE_KEY
//      yang sama dipakai aplikasi utama). Set SETUP_SECRET di env Vercel,
//      redeploy, lalu buka:
//         https://agha.nlstoreshop.my.id/admin/migrate-images?secret=SETUP_SECRET_KAMU
//      Endpoint ini butuh secret yang cocok (sama seperti /agha-setup)
//      supaya tidak bisa dipicu orang lain -- otomatis nonaktif (403) kalau
//      SETUP_SECRET tidak di-set. Hapus SETUP_SECRET dari env setelah selesai.
//
// Idempotent: aman dijalankan/diakses berkali-kali (file yang sudah
// .webp otomatis dilewati).
//
// CATATAN: tidak menyentuh file lokal /public/uploads/ (logo bawaan
// default) -- hanya file yang tersimpan di Supabase Storage.

const sharp = require('sharp');

const MAX_IMAGE_DIMENSION = 1600;
const WEBP_QUALITY = 80;
const BUCKET = 'product-images';

// Ganti setiap kemunculan oldUrl -> newUrl di seluruh struktur data
// (rekursif, supaya tidak perlu tahu persis nama field di tiap tempat --
// products.image, settings.logoUrl, settings.banners[].imageUrl, dst
// semua kena tanpa perlu didaftar satu-satu).
function replaceUrlDeep(obj, oldUrl, newUrl) {
  let changed = false;
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      if (obj[i] === oldUrl) { obj[i] = newUrl; changed = true; }
      else if (obj[i] && typeof obj[i] === 'object') { if (replaceUrlDeep(obj[i], oldUrl, newUrl)) changed = true; }
    }
  } else if (obj && typeof obj === 'object') {
    for (const k of Object.keys(obj)) {
      if (obj[k] === oldUrl) { obj[k] = newUrl; changed = true; }
      else if (obj[k] && typeof obj[k] === 'object') { if (replaceUrlDeep(obj[k], oldUrl, newUrl)) changed = true; }
    }
  }
  return changed;
}

async function blobToBuffer(blob) {
  // Blob.arrayBuffer() butuh Node 18+. Fallback manual untuk Node lebih lama.
  return typeof blob.arrayBuffer === 'function'
    ? Buffer.from(await blob.arrayBuffer())
    : Buffer.from(await new Response(blob).arrayBuffer());
}

/**
 * Jalankan migrasi. `client` harus Supabase client yang SUDAH terkoneksi
 * (dari getClient() punya caller -- CLI atau server.js -- supaya modul
 * ini tidak perlu tahu cara baca env sendiri).
 * `onProgress(line)` opsional dipanggil per baris log (dipakai server.js
 * untuk stream progress ke response; CLI pakai console.log).
 * `maxFiles` opsional membatasi berapa file diproses dalam satu
 * pemanggilan -- penting untuk mode route/serverless yang punya batas
 * waktu eksekusi (Vercel maxDuration). Karena idempotent, sisa file yang
 * belum kebagian giliran otomatis kepakai kalau fungsi ini dipanggil
 * lagi (mis. refresh URL /admin/migrate-images beberapa kali sampai
 * "perlu diproses" menyentuh 0).
 * Return: objek ringkasan (summary) untuk ditampilkan / dikirim sebagai JSON.
 */
async function runMigration(client, { onProgress, maxFiles } = {}) {
  const log = onProgress || (() => {});
  const summary = {
    totalFiles: 0, processed: 0, success: 0, skippedGif: 0, skippedAlreadyWebp: 0,
    failed: 0, remaining: 0, totalOldBytes: 0, totalNewBytes: 0, errors: [],
    productsUpdated: false, usersUpdated: false, settingsUpdated: false,
  };

  log('Mengambil daftar file di bucket "' + BUCKET + '"...');
  const { data: files, error: listErr } = await client.storage.from(BUCKET).list('', { limit: 1000 });
  if (listErr) throw new Error('Gagal list file: ' + listErr.message);
  if (!files || files.length === 0) {
    log('Tidak ada file ditemukan di bucket. Selesai.');
    return summary;
  }
  summary.totalFiles = files.length;

  const allTargets = files.filter(f => !f.name.toLowerCase().endsWith('.webp'));
  summary.skippedAlreadyWebp = files.length - allTargets.length;
  const targets = maxFiles ? allTargets.slice(0, maxFiles) : allTargets;
  const remaining = allTargets.length - targets.length;
  log(`Ditemukan ${files.length} file, ${allTargets.length} perlu diproses (${summary.skippedAlreadyWebp} sudah .webp, dilewati).`);
  if (maxFiles && remaining > 0) {
    log(`Memproses ${targets.length} file dulu (batas per-panggilan: ${maxFiles}), sisa ${remaining} akan diproses kalau endpoint ini diakses/dipanggil lagi.`);
  }
  summary.remaining = remaining;

  if (targets.length === 0) {
    log('Semua file sudah WebP. Tidak ada yang perlu dimigrasikan.');
    return summary;
  }

  log('Memuat products.json, users.json, settings.json...');
  const readJsonKey = async (key, fallback) => {
    const { data, error } = await client.from('keyvalue_store').select('value').eq('key', key).single();
    if (error || !data) return fallback;
    return data.value ?? fallback;
  };
  const writeJsonKey = async (key, value) => {
    const { error } = await client.from('keyvalue_store').upsert({ key, value }, { onConflict: 'key' });
    if (error) throw new Error(`Gagal simpan ${key}: ${error.message}`);
  };

  const products = await readJsonKey('products.json', []);
  const users = await readJsonKey('users.json', []);
  const settings = await readJsonKey('settings.json', {});

  const { data: { publicUrl: sampleUrl } } = client.storage.from(BUCKET).getPublicUrl('x');
  const baseUrl = sampleUrl.replace(/\/x$/, '');

  for (const file of targets) {
    const oldUrl = `${baseUrl}/${file.name}`;
    try {
      const isGif = file.name.toLowerCase().endsWith('.gif');
      const { data: blob, error: dlErr } = await client.storage.from(BUCKET).download(file.name);
      if (dlErr) throw new Error(dlErr.message);
      const inputBuffer = await blobToBuffer(blob);
      summary.totalOldBytes += inputBuffer.length;

      if (isGif) {
        log(`  ${file.name}: dilewati (GIF, dibiarkan apa adanya untuk animasi)`);
        summary.totalNewBytes += inputBuffer.length;
        summary.skippedGif++;
        summary.processed++;
        continue;
      }

      const compressed = await sharp(inputBuffer)
        .resize({ width: MAX_IMAGE_DIMENSION, height: MAX_IMAGE_DIMENSION, fit: 'inside', withoutEnlargement: true })
        .webp({ quality: WEBP_QUALITY })
        .toBuffer();
      summary.totalNewBytes += compressed.length;

      const newName = file.name.replace(/\.[^.]+$/, '') + '.webp';
      const { error: upErr } = await client.storage.from(BUCKET).upload(newName, compressed, {
        contentType: 'image/webp', upsert: true
      });
      if (upErr) throw new Error(upErr.message);

      const newUrl = `${baseUrl}/${newName}`;
      if (replaceUrlDeep(products, oldUrl, newUrl)) summary.productsUpdated = true;
      if (replaceUrlDeep(users, oldUrl, newUrl)) summary.usersUpdated = true;
      if (replaceUrlDeep(settings, oldUrl, newUrl)) summary.settingsUpdated = true;

      const { error: delErr } = await client.storage.from(BUCKET).remove([file.name]);
      if (delErr) log(`  (upload ${newName} OK, tapi gagal hapus file lama ${file.name}: ${delErr.message})`);

      const savedPct = ((1 - compressed.length / inputBuffer.length) * 100).toFixed(0);
      log(`  ${file.name}: OK -> ${newName} — ${(inputBuffer.length/1024).toFixed(0)}KB -> ${(compressed.length/1024).toFixed(0)}KB (hemat ${savedPct}%)`);
      summary.success++;
    } catch (err) {
      log(`  ${file.name}: GAGAL (${err.message})`);
      summary.errors.push({ file: file.name, error: err.message });
      summary.failed++;
    }
    summary.processed++;
  }

  log('Menyimpan referensi URL yang sudah diperbarui...');
  if (summary.productsUpdated) { await writeJsonKey('products.json', products); log('  products.json diperbarui'); }
  if (summary.usersUpdated) { await writeJsonKey('users.json', users); log('  users.json diperbarui'); }
  if (summary.settingsUpdated) { await writeJsonKey('settings.json', settings); log('  settings.json diperbarui'); }
  if (!summary.productsUpdated && !summary.usersUpdated && !summary.settingsUpdated && summary.success > 0) {
    log('  Tidak ada referensi URL yang cocok ditemukan di data JSON (kemungkinan file yang dikompres sudah tidak dipakai / orphan).');
  }

  return summary;
}

function formatSummary(summary) {
  const lines = [];
  lines.push('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  lines.push('RINGKASAN MIGRASI');
  lines.push('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  lines.push(`Total file di bucket   : ${summary.totalFiles}`);
  lines.push(`Berhasil dikompres     : ${summary.success}`);
  lines.push(`Dilewati (GIF)         : ${summary.skippedGif}`);
  lines.push(`Dilewati (sudah .webp) : ${summary.skippedAlreadyWebp}`);
  lines.push(`Gagal                  : ${summary.failed}`);
  if (summary.remaining > 0) {
    lines.push(`Sisa belum diproses    : ${summary.remaining} (akses ulang endpoint ini untuk lanjut)`);
  }
  if (summary.totalOldBytes > 0) {
    lines.push(`Total ukuran lama      : ${(summary.totalOldBytes/1024/1024).toFixed(2)} MB`);
    lines.push(`Total ukuran baru      : ${(summary.totalNewBytes/1024/1024).toFixed(2)} MB`);
    lines.push(`Total penghematan      : ${((1 - summary.totalNewBytes/summary.totalOldBytes) * 100).toFixed(0)}%`);
  }
  return lines.join('\n');
}

module.exports = { runMigration, formatSummary, replaceUrlDeep };

// ── Mode CLI: jalan hanya kalau file ini dieksekusi langsung
// (node migrate-images-to-webp.js), TIDAK jalan kalau di-require dari
// server.js. ──
if (require.main === module) {
  require('dotenv').config();
  const { createClient } = require('@supabase/supabase-js');

  const url = (process.env.SUPABASE_URL || '').trim();
  const key = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();
  if (!url || !key) {
    console.error('❌ SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY belum di-set di .env');
    console.error('   (Kalau malas isi .env lokal, pakai cara B di komentar atas file ini:');
    console.error('   akses /admin/migrate-images?secret=SETUP_SECRET setelah set SETUP_SECRET di env Vercel.)');
    process.exit(1);
  }
  const client = createClient(url, key, { auth: { persistSession: false } });

  runMigration(client, { onProgress: (line) => console.log(line) })
    .then(summary => {
      console.log('\n' + formatSummary(summary));
      console.log('\nSelesai. Buka kembali homepage dan cek PageSpeed Insights untuk verifikasi.');
    })
    .catch(err => {
      console.error('\n❌ Migrasi berhenti karena error tak terduga:', err);
      process.exit(1);
    });
}
