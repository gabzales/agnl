/* Hapus file lama yang sudah tidak dipakai dari folder project kamu.
   Kenapa perlu: menimpa project dengan zip baru TIDAK menghapus file yang sudah dihapus di versi baru,
   jadi file lama menumpuk. Jalankan dari folder project:

     node tools/cleanup-legacy.js          -> hanya menampilkan apa yang akan dihapus (aman)
     node tools/cleanup-legacy.js --yes    -> benar-benar menghapus

   Yang TIDAK disentuh: .env, database/, node_modules/, export.json (cadangan data — lihat catatan di bawah). */
const fs = require('fs'), path = require('path');
const root = path.join(__dirname, '..');
const LEGACY = [
  // skrip sekali pakai / pengujian lama
  'add-client-products.js', 'check-readiness.sh', 'migrate-images.js', 'migrate-images-to-webp.js', 'migrate-supabase.js',
  'seed.js', 'setup.sh', 'stock_logic_test.js',
  // catatan perbaikan lama (ringkasan terbaru ada di CHANGES.md)
  'DOCS_INDEX.md', 'FINAL-SUMMARY.md', 'FIX-DRIPSTORE-RATELIMIT.md', 'FIX-EGRESS-IMPORT-4OKT.md', 'FIX-GUIDE.md', 'FIX-SUMMARY.md',
  'FIX_CS_DAN_ICON.md', 'HEMAT-VERCEL-6OKT.md', 'LEADERBOARD.md', 'LOG-VIEWER.md', 'MIGRATION_SUMMARY.md', 'PATCH-README.txt',
  'PRODUCT-DETAIL-README.md', 'QUICK_START.txt', 'RINGKASAN.md', 'STOCK_AUDIT.md', 'TESTIMONIALS-README.md', 'VERCEL-DEPLOY-FIX.md',
  // dokumen yang sekarang tinggal di docs/
  'ADMIN-PANEL-DOCS.md', 'CLOUDFLARE-SECURITY.md', 'PANDUAN-STOK-KEY-QRIS-PRIBADI.md',
  // halaman/aset yang sudah diganti
  'views/pages/leaderboard.ejs', 'views/pages/buy.ejs', 'views/pages/admin.ejs.pre-darkmode', 'public/css/layout.css'
];
const apply = process.argv.includes('--yes');
let n = 0, bytes = 0;
for (const rel of LEGACY) {
  const f = path.join(root, rel);
  if (!fs.existsSync(f)) continue;
  const size = fs.statSync(f).size; n++; bytes += size;
  console.log((apply ? 'hapus  ' : 'akan dihapus  ') + rel + '  (' + (size / 1024).toFixed(1) + ' KB)');
  if (apply) fs.rmSync(f, { force: true });
}
// folder docs/: sisakan hanya 3 dokumen yang masih berguna
const KEEP_DOCS = new Set(['ADMIN-PANEL-DOCS.md', 'CLOUDFLARE-SECURITY.md', 'PANDUAN-STOK-KEY-QRIS-PRIBADI.md']);
const docs = path.join(root, 'docs');
if (fs.existsSync(docs)) for (const f of fs.readdirSync(docs)) {
  if (KEEP_DOCS.has(f)) continue;
  const p = path.join(docs, f), size = fs.statSync(p).size; n++; bytes += size;
  console.log((apply ? 'hapus  ' : 'akan dihapus  ') + 'docs/' + f + '  (' + (size / 1024).toFixed(1) + ' KB)');
  if (apply) fs.rmSync(p, { force: true });
}
console.log('\n' + n + ' file, ' + (bytes / 1024).toFixed(0) + ' KB' + (apply ? ' dihapus.' : ' (belum dihapus; jalankan lagi dengan --yes).'));
if (fs.existsSync(path.join(root, 'export.json'))) {
  console.log('\nCATATAN: export.json (hasil Export Database) berisi data user & transaksi. Jangan disimpan di dalam project/git:\n         pindahkan ke luar folder project (mis. folder cadangan) lalu hapus dari sini.');
}
