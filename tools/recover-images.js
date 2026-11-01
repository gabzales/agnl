#!/usr/bin/env node
/**
 * PULIHKAN GAMBAR dari situs yang masih hidup, saat bucket Supabase lama sudah tidak bisa diakses.
 *
 * Situs menyajikan gambar lewat /media/<file>?w=<lebar> dengan cache CDN Vercel (s-maxage 1 tahun), sehingga salinan
 * yang pernah dilihat pengunjung biasanya MASIH ada di CDN walau Supabase sudah mati. Skrip ini mencarinya
 * (lebar terbesar lebih dulu) dan menyimpannya ke folder backup yang sama dengan tools/restore-supabase.js.
 *
 *   node tools/recover-images.js --site=https://aghanlshop.my.id --from=keyvalue_store.csv [--out=backup-recovered]
 *
 *   --from  satu/lebih file atau folder (.csv/.json/.sql/.txt hasil export) yang berisi URL gambar; pisahkan dengan koma.
 *
 * ⚠ JALANKAN SEBELUM redeploy / ganti env di Vercel: cache CDN terikat ke deployment yang sedang aktif.
 * Hasilnya ber-format WEBP berukuran kecil (≤1280px) — cukup untuk menampilkan toko lagi; unggah ulang file asli bila ada.
 */
const fs = require('fs');
const path = require('path');
const arg = (n, d) => { const a = process.argv.find(x => x.startsWith(`--${n}=`)); return a ? a.split('=').slice(1).join('=') : d; };
const SITE = String(arg('site', '')).replace(/\/+$/, '');
const FROM = String(arg('from', '')).split(',').map(s => s.trim()).filter(Boolean);
const OUT = path.resolve(arg('out', 'backup-recovered'));
if (!SITE || !FROM.length) { console.error('Pemakaian: node tools/recover-images.js --site=https://domain-toko --from=export.csv [--out=folder]'); process.exit(1); }
const WIDTHS = [1280, 960, 640, 480, 320, 240, 160, 96];
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function* walk(p) { const st = fs.statSync(p); if (st.isDirectory()) for (const n of fs.readdirSync(p)) yield* walk(path.join(p, n)); else yield p; }
const refs = new Map(); // "bucket/file" -> {bucket,file}
let oldUrl = '';
for (const src of FROM) {
  if (!fs.existsSync(src)) { console.error('✗ Tidak ditemukan: ' + src); process.exit(1); }
  for (const f of walk(src)) {
    if (!/\.(csv|json|sql|txt)$/i.test(f)) continue;
    const t = fs.readFileSync(f, 'utf8').replace(/\\\//g, '/');
    for (const m of t.matchAll(/https:\/\/([a-z0-9]+)\.supabase\.co\/storage\/v1\/object\/public\/([A-Za-z0-9_-]+)\/([A-Za-z0-9._%\/-]+)/gi)) {
      oldUrl = oldUrl || `https://${m[1]}.supabase.co`;
      const file = decodeURIComponent(m[3]).replace(/[)\]'"\\]+$/, '');
      refs.set(`${m[2]}/${file}`, { bucket: m[2], file });
    }
    for (const m of t.matchAll(/\/media\/([A-Za-z0-9._-]{1,200})/g)) refs.set(`product-images/${m[1]}`, { bucket: 'product-images', file: m[1] });
  }
}
const list = [...refs.values()];
if (!list.length) { console.error('✗ Tidak ada URL gambar ditemukan di file yang diberikan.'); process.exit(1); }
console.log(`Ditemukan ${list.length} gambar yang direferensikan data. Mencari di ${SITE} …`);

function sniff(buf) {
  if (buf.length > 12 && buf.slice(0, 4).toString() === 'RIFF' && buf.slice(8, 12).toString() === 'WEBP') return 'webp';
  if (buf[0] === 0x89 && buf[1] === 0x50) return 'png';
  if (buf[0] === 0xFF && buf[1] === 0xD8) return 'jpg';
  if (buf.slice(0, 3).toString() === 'GIF') return 'gif';
  return null;
}
async function get(url) {
  try {
    const r = await fetch(url, { redirect: 'follow' });
    if (!r.ok) return null;
    if (!/^image\//i.test(r.headers.get('content-type') || '')) return null;
    return { buf: Buffer.from(await r.arrayBuffer()), cache: r.headers.get('x-vercel-cache') || r.headers.get('cf-cache-status') || '' };
  } catch (_) { return null; }
}
async function recover(it) {
  if (it.file.includes('/')) return { ...it, status: 'skip', note: 'di dalam subfolder (tidak bisa lewat /media)' };
  const enc = encodeURIComponent(it.file);
  for (const w of [...WIDTHS, 0]) {
    const r = await get(`${SITE}/media/${enc}${w ? `?w=${w}` : ''}`);
    if (r && r.buf.length > 200 && sniff(r.buf)) {
      const dest = path.join(OUT, 'storage', it.bucket, it.file);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, r.buf);
      return { ...it, status: 'ok', width: w || 'asli', bytes: r.buf.length, cache: r.cache };
    }
    await sleep(120);
  }
  return { ...it, status: 'miss' };
}
(async () => {
  const results = []; const q = list.slice(); let n = 0;
  const worker = async () => { while (q.length) { const it = q.shift(); const r = await recover(it); results.push(r); n++; process.stdout.write(`  ${n}/${list.length}  ${r.status === 'ok' ? '✓' : '✗'} ${it.file}${r.status === 'ok' ? ` (${r.width}${r.width === 'asli' ? '' : 'px'}, ${(r.bytes / 1024).toFixed(0)} KB)` : ''}\n`); } };
  await Promise.all([worker(), worker(), worker()]);
  const ok = results.filter(r => r.status === 'ok'), miss = results.filter(r => r.status !== 'ok');
  const mfPath = path.join(OUT, 'manifest.json');
  const mf = fs.existsSync(mfPath) ? JSON.parse(fs.readFileSync(mfPath, 'utf8')) : { createdAt: new Date().toISOString() };
  mf.projectUrl = mf.projectUrl || oldUrl;
  mf.buckets = mf.buckets || {};
  for (const b of new Set(list.map(i => i.bucket))) mf.buckets[b] = { public: true, files: ok.filter(r => r.bucket === b).length, recovered: true };
  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(mfPath, JSON.stringify(mf, null, 2));
  fs.writeFileSync(path.join(OUT, 'gambar-tidak-ditemukan.txt'), miss.map(r => `${r.bucket}/${r.file}${r.note ? '  # ' + r.note : ''}`).join('\n'));
  console.log(`\n✅ Terpulihkan: ${ok.length}/${list.length}${miss.length ? `   ✗ Tidak ditemukan: ${miss.length} (lihat ${path.join(OUT, 'gambar-tidak-ditemukan.txt')} — unggah ulang lewat Admin)` : ''}`);
  console.log('Folder: ' + OUT);
})();
