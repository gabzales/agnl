# FIX: Gagal deploy dari GitHub ke Vercel (30 Sep 2026)

## Penyebab
`vercel.json` memakai DUA properti yang SALING KONFLIK sekaligus:
```json
{
  "builds": [ ... ],      // <- legacy
  "functions": { ... }    // <- modern, ditambahkan minggu lalu untuk maxDuration
}
```
Vercel MENOLAK kombinasi ini sejak awal (bukan baru-baru ini berubah). Pesan
error yang muncul biasanya:
```
The vercel.json schema validation failed with the following message:
builds[0] should NOT have additional property functions
```
atau di GitHub muncul sebagai "Vercel failed to produce [deployment]" tanpa
detail -- itu sebabnya terasa "ga jelas", pesan aslinya ada di Vercel, bukan GitHub.

`functions` (untuk `maxDuration: 60`, fix timeout provider DripStore minggu
lalu) ditambahkan ke file yang masih pakai `builds` tanpa mengecek konflik ini
-- murni kelalaian, bukan sesuatu yang berubah di sisi Vercel.

## Fix
Migrasi penuh dari `builds` (legacy) ke `functions` (modern), sesuai rekomendasi
resmi Vercel ("we recommend dropping [builds] in favor of the new one"):

**Sebelum:**
```json
{
  "version": 2,
  "builds": [{ "src": "server.js", "use": "@vercel/node", "config": { "includeFiles": ["views/**", "public/**"] } }],
  "functions": { "server.js": { "maxDuration": 60 } },
  "routes": [
    { "src": "/uploads/(.*)", "headers": { "Cache-Control": "..." }, "continue": true },
    { "src": "/(.*)", "dest": "server.js" }
  ]
}
```

**Sesudah:**
```json
{
  "version": 2,
  "functions": { "server.js": { "maxDuration": 60, "includeFiles": "{views,public}/**" } },
  "headers": [
    { "source": "/uploads/(.*)", "headers": [{ "key": "Cache-Control", "value": "..." }] }
  ]
}
```

Perubahan:
- `builds` dihapus. `includeFiles` dipindah ke dalam `functions.server.js`.
- `routes` (legacy, selalu berpasangan dengan `builds`) diganti `headers`
  (modern) untuk header Cache-Control di /uploads.
- Catch-all `routes` ke server.js TIDAK PERLU diganti dengan apa pun: Vercel
  otomatis mendeteksi Express app di server.js (root) dan mengirim SEMUA
  request ke situ sebagai satu Function -- ini perilaku default zero-config
  Express di Vercel, dikonfirmasi dokumentasi resmi (diperbarui 29 Sep 2026).

## Yang TIDAK diubah (sengaja)
- `express.static()` untuk /uploads di server.js dibiarkan apa adanya.
  Vercel memang mengabaikan express.static() sepenuhnya di produksi (ini
  perilaku resmi Vercel, bukan bug), TAPI kode ini sudah menangani itu dengan
  benar: untuk aset penting (logo, banner) ada redirect ke Supabase Storage
  khusus saat `process.env.VERCEL === '1'`. Developer sebelumnya sudah sadar
  akan keterbatasan ini -- tidak perlu diubah.

## Cara verifikasi setelah deploy ulang
1. Vercel Dashboard -> Deployments -> deployment terbaru harus berstatus
   "Ready" (bukan "Error").
2. Buka situsnya, pastikan homepage dan halaman produk tampil normal.
3. Cek logo/banner tetap muncul (ini yang paling berisiko kalau ada salah
   konfigurasi SUPABASE_URL di env Vercel).
