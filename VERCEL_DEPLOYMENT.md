# AGHA NL DIGITAL STORE — Panduan Deploy ke Vercel (Supabase)

## 1. Siapkan Supabase

1. Buat project di https://supabase.com
2. Buka **SQL Editor**, jalankan isi file `supabase-schema.sql` (bikin tabel `keyvalue_store` + storage bucket `product-images`)
3. Ambil dari **Settings → API**:
   - `SUPABASE_URL`
   - `SUPABASE_SERVICE_ROLE_KEY` (bukan `anon key` — server butuh akses penuh, RLS memblokir anon)

## 2. Set Environment Variables di Vercel

Vercel Dashboard → Project → Settings → Environment Variables. Isi minimal:

| Key | Wajib? | Keterangan |
|---|---|---|
| `SUPABASE_URL` | ✅ | dari Supabase Settings → API |
| `SUPABASE_SERVICE_ROLE_KEY` | ✅ | Service Role key, JANGAN anon key |
| `SESSION_SECRET` | ✅ | string random panjang — generate: `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"` |
| `SUPABASE_DB_PASSWORD` | opsional | untuk auto-create tabel kalau belum ada |
| `PAKASIR_API_KEY` / `PAKASIR_PROJECT` | opsional | kalau pakai Pakasir QRIS (atau isi lewat Admin Panel) |
| `GENSPAY_API_KEY` | opsional | kalau pakai GensPay QRIS |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | opsional | login Google, kosongkan = tombol Google disembunyikan otomatis |
| `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET_KEY` | opsional | anti-bot Cloudflare Turnstile |

Lengkapnya lihat `.env.example` di root project ini.

`VERCEL=1` dan `NODE_ENV=production` **tidak perlu diisi manual** — dua-duanya sudah otomatis di-set oleh platform Vercel sendiri untuk setiap deployment.

## 3. Konfigurasi `vercel.json` (SUDAH disiapkan, jangan diubah sembarangan)

```json
{
  "version": 2,
  "builds": [
    { "src": "server.js", "use": "@vercel/node", "config": { "includeFiles": ["views/**", "public/**"] } }
  ],
  "routes": [
    { "src": "/uploads/(.*)", "headers": { "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400" }, "continue": true },
    { "src": "/(.*)", "dest": "server.js" }
  ]
}
```

**Kenapa harus begini:** `server.js` ada di root project (bukan di folder `api/`). Vercel punya dua cara mendaftarkan serverless function:
- `"functions": { "api/index.js": {...} }` → HANYA jalan untuk file di dalam folder `api/`
- `"builds": [{ "src": "server.js", "use": "@vercel/node" }]` → bisa untuk file di mana saja, termasuk root

Kalau `vercel.json` diubah pakai `"functions": { "server.js": {...} }` padahal `server.js` di root (bukan di `api/`), Vercel akan gagal deploy dengan error:
> *The pattern "server.js" defined in `functions` doesn't match any Serverless Functions inside the `api` directory.*

Jadi: **selama `server.js` masih di root, pakai `"builds"`, bukan `"functions"`.** `includeFiles: ["views/**", "public/**"]` wajib ada supaya template EJS dan asset (logo, dll) ikut ter-bundle — tanpa ini halaman bisa render error "template not found" atau logo/gambar 404 di production walau lokal jalan normal.

## 4. Deploy

**Via GitHub (disarankan):**
1. Push project ini ke repo GitHub
2. https://vercel.com/new → Import repo
3. Root Directory: `.` (folder ini sendiri, bukan sub-folder)
4. Isi Environment Variables (langkah 2)
5. Deploy

**Via CLI:**
```bash
npm i -g vercel
vercel login
vercel --prod
```

## 5. Setelah Deploy Pertama

```bash
# dari lokal, .env mengarah ke Supabase yang SAMA dengan yang dipakai Vercel
node seed-settings.js
```
Ini push nama toko, logo, tema warna, dll ke Supabase. Kalau admin password belum diset, cek log server (`Vercel → Deployments → Function Logs`) — password random di-print sekali saat pertama kali database di-init, lalu ganti lewat Admin Panel.

## 6. Custom Domain

Vercel Project → Settings → Domains → tambah domain (mis. `agha.nlstoreshop.my.id`), lalu ikuti instruksi DNS (biasanya CNAME ke `cname.vercel-dns.com`). Setelah aktif, update `siteUrl` di Admin Panel → Settings biar sesuai domain baru.

## Troubleshooting

| Gejala | Penyebab umum | Solusi |
|---|---|---|
| `pattern "server.js" ... doesn't match any Serverless Functions` | `vercel.json` pakai `"functions"` bukan `"builds"` | Pakai config di langkah 3 di atas |
| Halaman blank / "Cannot find module" saat render | `views/` tidak ke-bundle | Pastikan `includeFiles` di `vercel.json` mencakup `views/**` |
| Logo/gambar 404 di production tapi OK di lokal | `public/**` tidak ke-bundle, atau file belum ke-commit | Pastikan `includeFiles` mencakup `public/**`, dan file ada di repo (bukan di `.gitignore`) |
| Upload gambar gagal di production | Filesystem Vercel read-only, kode coba tulis ke disk lokal | Sudah dihandle otomatis — kode upload ke Supabase Storage saat `process.env.VERCEL === '1'`. Kalau masih gagal, cek `SUPABASE_SERVICE_ROLE_KEY` valid |
| Data hilang tiap redeploy | Salah pakai penyimpanan file lokal untuk data | Semua data HARUS lewat Supabase (`keyvalue_store`), bukan file JSON lokal — filesystem Vercel di-reset tiap deploy |
| Login admin gagal padahal password benar | Env var Supabase salah / belum di-set | Cek `SUPABASE_URL` & `SUPABASE_SERVICE_ROLE_KEY` di Vercel Environment Variables, redeploy setelah ubah env |
