# AGHA NL DIGITAL STORE — Backend

Backend Node.js (Express + EJS) untuk toko top up, files, dan access game **AGHA NL DIGITAL STORE**, dengan Supabase sebagai database dan Vercel sebagai target deploy utama.

## Stack

- **Server**: Node.js + Express + EJS (server-side rendered, tanpa framework frontend terpisah)
- **Database**: Supabase (Postgres via `keyvalue_store`, lihat `supabase-schema.sql`) — bukan JSONBin, bukan file JSON lokal di production
- **Storage file**: Supabase Storage (logo, banner, foto produk, avatar) — filesystem lokal cuma dipakai saat development di komputer sendiri
- **Payment**: Pakasir dan/atau GensPay (QRIS)
- **Auth**: session (cookie-session) + opsional Google OAuth

## Setup Lokal

```bash
npm install
cp .env.example .env
# isi .env: minimal SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SESSION_SECRET
npm start
```
Buka `http://localhost:3000`.

Untuk push/update settings awal (nama toko, logo, tema warna, dll) ke Supabase:
```bash
node seed-settings.js
```

## Deploy ke Vercel

Lihat `VERCEL_DEPLOYMENT.md` untuk panduan lengkap. Ringkas:

1. Set environment variables di Vercel Project Settings sesuai `.env.example` (minimal `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `SESSION_SECRET`).
2. `vercel.json` sudah dikonfigurasi (`builds` → `server.js` pakai `@vercel/node`, semua route diarahkan ke situ). Jangan ubah jadi `"functions"` kecuali `server.js` dipindah ke folder `api/`, atau deploy akan gagal dengan error *"pattern doesn't match any Serverless Functions"*.
3. Push ke GitHub lalu import di Vercel, atau `vercel --prod` dari folder ini.
4. Jalankan `node seed-settings.js` dari lokal (dengan `.env` mengarah ke Supabase yang sama) untuk isi data awal.

## Struktur Folder

```
server.js              # entrypoint utama (Express app)
supabase.js             # semua akses database & storage
seed-settings.js        # push/update settings awal ke Supabase
views/                  # EJS templates (layout.ejs + partials/ + pages/)
public/uploads/         # asset statis (logo-main.png, logo-text.png) — dibundle ke deploy
src/input.css           # source Tailwind, di-build ke public/css/tailwind.css saat `npm run build`
```

## Catatan Penting

- **Jangan** commit `.env` — semua secret lewat environment variables.
- Ganti password admin lewat Admin Panel setelah deploy pertama, jangan hardcode di kode.
- File yang diupload lewat Admin Panel (banner, foto produk, avatar) otomatis disimpan ke Supabase Storage saat jalan di Vercel (filesystem Vercel read-only & tidak persistent), dan ke `public/uploads/...` lokal saat development.
