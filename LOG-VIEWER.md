# Log Live (/admin/logs)

Buka: login admin -> Dashboard -> tombol "Log Live" (atau langsung /admin/logs).
Tidak perlu buka Vercel.

## Isi halaman
- Diagnosa: status breaker DripStore, cache katalog, total 429, request ke provider
  (ok / limit / error), status gate challenge (aktif? berapa yang lolos/ditolak),
  flag env (ada/tidak, TANPA nilai), dan tabel "siapa yang nembak provider".
- Daftar log: auto-refresh 10 detik (berhenti saat tab disembunyikan), filter level
  (Error/Warn/Info), kategori (DripStore/Pembayaran/Keamanan/Database/App), pencarian,
  Jeda, Salin (untuk kirim ke gue), Bersihkan.

## Cara baca soal limit DripStore
1. Buka "Siapa yang nembak provider". Kalau `GET /api/catalog/stock` atau `GET /` mendominasi,
   pemicunya traffic publik. Kalau `background/warm` mendominasi, pemicunya refresh otomatis.
   Kalau `POST ... generate_key.php`, itu order asli.
2. "429 terakhir" + baris warn `[dripstore] ... GAGAL ... Daily request limit reached`
   menunjukkan kapan tepatnya kuota habis.
3. Breaker TERBUKA berarti server sudah berhenti nembak provider sampai waktunya habis.

## Keamanan
- Hanya admin (sesi yang sama dengan panel admin, termasuk single-device lock). Non-admin dapat 404.
- Secret otomatis disensor sebelum masuk log: Bearer/Authorization, X-API-Token, apiToken,
  password, secret, signature, cookie sesi, cf_gate, JWT, string hex panjang.
  Nilai token TIDAK dikirim ke halaman (hanya "ada/tidak ada").
- Isi log dirender sebagai teks (bukan HTML), jadi path/User-Agent berisi script tidak dieksekusi.
- Tombol Bersihkan hanya menerima JSON dari origin yang sama (anti-CSRF).
- Yang dicatat per request: metode, path, status, durasi, IP, User-Agent (dipotong). IP ada
  di log supaya penyerang bisa diblok di Cloudflare. Ingat ini data pengunjung.

## Batasan (jujur)
- Buffer memori 600 entri PER INSTANCE Vercel dan hilang saat cold start. Entri 'info'
  dibuang lebih dulu saat penuh, jadi warn/error bertahan.
- Warn/error disimpan ke Supabase (app_logs.json), maks 1x per 60 dtk (+ satu flush
  susulan), 200 entri terakhir. 'info' TIDAK pernah disimpan (hemat egress).
- Kalau ada beberapa instance aktif bersamaan, penyimpanan bersifat last-writer-wins,
  jadi sebagian entri warn/error bisa hilang. Di Vercel, fungsi bisa dibekukan segera
  setelah respons; flush latar belakang bersifat best-effort.
- Yang dicatat hanya request yang lewat aplikasi ini. Error di luar app (build gagal,
  crash sebelum server jalan, timeout platform Vercel) tetap hanya ada di Vercel.
- 404 biasa (bot scanning) tidak dicatat kecuali ke path /admin atau /vpr-secure.
