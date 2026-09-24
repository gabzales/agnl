# FIX: "Daily request limit reached" dari DripStore (23 Sep 2026)

## Akar masalah
1. Refresh snapshot yang gagal sebagian (429) tidak mengisi cache, jadi TIAP page load
   nembak ulang balance.php + products.php. Terbukti simulasi: 200 page load = 400 request.
2. Tidak ada circuit breaker. Provider bilang retry-after, kode tetap nembak. Request yang
   ditolak tetap dihitung kuota harian -> limit tidak pernah pulih.
3. warmDripstoreCatalog() dipanggil di setiap page load (home/buy/admin).
4. Checkout boros: 6 request per order (products.php 3x, balance.php 2x, generate 1x).

## Perubahan
- dripstoreCall: circuit breaker (buka saat 429, min 60s; limit HARIAN = 15 menit),
  coalescing GET identik, micro-cache products.php 20s / balance.php 8s.
- Snapshot: negative cache 45s setelah gagal, fail-fast saat breaker terbuka,
  warm dihentikan saat breaker/cooldown/cache masih segar.
- Checkout: pakai last-known-good saat breaker terbuka. Order yang sudah dibayar TETAP
  dapat key (POST generate_key.php tidak diblok breaker).
- /api/catalog/stock & /api/products/:id/stock: kirim rateLimited + header Retry-After.
- home.ejs & buy.ejs: berhenti retry kalau rateLimited / HTTP 429.
- Endpoint baru: GET /admin/dripstore/status (cek breaker).

## Hasil uji (mock provider)
| Skenario                          | Lama            | Baru            |
|-----------------------------------|-----------------|-----------------|
| 200 page load saat provider limit | 200+200 hit     | 1+1 hit         |
| Page load saat breaker terbuka    | tetap nembak    | 0 hit           |
| 1 order LIVE, cache dingin        | 6 request       | 3 request       |
| Order berbayar saat breaker buka  | -               | dapat key (1 hit)|

## Catatan penting
- Limit HARIAN di sisi DripStore baru reset sesuai jadwal mereka. Fix ini mencegah
  limit kebakar lagi, bukan mereset kuota yang sudah habis.
- Breaker & cache bersifat per-instance Vercel (in-memory). Snapshot lintas instance
  tetap lewat dripstore_snapshot.json di Supabase seperti sebelumnya.
- Kalau limit tetap sering kena, tanya owner DripStore kuota harian akun lo, lalu
  pertimbangkan naikin DRIPSTORE_CATALOG_CACHE_TTL (sekarang 30000 ms).

## Update (23 Sep 2026): tombol "Cek stok" di banyak produk
Gejala: saat kuota DripStore habis, produk provider-backed tanpa key lokal jadi
"Cek stok" (putih), sementara produk dengan key lokal (mis. XREG) tetap "Beli".
Penyebab: getLastGoodDripstoreSnapshot() membuang data kalau SALDO > 10 menit, padahal
tampilan tombol cuma butuh katalog+stok, bukan saldo. Snapshot jadi kosong -> Cek stok.
Fix: getDisplayDripstoreSnapshot() khusus tampilan (katalog basi maks 24 jam, tanpa syarat
saldo). Guard checkout TETAP memakai varian ketat (saldo wajib <10 menit), jadi tombol
"Beli" dari stok basi tidak bisa menembus checkout (diuji: order tetap ditolak).
Batasan: kalau belum pernah ada snapshot sukses sama sekali (deploy baru + kuota sudah habis
+ snapshot Supabase kosong), tetap tampil "Cek stok" sampai kuota reset dan 1 refresh sukses.
