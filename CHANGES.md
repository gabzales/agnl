# AGNL — Redesign ringan (gaya ThanHub, tema hitam-merah)

## Hasil ukur (home, 6 produk contoh)
| | Sebelum | Sesudah |
|---|---|---|
| HTML beranda | 118,7 KB (gzip 25,1 KB) | 32,4 KB (gzip 6,6 KB) |
| Request ke domain luar (icon/font) | Iconify API per icon + Google Fonts | 0 |
| Delay pindah halaman | fade-out 150 ms tiap klik | tidak ada |
| CSS+JS (di-cache browser, versi `?v=`) | CSS/JS inline di tiap halaman | tailwind 6 KB + app.css 7 KB + icons 21 KB + layout 4 KB + home 3 KB (gzip) |

## Tampilan
- Tema: gelap hitam-merah default; mode terang tetap ada, tombol matahari/bulan melayang (ala ThanHub). Pilihan tersimpan di `localStorage` (`agnl-theme`). Warna aksen ikut Admin → Tema (`primaryColor`).
- Header + menu samping, banner (swipe native, autoplay), chip kategori + cari, kartu produk horizontal, slider ulasan, benefit strip, footer pill komunitas, tombol WA + tema melayang.
- Semua halaman publik (beli, dashboard, invoice, track, aktivasi key, informasi, login/daftar, reseller) memakai header/footer/tema yang sama.
- Icon: `public/js/icons.js` (custom element `<iconify-icon>` lokal). Icon baru → tambahkan nama di view lalu jalankan `tools/build-icons.js` (petunjuk di dalam file).

## Dihapus
- Section & pengaturan **Popular**; **Leaderboard** (home, `/leaderboard`, `/api/leaderboard`, tab + modal admin, entri palsu).
- **Testimoni palsu** hardcode (home dan `/api/testimonials`). Ulasan sekarang dari data nyata + yang ditambah admin (form admin menerima tanggal opsional). Badge "Verified Buyer" hanya untuk yang bertanda verified.
- Tool admin sekali pakai: `/agha-setup`, `fix-categories-agha`, `cleanup-categories-agha`, `import-client-apk`, `repair-apk-no-root`, `migrate-images`, `audit/xreg-aim-hack`, Auto Gambar AI; skrip `add-client-products`, `migrate-images*`, `migrate-supabase`, `seed.js`, `setup.sh`; backup `.pre-darkmode`. Dokumen lama dipindah ke `docs/`.
- `reset-admin.js`: kredensial default di source dihapus (wajib isi `SEED_ADMIN_USERNAME/PASSWORD` di `.env`).

## Performa server
- `/media/<file>?w=` (96–1280) → webp kecil, cache CDN 1 tahun; gambar produk/banner/logo memakai ukuran kecil.
- `s-maxage` untuk API baca publik (products, stats, testimonials, notifications, banners; stok 15 dtk). Otomatis dibatalkan kalau response bukan 200 atau bawa Set-Cookie.
- Beranda memakai `readSmart` (bukan `readFresh`), banner di-render server-side (hemat 1 request).
- Popup "baru saja beli": maks 1x per 3 menit per browser, dilewati saat tab background.

## Catatan
- Zip yang diunggah berisi dokumen `HEMAT-VERCEL-6OKT.md` tetapi kodenya (resize `?w=`, s-maxage, dll.) belum ada; bagian tersebut sudah dimasukkan di sini.
- Alur beli tetap halaman `/buy/:id` (logika pembayaran tidak diubah), hanya tampilannya diseragamkan. Panel admin tidak di-restyle (hanya dibersihkan & icon lokal).
- Tidak dilakukan: cache CDN untuk HTML beranda (berisi status login).


---

# Update 2 (9 Okt 2026) — alur beli ala ThanHub, WijayaPay, hemat Vercel & DripStore

## Alur beli = sama dengan ThanHub
- Tombol **BELI SEKARANG** membuka **bottom-sheet 2 langkah** (Durasi → Konfirmasi) tanpa pindah halaman dan tanpa request (data durasi/harga/stok sudah ada di halaman). Isi: pilih durasi, voucher, nama, WhatsApp, **BAYAR SEKARANG** (+ **BAYAR PAKAI SALDO** untuk reseller).
- Setelah bayar → halaman **/pay/:refId** (Scan QRIS, total, cara bayar, countdown, cek status) → otomatis berubah jadi **Pembayaran Berhasil** + key + tombol salin.
- QR dirender **lokal** (`public/js/qr.js`), bukan lagi lewat `api.qrserver.com` (lebih cepat dan data pembayaran tidak dikirim ke pihak ketiga).
- `/buy/:id` lama → redirect ke beranda dan langsung membuka sheet produk itu (link lama tetap hidup). Halaman beli lama (1.281 baris) dihapus.
- Hasil tes lokal: klik BAYAR → halaman QRIS tampil ±0,5 dtk (di luar waktu API gateway).

## WijayaPay (gateway ketiga, selain PakKasir & GensPay)
- `wijayapay.js` + route `/webhook/wijayapay` + Admin → QRIS → tombol **WijayaPay** (Code Merchant, API Key, Test Koneksi, URL webhook).
- Webhook: cek `X-Signature` (md5), cek nominal terhadap database, idempotent, balas `{status:true}`. Status juga dicek lewat `get-status` (polling hemat).
- Isi `APP_URL` di env supaya `callback_url` dikirim otomatis per transaksi (atau daftarkan `https://domain/webhook/wijayapay` di dashboard WijayaPay).
- Diuji end-to-end dengan gateway tiruan: buat order, signature, webhook palsu ditolak, nominal salah ditolak, webhook valid → key terkirim, ulang webhook aman, polling paid, expired.

## Hemat Vercel (Active CPU / Origin Transfer / Invocations)
- **HTML beranda & informasi di-cache CDN** (`s-maxage` 60 dtk / 300 dtk + stale-while-revalidate). Syaratnya HTML tidak boleh beda per pengunjung, jadi status login sekarang dibaca browser dari cookie petunjuk `agu` (hanya untuk tampilan; keamanan tetap dicek server). Ini menghilangkan 1 invocation per page view untuk sebagian besar kunjungan.
- Panggilan `/api/catalog/stock` dari beranda dihapus (stok sudah ada di HTML). Banner di-render server-side. Notifikasi "baru saja beli" maks 1x/3 menit/browser.
- **Polling pembayaran** diperlambat bertahap (5 dtk ×4 → 10 dtk ×6 → 20 dtk; QRIS statis 30 dtk; berhenti saat tab tersembunyi). Webhook tetap jalur utama.
- Halaman beli lama yang membaca produk + stok provider + transaksi tiap kunjungan sudah tidak ada.
- Gambar via `/media/…?w=` (webp kecil, cache CDN setahun), CSS/JS statis ber-versi.

## Hemat API DripStore
- Cache `products.php` 20 dtk → **10 menit**, `balance.php` 8 dtk → **60 dtk** (per instance), snapshot katalog 5 → **10 menit**.
- Tepat sebelum `generate_key` (uang keluar) saldo **wajib ≤5 dtk** (dicek ulang live), jadi akurasi pembelian tidak berkurang.
- Setiap penjualan tidak lagi menulis ulang snapshot DripStore ke Supabase.
- Sisa ide yang belum dikerjakan: kolom `transactions.json` masih satu blob JSON (tiap order/poll membaca seluruh blob) — pemecahan jadi tabel per transaksi akan memangkas CPU/egress paling besar, tapi perubahan struktur data dan sebaiknya dikerjakan terpisah.

## Belum disamakan 100% dengan ThanHub
- Halaman **dashboard** dan **invoice/cek pesanan** sudah satu tema (gelap-merah, header/footer sama) tetapi susunannya belum ditulis ulang persis seperti halaman Akun/Status ThanHub; fitur wallet/top-up reseller membuat dashboard lebih kompleks.
- Sheet tidak punya pilihan jumlah (qty) karena checkout AGNL memang 1 key per order.
- Form ulasan per produk (di halaman beli lama) hilang; ulasan ditampilkan dari testimoni di beranda.

---

# Update 3 (10 Okt 2026)

- **Tombol Download APK / Saluran per produk**: muncul di sheet beli (di bawah tombol bayar) dan di halaman Pembayaran Berhasil. Link diambil dari kolom *Link Saluran* produk di admin (`channelUrl`; kalau kosong dipakai `downloadUrl`).
- **Proses pesanan dipercepat**: pembacaan users/products/transactions di `/create-order` sekarang paralel (dulu berurutan, tiap pembacaan = 1 round-trip ke Supabase), penulisan transaksi + voucher paralel. Respons membawa header `Server-Timing` (DevTools → Network → klik `create-order` → Timing) berisi durasi tiap tahap: `db_read`, `pre_checks`, `gateway`, `db_write`, `total`.
- **Dashboard** ditulis ulang seperti halaman Akun ThanHub: profil, saldo reseller (top up tetap), ringkasan, riwayat pesanan berupa kartu dengan tombol *Bayar* untuk pesanan pending dan *Detail* untuk yang lain.

## Catatan latensi (penting)
`vercel.json` belum menentukan `regions`, jadi fungsi berjalan di region default Vercel (Washington D.C.) sementara pembeli dan (kemungkinan) database Supabase ada di Asia. Tiap query ke Supabase jadi menyeberang benua, dan satu order butuh beberapa query. Cek region project Supabase (Project Settings → General). Kalau Singapore, tambahkan `"regions": ["sin1"]` di `vercel.json` (bagian atas, sejajar `"functions"`) lalu redeploy; biasanya ini pemangkas delay terbesar. Kalau Supabase di region lain, pilih region Vercel yang terdekat dengannya.

## Region fungsi Vercel
`vercel.json` sekarang memuat `"regions": ["sin1"]` (Singapore) agar fungsi berjalan di region yang sama dengan Supabase (ap-southeast-1). Tanpa ini fungsi jalan di Washington D.C. dan tiap query ke Supabase menyeberang benua. Kalau di dashboard Vercel (Settings → Functions → Function Region) sudah ada pengaturan sendiri, samakan ke Singapore (sin1).

---

# Update 4 — pemangkasan project
- Dihapus: `express-session` (tidak dipakai, sudah `cookie-session`), `check-readiness.sh`, `stock_logic_test.js`, dan ±15 dokumen catatan perbaikan lama di `docs/` (tersisa 3 yang masih berguna: ADMIN-PANEL-DOCS, CLOUDFLARE-SECURITY, PANDUAN-STOK-KEY-QRIS-PRIBADI).
- Logo di-compress: `logo-main.png` 109 KB → 11 KB, `logo-text.png` 154 KB → 17 KB (tampilan sama; dipakai di header/footer tiap halaman).
- `qr.js` di-minify 57 KB → 21 KB.
- `vercel.json`: `/css/*` dan `/js/*` cache 1 tahun (immutable; URL sudah ber-versi `?v=`), `/uploads/*` cache 1 hari → browser tidak lagi meminta ulang aset tiap kunjungan.
- Catatan: jumlah file tidak memengaruhi kecepatan memproses pesanan; yang memengaruhi adalah jarak server ke database (region) dan jumlah query per pesanan.

---

# Update 5 — deteksi pembayaran
- `vercel.json`: cron `/cron/reconcile` dari **1x sehari** menjadi **tiap 5 menit**. Order pending yang gatewaynya punya API status (PakKasir, WijayaPay) otomatis dicek ulang dan key dikirim walau webhook belum dipasang / pembeli menutup halaman. Wajib set env `CRON_SECRET` di Vercel (isi bebas, string acak panjang).
- **GensPay tidak punya API status**: pembayarannya HANYA terdeteksi lewat webhook `https://DOMAIN/webhook/genspay` (isi di dashboard GensPay → project → Webhook URL). Tanpa itu order GensPay tidak akan pernah lunas otomatis.
- **PakKasir**: webhook `https://DOMAIN/webhook/pakasir` + isi *Webhook Secret* di Admin → QRIS → PakKasir (dikirim sebagai header `X-Secret`).
- **WijayaPay**: webhook `https://DOMAIN/webhook/wijayapay` (daftarkan di dashboard WijayaPay, atau isi env `APP_URL` supaya dikirim per transaksi). Punya API status, jadi terdeteksi walau webhook belum terpasang.

---

# Update 6 — bantuan WhatsApp di halaman bayar (tanpa bot)
- Halaman `/pay/:id` (menunggu bayar): tombol **"Sudah bayar tapi belum masuk? Chat CS via WhatsApp"**. Membuka WhatsApp CS dengan pesan siap kirim berisi Order, Kode, Produk, dan Total, jadi admin langsung tahu pesanan mana yang harus dicek/konfirmasi. Nomor diambil dari Admin → Kontak (CS WhatsApp).
- Halaman "Pembayaran Berhasil": tombol **"Butuh bantuan? Chat CS"**.
- Ini bukan notifikasi otomatis ke WA pembeli (itu butuh bot/API WhatsApp). Key tetap tampil di layar dan bisa dilihat lagi lewat Cek Pesanan.

# Update 7 — popup bantuan 1 menit
Di halaman `/pay/:id`, kalau pesanan masih menunggu pembayaran setelah **1 menit**, muncul popup "Sudah bayar tapi key belum masuk?" dengan tombol **Hubungi CS via WhatsApp** (pesan berisi Order/Kode/Produk/Total) dan **Cek status lagi**. Kalau masih pending, muncul lagi tiap 3 menit (maksimal 3 kali). Popup otomatis hilang begitu pembayaran terdeteksi atau order expired, tidak muncul saat tab sedang tersembunyi, dan tidak muncul kalau nomor CS WhatsApp belum diisi.

---

# Update 8 — kode pesanan, alur QRIS statis, maintenance
- **Bug kode pesanan:** halaman bayar menampilkan `Order #FX-1791…` (ID internal berbasis waktu) sedangkan Cek Pesanan memakai kode `FX-XXXX-XXXX`, jadi pembeli menyalin kode yang salah ("Pesanan tidak ditemukan"). Sekarang halaman bayar menampilkan **Kode Pesanan** yang benar + tombol Salin, dan pesan WhatsApp ke CS memakai kode itu. ID internal sengaja TIDAK bisa dipakai untuk lookup publik (mudah ditebak, dan halaman pesanan menampilkan key). Input Cek Pesanan juga dinormalisasi (huruf kecil/spasi/tanda hubung aneh) dan tidak lagi error kalau kosong.
- **QRIS statis (konfirmasi manual):** panel hijau tepat di bawah total bayar: "Setelah transfer, kirim bukti pembayaran ke CS" + tombol **SUDAH TRANSFER? KIRIM BUKTI KE CS** (WhatsApp, pesan terisi kode pesanan, produk, total). Popup bantuan muncul 30 detik setelah halaman dibuka, dan langsung saat pembeli kembali dari aplikasi bank/e-wallet (setelah ≥10 dtk pergi).
- **Maintenance:** (1) per produk, tombol **Maintenance** di kartu produk Admin → kartu beranda menampilkan pill "Maintenance" + tombol nonaktif "SEDANG MAINTENANCE"; (2) **Maintenance TOKO** (tombol di header Manajemen Produk) → banner di beranda dan semua produk nonaktif. Penegakan di server (`/create-order` dan `/wallet/buy`), jadi langsung berlaku walau beranda masih ter-cache CDN (tampilan beranda mengikuti dalam ±1 menit).

---

# Update 9 — stok DripStore, pangkas kode, alur bukti bayar ala toko lama
- **Stok "habis" padahal produk ada di DripStore**: provider tidak memberi angka stok per varian, jadi stok di web = `FLOOR(saldo DripStore ÷ harga modal varian)`. Kalau saldo tipis, varian mahal tampil habis (itu pengaman agar tidak menjual key yang tidak bisa dibeli). **Solusi: top up saldo DripStore**, lalu klik **Admin → Pengaturan → DripStore → "Refresh Stok Sekarang"**. TTL snapshot tampilan dipendekkan 10 → 2 menit (biaya API tetap kecil: katalog di-cache 10 menit, saldo 60 dtk). Cache halaman beranda: `stale-while-revalidate` 600 → 120 dtk.
- **Halaman QRIS statis** meniru toko lama: "Langkah selanjutnya: scan QRIS di atas, bayar sesuai nominal, lalu kirim screenshot bukti pembayaran ke WhatsApp admin untuk di-ACC" + tombol **Kirim Bukti Pembayaran ke WhatsApp** dengan pesan format lama (Produk, Durasi, Total) ditambah Kode Pesanan.
- **Pangkas kode**: `server.js` 412 KB → 363 KB (−12%, 8.092 → 7.386 baris): 8 fungsi/variabel mati dihapus, 88 blok komentar naratif panjang diringkas jadi 1–2 baris (versi lengkapnya ada di riwayat git). Kompresi gzip di dalam fungsi dimatikan di Vercel (CDN sudah meng-compress; hemat Active CPU).
- **`tools/cleanup-legacy.js`**: menimpa project dengan zip tidak menghapus file lama. Jalankan `node tools/cleanup-legacy.js` (pratinjau) lalu `node tools/cleanup-legacy.js --yes` untuk membuang sisa file lama di foldermu. `export.json` (hasil Export Database, berisi data user & transaksi) jangan disimpan di folder project; sudah masuk `.gitignore`.
