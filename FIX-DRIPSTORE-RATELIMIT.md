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

## Update (24 Sep 2026): produk yang namanya beda dari nama asli di DripStore
Kasus: HG APK MOD GLOBAL (RANK) = "HG CHEAT SAFE SERVER" di DripStore, dan
HG APK MOD CR (COSTUM ROOM) = "HG CHEAT BRUTAL". Nama beda -> tidak nyambung -> "Cek stok".
Fix: DRIPSTORE_STRICT_ALIASES di server.js. Aturannya lebih ketat dari alias lama:
nama provider harus SAMA dengan alias atau MENGANDUNG alias sebagai kata utuh, dan nama
lokal tidak dipakai buat mencocokkan. Sebabnya: di kode lama, kedua nama itu bisa nyasar
ke produk provider bernama "HG APK MOD" (saling-mengandung), yaitu produk yang SALAH.
Produk lama tidak berubah (diuji 80 kombinasi nama x durasi, hasil lama = baru).

Setelah deploy: Admin -> "Sync & Auto Map". Ini juga menimpa Variant ID lama yang mungkin
kesimpan salah. Kalau kedua produk masih masuk daftar "unmatched", nama asli di API DripStore
beda dari nama di chat: ketik "hg" di kotak "Cari katalog DripStore", baca nama aslinya,
lalu ubah alias di DRIPSTORE_STRICT_ALIASES.
Catatan: checkout live selalu resolve variant dari NAMA di katalog terkini (ID tersimpan
cuma fallback), jadi mapping lama yang salah tidak bisa menyebabkan salah kirim key.

## Update (24 Sep 2026): provider TIMEOUT (bukan 429) bikin order kepending/gagal
Dari Log Live: 0 kena 429, tapi puluhan "DripStore timeout (4 detik)" per jam, sampai
order FX-DR67-YN6V gagal fulfill (dana sudah masuk, key kosong, harus diproses manual).

Penyebab: timeout GET/POST ke provider di-set 4/5 detik. Dari pola log, DripStore
normalnya balas 1-2 detik tapi kadang butuh 5-13 detik (bahkan pernah 90+ detik untuk
1 request yang akhirnya tetap gagal). 4 detik terlalu ketat untuk provider selelet ini,
jadi request yang sebenarnya cuma "belum sempat kejawab" divonis gagal.

Fix:
1. Timeout GET dinaikkan 4dtk -> 8dtk, POST 5dtk -> 20dtk (generate_key.php butuh
   waktu lebih lama karena provider benar-benar memproses pembelian).
2. Error jaringan (ECONNRESET dkk) sekarang dianggap transient juga (sebelumnya cuma
   HTTP 5xx/JSON-invalid yang di-retry otomatis 1x oleh dripstoreCall()).
3. Retry otomatis di-skip kalau breaker rate-limit baru saja trip (menghindari buang
   8 detik lagi untuk kasus yang sudah pasti 429, bukan cuma lelet).
4. vercel.json: functions.server.js.maxDuration=60 (eksplisit). Tanpa ini, worst-case
   proses checkout (guard+fulfill+generate, semua GET timeout penuh) bisa lebih lama
   dari batas default Vercel dan function dipotong paksa di tengah proses pembayaran
   -- ini LEBIH BURUK daripada gagal biasa (order bisa nyangkut status tidak jelas).
5. PALING PENTING -- pembedaan error transient vs stok habis definitif:
   Sebelumnya SEMUA kegagalan fulfillment (termasuk timeout) langsung membuat order
   berstatus 'done' dengan outOfStock=true PERMANEN + notif WA "proses manual".
   Sekarang: kalau kegagalannya transient (timeout/network/5xx/rate-limit), order
   TETAP 'pending' (bukan 'done'), klaim fulfillment dilepas, dan percobaan
   berikutnya (polling client /check-payment ATAU admin klik "Konfirmasi Manual")
   akan mencoba fulfillment lagi secara otomatis begitu provider merespons. outOfStock
   permanen hanya terjadi kalau provider BENERAN bilang variant/stok tidak ada.
   Diuji: timeout 1x pulih sendiri (retry internal), timeout berulang -> pending
   (bukan outOfStock), lalu begitu provider sehat -- percobaan berikutnya langsung
   dapat key tanpa nunggu 5 menit guard klaim-yatim.

Log Live sekarang juga memisahkan "timeout" dari error lain, dan menghitung berapa
order yang sedang menunggu retry otomatis (panel Diagnosa -> "Order menunggu retry
otomatis"). Kalau angka ini terus > 0 dalam waktu lama, itu tanda provider memang
lagi bermasalah beneran (bukan cuma lelet sesaat) -- saatnya hubungi CS DripStore.

Batasan: kalau providernya down TOTAL (bukan cuma lelet), order tetap 'pending'
selamanya sampai ada yang polling ulang. Kalau pembeli menutup tab dan tidak ada
webhook susulan, order tidak otomatis re-check dengan sendirinya -- solusinya klik
"Konfirmasi Manual" di admin begitu provider pulih (jalur ini sekarang aman dipakai
kapan saja karena idempotent dan langsung retry fulfillment).

## Update (25 Sep 2026): laporan client -- stok "habis" padahal sebagian aman, kode order sulit dilacak

### A. Stale-While-Revalidate murni untuk rute publik (/, /buy/:id, /admin)
Root cause tambahan dari laporan ini (dikonfirmasi log client: 47.9% request ke DripStore
gagal/timeout): rute publik masih MENUNGGU (await) hasil fetch live ke provider sampai
2.5-4.5 detik setiap kali cache fresh (TTL 30 dtk) habis -- bukan cuma saat cold start.
Saat provider lelet/timeout, SEMUA pengunjung yang datang di jendela itu ikut nunggu lama,
dan kalau providernya mati total, mereka tetap dapat kondisi "gagal" walau sebenarnya ada
data katalog basi yang valid untuk ditampilkan. Ini match dengan laporan "sebagian konsumen
aman aja" -- yang beruntung dapat cache fresh, yang apes kena jendela tunggu penuh.

Fix: home/buy/admin sekarang HANYA menunggu network kalau BENAR-BENAR tidak ada snapshot
apa pun di memori (kondisi ini cuma terjadi sekali per cold start Vercel). Begitu pernah
ada 1 snapshot sukses, request berikutnya SELALU pakai data (fresh atau basi, maks 24 jam)
tanpa menunggu network sama sekali -- refresh tetap terjadi tapi di background
(warmDripstoreCatalog), dengan throttle 5 detik antar percobaan supaya tidak membombardir
provider yang sedang bermasalah.
Diuji: homepage & /buy/:id tetap balas <500ms walau provider timeout total (sebelumnya
3500-4500ms per request); pengunjung kedua tidak memicu outbound call tambahan (throttle).

### B. Kapasitas log tersimpan dinaikkan (300 -> 1500 baris)
Client melaporkan tidak bisa lagi menemukan log error yang relevan ("udah kehapus/gak
nemu lagi") saat diminta. Kemungkinan penyebab: pada traffic tinggi + provider bermasalah,
warn/error yang menumpuk cepat menggeser baris lama sebelum sempat dibaca (300 baris habis
dalam hitungan menit saat error beruntun). Dinaikkan ke 1500 baris supaya jendela waktu
untuk investigasi lebih longgar. Tombol "Bersihkan" tetap ada konfirmasi sebelum menghapus.

### C. "Sebagian kode pesanan ga kebaca" -- BELUM bisa dipastikan akar penyebabnya
Client tidak sempat menyimpan log dari kejadian ini sebelum terhapus, jadi tidak bisa
dikonfirmasi lewat bukti. Kemungkinan yang SUDAH diperiksa dan TIDAK bermasalah:
resolveDripstoreVariantFromCatalog() sudah aman (return null saat katalog kosong/timeout,
tidak pernah menampilkan kode yang salah/rusak). Kemungkinan lain: potongan/kegagalan
rendering pada sisi pengiriman WhatsApp (Fonnte) -- di luar kendali kode aplikasi ini.
TINDAK LANJUT: kalau kejadian lagi, SEGERA salin baris log dari /admin/logs (tombol
Salin) SEBELUM melakukan hal lain, lalu kirim ke gue. Tanpa log asli, ini tidak bisa
didiagnosis lebih jauh -- dugaan tanpa bukti berisiko salah perbaikan.


## Update (25 Sep 2026, sore): alias HG CHEAT BRUTAL ternyata masih belum nyambung
Client konfirmasi ulang lewat screenshot chat (client sudah bilang instruksi yang sama
sejak 24 Sep) bahwa produk masih "ga kontek ke web Drip". Diselidiki ulang dengan
memeriksa nama produk PERSIS dari screenshot, bukan dari ingatan chat sebelumnya.

Penyebab: nama produk lokal yang sebenarnya adalah "HG APK MOD CR (COSTUM ROOM ONLY)"
-- ada kata "ONLY" di akhir yang tidak ada di alias yang didaftarkan sebelumnya
('hg apk mod cr costum room', tanpa "only"). Karena DRIPSTORE_STRICT_ALIASES mencocokkan
KEY secara persis (bukan substring), kata tambahan ini membuat produk sama sekali tidak
ketemu aliasnya -- persis seperti sebelum di-alias sama sekali.

Fix: ditambahkan key 'hg apk mod cr costum room only' dan 'hg apk mod cr custom room
only' ke DRIPSTORE_STRICT_ALIASES, plus tetap mempertahankan variasi lama sebagai
jaga-jaga (custom/costum, dengan/tanpa "only"). "HG APK MOD GLOBAL (RANK)" = HG CHEAT
SAFE SERVER sendiri sudah cocok dari alias sebelumnya, tidak perlu diubah.

Pelajaran untuk ke depan: kalau admin bilang "produk X masih belum nyambung ke provider"
padahal alias sudah pernah ditambahkan, JANGAN asumsikan nama produknya sama seperti
yang tercatat di riwayat chat sebelumnya -- minta screenshot/nama PERSIS dari halaman
produk sekali lagi, karena satu kata tambahan (seperti "ONLY") sudah cukup membuat
strict-match gagal total, dan gejalanya identik dengan alias yang belum pernah dipasang.
