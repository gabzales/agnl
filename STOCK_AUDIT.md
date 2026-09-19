# AGHA NL — Stock Root Audit v22

Audit scope: source-of-truth stok lokal, mapping DripStore, per-variant capacity, cache/fail-closed, checkout guards, concurrency/lost-update, dan UI status di Home / Buy / Admin / Product Edit.

## 1. Source of truth

- **Local stock** = key lokal yang usable, unik secara string, lalu dicocokkan **exact** berdasarkan `(durasi, unit)`.
- Placeholder seperti `Stok tidak tersedia:*`, `Stock unavailable:*`, dan `Produk tidak tersedia:*` tidak dihitung sebagai inventory.
- **Provider stock** = `floor(balance_cents / variant_cost_cents)` untuk **setiap variant**. Perhitungan memakai integer cents agar tidak kena floating-point error.
- **HYBRID** = `local exact stock + provider capacity` untuk durasi/unit yang sama.
- **LIVE** = provider capacity saja untuk tampilan/fulfillment; stok lokal tidak boleh membuat variant LIVE yang belum ter-map terlihat tersedia.
- **LOCAL** = local exact stock saja.
- Stok level produk menggunakan **MAX antar-variant**, bukan penjumlahan antar durasi. Menjumlahkan 3 hari + 7 hari + 30 hari menjadi satu angka akan misleading karena customer membeli salah satu variant, bukan semuanya sekaligus.

## 2. Mapping provider

- `products.php` provider terkini adalah authority untuk resolve variant saat checkout.
- `dripstoreVariantId` yang tersimpan hanya metadata/fallback; sistem tidak percaya ID lama sebagai authority final.
- Matching nama sengaja dibatasi ke **exact / containment + explicit aliases**. Broad token-overlap fuzzy matching dihapus agar produk mirip seperti `DRIP CLINT APK MOD` tidak salah masuk ke `DRIP CLINT ROOT`.
- Alias eksplisit yang dipakai saat ini mencakup `XREG APK MOD -> AIM HACK` dan `DRIP CLINT APK MOD -> Drip client apk mod`.
- Parser durasi mendukung jam, hari, dan tahun (`thn/tahun/year/...`). Satu tahun dinormalisasi menjadi **365 hari**.

## 3. Per-variant semantics

Setiap variant berdiri sendiri.

Contoh saldo provider `$1.34`:

- `$0.90` => `floor(1.34 / 0.90) = 1` provider capacity.
- `$1.40` => `0` provider capacity.
- `$5.00` => `0` provider capacity.

Pada HYBRID, hasil akhirnya tetap ditambah stok lokal untuk variant yang sama.

Jadi satu variant mahal yang tidak terjangkau **tidak boleh mematikan variant murah** pada produk yang sama.

## 4. Checkout authority

- `/create-order` melakukan pre-flight guard hanya untuk variant yang memang akan membutuhkan provider.
- Final fulfillment selalu resolve product + duration terhadap katalog provider terbaru sebelum purchase.
- LIVE: provider first.
- HYBRID: local exact first, lalu provider fallback bila local exact kosong.
- LOCAL: local exact only.
- Tepat sebelum `generate_key.php`, balance + harga variant dicek ulang dan purchase dipagari dengan purchase lock.
- Sync / mapping tidak pernah memanggil `generate_key.php`.

## 5. Local inventory safety

- Semua jalur konsumsi key lokal lewat `consumeLocalProductKey()`.
- Durasi + unit harus exact; key durasi lain tidak dipakai.
- Duplicate key identik dipurge saat satu key berhasil dikonsumsi sehingga legacy duplicate tidak bisa dijual dua kali.
- Mutasi stok hot-path menggunakan product lock + single `products.json` writer untuk mencegah lost-update saat checkout bersamaan dengan mapping/restock/admin inventory write.

## 6. Cache / fail-closed

- Provider catalog cache TTL: 30 detik.
- Cache hanya dianggap authoritative jika balance dan `products.php` sama-sama berhasil dibaca.
- Setelah TTL kedaluwarsa, refresh gagal => provider dianggap **unknown**, bukan dianggap nol dan bukan memakai saldo lama sebagai stok baru.
- HYBRID masih boleh menampilkan local stock yang benar ketika provider unknown.
- LIVE menampilkan `Cek stok provider` ketika kapasitas provider belum bisa diverifikasi.

## 7. Frontend audit

### Home / Dashboard

- Tombol `Beli` muncul bila minimal satu variant punya stock > 0.
- Bila tidak ada stock tetapi provider masih unknown, status `Cek stok`.
- Bila provider sudah known dan semua variant 0, status `Habis`.
- Tidak ada raw local key yang dikirim ke JS publik.

### Buy detail

- Setiap kartu durasi memiliki status sendiri: `N stok`, `Habis`, atau `Cek stok provider`.
- Satu variant 0 tidak men-disable variant lain yang masih tersedia.
- Setelah refresh stock, state `selPkg.stock` ikut diperbarui agar tombol checkout tidak memakai angka lama.
- Halaman melakukan satu refresh stock ringan untuk produk yang memang provider-backed; endpoint menggunakan cache provider sehingga tidak otomatis menembak provider sekali per kartu.
- Jika response stock tidak sejajar dengan jumlah kartu yang dirender, kartu tanpa data dibuat nonaktif + `Cek stok provider` agar status lama tidak tertinggal secara misleading.
- Checkout backend tetap menjadi authority terakhir; angka UI hanya informasi/prefilter.

### Admin product edit

- Per opsi ditampilkan `Lokal X + Provider Y = Z stok` ketika provider known.
- Provider unknown ditampilkan sebagai `Provider cek stok`, bukan `0` palsu.
- Produk tahun legacy tetap dikenali sebagai 365 hari; label tampilan mempertahankan label human-friendly dari `items`.

## 8. Tests / validation

- `node --check server.js` : **PASS**
- `node stock_logic_test.js` : **PASS**
- JS blocks dari `buy.ejs`, `home.ejs`, `admin.ejs`, `admin-product-edit.ejs` diekstrak dan dicek dengan `node --check` : **PASS**
- Test fixture reproduces the important case: balance `$1.34`, XREG alias -> AIM HACK, local 3d + provider 3d = combined stock 3, while provider 7d capacity stays 0.

## 9. Known architectural limits

- Provider virtual capacity bukan reservation. Dua buyer yang melihat angka capacity yang sama tetap bisa bersaing; final balance guard + provider API adalah authority terakhir.
- API provider yang terintegrasi tidak menyediakan mekanisme idempotency/refund yang sudah terverifikasi. Crash yang sangat jarang setelah provider sukses purchase tetapi sebelum hasil disimpan bisa membutuhkan reconciliation manual.
- Ada beberapa tool maintenance kategori lama yang masih melakukan write `products.json` di luar hot-path stock lock. Itu tidak dipakai oleh checkout/stock refresh/mapping normal, tetapi sengaja tidak diubah dalam audit ini agar tool one-off tidak berubah perilakunya.
