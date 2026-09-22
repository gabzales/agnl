# Fix: Icon WA/Telegram Kepotong + Tombol Hubungi CS (AGNL)

## 1. Bug icon WA/Telegram footer kepotong/geser (bukan kosong)
Root cause: SVG inline dengan `width="20" height="20"` sebagai attribute
HTML tidak center dengan benar di dalam flex container `.fz-social` --
hasilnya cuma sudut kecil SVG yang kelihatan (screenshot kamu tunjukin
ini persis).

**Fix:** diganti dari SVG inline ke `<iconify-icon>` (konsisten dengan
SEMUA icon lain di seluruh situs ini yang sudah terbukti center dengan
benar -- navbar, tombol search, dll), plus `border-radius` diubah dari
50% (bulat) ke 10px (rounded square, sesuai referensi kompetitor yang
kamu kasih).

File: `views/pages/home.ejs`

## 2. Tombol Hubungi CS (WA) -- 3 halaman

### Halaman detail produk (`buy.ejs`)
**SUDAH ADA** sebelumnya -- tombol "WA CS" di dekat tombol "Simpan ke
Keranjang". Tidak perlu ditambah lagi.

### Halaman pembayaran (`buy.ejs`, bagian modal QRIS)
**BARU DITAMBAHKAN.** Sebelumnya tombol WA CUMA muncul untuk mode QRIS
statis (`#staticNote`, cuma untuk konfirmasi transfer manual) -- kalau
toko pakai QRIS dinamis (API Pakasir/GensPay/Stenly), user yang lagi
nunggu bayar TIDAK PUNYA jalur kontak CS sama sekali. Sekarang ada
tombol "Ada Kendala? Hubungi CS" yang SELALU tampil apapun mode
pembayarannya.

### Halaman sesudah bayar (`invoice.ejs`)
**BARU DITAMBAHKAN**, 2 tempat:
- Transaksi sukses (`status: 'done'`, ada key) -- tombol "Ada Kendala
  dengan Pesanan? Hubungi CS", pesan WA sudah terisi otomatis dengan
  kode pesanan.
- Transaksi sukses tapi stok kosong (`outOfStock`) -- tombol "Hubungi
  CS via WhatsApp" lebih ditekankan di sini karena user memang perlu
  tindak lanjut manual dari admin.

File: `views/pages/buy.ejs`, `views/pages/invoice.ejs`

## Cara pasang
Timpa `views/pages/home.ejs`, `views/pages/buy.ejs`,
`views/pages/invoice.ejs`, deploy ulang.
