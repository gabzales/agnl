# Panduan: stok key sendiri + QRIS pribadi + kontak (AGHA NL)

## A. Pasang QRIS pribadi
1. Admin > Setting > Pengaturan QRIS > pilih "Statis (Gambar)".
2. Upload foto QRIS (GoPay/DANA/OVO/QRIS merchant) > "Upload Gambar QRIS".
3. Pembeli akan lihat QRIS itu + tombol konfirmasi WA. Order masuk status PENDING.
4. Admin cek mutasi masuk, lalu Admin > Transaksi > "Konfirmasi Bayar". Key terkirim otomatis.
   (Kalau key sudah dikirim manual lewat WA: tombol "Tandai Diproses".)

## B. Pilih sumber key (Setting > DripStore > Mode fulfillment)
- LOCAL STOCK : hanya pakai stok key yang kamu input sendiri. Tidak pernah beli ke DripStore.
- HYBRID      : stok lokal dulu, kalau habis baru beli dari DripStore (saldo reseller terpotong).
- LIVE        : selalu beli dari DripStore saat order dikonfirmasi.
Mau jual dari stok sendiri + QRIS pribadi saja => pilih LOCAL STOCK.

## C. Cara input stok key
Admin > Produk > ikon Keys (atau edit produk > Keys). Satu baris = satu key.

    ABC-111            <- key umum (tanpa durasi)
    ABC-222=1          <- key untuk varian 1 HARI
    ABC-333=7          <- key varian 7 hari
    ABC-444=3h         <- key varian 3 JAM
    ABC-555=30d        <- sama dengan =30 (d = hari, h = jam)

- Pakai tanda SAMA DENGAN (=), BUKAN titik dua (:).
- Angka di belakang = harus sama dengan durasi varian produk (1 hari, 7 hari, 3 jam, dst).
  Key dengan durasi hanya terjual di varian yang durasinya sama.
- Pilih "Tambahkan" untuk menambah stok, "Ganti semua" untuk menimpa seluruh stok.
- Key dobel otomatis dibuang. Jumlah stok muncul di kartu produk.

## D. Kontak yang bisa diganti
Admin > Setting > Kontak: WhatsApp, Telegram, Instagram (username atau link), Saluran WA.
Yang diisi otomatis tampil di footer beranda, menu, dan halaman beli. Kosongkan untuk menyembunyikan.
