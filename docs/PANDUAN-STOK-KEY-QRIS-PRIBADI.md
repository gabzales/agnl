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

Provider cadangan (aktif di mode HYBRID/LIVE, hanya untuk paket yang sudah dipetakan di Edit Produk):
DripStore -> DripStore Web 2 -> Bantibhaiya -> Panelstore. Kalau satu provider habis stok/saldo, otomatis lanjut
ke berikutnya. Kalau timeout/error server, berhenti dan pesanan masuk retry (supaya tidak beli ganda).
Mode LOCAL STOCK tidak pernah memakai provider manapun.

## C. Cara input stok key
Admin > Produk > ikon Keys (atau edit produk > Keys & Stok). Satu baris = satu key.

### Cara mudah (disarankan): pilih varian, tempel key ASLI
1. Di kotak "Masukkan ke varian", pilih paket tujuan (mis. "1 jam"). Produk dengan 1 paket: otomatis terpilih.
2. Tempel key asli (atau "Import dari File (.txt)"), mis. `PHTM-FF48-CC84-0ABD`. Tidak perlu mengetik tag.
3. Pilih "+ Tambah" (atau "Ganti Semua"), lalu Simpan. Tag durasi dipasang otomatis saat simpan.
   Di bawah kotak tampil hitungan "N key akan masuk ke varian X".
- Baris yang sudah kamu beri tag sendiri (mis. `KEY=7d`) dipertahankan apa adanya.
- Daftar key tersimpan menampilkan key asli + label varian (mis. `XXXX · 1 jam`).

### Cara manual (pilih "Sesuai tag di tiap baris")
Tulis tag sendiri di akhir tiap key:

    ABC-222=1          <- key untuk varian 1 HARI
    ABC-333=7          <- key varian 7 hari
    ABC-444=3h         <- key varian 3 JAM
    ABC-555=30d        <- sama dengan =30 (d = hari, h = jam)

- Pakai tanda SAMA DENGAN (=), BUKAN titik dua (:).
- Angka di belakang harus sama dengan durasi paket (1 hari, 7 hari, 3 jam, dst).

### Penting
- Tag `=1h` / `=7d` hanya penanda internal di stok. Saat key dikirim ke pembeli, tag DIBUANG — pembeli hanya
  menerima key aslinya.
- Key TANPA tag (key umum) TIDAK akan terpakai untuk pesanan paket berdurasi: sistem hanya mengambil key yang
  tag-nya persis cocok. Key tanpa tag menumpuk di stok dan pembeli tetap melihat "stok kosong". Selalu pilih
  varian saat menempel key.
- Tombol Export mengeluarkan key lengkap dengan tag, supaya bisa langsung di-import lagi.
- Pilih "Tambah" untuk menambah stok, "Ganti Semua" untuk menimpa seluruh stok.
- Key dobel otomatis dibuang. Jumlah stok muncul di kartu produk.

## D. Kontak yang bisa diganti
Admin > Setting > Kontak: WhatsApp, Telegram, Instagram (username atau link), Saluran WA.
Yang diisi otomatis tampil di footer beranda, menu, dan halaman beli. Kosongkan untuk menyembunyikan.
