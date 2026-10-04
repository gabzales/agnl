# 4 Okt 2026

## 1. Supabase "Services restricted" (quota habis)
Bukan banned, tapi org kena restrict karena Cached Egress > kuota free (5GB).
Cached Egress = Storage (gambar), bukan query DB. Sumbernya gambar produk/banner
yang di-embed langsung dari Supabase ke tiap pengunjung (~1.7GB/hari).

Fix di kode (paket ini):
- Semua URL storage ditulis ulang ke /media/<file>, disajikan lewat CDN Vercel
  (cache 1 tahun). Supabase kena 1x per file, bukan per pengunjung.
- Upload baru otomatis cacheControl 1 tahun.

Cara balikin toko (pilih satu):
- A. Upgrade org ke Pro (spend cap ON) -> restrict langsung kebuka.
- B. Tunggu reset siklus 14 Okt 2026.
- C. Pindah ke project/org baru: migrate-supabase.js (lihat header file).
  Gambar lama ikut hilang kecuali di-download dari Storage dan di-upload ulang.

Deploy paket ini DULU sebelum kuota baru, kalau nggak habis lagi.

## 2 & 3. Import varian DripStore + harga margin
Admin -> Settings DripStore -> kotak "Import Varian dari DripStore".
- Untung (%) : harga jual = harga provider x kurs x (1+%), dibulatkan ke atas.
- Kurs       : isi 1 kalau harga provider sudah Rupiah; kalau USD isi kurs (mis. 16500).
- Mode "varian": tambah durasi baru ke produk yang sudah ada.
- Mode "semua" : + bikin produk baru dari katalog provider (default nonaktif).
- Preview dulu, baru Import Sekarang. Opsi update harga varian yang sudah ada.
- Varian provider tanpa durasi terbaca (mis. "Permanent") dilewati.
