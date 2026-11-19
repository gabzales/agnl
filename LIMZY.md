# Provider Limzy (limzyyxit.my.id) — khusus AGNL
1. Admin > Settings > "Limzy — Provider Auto Restock": isi API Key (disimpan di settings.limzy, TIDAK ada di kode) > Simpan > Tes Kunci.
2. Edit Produk > tiap paket: pilih "Limzy 1/3/7/30 hari" (dropdown hijau). Kosong = Limzy tidak dipakai.
3. Urutan: DripStore > DripStore Web 2 > Panelstore > Limzy. Error timeout/5xx tidak lanjut ke provider lain (cegah beli dobel).
4. POST /admin/limzy/reset-hwid {key} tersedia untuk reset HWID (reset_hwid.php).
Catatan: API key yang sempat dipaste ke chat sebaiknya di-regenerate di dashboard Limzy.
