# HEMAT SUPABASE — cara pasang (12 Nov 2026)

## Urutan pasang
1. **Supabase (project baru) > SQL Editor** → jalankan isi `supabase-hemat.sql` (sekali, aman diulang).
2. **Vercel > Settings > Environment Variables**: isi `SUPABASE_URL` (https://xxxx.supabase.co) dan
   `SUPABASE_SERVICE_ROLE_KEY` (service_role / secret key, BUKAN anon) dari project Supabase baru → **Redeploy**.
3. Upload kode ini ke GitHub/Vercel (deploy ulang). Buka website sekali. Di Runtime Logs akan muncul:
   `[tx] migrasi selesai: N transaksi dipindah ...` — blob lama otomatis dipecah jadi baris per transaksi.
4. Cek `/admin/db-usage` (jumlah transaksi per status) dan `/admin` (statistik & 20 transaksi terbaru).
5. Setelah yakin semua normal, baris cadangan `backup:transactions-premigrasi-*` di tabel `keyvalue_store`
   boleh dihapus (opsional; ukurannya ±4,5 MB).

## Perkiraan penghematan
| Aksi | Dulu | Sekarang |
|---|---|---|
| Baca transaksi (cek bayar, webhook, /pay, invoice) | 4,5 MB | ±0,7 KB |
| Cold start Vercel | ≥ 4,5 MB | ±50 KB |
| Buka /admin | ≥ 4,5 MB | ±60 KB |
| Satu order dari awal sampai key terkirim | puluhan MB | ±0,1–0,2 MB |

## Catatan
- Transaksi disimpan sebagai `tx:<id>` di `keyvalue_store`. Backup web/CLI tetap menghasilkan `transactions.json`.
- Jika `supabase-hemat.sql` belum dijalankan, aplikasi tetap jalan (statistik admin memakai cara lebih lambat, ada peringatan di log).
