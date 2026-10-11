# Pengecekan browser fullscreen (Cloudflare) - AGHA NL

Ada 2 jalur. Pakai Jalur 1 kalau domain bisa dipindah nameserver ke Cloudflare.
Jalur 2 jalan tanpa itu. Boleh dipakai dua-duanya.

## JALUR 1 - Cloudflare di depan (halaman "Checking your browser" asli)
Ini setting dashboard, bukan kode.

1. dash.cloudflare.com -> Add site -> masukin domain -> pilih Free.
2. Ganti nameserver domain di registrar ke nameserver yang dikasih Cloudflare.
3. DNS: record ke Vercel harus Proxied (awan ORANYE):
   - CNAME  @    cname.vercel-dns.com   (proxied)
   - CNAME  www  cname.vercel-dns.com   (proxied)
4. SSL/TLS -> Overview -> mode "Full (strict)". JANGAN "Flexible" (bikin redirect loop di Vercel).
5. Security -> Settings -> Security Level: "Medium" atau "High".
   Buat mode darurat serangan: "I'm Under Attack!" (challenge ke SEMUA pengunjung).
6. Security -> WAF -> Custom rules -> buat rule SKIP supaya webhook tidak ke-challenge:
     Expression : (http.request.uri.path contains "/webhook/")
                  or (http.request.uri.path eq "/robots.txt")
                  or (http.request.uri.path eq "/sitemap.xml")
     Action     : Skip -> centang semua (Managed Challenge, Bot Fight Mode, Rate limiting)
   Taruh rule ini URUTAN PALING ATAS.
7. Security -> Bots -> Bot Fight Mode: ON (Free). Catatan: ini bisa nge-challenge
   server-to-server, makanya rule skip di langkah 6 wajib ada.
8. Set env Vercel:  CLOUDFLARE_PROXY=on   lalu redeploy.
   Ini wajib supaya rate-limit login/invoice membaca IP asli pengunjung.
9. Vercel -> Settings -> Domains: pastikan domain tetap terdaftar.
   (Kalau ada IP allowlist di GensPay/PakKasir, itu tidak terpengaruh.)

Tes: buka domain di jendela incognito -> harus muncul halaman challenge ->
lalu masuk. Tes webhook: kirim test dari dashboard GensPay, harus 200.

## JALUR 2 - Gate bawaan aplikasi (tanpa pindah nameserver)
Sudah ada di kode (server.js). Aktifkan lewat env Vercel:

  TURNSTILE_SITE_KEY=...      (dari dash.cloudflare.com -> Turnstile -> Add widget, mode Managed)
  TURNSTILE_SECRET_KEY=...
  SITE_CHALLENGE=on

Di widget Turnstile, isi Hostname dengan domain toko lo. Redeploy.
Matikan kapan saja: hapus SITE_CHALLENGE (atau isi off), redeploy.

Yang lolos tanpa challenge: /webhook/*, /auth/google*, /robots.txt, /sitemap.xml,
aset statis, dan Googlebot/Bingbot/WhatsApp/Telegram preview (biar SEO dan preview link aman).
Cookie: cf_gate, HttpOnly, 12 jam, terikat User-Agent, ditandatangani HMAC.
Fail-open: kalau challenges.cloudflare.com sedang down/timeout/5xx, pengunjung
diloloskan sementara (cookie 10 menit), supaya toko tidak mati gara-gara Cloudflare.
Token yang DITOLAK (bot) tetap fail-closed. Klien yang ngaku "script gagal dimuat"
diprobe ulang oleh server, jadi gak bisa dipakai buat bypass dengan blok script.
Gate berlaku seragam ke semua path (termasuk /admin dan path ngawur) jadi tidak
membocorkan route mana yang beneran ada.

## Catatan
- Pakai Jalur 1 saja sudah cukup buat 95% kasus. Jalur 2 = cadangan.
- Kalau dua-duanya aktif, pengunjung baru kena dua challenge berurutan. Kalau mau
  satu saja, pakai Jalur 1 dan JANGAN set SITE_CHALLENGE.
- Gate bawaan bukan pengganti login: itu lapisan anti-bot, bukan autentikasi.
