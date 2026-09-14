/** @type {import('tailwindcss').Config} */
module.exports = {
  // FIX PERFORMA (diminta client 22 Agu 2026): sebelumnya pakai Tailwind
  // Play CDN (<script src="https://cdn.tailwindcss.com">), yang menurut
  // dokumentasi resmi Tailwind sendiri "designed for development purposes
  // only, not the best choice for production" -- itu JIT compiler yang
  // jalan penuh di browser (scan seluruh DOM + generate CSS realtime),
  // berat khususnya di HP Android low-end. Sekarang pakai Tailwind CLI:
  // build sekali di server jadi 1 file CSS statis kecil (cuma class yang
  // beneran dipakai), di-serve sebagai <link> biasa -- jauh lebih ringan
  // dan tidak butuh JS runtime tambahan.
  content: [
    './views/**/*.ejs',
  ],
  theme: {
    extend: {
      fontFamily: {
        inter: ['Inter', 'sans-serif'],
        orbitron: ['Orbitron', 'sans-serif'],
      },
    },
  },
  // safelist: class yang di-generate secara dinamis lewat JS string
  // template (mis. `bg-${color}-500`) tidak akan ke-detect oleh content
  // scanner Tailwind (karena bukan literal string utuh di file). Kalau
  // nanti ada class yang hilang di production, tambahkan pattern-nya di
  // sini.
  safelist: [],
  plugins: [],
}
