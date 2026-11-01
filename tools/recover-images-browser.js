/**
 * PULIHKAN GAMBAR — versi BROWSER (tanpa Node, tanpa instal).
 *
 * Cara: buka SITUS TOKO LAMA (mis. https://aghanlshop.my.id) di Chrome/Edge (komputer) → tekan F12 → tab "Console"
 * → tempel seluruh isi file ini → Enter. (Jika Chrome meminta, ketik: allow pasting, Enter, lalu tempel lagi.)
 * Muncul panel kecil di kanan atas: pilih file export CSV dari Supabase → tunggu → klik "Unduh ZIP".
 *
 * Gambar dicari di (1) cache browser kamu sendiri, lalu (2) CDN situs (/media/<file>?w=<lebar>, lebar terbesar dulu).
 * Karena dijalankan di situs yang sama, tidak ada masalah CORS. JANGAN redeploy situs sebelum selesai.
 */
(function () {
  if (window.__recov) { alert('Panel pemulihan sudah terbuka.'); return; }
  window.__recov = true;
  var WIDTHS = [1280, 960, 640, 480, 320, 240, 160, 96];
  var te = new TextEncoder();

  /* ── ZIP tanpa kompresi ── */
  var CRC = (function () { var t = new Uint32Array(256); for (var n = 0; n < 256; n++) { var c = n; for (var k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
  function crc32(b) { var c = 0xFFFFFFFF; for (var i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 255] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }
  function Zip() { this.parts = []; this.cen = []; this.off = 0; var d = new Date(); this.t = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1); this.d = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(); this.n = 0; }
  Zip.prototype.add = function (name, data) {
    var nb = te.encode(name), crc = crc32(data), sz = data.length;
    var h = new DataView(new ArrayBuffer(30)); h.setUint32(0, 0x04034b50, true); h.setUint16(4, 20, true); h.setUint16(6, 0x0800, true); h.setUint16(8, 0, true); h.setUint16(10, this.t, true); h.setUint16(12, this.d, true); h.setUint32(14, crc, true); h.setUint32(18, sz, true); h.setUint32(22, sz, true); h.setUint16(26, nb.length, true); h.setUint16(28, 0, true);
    var c = new DataView(new ArrayBuffer(46)); c.setUint32(0, 0x02014b50, true); c.setUint16(4, 20, true); c.setUint16(6, 20, true); c.setUint16(8, 0x0800, true); c.setUint16(10, 0, true); c.setUint16(12, this.t, true); c.setUint16(14, this.d, true); c.setUint32(16, crc, true); c.setUint32(20, sz, true); c.setUint32(24, sz, true); c.setUint16(28, nb.length, true); c.setUint16(30, 0, true); c.setUint16(32, 0, true); c.setUint16(34, 0, true); c.setUint16(36, 0, true); c.setUint32(38, 0, true); c.setUint32(42, this.off, true);
    this.parts.push(h.buffer, nb, data); this.cen.push(c.buffer, nb); this.off += 30 + nb.length + sz; this.n++;
  };
  Zip.prototype.finish = function () {
    var cs = 0; for (var i = 0; i < this.cen.length; i++) cs += this.cen[i].byteLength || this.cen[i].length;
    var e = new DataView(new ArrayBuffer(22)); e.setUint32(0, 0x06054b50, true); e.setUint16(8, this.n, true); e.setUint16(10, this.n, true); e.setUint32(12, cs, true); e.setUint32(16, this.off, true);
    return new Blob(this.parts.concat(this.cen, [e.buffer]), { type: 'application/zip' });
  };

  /* ── logika pemulihan ── */
  function sniff(b) {
    if (b.length > 12 && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return 'webp';
    if (b[0] === 0x89 && b[1] === 0x50) return 'png';
    if (b[0] === 0xFF && b[1] === 0xD8) return 'jpg';
    if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46) return 'gif';
    return null;
  }
  function extractRefs(text) {
    var refs = {}, oldUrl = '', m, t = text.replace(/\\\//g, '/');
    var re = /https:\/\/([a-z0-9]+)\.supabase\.co\/storage\/v1\/object\/public\/([A-Za-z0-9_-]+)\/([A-Za-z0-9._%\/-]+)/gi;
    while ((m = re.exec(t))) { oldUrl = oldUrl || 'https://' + m[1] + '.supabase.co'; var f; try { f = decodeURIComponent(m[3]); } catch (_) { f = m[3]; } f = f.replace(/[)\]'"\\]+$/, ''); refs[m[2] + '/' + f] = { bucket: m[2], file: f }; }
    var re2 = /\/media\/([A-Za-z0-9._-]{1,200})/g;
    while ((m = re2.exec(t))) refs['product-images/' + m[1]] = { bucket: 'product-images', file: m[1] };
    return { list: Object.keys(refs).map(function (k) { return refs[k]; }), oldUrl: oldUrl };
  }
  async function tryFetch(url) {
    var modes = [{ cache: 'only-if-cached', mode: 'same-origin' }, {}];   // 1) cache browser  2) jaringan/CDN
    for (var i = 0; i < modes.length; i++) {
      try {
        var r = await fetch(url, modes[i]);
        if (r.ok && /^image\//i.test(r.headers.get('content-type') || '')) {
          var b = new Uint8Array(await r.arrayBuffer());
          if (b.length > 200 && sniff(b)) return { b: b, via: i === 0 ? 'cache browser' : 'CDN' };
        }
      } catch (_) { }
    }
    return null;
  }
  async function recoverOne(ref) {
    if (ref.file.indexOf('/') >= 0) return { ref: ref, status: 'skip' };
    var enc = encodeURIComponent(ref.file);
    for (var i = 0; i <= WIDTHS.length; i++) {
      var w = WIDTHS[i] || 0, r = await tryFetch('/media/' + enc + (w ? '?w=' + w : ''));
      if (r) return { ref: ref, status: 'ok', b: r.b, w: w || 'asli', via: r.via };
    }
    return { ref: ref, status: 'miss' };
  }
  window.__recovCore = { extractRefs: extractRefs, recoverOne: recoverOne, Zip: Zip, sniff: sniff };

  /*UI*/
  var box = document.createElement('div');
  box.style.cssText = 'position:fixed;top:10px;right:10px;z-index:2147483647;width:340px;max-height:90vh;overflow:auto;background:#111;color:#eee;font:13px/1.45 system-ui,sans-serif;border:1px solid #0891b2;border-radius:10px;padding:12px;box-shadow:0 8px 30px #000a';
  box.innerHTML = '<b>Pulihkan gambar toko</b><div style="color:#9ca3af;margin:4px 0 8px">1) Pilih file export CSV dari Supabase (keyvalue_store). Biarkan halaman ini terbuka.</div>' +
    '<button id="rc_pick" style="padding:8px 12px;border-radius:8px;border:0;background:#0e7490;color:#fff;font-weight:700;cursor:pointer">Pilih file export…</button> ' +
    '<button id="rc_x" style="padding:8px 10px;border-radius:8px;border:1px solid #444;background:#222;color:#ccc;cursor:pointer">Tutup</button>' +
    '<div id="rc_s" style="margin-top:8px;color:#9ca3af"></div><div id="rc_l" style="margin-top:6px;max-height:200px;overflow:auto;font:11px/1.4 monospace;color:#a1a1aa"></div>';
  document.body.appendChild(box);
  var $ = function (i) { return document.getElementById(i); };
  $('rc_x').onclick = function () { box.remove(); window.__recov = false; };
  $('rc_pick').onclick = function () {
    var inp = document.createElement('input'); inp.type = 'file'; inp.multiple = true; inp.accept = '.csv,.json,.sql,.txt';
    inp.onchange = async function () {
      $('rc_pick').disabled = true; $('rc_s').textContent = 'Membaca file…';
      var text = ''; for (var i = 0; i < inp.files.length; i++) text += await inp.files[i].text() + '\n';
      var ex = extractRefs(text), list = ex.list;
      if (!list.length) { $('rc_s').textContent = 'Tidak ada URL gambar di file itu.'; $('rc_pick').disabled = false; return; }
      $('rc_s').textContent = list.length + ' gambar dirujuk data. Mencari…';
      var zip = new Zip(), ok = 0, miss = [], done = 0, q = list.slice(), bytes = 0;
      var worker = async function () {
        while (q.length) {
          var it = q.shift(), r = await recoverOne(it); done++;
          if (r.status === 'ok') { zip.add('storage/' + it.bucket + '/' + it.file, r.b); ok++; bytes += r.b.length; }
          else miss.push(it.bucket + '/' + it.file + (r.status === 'skip' ? '   # di dalam subfolder' : ''));
          $('rc_s').textContent = done + ' / ' + list.length + ' diproses — ' + ok + ' ketemu';
          var d = document.createElement('div'); d.textContent = (r.status === 'ok' ? '✓ ' : '✗ ') + it.file + (r.status === 'ok' ? ' (' + r.w + (r.w === 'asli' ? '' : 'px') + ', ' + r.via + ')' : ''); $('rc_l').appendChild(d);
        }
      };
      await Promise.all([worker(), worker(), worker()]);
      var mf = { createdAt: new Date().toISOString(), projectUrl: ex.oldUrl, buckets: {} };
      list.forEach(function (x) { mf.buckets[x.bucket] = { public: true, recovered: true }; });
      zip.add('manifest.json', te.encode(JSON.stringify(mf, null, 2)));
      zip.add('gambar-tidak-ditemukan.txt', te.encode(miss.join('\n')));
      var blob = zip.finish(), url = URL.createObjectURL(blob);
      $('rc_s').innerHTML = '✅ <b>' + ok + '/' + list.length + '</b> gambar terpulihkan (' + (bytes / 1048576).toFixed(1) + ' MB)' + (miss.length ? ' — ' + miss.length + ' tidak ditemukan' : '') + '<br>';
      var a = document.createElement('a'); a.href = url; a.download = 'gambar-pulih.zip'; a.textContent = '⬇ Unduh gambar-pulih.zip';
      a.style.cssText = 'display:inline-block;margin-top:6px;padding:8px 12px;border-radius:8px;background:#059669;color:#fff;font-weight:700;text-decoration:none';
      $('rc_s').appendChild(a);
    };
    inp.click();
  };
})();
