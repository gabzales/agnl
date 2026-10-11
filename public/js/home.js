/* AGHA NL — logika beranda (di-cache browser) */
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var cards = Array.prototype.slice.call(document.querySelectorAll('#agProducts .ag-card'));
  var state = { cat: 'all', q: '' };

  // ── Banner: scroll-snap native + autoplay + dots ──
  (function () {
    var track = $('bannerTrack'), dots = $('bannerDots');
    if (!track || !dots) return;
    var n = track.children.length, idx = 0, timer = null;
    function paint() { Array.prototype.forEach.call(dots.children, function (d, i) { d.classList.toggle('on', i === idx); }); }
    track.addEventListener('scroll', function () {
      var i = Math.round(track.scrollLeft / track.clientWidth);
      if (i !== idx) { idx = i; paint(); }
    }, { passive: true });
    function go(i) { idx = (i + n) % n; track.scrollTo({ left: idx * track.clientWidth, behavior: 'smooth' }); }
    function start() { stop(); timer = setInterval(function () { if (!document.hidden) go(idx + 1); }, 5000); }
    function stop() { if (timer) clearInterval(timer); }
    track.addEventListener('pointerdown', stop, { passive: true });
    track.addEventListener('pointerup', start, { passive: true });
    start();
  })();

  // ── Filter kategori + cari ──
  function apply() {
    var shown = 0;
    cards.forEach(function (c) {
      var cats = []; try { cats = JSON.parse(c.dataset.categories || '[]'); } catch (e) {}
      var okCat = state.cat === 'all' || cats.indexOf(state.cat) > -1;
      var okQ = !state.q || (c.dataset.name || '').indexOf(state.q) > -1;
      var ok = okCat && okQ;
      c.style.display = ok ? '' : 'none';
      if (ok) shown++;
    });
    var nr = $('agNoResult'); if (nr) nr.hidden = shown !== 0 || !cards.length;
  }
  var row = $('filterRow');
  if (row) row.addEventListener('click', function (e) {
    var b = e.target.closest('[data-pf]'); if (!b) return;
    state.cat = b.dataset.pf;
    Array.prototype.forEach.call(row.querySelectorAll('.ag-chip'), function (x) { x.classList.toggle('active', x === b); });
    apply();
  });
  var tb = $('agToolbar'), inp = $('agSearchInput');
  if ($('agSearchOpen')) $('agSearchOpen').addEventListener('click', function () { tb.classList.add('searching'); inp.focus(); });
  if ($('agSearchClose')) $('agSearchClose').addEventListener('click', function () { tb.classList.remove('searching'); inp.value = ''; state.q = ''; apply(); });
  if (inp) inp.addEventListener('input', function () { state.q = inp.value.trim().toLowerCase(); apply(); });

  // ── BUY SHEET (ala ThanHub): data produk sudah ada di halaman (AG_PRODUCTS) -> 0 request saat dibuka ──
  var cur = null, curOpt = null, applied = null;
  var rp = function (n) { return 'Rp ' + Number(n || 0).toLocaleString('id-ID'); };
  var esc = function (t) { return String(t == null ? '' : t).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  function durLabel(o) {
    if (o.d != null) return o.d + ' ' + (o.u === 'h' ? 'Jam' : 'Hari');
    return o.l;
  }
  function savedBuyer() { try { return JSON.parse(localStorage.getItem('ag_buyer') || '{}'); } catch (e) { return {}; } }

  window.agOpenBuy = function (id) {
    var p = (window.AG_PRODUCTS || {})[id];
    if (!p) { if (window.showToast) showToast('Produk tidak ditemukan', 'error'); return; }
    if (p.m) { if (window.showToast) showToast('Produk sedang maintenance, coba lagi nanti.', 'info'); return; }
    cur = Object.assign({ id: id }, p); curOpt = null; applied = null;
    $('voucherCodeInput').value = ''; $('voucherFeedback').textContent = '';
    $('modalProductName').textContent = p.name || p.n;
    $('modalProductName').textContent = p.n;
    var list = $('durationCardList');
    list.innerHTML = p.o.map(function (o, i) {
      var out = o.s <= 0 && !o.k;
      return '<button type="button" class="ag-dur' + (out ? ' disabled' : '') + '" data-i="' + i + '"' + (out ? ' disabled' : '') + '>' +
        '<span class="ag-dur-icon"><iconify-icon icon="mdi:clock-outline"></iconify-icon></span>' +
        '<span class="ag-dur-info"><span class="ag-dur-label">' + esc(durLabel(o)) + '</span>' +
        '<span class="ag-dur-sub">Masa aktif ' + esc(durLabel(o).toLowerCase()) + ' <span class="ag-dur-stock' + (out ? ' out' : '') + '">' + (out ? 'Stok habis' : (o.k ? 'Cek stok' : 'Stok: ' + o.s)) + '</span></span></span>' +
        '<span class="ag-dur-price">' + rp(o.p) + '</span><iconify-icon class="ag-dur-chev" icon="mdi:chevron-right"></iconify-icon></button>';
    }).join('') || '<div class="ag-redirect">Belum ada durasi untuk produk ini.</div>';
    var b = savedBuyer(), a = window.agAuthInfo ? window.agAuthInfo() : null;
    $('customerName').value = b.n || (a && a.n) || '';
    $('waInput').value = b.w || '';
    var isRes = !!(a && a.r && !a.a);
    $('walletBtn').hidden = !isRes; $('summaryResellerNote').hidden = !isRes;
    var ch = $('channelBtn'), cu = /^https?:\/\//i.test(cur.c || '') ? cur.c : '';
    ch.hidden = !cu; if (cu) { ch.href = cu; ch.querySelector('span').textContent = 'Download APK / Saluran ' + cur.n; }
    var pb = $('checkoutBtn'); pb.disabled = false; pb.innerHTML = '<iconify-icon icon="mdi:credit-card-outline"></iconify-icon> BAYAR SEKARANG';
    agGoStep(1);
    $('buyModal').classList.add('show'); document.body.classList.add('no-scroll');
  };
  window.agCloseBuy = function () { $('buyModal').classList.remove('show'); document.body.classList.remove('no-scroll'); };
  $('durationCardList').addEventListener('click', function (e) {
    var b = e.target.closest('.ag-dur'); if (!b || b.disabled) return;
    curOpt = cur.o[Number(b.dataset.i)]; applied = null; $('voucherFeedback').textContent = '';
    agGoStep(2);
  });
  function totals() {
    if (!curOpt) return;
    var disc = applied ? applied.discount : 0, total = Math.max(0, curOpt.p - disc);
    $('summarySubtotalRow').hidden = !applied; $('summaryDiscountRow').hidden = !applied;
    if (applied) { $('summarySubtotal').textContent = rp(curOpt.p); $('summaryDiscountLabel').textContent = 'Voucher ' + applied.code; $('summaryDiscount').textContent = '- ' + rp(disc); }
    $('summaryTotal').textContent = rp(total);
  }
  window.agGoStep = function (n) {
    if (n === 2 && !curOpt) return;
    ['stepPanel1', 'stepPanel2', 'stepPanel3'].forEach(function (id, i) { $(id).classList.toggle('active', i + 1 === n); });
    for (var i = 1; i <= 2; i++) { var d = $('stepDot' + i); d.classList.remove('active', 'done'); if (i < n) d.classList.add('done'); if (i === n) d.classList.add('active'); }
    $('sheetKicker').textContent = n === 1 ? 'PILIH DURASI' : (n === 2 ? 'KONFIRMASI PESANAN' : 'MEMPROSES PEMBAYARAN');
    if (n === 2) { $('summaryProductName').textContent = cur.n + ' (' + durLabel(curOpt) + ')'; totals(); }
  };
  window.agResetVoucher = function () { applied = null; $('voucherFeedback').textContent = ''; totals(); };
  window.agApplyVoucher = async function () {
    var code = $('voucherCodeInput').value.trim().toUpperCase(), fb = $('voucherFeedback');
    if (!code) { fb.style.color = 'var(--red)'; fb.textContent = 'Masukkan kode voucher dulu'; return; }
    var btn = $('btnApplyVoucher'); btn.disabled = true; var old = btn.textContent; btn.textContent = '...';
    try {
      var d = await (await fetch('/api/voucher/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: code, price: curOpt.p }) })).json();
      if (d.valid) { applied = { code: d.code, discount: Number(d.discount) || 0 }; fb.style.color = 'var(--green)'; fb.textContent = 'Voucher "' + d.code + '" berhasil diterapkan! Hemat ' + rp(applied.discount); }
      else { applied = null; fb.style.color = 'var(--red)'; fb.textContent = d.error || 'Voucher tidak valid'; }
    } catch (e) { applied = null; fb.style.color = 'var(--red)'; fb.textContent = 'Gagal memeriksa voucher, coba lagi'; }
    btn.disabled = false; btn.textContent = old; totals();
  };
  window.agCheckout = async function (useWallet) {
    var name = $('customerName').value.trim(), wa = $('waInput').value.trim().replace(/[\s\-()]/g, '');
    if (!name) { showToast('Masukkan nama kamu', 'error'); return; }
    if (!/^(\+62|62|0)[0-9]{8,13}$/.test(wa)) { showToast('Nomor WhatsApp tidak valid (contoh 08123456789)', 'error'); return; }
    var btn = useWallet ? $('walletBtn') : $('checkoutBtn'), html = btn.innerHTML;
    $('checkoutBtn').disabled = true; $('walletBtn').disabled = true;
    btn.innerHTML = '<span class="ag-spinner"></span> Memproses...';
    try { localStorage.setItem('ag_buyer', JSON.stringify({ n: name, w: wa })); } catch (e) {}
    function reset() { $('checkoutBtn').disabled = false; $('walletBtn').disabled = false; btn.innerHTML = html; }
    try {
      var res = await fetch(useWallet ? '/wallet/buy' : '/create-order', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
        productId: cur.id, duration: curOpt.d != null ? curOpt.d : curOpt.l, durationUnit: curOpt.u || 'd', customerName: name, wa: wa, voucherCode: applied ? applied.code : undefined }) });
      var d = await res.json();
      if (d.success) {
        agGoStep(3);
        location.href = useWallet ? ('/invoice?code=' + encodeURIComponent(d.code)) : ('/pay/' + encodeURIComponent(d.refId));
        return;
      }
      if (d.redirect) { location.href = d.redirect; return; }
      if (d.message === 'insufficient_balance') { showToast(d.plainMessage || 'Saldo tidak cukup, top up dulu', 'error'); setTimeout(function () { location.href = '/dashboard#wallet'; }, 1200); return; }
      showToast(d.message || 'Gagal membuat pesanan', 'error'); reset();
    } catch (e) { showToast('Koneksi bermasalah, coba lagi', 'error'); reset(); }
  };
  // Tautan lama /buy/:id -> /?buy=:id membuka sheet langsung
  (function () { var m = /[?&]buy=([^&]+)/.exec(location.search); if (m && window.AG_PRODUCTS) { var id = decodeURIComponent(m[1]); if (window.AG_PRODUCTS[id]) setTimeout(function () { agOpenBuy(id); }, 50); } })();

  // ── Popup CS: sekali per 24 jam ──
  var cs = $('csPopup');
  window.csPopupClose = function () { if (cs) cs.style.display = 'none'; try { localStorage.setItem('agnl_cs_popup', JSON.stringify({ t: Date.now() })); } catch (e) {} };
  if (cs && window.AG && window.AG.hasCS) {
    var st; try { st = JSON.parse(localStorage.getItem('agnl_cs_popup') || 'null'); } catch (e) {}
    if (!(st && Date.now() - st.t < 86400000)) setTimeout(function () { cs.style.display = 'flex'; }, 3500);
  }

  // ── Modal login / daftar ──
  var tsLogin = null, tsReg = null;
  window.renderTurnstileWidgets = function () {
    if (!window.AG.tsReady || typeof turnstile === 'undefined' || !window.AG.turnstileKey) return;
    var a = $('turnstileWidgetLogin'), b = $('turnstileWidgetRegister');
    if (a && tsLogin === null) tsLogin = turnstile.render(a, { sitekey: window.AG.turnstileKey });
    if (b && tsReg === null) tsReg = turnstile.render(b, { sitekey: window.AG.turnstileKey });
  };
  window.openAuthModal = function (tab) {
    $('authModalOverlay').classList.remove('hidden'); document.body.classList.add('no-scroll');
    switchAuthTab(tab || 'login'); window.renderTurnstileWidgets();
  };
  window.closeAuthModal = function () {
    $('authModalOverlay').classList.add('hidden'); document.body.classList.remove('no-scroll');
    $('authErrorBox').classList.add('hidden');
    if (typeof turnstile !== 'undefined') { if (tsLogin !== null) turnstile.reset(tsLogin); if (tsReg !== null) turnstile.reset(tsReg); }
  };
  window.switchAuthTab = function (tab) {
    var login = tab === 'login';
    $('authFormLogin').classList.toggle('hidden', !login); $('authFormRegister').classList.toggle('hidden', login);
    $('authTabLogin').classList.toggle('on', login); $('authTabRegister').classList.toggle('on', !login);
    $('authModalTitle').textContent = login ? 'Masuk ke Akun Anda' : 'Buat Akun Baru';
    $('authErrorBox').classList.add('hidden');
  };
  window.togglePasswordVisibility = function (id, btn) {
    var i = $(id), ic = btn.querySelector('iconify-icon'), hide = i.type === 'password';
    i.type = hide ? 'text' : 'password'; ic.setAttribute('icon', hide ? 'mdi:eye-off-outline' : 'mdi:eye-outline');
  };
  window.handleAuthSubmit = async function (e, type) {
    e.preventDefault();
    var form = e.target, btn = $(type === 'login' ? 'authSubmitBtnLogin' : 'authSubmitBtnRegister'), box = $('authErrorBox');
    box.classList.add('hidden'); btn.disabled = true; var txt = btn.textContent; btn.textContent = 'Memproses...';
    var body = {}; new FormData(form).forEach(function (v, k) { body[k] = v; });
    if (typeof turnstile !== 'undefined') { var w = type === 'login' ? tsLogin : tsReg; if (w !== null) body['cf-turnstile-response'] = turnstile.getResponse(w) || ''; }
    function fail(m) { box.textContent = m; box.classList.remove('hidden'); btn.disabled = false; btn.textContent = txt; }
    try {
      var res = await fetch(type === 'login' ? '/api/auth/login' : '/api/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      var d = await res.json();
      if (d.success) location.href = d.redirect || '/'; else fail(d.message || 'Terjadi kesalahan, coba lagi.');
    } catch (err) { fail('Gagal terhubung ke server. Coba lagi.'); }
    return false;
  };
})();
