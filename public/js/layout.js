/* AGHA NL — skrip layout bersama (di-cache browser, tidak inline di tiap halaman) */
(function () {
  var $ = function (id) { return document.getElementById(id); };

  // Versi kecil gambar dari proxy /media (webp, di-cache CDN)
  window.imgW = function (u, w) {
    u = String(u || '');
    return (u.indexOf('/media/') === 0 && u.indexOf('?') === -1) ? u + '?w=' + w : u;
  };

  // ─── TEMA (gelap default, terang opsional) ───
  function syncThemeIcon() {
    var ic = $('agThemeIcon');
    if (ic) ic.setAttribute('icon', document.documentElement.getAttribute('data-theme') === 'light' ? 'mdi:weather-night' : 'mdi:white-balance-sunny');
  }
  window.agToggleTheme = function () {
    var next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('agnl-theme', next); } catch (e) {}
    syncThemeIcon();
  };
  document.addEventListener('DOMContentLoaded', syncThemeIcon);

  // ─── STATUS LOGIN (petunjuk UI dari cookie agu) ───
  window.agAuthInfo = function () {
    try { var m = document.cookie.match(/(?:^|; )agu=([^;]*)/); return m ? JSON.parse(decodeURIComponent(m[1])) : null; } catch (e) { return null; }
  };
  document.addEventListener('DOMContentLoaded', function () {
    var a = window.agAuthInfo(); if (!a) return;
    var acc = $('agAccountLink'); if (acc) acc.setAttribute('href', a.a ? '/admin' : '/dashboard');
    var nm = $('agMenuName'); if (nm) nm.textContent = a.n || '';
    var rl = $('agMenuRole'); if (rl) rl.textContent = a.a ? 'Administrator' : (a.r ? 'Reseller VIP' : 'Member');
    var av = $('agMenuAvatar');
    if (av) { if (a.p) { av.parentNode.innerHTML = '<img src="' + imgW(a.p, 96) + '" alt="" style="width:100%;height:100%;object-fit:cover;" id="profilePhotoImg">'; } else av.textContent = String(a.n || '?').charAt(0).toUpperCase(); }
    if (a.r) { var rlb = document.querySelector('.ag-res-label'); if (rlb) rlb.textContent = 'Status VIP'; }
  });

  // ─── AUTH: buka modal kalau ada (beranda), kalau tidak ikuti link ke /login /register ───
  window.agAuth = function (tab) {
    if (typeof window.openAuthModal === 'function') { window.openAuthModal(tab); return false; }
    return true;
  };

  window.doLogout = function (e) {
    e.preventDefault();
    try { localStorage.removeItem('vpr_cart'); localStorage.removeItem('vpr_notifs'); localStorage.removeItem('vpr_notif_t'); } catch (x) {}
    window.location.href = '/logout';
  };

  // ─── TOAST ───
  window.showToast = function (msg, type) {
    var c = $('toast-container'); if (!c) return;
    var icon = { success: 'mdi:check-circle', error: 'mdi:alert-circle', info: 'mdi:information' }[type] || 'mdi:information';
    var clr = { success: 'var(--green)', error: 'var(--red)', info: 'var(--accent)' }[type] || 'var(--accent)';
    var t = document.createElement('div');
    t.className = 'toast';
    t.innerHTML = '<iconify-icon icon="' + icon + '" style="color:' + clr + ';font-size:16px;flex-shrink:0;"></iconify-icon><span></span>';
    t.lastChild.textContent = msg;
    c.appendChild(t);
    setTimeout(function () { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(function () { t.remove(); }, 300); }, 3200);
  };

  // ─── PANELS ───
  function lock(on) { document.body.classList.toggle('no-scroll', !!on); }
  window.openSearch = function () {
    $('search-panel').style.display = 'flex'; lock(true);
    if (!allProducts.length) fetch('/api/products').then(function (r) { return r.json(); }).then(function (d) { allProducts = d; }).catch(function () {});
    setTimeout(function () { var i = $('searchInput'); if (i) i.focus(); }, 80);
  };
  window.closeSearch = function () { $('search-panel').style.display = 'none'; lock(false); };
  window.openCart = function () { renderCart(); $('cart-panel').style.display = 'block'; lock(true); };
  window.closeCart = function () { $('cart-panel').style.display = 'none'; lock(false); };
  window.openTrack = function () { $('track-panel').classList.remove('hidden'); lock(true); };
  window.closeTrack = function () { $('track-panel').classList.add('hidden'); lock(false); };
  window.openMenu = function () {
    $('menu-drawer').style.display = 'block';
    var d = $('menu-drawer-content'); d.style.animation = 'none'; void d.offsetWidth; d.style.animation = 'slideRight .22s ease both';
    lock(true);
  };
  window.closeMenu = function () { $('menu-drawer').style.display = 'none'; lock(false); };
  window.closeAll = function () { closeSearch(); closeCart(); closeTrack(); closeMenu(); };
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeAll(); });

  // ─── SEARCH (panel penuh, dipakai halaman selain beranda) ───
  var allProducts = [];
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  window.doSearch = function (q) {
    var rs = $('searchResults'); q = String(q || '').trim().toLowerCase();
    if (!q) { rs.innerHTML = '<div class="text-center py-16" style="color:var(--text-3);"><p class="text-sm">Ketik untuk mencari produk...</p></div>'; return; }
    var f = allProducts.filter(function (p) { return String(p.name || '').toLowerCase().indexOf(q) > -1 || String(p.category || '').toLowerCase().indexOf(q) > -1; });
    if (!f.length) { rs.innerHTML = '<div class="text-center py-16" style="color:var(--text-3);"><p class="text-sm">Produk tidak ditemukan</p></div>'; return; }
    rs.innerHTML = f.map(function (p) {
      var price = p.items && p.items[0] ? 'Rp ' + Number(p.items[0].p).toLocaleString('id-ID') : '';
      return '<a href="/?buy=' + encodeURIComponent(p.id) + '" class="ag-menu-link" style="margin-bottom:8px;border-color:var(--border);">' +
        '<span style="width:44px;height:44px;border-radius:12px;overflow:hidden;background:var(--bg-hover);flex-shrink:0;">' + (p.image ? '<img src="' + esc(imgW(p.image, 96)) + '" alt="" style="width:100%;height:100%;object-fit:cover;">' : '') + '</span>' +
        '<span class="grow"><b style="color:var(--text-1);font-size:13px;">' + esc(p.name) + '</b><small>' + esc(p.category || '') + '</small></span>' +
        '<b style="color:var(--accent-bright);font-size:12px;">' + price + '</b></a>';
    }).join('');
  };

  // ─── CART ───
  var cart = []; try { cart = JSON.parse(localStorage.getItem('vpr_cart') || '[]'); } catch (e) {}
  window.updateCartBadge = function () {
    var b = $('cart-badge'); if (!b) return;
    if (cart.length > 0) { b.textContent = cart.length; b.style.display = 'flex'; } else b.style.display = 'none';
  };
  function renderCart() {
    var el = $('cartItems');
    if (!cart.length) { el.innerHTML = '<div class="text-center py-10" style="color:var(--text-3);"><p class="text-sm">Keranjang kosong</p></div>'; return; }
    el.innerHTML = cart.map(function (item, i) {
      return '<div class="card p-3 flex items-center gap-3">' +
        '<div class="flex-1 min-w-0"><div class="font-semibold text-xs truncate">' + esc(item.name) + '</div>' +
        '<div class="text-[11px] mt-0.5" style="color:var(--text-3);">' + esc(item.duration) + '</div>' +
        '<div class="text-xs font-bold mt-0.5" style="color:var(--accent-bright);">Rp ' + Number(item.price || 0).toLocaleString('id-ID') + '</div></div>' +
        '<button onclick="removeFromCart(' + i + ')" class="ag-icon-btn" style="color:var(--red);" aria-label="Hapus"><iconify-icon icon="mdi:trash-can-outline"></iconify-icon></button></div>';
    }).join('') + '<a href="/?buy=' + encodeURIComponent(cart[0] && cart[0].productId) + '" class="btn btn-primary w-full py-2.5 mt-3 text-sm"><iconify-icon icon="mdi:lightning-bolt"></iconify-icon> Lanjut Beli</a>';
  }
  window.addToCart = function (item) { cart.push(item); localStorage.setItem('vpr_cart', JSON.stringify(cart)); updateCartBadge(); showToast('Ditambahkan ke keranjang', 'success'); };
  window.removeFromCart = function (i) { cart.splice(i, 1); localStorage.setItem('vpr_cart', JSON.stringify(cart)); updateCartBadge(); renderCart(); };

  // ─── TRACK ───
  window.doTrack = async function () {
    var code = $('trackCode').value.trim().toUpperCase(), rd = $('trackResult');
    if (!code) { showToast('Masukkan kode pesanan', 'error'); return; }
    rd.innerHTML = '<div class="text-center py-4"><iconify-icon icon="mdi:loading" style="color:var(--accent);font-size:20px;" class="animate-spin"></iconify-icon></div>';
    try {
      var r = await fetch('/invoice', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'code=' + encodeURIComponent(code) });
      var doc = new DOMParser().parseFromString(await r.text(), 'text/html');
      var trx = doc.querySelector('.p-4.rounded-lg');
      rd.innerHTML = trx ? '<div class="card p-4 mt-3">' + trx.innerHTML + '</div>' : '<div class="card p-3 mt-3 text-xs" style="color:var(--red);">Kode pesanan tidak ditemukan</div>';
    } catch (e) { rd.innerHTML = '<div class="card p-3 mt-3 text-xs" style="color:var(--red);">Gagal mengambil data</div>'; }
  };

  // ─── AVATAR ───
  window.uploadAvatar = async function (input) {
    var file = input.files[0]; if (!file) return;
    if (file.size > 2 * 1024 * 1024) { showToast('Maks 2MB', 'error'); return; }
    var fd = new FormData(); fd.append('photo', file);
    try {
      showToast('Mengupload...', 'info');
      var d = await (await fetch('/profile/photo', { method: 'POST', body: fd })).json();
      if (d.success) {
        var wrap = $('profilePhotoWrap');
        if (wrap) wrap.innerHTML = '<img src="' + esc(d.photo) + '?t=' + Date.now() + '" alt="" style="width:100%;height:100%;object-fit:cover;">';
        showToast('Foto berhasil diperbarui', 'success');
      } else showToast(d.message || 'Gagal upload', 'error');
    } catch (e) { showToast('Gagal upload foto', 'error'); }
    input.value = '';
  };

  // ─── NOTIF "baru saja beli": maks 1x per 3 menit per browser, lewati tab background ───
  var shown = new Set(); try { shown = new Set(JSON.parse(localStorage.getItem('vpr_notifs') || '[]')); } catch (e) {}
  var queue = [], playing = false;
  async function loadNotifs() {
    if (document.hidden) return;
    try {
      var last = Number(localStorage.getItem('vpr_notif_t') || 0);
      if (Date.now() - last < 180000) return;
      localStorage.setItem('vpr_notif_t', String(Date.now()));
      var list = await (await fetch('/api/notifications')).json();
      (Array.isArray(list) ? list : []).forEach(function (n) { if (!shown.has(n.id)) { queue.push(n); shown.add(n.id); } });
      localStorage.setItem('vpr_notifs', JSON.stringify(Array.from(shown).slice(-100)));
      if (!playing && queue.length) next();
    } catch (e) {}
  }
  function next() { if (!queue.length) { playing = false; return; } playing = true; show(queue.shift()); setTimeout(next, 4500); }
  function show(n) {
    var c = $('purchase-notif-container'); if (!c) return;
    var name = String(n.buyerName || '?');
    var bg = ['#b91c1c', '#0891b2', '#15803d', '#ea580c', '#7c3aed'][name.charCodeAt(0) % 5];
    var el = document.createElement('div'); el.className = 'purchase-notif';
    el.innerHTML = '<div class="purchase-notif-avatar" style="background:' + bg + ';">' + esc(name.charAt(0).toUpperCase()) + '</div>' +
      '<div style="min-width:0;"><div class="purchase-notif-name">' + esc(name) + ' baru saja beli</div><div class="purchase-notif-product">' + esc(n.productName || '') + '</div></div>' +
      '<div class="purchase-notif-price">' + (n.price ? 'Rp ' + Number(n.price).toLocaleString('id-ID') : '') + '</div>';
    c.appendChild(el);
    setTimeout(function () { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; setTimeout(function () { el.remove(); }, 300); }, 3800);
  }

  document.addEventListener('DOMContentLoaded', function () { updateCartBadge(); setTimeout(loadNotifs, 2500); });
})();
