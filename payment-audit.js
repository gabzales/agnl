'use strict';
/**
 * PAYMENT AUDIT — riwayat pembayaran selengkap mungkin, untuk bukti banding ke payment gateway.
 *
 * 1) record(type, data)  : catat event pembayaran PERMANEN (Supabase keyvalue 'payment_events.json'):
 *      order.created, genspay.create (request/response/durasi), webhook.received (IP, header, body mentah),
 *      webhook.result, order.manual_confirm, order.blocked_duplicate, dst.
 * 2) mount(app, requireAdmin) memasang halaman admin:
 *      GET /admin/payment-history              -> dashboard riwayat (filter, kronologi per order)
 *      GET /admin/payment-history/data         -> JSON
 *      GET /admin/payment-history/export.csv   -> semua transaksi (CSV)
 *      GET /admin/payment-history/export.json  -> semua transaksi + event + log tersimpan (JSON lengkap)
 *      GET /admin/payment-history/report       -> "Laporan Banding" siap cetak / simpan PDF
 *
 * Data lama: yang tersedia untuk transaksi SEBELUM modul ini dipasang hanyalah transactions.json
 * (+ log warn/error yang sempat tersimpan di app_logs.json). Request/response & payload webhook
 * baru terekam mulai modul ini aktif.
 */
const crypto = require('crypto');

const EVENTS_FILE = 'payment_events.json';
const LOGS_FILE = 'app_logs.json';
const MAX_EVENTS = 1500;
const BODY_MAX = 800;
const GENSPAY_LIMIT_PER_3MIN = 30; // batas kebijakan GensPay (sama dengan PAYMENT_RATE_LIMIT di server.js)

let deps = null;
const queue = [];
let flushing = null;
let base = null;

function init(d) { deps = d; }

const clip = (v, n = BODY_MAX) => {
  if (v === undefined || v === null) return v;
  const s = typeof v === 'string' ? v : (() => { try { return JSON.stringify(v); } catch (_) { return String(v); } })();
  return s.length > n ? s.slice(0, n) + '…[+' + (s.length - n) + ' char]' : s;
};
const timeout = (ms, val) => new Promise(r => setTimeout(() => r(val), ms));

function sanitize(data) {
  const out = {};
  for (const [k, v] of Object.entries(data || {})) {
    if (/api[-_]?key|secret|token|password|authorization/i.test(k)) continue; // jangan pernah simpan kredensial
    out[k] = (v && typeof v === 'object') ? clip(v) : (typeof v === 'string' ? clip(v) : v);
  }
  return out;
}

function flush() {
  if (flushing) return flushing;
  flushing = (async () => {
    try {
      while (queue.length) {
        const batch = queue.splice(0, queue.length);
        let prev = null;
        try { prev = await Promise.race([deps.readFresh(EVENTS_FILE), timeout(3000, null)]); } catch (_) {}
        if (Array.isArray(prev)) base = prev; else if (base === null) base = [];
        const seen = new Set(); const merged = [];
        for (const e of base.concat(batch)) { if (e && e.id && !seen.has(e.id)) { seen.add(e.id); merged.push(e); } }
        base = merged.sort((a, b) => String(a.t).localeCompare(String(b.t))).slice(-MAX_EVENTS);
        await deps.writeDB(EVENTS_FILE, base);
      }
    } catch (_) { /* audit tidak boleh mengganggu pembayaran */ }
    finally { flushing = null; }
  })();
  return flushing;
}

/** Catat event. Tidak pernah throw. Return promise yang selesai saat sudah tersimpan (maks ±4 dtk). */
function record(type, data) {
  try {
    if (!deps) return Promise.resolve();
    queue.push({ id: crypto.randomBytes(6).toString('hex'), t: new Date().toISOString(), type, ...sanitize(data) });
    return Promise.race([flush(), timeout(4000)]);
  } catch (_) { return Promise.resolve(); }
}

// ───────────────────────── Analisis ─────────────────────────
const GW = (t) => t.paymentGateway || 'pakasir';
const isDone = (t) => t.status === 'done';

function peakWindow(timestamps, windowMs) {
  const a = timestamps.slice().sort((x, y) => x - y);
  let best = 0, bestStart = null, j = 0;
  for (let i = 0; i < a.length; i++) {
    while (a[i] - a[j] > windowMs) j++;
    if (i - j + 1 > best) { best = i - j + 1; bestStart = a[j]; }
  }
  return { count: best, start: bestStart };
}

async function load(opts = {}) {
  const [txRaw, usersRaw, evRaw, logRaw] = await Promise.all([
    deps.readFresh('transactions.json').catch(() => []),
    deps.readFresh('users.json').catch(() => []),
    deps.readFresh(EVENTS_FILE).catch(() => []),
    deps.readFresh(LOGS_FILE).catch(() => [])
  ]);
  const tx = (Array.isArray(txRaw) ? txRaw : []);
  const users = new Map((Array.isArray(usersRaw) ? usersRaw : []).map(u => [u.id, u]));
  const events = Array.isArray(evRaw) ? evRaw : [];
  const logs = (Array.isArray(logRaw) ? logRaw : []).filter(l => l && /genspay|webhook|payment|qris|pakasir/i.test(String(l.msg || '') + String(l.cat || '')));
  return { tx, users, events, logs };
}

function filterTx(tx, opts) {
  const gateway = opts.gateway || 'all';
  const from = opts.from ? Date.parse(opts.from) : null;
  const to = opts.to ? Date.parse(opts.to) + 86400000 : null;
  const q = String(opts.q || '').toLowerCase().trim();
  return tx.filter(t => {
    if (!t) return false;
    if (gateway !== 'all' && GW(t) !== gateway) return false;
    if (opts.status && opts.status !== 'all' && t.status !== opts.status) return false;
    const c = Date.parse(t.createdAt || '');
    if (from && !(c >= from)) return false;
    if (to && !(c < to)) return false;
    if (q) {
      const hay = [t.orderId, t.code, t.customerName, t.wa, t.productName, t.id].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function timelineFor(t, events, logs) {
  const tl = [];
  tl.push({ t: t.createdAt, type: 'order.created (data transaksi)', note: `Rp${t.price} · ${t.productName || t.type || '-'} · ${t.isStatic ? 'QRIS statis' : 'QRIS dinamis via ' + GW(t)}` });
  for (const e of events) if (e.orderId && (e.orderId === t.orderId || e.orderId === t.id)) tl.push({ t: e.t, type: e.type, note: Object.entries(e).filter(([k]) => !['id', 't', 'type', 'orderId'].includes(k)).map(([k, v]) => `${k}=${v}`).join(' | ') });
  for (const l of logs) if (l.msg && t.orderId && String(l.msg).includes(t.orderId)) tl.push({ t: l.t ? new Date(l.t).toISOString() : null, type: 'log.' + (l.lv || ''), note: String(l.msg).slice(0, 300) });
  if (t.doneAt || t.paidAt) tl.push({ t: t.doneAt || t.paidAt, type: 'order.paid', note: 'status done' });
  tl.sort((a, b) => String(a.t || '').localeCompare(String(b.t || '')));
  return tl;
}

function summarize(rows, events, logs) {
  const gwRows = rows.filter(t => !t.isStatic);   // hanya yang benar-benar memanggil gateway
  const byStatus = {};
  for (const t of rows) byStatus[t.status] = (byStatus[t.status] || 0) + 1;
  const paid = rows.filter(isDone);
  const paidAmount = paid.reduce((s, t) => s + (Number(t.price) || 0), 0);

  const byUser = new Map();
  for (const t of gwRows) { const k = t.userId || t.wa || '?'; if (!byUser.has(k)) byUser.set(k, []); byUser.get(k).push(Date.parse(t.createdAt)); }
  const userPeaks = [...byUser.entries()].map(([k, ts]) => ({ user: k, total: ts.length, peak3min: peakWindow(ts.filter(Number.isFinite), 180000).count }))
    .sort((a, b) => b.total - a.total).slice(0, 10);
  const allTs = gwRows.map(t => Date.parse(t.createdAt)).filter(Number.isFinite);
  const global3 = peakWindow(allTs, 180000);
  const global1 = peakWindow(allTs, 60000);

  const perDay = {};
  for (const t of rows) {
    const d = new Date(Date.parse(t.createdAt) + 7 * 3600000).toISOString().slice(0, 10);
    perDay[d] = perDay[d] || { created: 0, done: 0, pending: 0, other: 0 };
    perDay[d].created++;
    if (isDone(t)) perDay[d].done++; else if (t.status === 'pending') perDay[d].pending++; else perDay[d].other++;
  }

  const createEv = events.filter(e => e.type === 'genspay.create');
  const hooks = events.filter(e => /^webhook\./.test(e.type));
  const hookRecv = hooks.filter(e => e.type === 'webhook.genspay.received').length;
  const hookResults = {};
  for (const e of hooks) if (e.type === 'webhook.genspay.result') hookResults[e.result || '?'] = (hookResults[e.result || '?'] || 0) + 1;
  const dupBlocked = events.filter(e => e.type === 'order.blocked_duplicate').length;

  const times = rows.map(t => Date.parse(t.createdAt)).filter(Number.isFinite);
  return {
    totalOrders: rows.length, hitGateway: gwRows.length, staticOrders: rows.length - gwRows.length,
    byStatus, paidCount: paid.length, paidAmount,
    conversionPct: gwRows.length ? Math.round((gwRows.filter(isDone).length / gwRows.length) * 1000) / 10 : 0,
    uniqueUsers: byUser.size, userPeaks,
    peak3minGlobal: global3.count, peak3minGlobalAt: global3.start ? new Date(global3.start).toISOString() : null,
    peak1minGlobal: global1.count,
    limitPer3min: GENSPAY_LIMIT_PER_3MIN,
    perDay,
    eventsTotal: events.length, createCallsLogged: createEv.length,
    createCallsFailed: createEv.filter(e => e.ok === false || e.ok === 'false').length,
    webhookReceived: hookRecv, webhookResults: hookResults, duplicateBlocked: dupBlocked,
    persistedLogLines: logs.length,
    periodFrom: times.length ? new Date(Math.min(...times)).toISOString() : null,
    periodTo: times.length ? new Date(Math.max(...times)).toISOString() : null
  };
}

async function buildAudit(opts) {
  const { tx, users, events, logs } = await load(opts);
  const rows = filterTx(tx, opts).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  const now = Date.now();
  const list = rows.map(t => {
    const u = users.get(t.userId) || {};
    return {
      id: t.id, orderId: t.orderId, code: t.code, status: t.status, gateway: GW(t), isStatic: !!t.isStatic,
      productName: t.productName || t.type || '-', duration: t.duration || null,
      price: t.price, totalPayment: t.totalPayment, customerName: t.customerName || u.username || null,
      wa: t.wa || u.wa || null, userId: t.userId || null, isGuest: !!u.isGuest,
      createdAt: t.createdAt, ageMinutes: Math.round((now - Date.parse(t.createdAt)) / 60000),
      ip: t.ip || null, hasKey: !!t.key,
      paidAt: t.paidAt || null, gatewayStatus: t.gatewayStatus || null, gatewayUpdatedAt: t.gatewayUpdatedAt || null, keySource: t.keySource || null
    };
  });
  return { rows, list, events, logs, summary: summarize(rows, events, logs), users };
}

// ───────────────────────── Tampilan ─────────────────────────
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const jkt = (iso) => { const d = Date.parse(iso); return Number.isFinite(d) ? new Date(d).toLocaleString('id-ID', { timeZone: 'Asia/Jakarta', hour12: false }) + ' WIB' : '-'; };
const maskWa = (w) => { const s = String(w || ''); return s.length > 7 ? s.slice(0, 4) + '****' + s.slice(-3) : s; };
const rp = (n) => 'Rp ' + Number(n || 0).toLocaleString('id-ID');

function pageHtml(adminPath) {
  return `<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Riwayat Pembayaran</title><style>
*{box-sizing:border-box}body{margin:0;background:#0b0b10;color:#e8e8f0;font:14px/1.45 system-ui,Segoe UI,Roboto,sans-serif;padding:16px;max-width:1100px;margin:auto}
a{color:#7dd3fc}h1{font-size:18px;margin:0 0 4px}.sub{color:#9aa;font-size:12px;margin-bottom:14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin-bottom:14px}
.card{background:#15151e;border:1px solid #262634;border-radius:10px;padding:10px}.card b{display:block;font-size:20px}.card span{font-size:11px;color:#9aa}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}input,select,button{background:#15151e;color:#e8e8f0;border:1px solid #333;border-radius:8px;padding:8px 10px;font-size:13px}
button.p{background:#e11d48;border-color:#e11d48;font-weight:700;cursor:pointer}button{cursor:pointer}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{padding:7px 6px;border-bottom:1px solid #22222e;text-align:left;vertical-align:top}th{color:#9aa;font-weight:600;position:sticky;top:0;background:#0b0b10}
.tag{padding:2px 8px;border-radius:99px;font-size:11px;font-weight:700}.done{background:#06462a;color:#6ee7b7}.pending{background:#4a3a05;color:#fcd34d}.expired,.cancelled,.failed{background:#3b1a1a;color:#fca5a5}
tr.row{cursor:pointer}tr.row:hover{background:#12121a}.tl{background:#0f0f17;padding:8px 10px;border-left:3px solid #e11d48;margin:4px 0}.tl div{margin:2px 0;font-family:ui-monospace,monospace;font-size:11px;color:#cbd}
.box{background:#15151e;border:1px solid #262634;border-radius:10px;padding:10px;margin-bottom:14px}.wrap{overflow-x:auto}.muted{color:#9aa}
</style></head><body>
<h1>Riwayat Pembayaran (bukti banding)</h1>
<div class="sub">Semua transaksi + kronologi + export. Waktu ditampilkan WIB.</div>
<div class="cards" id="cards"></div>
<div class="bar">
 <select id="gw"><option value="all">Semua gateway</option><option value="genspay">GensPay</option><option value="pakasir">Pakasir</option></select>
 <select id="st"><option value="all">Semua status</option><option value="pending">Pending</option><option value="done">Done</option><option value="failed">Failed</option><option value="expired">Expired</option></select>
 <input type="date" id="from"><input type="date" id="to"><input id="q" placeholder="cari order/WA/nama/produk">
 <button class="p" onclick="load()">Tampilkan</button>
</div>
<div class="bar">
 <button onclick="dl('csv')">⬇ CSV semua transaksi</button>
 <button onclick="dl('json')">⬇ JSON lengkap (transaksi+event+log)</button>
 <button class="p" onclick="rep()">📄 Laporan Banding (cetak / PDF)</button>
</div>
<div class="box" id="peaks"></div>
<div class="wrap"><table><thead><tr><th>Waktu (WIB)</th><th>Order</th><th>Produk</th><th>Nominal</th><th>Customer</th><th>Status</th><th>Umur</th></tr></thead><tbody id="rows"></tbody></table></div>
<script>
var AP='/${adminPath}/payment-history';
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function qs(){return 'gateway='+gw.value+'&status='+st.value+'&from='+from.value+'&to='+to.value+'&q='+encodeURIComponent(q.value)}
function dl(f){location.href=AP+'/export.'+f+'?'+qs()}function rep(){window.open(AP+'/report?'+qs(),'_blank')}
function wib(i){var d=new Date(i);return isNaN(d)?'-':d.toLocaleString('id-ID',{timeZone:'Asia/Jakarta',hour12:false})}
async function load(){
 var r=await fetch(AP+'/data?'+qs(),{credentials:'same-origin'});var d=await r.json();var s=d.summary;
 cards.innerHTML=[['Total order',s.totalOrders],['Panggil gateway',s.hitGateway],['Lunas (done)',s.paidCount],['Pending',s.byStatus.pending||0],['Konversi',s.conversionPct+'%'],['Puncak /3 mnt',s.peak3minGlobal+' (batas '+s.limitPer3min+')'],['Pelanggan unik',s.uniqueUsers],['Event tercatat',s.eventsTotal]].map(function(x){return '<div class="card"><b>'+esc(x[1])+'</b><span>'+esc(x[0])+'</span></div>'}).join('');
 peaks.innerHTML='<b>Pengguna dengan order terbanyak</b><div class="muted" style="margin:4px 0">puncak = jumlah order terbanyak dalam jendela 3 menit</div>'+(s.userPeaks.length?s.userPeaks.map(function(u){return '<div>'+esc(u.user)+' — '+u.total+' order, puncak '+u.peak3min+'/3 mnt</div>'}).join(''):'<span class="muted">-</span>');
 rows.innerHTML=d.list.map(function(t,i){return '<tr class="row" onclick="tl('+i+')"><td>'+esc(wib(t.createdAt))+'</td><td>'+esc(t.orderId)+'<br><span class="muted">'+esc(t.code||'')+'</span></td><td>'+esc(t.productName)+'</td><td>'+esc(t.price)+'</td><td>'+esc(t.customerName||'')+'<br><span class="muted">'+esc(t.wa||'')+'</span></td><td><span class="tag '+esc(t.status)+'">'+esc(t.status)+'</span></td><td>'+t.ageMinutes+' mnt</td></tr><tr id="tl'+i+'" style="display:none"><td colspan="7"></td></tr>'}).join('');
 window._d=d;
}
function tl(i){var row=document.getElementById('tl'+i);if(row.style.display==='none'){var t=window._d.list[i];var ev=window._d.timelines[t.id]||[];row.firstChild.innerHTML='<div class="tl">'+(ev.length?ev.map(function(e){return '<div>'+esc(wib(e.t))+' · <b>'+esc(e.type)+'</b> '+esc(e.note)+'</div>'}).join(''):'<div>(tidak ada event)</div>')+'</div>';row.style.display=''}else row.style.display='none'}
load();
</script></body></html>`;
}

function reportHtml(a, opts, settings) {
  const s = a.summary;
  const site = esc(settings.siteName || settings.storeName || 'Toko Digital');
  const pend = a.list.filter(t => t.status === 'pending');
  const days = Object.entries(s.perDay).sort(([x], [y]) => x.localeCompare(y));
  const timelines = a.rows.filter(t => t.status !== 'done').slice(0, 60);
  const draft =
`Halo tim GensPay,

Kami mengajukan banding atas suspend akun merchant kami (${site}). Berikut ringkasan data dari sistem kami (periode ${jkt(s.periodFrom)} s.d. ${jkt(s.periodTo)}):
- Total order lewat GensPay: ${s.hitGateway}; lunas: ${s.byStatus.done || 0}; pending: ${s.byStatus.pending || 0}; konversi ${s.conversionPct}%.
- Puncak pembuatan order dalam 3 menit (seluruh pengguna): ${s.peak3minGlobal} (batas kebijakan ${s.limitPer3min} per pengguna / 3 menit). Per pengguna tertinggi: ${s.userPeaks[0] ? s.userPeaks[0].peak3min : 0}.
- Sistem kami TIDAK melakukan polling status ke GensPay (status hanya dari webhook), dan hanya memanggil endpoint create satu kali per order.
- Webhook diverifikasi dengan signature (HMAC) sebelum diproses.
Mohon bantuannya untuk meninjau ulang dan menunjukkan transaksi/aktivitas spesifik yang dianggap melanggar agar dapat kami perbaiki. Laporan lengkap terlampir.

Terima kasih.`;
  const rowsHtml = a.list.map(t => `<tr><td>${esc(jkt(t.createdAt))}</td><td>${esc(t.orderId)}</td><td>${esc(t.productName)}</td><td>${esc(rp(t.price))}</td><td>${esc(t.customerName || '')} ${esc(maskWa(t.wa))}</td><td>${esc(t.status)}</td><td>${t.isStatic ? 'statis' : 'dinamis'}</td></tr>`).join('');
  const tlHtml = timelines.map(t => {
    const tl = timelineFor(t, a.events, a.logs);
    return `<div class="tl"><b>${esc(t.orderId)}</b> · ${esc(t.status)} · ${esc(rp(t.price))} · ${esc(t.productName || '')}<br>` +
      tl.map(e => `<div>${esc(jkt(e.t))} — ${esc(e.type)} ${esc(e.note)}</div>`).join('') + '</div>';
  }).join('');
  return `<!doctype html><html lang="id"><head><meta charset="utf-8"><title>Laporan Banding Pembayaran</title><style>
body{font:13px/1.5 system-ui,Segoe UI,Roboto,sans-serif;color:#111;max-width:900px;margin:20px auto;padding:0 14px}
h1{font-size:20px;margin:0}h2{font-size:15px;margin:22px 0 6px;border-bottom:2px solid #111;padding-bottom:3px}table{width:100%;border-collapse:collapse;font-size:11.5px}
th,td{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top}th{background:#eee}.k{display:grid;grid-template-columns:1fr 1fr;gap:4px 18px}.k div{border-bottom:1px dotted #bbb;padding:2px 0}
textarea{width:100%;height:230px;font:12px/1.4 ui-monospace,monospace}.tl{border-left:3px solid #999;padding:3px 8px;margin:6px 0;font-size:11.5px}.note{background:#fff8dc;border:1px solid #e5d08a;padding:8px;border-radius:6px}
button{padding:8px 14px;font-weight:700}@media print{.noprint{display:none}body{margin:0}}
</style></head><body>
<div class="noprint" style="margin-bottom:10px"><button onclick="window.print()">🖨 Cetak / Simpan PDF</button></div>
<h1>Laporan Riwayat Pembayaran — ${site}</h1>
<div>Dibuat: ${esc(jkt(new Date().toISOString()))} · Gateway: ${esc(opts.gateway || 'genspay')} · Periode data: ${esc(jkt(s.periodFrom))} s.d. ${esc(jkt(s.periodTo))}</div>

<h2>1. Ringkasan</h2><div class="k">
<div>Total order: <b>${s.totalOrders}</b></div><div>Order yang memanggil gateway (QRIS dinamis): <b>${s.hitGateway}</b></div>
<div>Lunas (done): <b>${s.byStatus.done || 0}</b> (${esc(rp(s.paidAmount))})</div><div>Pending: <b>${s.byStatus.pending || 0}</b></div>
<div>Expired/lainnya: <b>${s.totalOrders - (s.byStatus.done || 0) - (s.byStatus.pending || 0)}</b></div><div>Konversi order→lunas: <b>${s.conversionPct}%</b></div>
<div>Pelanggan unik: <b>${s.uniqueUsers}</b></div><div>Order QRIS statis (tanpa panggilan gateway): <b>${s.staticOrders}</b></div></div>

<h2>2. Kepatuhan batas request</h2>
<div class="k"><div>Batas kebijakan: <b>${s.limitPer3min} request / 3 menit / pengguna</b></div><div>Puncak seluruh pengguna / 3 menit: <b>${s.peak3minGlobal}</b>${s.peak3minGlobalAt ? ' (mulai ' + esc(jkt(s.peak3minGlobalAt)) + ')' : ''}</div>
<div>Puncak seluruh pengguna / 1 menit: <b>${s.peak1minGlobal}</b></div><div>Pengguna dengan puncak tertinggi / 3 menit: <b>${s.userPeaks[0] ? s.userPeaks[0].peak3min : 0}</b></div></div>
<table style="margin-top:8px"><tr><th>Pengguna (ID / WA)</th><th>Total order</th><th>Puncak / 3 menit</th></tr>
${s.userPeaks.map(u => `<tr><td>${esc(String(u.user).length > 12 ? maskWa(u.user) : u.user)}</td><td>${u.total}</td><td>${u.peak3min}</td></tr>`).join('')}</table>
<p class="note">Catatan teknis: aplikasi tidak memanggil endpoint status GensPay sama sekali (GensPay tidak menyediakannya; status hanya dari webhook), sehingga satu-satunya panggilan keluar ke GensPay adalah <i>transaction/create</i> saat order dibuat. Panggilan create yang tercatat permanen sejak audit aktif: <b>${s.createCallsLogged}</b> (gagal: ${s.createCallsFailed}). Order yang ditolak karena duplikat tercatat: <b>${s.duplicateBlocked}</b>. Webhook diterima (tercatat): <b>${s.webhookReceived}</b>; hasil: ${esc(JSON.stringify(s.webhookResults))}.</p>

<h2>3. Sebaran per hari (WIB)</h2>
<table><tr><th>Tanggal</th><th>Dibuat</th><th>Lunas</th><th>Pending</th><th>Lainnya</th></tr>
${days.map(([d, v]) => `<tr><td>${d}</td><td>${v.created}</td><td>${v.done}</td><td>${v.pending}</td><td>${v.other}</td></tr>`).join('')}</table>

<h2>4. Draft pesan banding (salin &amp; sesuaikan)</h2><textarea class="noprint" readonly>${esc(draft)}</textarea>
<pre class="noprint" style="display:none"></pre>

<h2>5. Kronologi order belum lunas (maks 60 terbaru)</h2>${tlHtml || '<i>Tidak ada.</i>'}

<h2>6. Lampiran: seluruh transaksi (${a.list.length})</h2>
<table><tr><th>Waktu (WIB)</th><th>Order ID</th><th>Produk</th><th>Nominal</th><th>Customer</th><th>Status</th><th>Jenis QRIS</th></tr>${rowsHtml}</table>
<p class="note">Sumber data: transactions.json (seluruh riwayat), payment_events.json (event permanen sejak audit aktif), app_logs.json (log peringatan/error tersimpan). Nomor WhatsApp disamarkan di laporan; data lengkap tersedia di export JSON/CSV admin.</p>
</body></html>`;
}

const csvCell = (v) => { const s = String(v == null ? '' : v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };

function mount(app, requireAdmin, adminPathFn) {
  const AP = 'admin';
  const O = (req) => ({ gateway: req.query.gateway || 'all', status: req.query.status, from: req.query.from, to: req.query.to, q: req.query.q });

  app.get('/admin/payment-history', requireAdmin, (req, res) => {
    res.set('Cache-Control', 'no-store'); res.type('html').send(pageHtml(AP));
  });
  app.get('/admin/payment-history/data', requireAdmin, async (req, res) => {
    res.set('Cache-Control', 'no-store');
    try {
      const a = await buildAudit(O(req));
      const timelines = {};
      for (const t of a.rows.slice(0, 400)) timelines[t.id] = timelineFor(t, a.events, a.logs);
      res.json({ success: true, summary: a.summary, list: a.list.slice(0, 400), timelines, truncated: a.list.length > 400 });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
  });
  app.get('/admin/payment-history/export.csv', requireAdmin, async (req, res) => {
    try {
      const a = await buildAudit(O(req));
      const head = ['createdAt_WIB', 'createdAt_ISO', 'paidAt_WIB', 'paidAt_ISO', 'orderId', 'refId', 'code', 'gateway', 'jenis_qris', 'status', 'status_gateway', 'status_gateway_update_ISO', 'produk', 'durasi', 'harga', 'totalPayment', 'key_terkirim', 'sumber_key', 'customer', 'wa', 'userId', 'guest', 'ip', 'umur_menit'];
      const lines = [head.join(',')].concat(a.list.map(t => [jkt(t.createdAt), t.createdAt, t.paidAt ? jkt(t.paidAt) : '', t.paidAt || '', t.orderId, t.id, t.code, t.gateway, t.isStatic ? 'statis' : 'dinamis', t.status, t.gatewayStatus || '', t.gatewayUpdatedAt || '', t.productName, t.duration, t.price, t.totalPayment, t.hasKey ? 'ya' : 'tidak', t.keySource || '', t.customerName, t.wa, t.userId, t.isGuest, t.ip, t.ageMinutes].map(csvCell).join(',')));
      res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="riwayat-pembayaran.csv"' });
      res.send('\ufeff' + lines.join('\n'));
    } catch (e) { res.status(500).send(e.message); }
  });
  app.get('/admin/payment-history/export.json', requireAdmin, async (req, res) => {
    try {
      const a = await buildAudit(O(req));
      res.set({ 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': 'attachment; filename="riwayat-pembayaran-lengkap.json"' });
      res.send(JSON.stringify({ generatedAt: new Date().toISOString(), filter: O(req), summary: a.summary, transactions: a.rows, events: a.events, persistedLogs: a.logs }, null, 2));
    } catch (e) { res.status(500).send(e.message); }
  });
  app.get('/admin/payment-history/report', requireAdmin, async (req, res) => {
    try {
      const a = await buildAudit(O(req));
      let settings = {}; try { settings = await deps.readFresh('settings.json'); } catch (_) {}
      res.set('Cache-Control', 'no-store'); res.type('html').send(reportHtml(a, O(req), settings || {}));
    } catch (e) { res.status(500).send(e.message); }
  });
}

module.exports = { init, record, mount, buildAudit, peakWindow };
