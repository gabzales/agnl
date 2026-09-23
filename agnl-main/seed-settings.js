/**
 * seed-settings.js — Push settings + logo ke Supabase
 * 
 * CARA PAKAI:
 *   node seed-settings.js
 * 
 * Jalankan SEKALI setelah deploy atau setiap kali ganti credentials.
 * Script ini akan:
 *   1. Upload logo ke Supabase Storage → dapat URL publik
 *   2. Overwrite settings di Supabase dengan kredensial & konfigurasi terbaru
 */

require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY; // bukan anon key — RLS sekarang blokir anon

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('❌ Set SUPABASE_URL dan SUPABASE_SERVICE_ROLE_KEY di file .env dulu!');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, { auth: { persistSession: false } });

// ── KREDENSIAL — bisa override via .env ──
const ADMIN_USERNAME = process.env.SEED_ADMIN_USERNAME || 'Abdurahman Mulvi Tarakan';
const ADMIN_PASSWORD = process.env.SEED_ADMIN_PASSWORD || 'Tarakan11#';

const SITE_NAME   = 'AGHA NL';
const WA_NUMBER   = '6282253090432';
const WA_TELEGRAM = 'AghaNLOfficial';
const WA_CHANNEL  = ''; // isi manual lewat admin panel — Pengaturan > Kontak > Link Saluran WA
const WA_GROUP    = ''; // isi manual lewat admin panel — Pengaturan > Kontak > Link Grup WA
const YOUTUBE_URL = ''; // isi manual lewat admin panel kalau ada
// ─────────────────────────────────────────────────────────

async function uploadLogo() {
  const logoPath = path.join(__dirname, 'public', 'uploads', 'logo-main.png');
  if (!fs.existsSync(logoPath)) {
    console.log('⚠️  Logo file tidak ditemukan di public/uploads/logo-main.png, skip upload.');
    return null;
  }
  const fileBuffer = fs.readFileSync(logoPath);

  // Selalu upload ulang logo (upsert: true) agar logo baru menimpa yang lama
  const { error } = await supabase.storage
    .from('product-images')
    .upload('logo-main.png', fileBuffer, { contentType: 'image/png', upsert: true });

  if (error) {
    console.error('⚠️  Gagal upload logo ke storage:', error.message);
    return null;
  }
  const { data: { publicUrl } } = supabase.storage
    .from('product-images').getPublicUrl('logo-main.png');
  console.log('✅ Logo diupload ke Supabase Storage:', publicUrl);
  return publicUrl;
}

async function uploadLogoText() {
  const logoTextPath = path.join(__dirname, 'public', 'uploads', 'logo-text.png');
  if (!fs.existsSync(logoTextPath)) {
    console.log('⚠️  Logo text file tidak ditemukan di public/uploads/logo-text.png, skip upload.');
    return null;
  }
  const fileBuffer = fs.readFileSync(logoTextPath);
  const { error } = await supabase.storage
    .from('product-images')
    .upload('logo-text.png', fileBuffer, { contentType: 'image/png', upsert: true });

  if (error) {
    console.error('⚠️  Gagal upload logo text ke storage:', error.message);
    return null;
  }
  const { data: { publicUrl } } = supabase.storage
    .from('product-images').getPublicUrl('logo-text.png');
  console.log('✅ Logo text (wordmark AGHA NL) diupload ke Supabase Storage:', publicUrl);
  return publicUrl;
}

async function uploadBanner() {
  const bannerPath = path.join(__dirname, 'public', 'uploads', 'banner-reseller.jpg');
  if (!require('fs').existsSync(bannerPath)) {
    console.log('⚠️  Banner file tidak ditemukan di public/uploads/banner-reseller.jpg, skip upload.');
    return null;
  }
  const fileBuffer = require('fs').readFileSync(bannerPath);
  const { data: existList } = await supabase.storage.from('product-images').list('', { search: 'banner-reseller.jpg' });
  if (existList && existList.length > 0) {
    const { data: { publicUrl } } = supabase.storage.from('product-images').getPublicUrl('banner-reseller.jpg');
    console.log('ℹ️  Banner sudah ada di storage:', publicUrl);
    return publicUrl;
  }
  const { error } = await supabase.storage.from('product-images').upload('banner-reseller.jpg', fileBuffer, { contentType: 'image/jpeg', upsert: true });
  if (error) { console.error('⚠️  Gagal upload banner:', error.message); return null; }
  const { data: { publicUrl } } = supabase.storage.from('product-images').getPublicUrl('banner-reseller.jpg');
  console.log('✅ Banner diupload ke Supabase Storage:', publicUrl);
  return publicUrl;
}

async function main() {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  AGHA NL — Seed Settings ke Supabase');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

  // 1. Upload logo & banner
  const logoUrl = await uploadLogo();
  const logoTextUrl = await uploadLogoText();
  const bannerUrl = await uploadBanner();

  // 2. Ambil settings existing
  const { data: existing } = await supabase
    .from('keyvalue_store').select('value').eq('key', 'settings.json').single();
  const current = (existing?.value && typeof existing.value === 'object') ? existing.value : {};
  console.log('📋 Existing adminUsername:', current.adminUsername || '(none)');

  // 3. Build settings baru
  const adminHash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
  const newSettings = {
    ...current,                          // pertahankan data yang ada (produk, pakasir key, dll)
    siteName: SITE_NAME,
    gamePanelName: SITE_NAME,
    about: `${SITE_NAME} DIGITAL STORE menyediakan layanan topup, files, dan access game terbaik #1 indonesia.`,
    marqueeText: 'TOP UP & FILES GAME TERMURAH, AMAN, DAN CEPAT!',
    contact: {
      whatsapp: current.contact?.whatsapp || WA_NUMBER,
      telegram: current.contact?.telegram || WA_TELEGRAM,
      email: current.contact?.email || 'support@agha.nlstoreshop.my.id',
      youtube: current.contact?.youtube || YOUTUBE_URL,
      waChannel: current.contact?.waChannel || WA_CHANNEL,
      waGroup: current.contact?.waGroup || WA_GROUP,
    },
    adminUsername: ADMIN_USERNAME,
    adminPassword: adminHash,
    logoUrl: logoUrl || current.logoUrl || '/uploads/logo-main.png',
    logoTextUrl: logoTextUrl || current.logoTextUrl || '/uploads/logo-text.png',
    siteUrl: current.siteUrl || 'https://agha.nlstoreshop.my.id',
    theme: current.theme || {
      primaryColor: '#dc2626', secondaryColor: '#7b2cbf', accentColor: '#a3123a',
      backgroundColor: '#0a0a0a', cardBackground: '#141414', borderColor: '#3a1414', glowColor: '#dc2626',
    },
    buyerGroupName: current.buyerGroupName || 'BUYER VIP BY AGHA NL',
    buyerGroupUrl: current.buyerGroupUrl || 'https://chat.whatsapp.com/DUSkETDjlxa5aksYJ0ar1m',
    resellerGroupName: current.resellerGroupName || 'RESELLER VIP BY AGHA NL',
    resellerGroupUrl: current.resellerGroupUrl || 'https://chat.whatsapp.com/GO9mZ1wec8LJwVmlpeSW7G',
    categories: current.categories || ['freefire','mlbb','pubgm','sertifikat'],
    categoryLabels: current.categoryLabels || {
      freefire:'FREE FIRE', mlbb:'MOBILE LEGENDS', pubgm:'PUBG MOBILE', sertifikat:'SERTIFIKAT'
    },
    resellerEnabled: true,
    resellerPrice: current.resellerPrice ?? 50000,
    resellerDiscount: current.resellerDiscount ?? 20,
    resellerNote: current.resellerNote || 'Dapatkan diskon eksklusif untuk semua produk!',
    popularProductIds: current.popularProductIds || [],
    fakeLeaderboard: current.fakeLeaderboard || [],
    pakasir: current.pakasir || { apiKey:'', project:'', mode:'production' },
    banners: current.banners?.length ? current.banners : [
      { url: bannerUrl || '/uploads/banner-reseller.jpg', title: 'Open Reseller', link: '/reseller', active: true }
    ],
  };

  // 4. Upsert ke Supabase
  const { error } = await supabase
    .from('keyvalue_store')
    .upsert({ key: 'settings.json', value: newSettings }, { onConflict: 'key' });

  if (error) {
    console.error('❌ Gagal simpan ke Supabase:', error.message);
    process.exit(1);
  }

  // 5. Verifikasi
  const { data: v } = await supabase
    .from('keyvalue_store').select('value').eq('key', 'settings.json').single();
  const saved = v?.value;

  console.log('\n✅ BERHASIL disimpan ke Supabase!');
  console.log('┌─────────────────────────────────────────');
  console.log('│ siteName     :', saved?.siteName);
  console.log('│ adminUsername:', saved?.adminUsername);
  console.log('│ logoUrl      :', saved?.logoUrl);
  console.log('│ whatsapp     :', saved?.contact?.whatsapp);
  console.log('│ banners      :', saved?.banners?.length ?? 0, 'item(s)');
  console.log('│ hash verify  :', bcrypt.compareSync(ADMIN_PASSWORD, saved?.adminPassword || '') ? '✅ OK' : '❌ GAGAL');
  console.log('└─────────────────────────────────────────');
  console.log(`\n🔐 Login admin: username=${ADMIN_USERNAME}  password=(dari .env, tidak ditampilkan)`);
  console.log('🌐 Deploy ulang Vercel agar settings baru aktif.\n');
}

main().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
