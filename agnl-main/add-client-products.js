#!/usr/bin/env node
/**
 * add-client-products.js
 *
 * Tambah daftar produk client ke products.json / Supabase melalui adapter
 * project AGHA NL.
 *
 * Aman secara default:
 * - TIDAK membeli key dari DripStore.
 * - TIDAK mengubah stok/key existing.
 * - Tidak membuat produk duplikat berdasarkan nama (case-insensitive).
 * - Menambahkan kategori "APK MOD NO ROOT" bila kategori belum ada.
 * - Harga & durasi WAJIB diberikan lewat argumen agar tidak ada harga ngarang.
 *
 * Contoh:
 *   node add-client-products.js --price=50000 --days=30
 *   node add-client-products.js --price=15000 --days=1 --unit=h
 *   node add-client-products.js --price=50000 --days=30 --dry-run
 *
 * ENV opsional:
 *   PRODUCT_DEFAULT_PRICE=50000
 *   PRODUCT_DEFAULT_DAYS=30
 *   PRODUCT_DEFAULT_UNIT=d
 */

try { require('dotenv').config(); } catch {}
const crypto = require('crypto');
const uuidv4 = () => (crypto.randomUUID ? crypto.randomUUID() : [4,2,2,2,6].map((n,i)=>crypto.randomBytes(n).toString('hex')).join('-'));
const db = require('./supabase');

const CLIENT_PRODUCTS = [
  'DRIP CLINT APK MOD',
  'ABCD PANEL',
  'DRIP WIRE',
  'AIM HACK',
  'SILENT CHEATS',
  'HG APK MOD',
  'XREG APK MOD',
  'PATO ORANGE',
  'PATO GREEN',
  'PATO BLUE'
];

const CATEGORY_LABEL = 'APK MOD NO ROOT';
const now = () => new Date().toISOString();

function arg(name) {
  const exact = process.argv.find(a => a === `--${name}`);
  if (exact) return true;
  const prefix = `--${name}=`;
  const item = process.argv.find(a => a.startsWith(prefix));
  return item ? item.slice(prefix.length) : undefined;
}

function boolArg(name) {
  const value = arg(name);
  if (value === true) return true;
  if (value === undefined) return false;
  return !['0', 'false', 'no', 'off'].includes(String(value).toLowerCase());
}

function parseMoney(value) {
  if (value === undefined || value === null || value === '') return NaN;
  const digits = String(value).replace(/[^\d]/g, '');
  return digits ? Number(digits) : NaN;
}

function normalizeName(value) {
  return String(value || '')
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[._|/\\-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function parseUnit(value) {
  const u = String(value || 'd').toLowerCase().trim();
  return ['h', 'hour', 'hours', 'jam'].includes(u) ? 'h' : 'd';
}

function durationLabel(days, unit) {
  return unit === 'h' ? `${days} JAM` : `${days} HARI`;
}

function makeProduct({ name, category, days, unit, price, description }) {
  const pricingOptions = [{
    days,
    unit,
    price,
    reseller_price: null,
    strike_price: null,
    dripstoreVariantId: null
  }];

  return {
    id: uuidv4(),
    name,
    categories: [category],
    description,
    image: '/images/placeholder.jpg',
    pricingOptions,
    items: [{
      l: `${name.toUpperCase()} ${durationLabel(days, unit)}`,
      p: price,
      reseller_price: null,
      strike_price: null
    }],
    status: 'active',
    keys: [],
    channelUrl: '',
    downloadUrl: '',
    fakeSold: null,
    sold: 0,
    createdAt: now()
  };
}

async function main() {
  const dryRun = boolArg('dry-run');
  const priceRaw = arg('price') ?? process.env.PRODUCT_DEFAULT_PRICE;
  const daysRaw = arg('days') ?? process.env.PRODUCT_DEFAULT_DAYS ?? '30';
  const unit = parseUnit(arg('unit') ?? process.env.PRODUCT_DEFAULT_UNIT ?? 'd');
  const categorySlugArg = arg('category-slug');
  const description = String(arg('description') ?? 'Produk APK MOD NO ROOT. Detail fitur dan akses menyesuaikan paket yang dipilih.').trim();

  const price = parseMoney(priceRaw);
  const days = Number(String(daysRaw).replace(/[^\d]/g, ''));

  if (!Number.isFinite(price) || price < 1) {
    throw new Error('Harga wajib diisi dan harus >= Rp1. Contoh: --price=50000');
  }
  if (!Number.isInteger(days) || days < 1) {
    throw new Error('Durasi wajib angka >= 1. Contoh: --days=30');
  }

  await db.initializeDB();
  const products = await db.readFresh('products.json');
  const settings = await db.readFresh('settings.json');

  const safeProducts = Array.isArray(products) ? products : [];
  const safeSettings = settings && typeof settings === 'object' ? settings : {};
  const categories = Array.isArray(safeSettings.categories) ? [...safeSettings.categories] : [];
  const categoryLabels = safeSettings.categoryLabels && typeof safeSettings.categoryLabels === 'object'
    ? { ...safeSettings.categoryLabels }
    : {};

  const existingCategorySlug = Object.keys(categoryLabels).find(
    slug => normalizeName(categoryLabels[slug]) === normalizeName(CATEGORY_LABEL)
  );
  const categorySlug = String(
    categorySlugArg || existingCategorySlug || normalizeName(CATEGORY_LABEL).replace(/\s+/g, '-')
  );

  if (!categories.includes(categorySlug)) categories.push(categorySlug);
  categoryLabels[categorySlug] = CATEGORY_LABEL;

  const existingByName = new Map();
  for (const product of safeProducts) {
    const key = normalizeName(product?.name);
    if (key && !existingByName.has(key)) existingByName.set(key, product);
  }
  const added = [];
  const updated = [];
  const skipped = [];

  for (const name of CLIENT_PRODUCTS) {
    const key = normalizeName(name);
    const existingProduct = existingByName.get(key);

    if (existingProduct) {
      const currentCategories = Array.isArray(existingProduct.categories)
        ? [...existingProduct.categories]
        : (existingProduct.category ? [existingProduct.category] : []);
      const normalizedCategories = [];
      let targetFound = false;

      for (const category of currentCategories) {
        const text = normalizeName(category);
        const label = normalizeName(categoryLabels[category]);
        const isTarget = text === normalizeName(categorySlug)
          || label === normalizeName(CATEGORY_LABEL)
          || text.replace(/[^a-z0-9]+/g, '') === 'apkmodnoroot';
        if (isTarget) {
          targetFound = true;
          if (!normalizedCategories.includes(categorySlug)) normalizedCategories.push(categorySlug);
        } else if (!normalizedCategories.includes(category)) {
          normalizedCategories.push(category);
        }
      }
      if (!targetFound) normalizedCategories.push(categorySlug);

      const changed = JSON.stringify(currentCategories) !== JSON.stringify(normalizedCategories)
        || Object.prototype.hasOwnProperty.call(existingProduct, 'category');
      if (changed) {
        existingProduct.categories = normalizedCategories;
        if (Object.prototype.hasOwnProperty.call(existingProduct, 'category')) delete existingProduct.category;
        updated.push({ name, reason: targetFound ? 'kategori dinormalisasi' : 'kategori ditambahkan' });
      } else {
        skipped.push({ name, reason: 'sudah benar di kategori' });
      }
      continue;
    }

    const product = makeProduct({
      name,
      category: categorySlug,
      days,
      unit,
      price,
      description
    });

    safeProducts.push(product);
    existingByName.set(key, product);
    added.push(product);
  }

  console.log(`Kategori: ${CATEGORY_LABEL} (${categorySlug})`);
  console.log(`Paket default: ${days} ${unit === 'h' ? 'jam' : 'hari'} | Rp${price.toLocaleString('id-ID')}`);
  console.log(`Akan ditambah: ${added.length}`);
  console.log(`Kategori existing diperbaiki: ${updated.length}`);
  console.log(`Sudah benar di kategori: ${skipped.length}`);

  if (updated.length) {
    updated.forEach(p => console.log(`  ~ ${p.name} (${p.reason})`));
  }
  if (added.length) {
    added.forEach(p => console.log(`  + ${p.name}`));
  }
  if (skipped.length) {
    skipped.forEach(p => console.log(`  = ${p.name} (${p.reason})`));
  }

  if (dryRun) {
    console.log('\nDRY RUN: tidak ada data yang ditulis.');
    return;
  }

  // Satu write untuk products dan satu write untuk settings.
  // Tidak ada endpoint DripStore yang disentuh di script ini.
  await db.writeDB('products.json', safeProducts);
  safeSettings.categories = categories;
  safeSettings.categoryLabels = categoryLabels;
  await db.writeDB('settings.json', safeSettings);

  console.log(`\nSELESAI: ${added.length} produk ditambahkan.`);
  console.log('Produk dibuat aktif, kategori sudah tersedia, stok lokal kosong, mapping DripStore belum diisi.');
  console.log('Setelah itu lakukan mapping variant dari Admin Panel.');
}

main().catch(err => {
  console.error('\nGAGAL:', err?.message || err);
  process.exitCode = 1;
});
