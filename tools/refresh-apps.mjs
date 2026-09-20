#!/usr/bin/env node
/**
 * يحدّث داخل apps.json: حجم الملف (sizeBytes) وتاريخ آخر تعديل (updated) وبصمة SHA-256 (sha256).
 * الاستخدام:   node tools/refresh-apps.mjs [مسار apps.json]
 * يحتاج Node 18 فأحدث. لا يثبّت أي حزمة، ولا يقرأ إلا الروابط المكتوبة في apps.json (https + github.com فقط).
 */
import fs from 'node:fs';
import crypto from 'node:crypto';

const FILE = process.argv[2] || 'apps.json';
const ALLOWED_HOSTS = ['github.com']; // اجعلها مطابقة لـ UPSTREAM_HOSTS في الـ Worker
const MAX_BYTES = 300 * 1024 * 1024;
const today = new Date().toISOString().slice(0, 10);

const data = JSON.parse(fs.readFileSync(FILE, 'utf8'));
let changedAny = false;

for (const app of data.apps || []) {
  try {
    const u = new URL(app.downloadUrl);
    if (u.protocol !== 'https:' || !ALLOWED_HOSTS.some((h) => u.hostname === h || u.hostname.endsWith('.' + h))) {
      console.log(`- ${app.id}: مضيف غير مسموح، تخطّي`);
      continue;
    }
    const res = await fetch(u, { redirect: 'follow', headers: { 'User-Agent': 'ossama-store-refresh' }, signal: AbortSignal.timeout(240000) });
    if (!res.ok || !res.body) throw new Error('HTTP ' + res.status);

    const hash = crypto.createHash('sha256');
    let size = 0;
    for await (const chunk of res.body) {
      size += chunk.length;
      if (size > MAX_BYTES) throw new Error('الملف أكبر من الحد المسموح');
      hash.update(chunk);
    }
    const sha256 = hash.digest('hex');
    const lm = res.headers.get('last-modified');
    const updated = lm && !isNaN(Date.parse(lm)) ? new Date(lm).toISOString().slice(0, 10) : app.updated;

    const changed = app.sha256 !== sha256 || app.sizeBytes !== size || (updated && app.updated !== updated);
    if (changed) {
      app.sizeBytes = size; app.sha256 = sha256; app.checked = today;
      if (updated) app.updated = updated;
      changedAny = true;
      console.log(`✓ ${app.id}: ${size} بايت | ${sha256.slice(0, 16)}… | ${updated || '—'}  (تغيّر)`);
    } else {
      console.log(`= ${app.id}: لا تغيير`);
    }
  } catch (e) {
    console.error(`✗ ${app.id}: ${e.message}`);
    process.exitCode = 1; // نُكمل بقية التطبيقات لكن نُعلن الفشل في النهاية
  }
}

if (changedAny) fs.writeFileSync(FILE, JSON.stringify(data, null, 2) + '\n');
console.log(changedAny ? 'تم تحديث ' + FILE : 'لا شيء لتحديثه');
