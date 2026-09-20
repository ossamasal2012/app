/**
 * ═══════════════════════════════════════════════════════════════════════
 *  OSSAMA STORE — واجهة عدّاد التحميلات الذكي
 *  Cloudflare Worker + قاعدة D1  (الخطة المجانية تكفي للاستخدام الصغير)
 * ═══════════════════════════════════════════════════════════════════════
 *  طبقات الحماية من التكرار (كل طبقة تلتقط حالة مختلفة):
 *   1) تذكرة تحميل موقّعة وقصيرة العمر — لا يمكن احتساب شيء بدونها.
 *   2) معرّف جهاز عشوائي موقّع (Token) يحفظه المتصفح في أكثر من مكان.
 *   3) قيد فريد في القاعدة (تطبيق + جهاز) — تحميل واحد مدى الحياة مهما تكرر.
 *   4) لا يُحتسب التحميل إلا بعد وصول ملف الـ APK كاملاً (بثّ عبر الخادم).
 *   5) التعرّف على الجهاز بعد مسح بيانات المتصفح: بصمة تقنية + الشبكة نفسها.
 *   6) حدود معدّل + التحقق من Origin + توقيع HMAC ضد التلاعب.
 *
 *  المتغيرات المطلوبة (Settings ← Variables and Secrets):
 *    DB        ربط قاعدة D1 (Binding)  — الاسم DB بالضبط
 *    SECRET    (Secret) نص عشوائي طويل لا تشاركه مع أحد (32 حرفاً فأكثر)
 *    SITE_URL  (Text)   رابط موقعك كاملاً ويوجد فيه apps.json، ويُفضّل أن ينتهي بـ /
 *  اختيارية:
 *    ADMIN_KEY, ALLOWED_ORIGINS, UPSTREAM_HOSTS, DOWNLOAD_MODE  (انظر README)
 */

// ───────────────────────── الثوابت ─────────────────────────
const TICKET_TTL = 15 * 60;              // صلاحية رابط التحميل (ثانية)
const LINK_TTL = 90 * 86400;             // مدة صلاحية "بصمة + شبكة" للتعرّف بعد مسح البيانات
const IDLE_DEVICE_TTL = 30 * 86400;      // حذف الأجهزة التي لم تُكمل أي تحميل
const CATALOG_TTL_MS = 5 * 60 * 1000;    // كم نحتفظ بنسخة apps.json في الذاكرة

// [الحد الأقصى، النافذة بالثواني]
const LIMITS = {
  ticketPerNet: [120, 600],
  ticketPerDevice: [12, 3600],
  newDevicePerNet: [60, 3600],
  downloadPerNet: [150, 3600],
  downloadPerDevice: [12, 3600],
  forgetPerNet: [20, 3600],
};

const HEX32 = /^[0-9a-f]{32}$/;
const APP_ID_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;
const enc = new TextEncoder();
const dec = new TextDecoder();

class HttpError extends Error {
  constructor(status, code) { super(code); this.status = status; this.code = code; }
}

// ───────────────────────── نقطة الدخول ─────────────────────────
export default {
  async fetch(request, env, ctx) {
    const cors = corsHeaders(request, env);
    try {
      return await route(request, env, ctx, cors);
    } catch (e) {
      if (e instanceof HttpError) {
        return json({ ok: false, error: e.code }, e.status, cors);
      }
      console.error('worker_error', (e && e.stack) || e);
      return json({ ok: false, error: 'server_error' }, 500, cors);
    }
  },

  // تنظيف يومي اختياري (Cron Trigger)
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(cleanup(env));
  },
};

async function route(request, env, ctx, cors) {
  const { pathname } = new URL(request.url);
  const method = request.method;

  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

  if (pathname.startsWith('/dl/')) {
    if (method !== 'GET' && method !== 'HEAD') throw new HttpError(405, 'method_not_allowed');
    return handleDownload(request, env, ctx, pathname.slice(4));
  }

  if (method === 'GET') {
    if (pathname === '/') return plain('OSSAMA STORE API ✓', 200);
    if (pathname === '/api/stats') return handleStats(env, cors);
    if (pathname === '/api/health') return handleHealth(env, cors);
    if (pathname === '/api/admin/report') return handleAdminReport(request, env);
  }

  if (method === 'POST') {
    if (pathname === '/api/admin/reconcile') return handleAdminReconcile(request, env);
    requireOrigin(request, env); // كل نقاط POST الأخرى لا تعمل إلا من موقعك فقط
    if (pathname === '/api/identify') return handleIdentify(request, env, cors);
    if (pathname === '/api/ticket') return handleTicket(request, env, ctx, cors);
    if (pathname === '/api/forget') return handleForget(request, env, cors);
  }

  throw new HttpError(404, 'not_found');
}

// ───────────────────────── نقاط الواجهة ─────────────────────────

// الأعداد العامة (قراءة فقط)
async function handleStats(env, cors) {
  const rows = await db(env).prepare('SELECT app_id, total FROM app_counts').all();
  const counts = {};
  let total = 0;
  for (const r of rows.results) { counts[r.app_id] = r.total; total += r.total; }
  return json({ ok: true, counts, total, ts: nowSec() }, 200, { ...cors, 'Cache-Control': 'public, max-age=10' });
}

// فحص ذاتي يساعدك على التأكد أن الإعداد صحيح
async function handleHealth(env, cors) {
  const out = { ok: true, db: false, secret: !!(env.SECRET && env.SECRET.length >= 16), site: false, apps: 0 };
  try { await db(env).prepare('SELECT 1').first(); out.db = true; } catch { /* يبقى false */ }
  try { out.apps = (await getCatalog(env)).size; out.site = true; } catch { /* يبقى false */ }
  out.ok = out.db && out.secret && out.site;
  return json(out, out.ok ? 200 : 503, cors);
}

// "هل أعرف هذا الجهاز؟" — قراءة فقط ولا تُنشئ أي سجل
async function handleIdentify(request, env, cors) {
  const body = await readJson(request);
  const net = netKey(request);
  const r = await resolveDevice(env, body, net);
  let seen = [];
  if (r.id) {
    const rows = await db(env).prepare('SELECT app_id FROM downloads WHERE device_id = ?1').bind(r.id).all();
    seen = rows.results.map((x) => x.app_id);
  }
  return json({ ok: true, known: !!r.id, t: r.id ? await makeToken(env, r.id) : undefined, seen }, 200, cors);
}

// طلب تذكرة تحميل: هنا يُنشأ الجهاز (إن لزم) وتُطبَّق حدود المعدّل
async function handleTicket(request, env, ctx, cors) {
  const body = await readJson(request);
  const app = (await getCatalog(env)).get(str(body.a, 40));
  if (!app) throw new HttpError(404, 'unknown_app');

  const net = netKey(request);
  const netId = await mac(env, 'net', net, 12);
  await enforce(env, 'tk', netId, LIMITS.ticketPerNet);

  const r = await resolveDevice(env, body, net);
  let deviceId = r.id;
  let counted = true;

  if (deviceId) {
    await enforce(env, 'tkd', deviceId, LIMITS.ticketPerDevice);
  } else if (await hit(env, 'nd', netId, ...LIMITS.newDevicePerNet)) {
    deviceId = r.tokId || randomHex(16); // نُعيد استخدام معرّف التوكن إن كان الجهاز قد حُذف تنظيفاً
  } else {
    counted = false; // تجاوز حد الأجهزة الجديدة من هذه الشبكة: يُقدَّم الملف دون احتساب
    console.warn('new_device_limit_reached');
  }

  let seen = false;
  if (deviceId) {
    const now = nowSec();
    const stmts = [
      db(env).prepare('INSERT INTO devices(id, created_at, last_seen) VALUES (?1, ?2, ?2) ON CONFLICT(id) DO UPDATE SET last_seen = excluded.last_seen').bind(deviceId, now),
    ];
    if (r.fnKey) stmts.push(linkUpsert(env, r.fnKey, deviceId, now));
    stmts.push(db(env).prepare('SELECT 1 AS x FROM downloads WHERE app_id = ?1 AND device_id = ?2').bind(app.id, deviceId));
    const res = await db(env).batch(stmts);
    seen = res[res.length - 1].results.length > 0;
  }

  if (Math.random() < 0.02) ctx.waitUntil(cleanup(env).catch(() => {})); // تنظيف انتهازي خفيف

  const ticket = await signTicket(env, { d: deviceId || '', a: app.id, e: nowSec() + TICKET_TTL });
  return json({
    ok: true,
    u: `${new URL(request.url).origin}/dl/${ticket}`,
    t: deviceId ? await makeToken(env, deviceId) : undefined,
    seen,
    counted,
  }, 200, cors);
}

// حق الحذف: يمسح كل ما يخص الجهاز ويُنقص العدّادات تبعاً لذلك
async function handleForget(request, env, cors) {
  const body = await readJson(request);
  const netId = await mac(env, 'net', netKey(request), 12);
  await enforce(env, 'fg', netId, LIMITS.forgetPerNet);
  const id = await verifyToken(env, body.t);
  if (id) {
    await db(env).batch([
      db(env).prepare('UPDATE app_counts SET total = MAX(total - (SELECT COUNT(*) FROM downloads WHERE downloads.device_id = ?1 AND downloads.app_id = app_counts.app_id), 0)').bind(id),
      db(env).prepare('DELETE FROM downloads WHERE device_id = ?1').bind(id),
      db(env).prepare('DELETE FROM links WHERE device_id = ?1').bind(id),
      db(env).prepare('DELETE FROM devices WHERE id = ?1').bind(id),
    ]);
  }
  return json({ ok: true }, 200, cors);
}

// ───────────────────────── التحميل (قلب النظام) ─────────────────────────
async function handleDownload(request, env, ctx, ticketStr) {
  const t = await verifyTicket(env, ticketStr);
  if (!t) return plain('انتهت صلاحية رابط التحميل. ارجع إلى صفحة المتجر واضغط تحميل من جديد.', 410);

  const app = (await getCatalog(env)).get(t.a);
  if (!app) return plain('هذا التطبيق غير موجود.', 404);

  if (request.method === 'HEAD') return new Response(null, { status: 200, headers: fileHeaders(app) });

  const netId = await mac(env, 'net', netKey(request), 12);
  const okNet = await hit(env, 'dln', netId, ...LIMITS.downloadPerNet);
  const okDev = t.d ? await hit(env, 'dld', t.d, ...LIMITS.downloadPerDevice) : true;
  if (!okNet || !okDev) return plain('محاولات تحميل كثيرة. حاول مرة أخرى بعد قليل.', 429);

  // وضع redirect: يُحتسب عند بدء التحميل بعد التحقق من التذكرة (أقل دقة من proxy)
  if (env.DOWNLOAD_MODE === 'redirect') {
    if (t.d) ctx.waitUntil(recordDownload(env, t.a, t.d).catch((e) => console.error('record_failed', e)));
    return new Response(null, { status: 302, headers: { Location: app.url, 'Cache-Control': 'no-store' } });
  }

  const upstream = await fetch(app.url, { redirect: 'follow' });
  if (!upstream.ok || !upstream.body) return plain('تعذّر جلب الملف من المصدر. حاول لاحقاً.', 502);

  const len = Number(upstream.headers.get('content-length'));
  const encoded = upstream.headers.get('content-encoding');
  const known = Number.isFinite(len) && len > 0 && !encoded;
  const { readable, writable } = known ? new FixedLengthStream(len) : new TransformStream();

  // pipeTo ينجح فقط إذا مرّت كل البايتات ولم يقطع الجهاز الاتصال في المنتصف
  const finished = upstream.body.pipeTo(writable).then(() => true, () => false);
  ctx.waitUntil(finished.then((complete) => {
    if (complete && t.d) return recordDownload(env, t.a, t.d).catch((e) => console.error('record_failed', e));
  }));

  return new Response(readable, { status: 200, headers: fileHeaders(app) });
}

// يُحتسب التحميل مرة واحدة فقط لكل (تطبيق + جهاز). الأمران يُنفَّذان معاً في معاملة واحدة.
async function recordDownload(env, appId, deviceId) {
  const now = nowSec();
  await db(env).batch([
    db(env).prepare('INSERT OR IGNORE INTO downloads(app_id, device_id, created_at) VALUES (?1, ?2, ?3)').bind(appId, deviceId, now),
    // changes() = عدد الصفوف التي أضافها الأمر السابق مباشرة (1 إذا كان تحميلاً جديداً، 0 إذا كان مكرراً)
    db(env).prepare('INSERT INTO app_counts(app_id, total) SELECT ?1, 1 WHERE changes() > 0 ON CONFLICT(app_id) DO UPDATE SET total = total + 1').bind(appId),
    db(env).prepare('UPDATE devices SET last_seen = ?2 WHERE id = ?1').bind(deviceId, now),
  ]);
}

function fileHeaders(app) {
  return {
    'Content-Type': 'application/vnd.android.package-archive',
    'Content-Disposition': `attachment; filename="${app.file}"`,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  };
}

// ───────────────────────── التعرّف على الجهاز ─────────────────────────
/**
 * الأولوية:
 *  1) توكن صحيح التوقيع لجهاز موجود  → تطابق قاطع.
 *  2) بصمة تقنية + نفس الشبكة خلال 90 يوماً → استعادة الجهاز بعد مسح البيانات.
 *  غير ذلك → جهاز جديد (لا ندمج أجهزة مختلفة بالتخمين حتى لا ننقص العدّاد ظلماً).
 */
async function resolveDevice(env, body, net) {
  const now = nowSec();
  const tokId = await verifyToken(env, body.t);
  let id = null;

  if (tokId) {
    const row = await db(env).prepare('SELECT id FROM devices WHERE id = ?1').bind(tokId).first();
    if (row) id = tokId;
  }

  let fnKey = null;
  if (typeof body.f === 'string' && HEX32.test(body.f) && body.q === 1) {
    fnKey = 'fn:' + (await mac(env, 'fn', body.f + '|' + net, 16));
    if (!id) {
      const row = await db(env)
        .prepare('SELECT device_id FROM links WHERE k = ?1 AND last_seen > ?2')
        .bind(fnKey, now - LINK_TTL)
        .first();
      if (row) id = row.device_id;
    }
  }
  return { id, tokId, fnKey };
}

// تحديث الرابط إن كان لنفس الجهاز، أو الاستيلاء عليه إن كان قديماً منتهياً
function linkUpsert(env, key, deviceId, now) {
  return db(env)
    .prepare(
      `INSERT INTO links(k, device_id, last_seen) VALUES (?1, ?2, ?3)
       ON CONFLICT(k) DO UPDATE SET device_id = excluded.device_id, last_seen = excluded.last_seen
       WHERE links.device_id = excluded.device_id OR links.last_seen < ?4`
    )
    .bind(key, deviceId, now, now - LINK_TTL);
}

// ───────────────────────── التوقيع والتوكن ─────────────────────────
let hmacKeyPromise = null;
function hmacKey(env) {
  if (!env.SECRET || env.SECRET.length < 16) throw new HttpError(500, 'not_configured');
  hmacKeyPromise ||= crypto.subtle.importKey('raw', enc.encode(env.SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hmacKeyPromise;
}

async function mac(env, purpose, data, bytes = 16) {
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(purpose + '\n' + data));
  return b64url(new Uint8Array(sig).subarray(0, bytes));
}

async function makeToken(env, deviceId) {
  return deviceId + '.' + (await mac(env, 'tok', deviceId, 16));
}

async function verifyToken(env, token) {
  if (typeof token !== 'string' || token.length > 80) return null;
  const parts = token.split('.');
  if (parts.length !== 2 || !HEX32.test(parts[0])) return null;
  const [id, sig] = parts;
  return safeEq(sig, await mac(env, 'tok', id, 16)) ? id : null;
}

async function signTicket(env, payload) {
  const p = b64url(enc.encode(JSON.stringify(payload)));
  return p + '.' + (await mac(env, 'tk', p, 16));
}

async function verifyTicket(env, ticket) {
  if (typeof ticket !== 'string' || ticket.length > 400) return null;
  const parts = ticket.split('.');
  if (parts.length !== 2) return null;
  const [p, sig] = parts;
  if (!p || !sig || !safeEq(sig, await mac(env, 'tk', p, 16))) return null;
  try {
    const d = JSON.parse(dec.decode(fromB64url(p)));
    if (typeof d.a !== 'string' || typeof d.e !== 'number' || d.e < nowSec()) return null;
    if (d.d && !HEX32.test(d.d)) return null;
    return d;
  } catch { return null; }
}

// ───────────────────────── حدود المعدّل ─────────────────────────
async function hit(env, scope, id, max, windowSec) {
  const now = nowSec();
  const win = Math.floor(now / windowSec);
  const row = await db(env)
    .prepare(
      `INSERT INTO rl(k, win, n, exp) VALUES (?1, ?2, 1, ?3)
       ON CONFLICT(k) DO UPDATE SET
         n = CASE WHEN rl.win = excluded.win THEN rl.n + 1 ELSE 1 END,
         win = excluded.win, exp = excluded.exp
       RETURNING n`
    )
    .bind(scope + ':' + id, win, (win + 1) * windowSec)
    .first();
  return (row ? row.n : 1) <= max;
}

async function enforce(env, scope, id, [max, windowSec]) {
  if (!(await hit(env, scope, id, max, windowSec))) throw new HttpError(429, 'rate_limited');
}

// ───────────────────────── الكتالوج (apps.json من موقعك) ─────────────────────────
let catalogCache = { at: 0, map: null };

async function getCatalog(env) {
  if (catalogCache.map && Date.now() - catalogCache.at < CATALOG_TTL_MS) return catalogCache.map;
  if (!env.SITE_URL) throw new HttpError(500, 'not_configured');
  try {
    const base = new URL(env.SITE_URL);
    if (!base.pathname.endsWith('/') && !/\.[a-z0-9]+$/i.test(base.pathname)) base.pathname += '/';
    const res = await fetch(new URL('apps.json', base).href, {
      headers: { accept: 'application/json' },
      cf: { cacheTtl: 60, cacheEverything: true },
    });
    if (!res.ok) throw new Error('catalog_http_' + res.status);
    const data = await res.json();
    const map = new Map();
    for (const a of Array.isArray(data.apps) ? data.apps : []) {
      if (!a || !APP_ID_RE.test(a.id) || !upstreamAllowed(a.downloadUrl, env)) continue;
      const file = String(a.apkName || a.id + '.apk').replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80);
      map.set(a.id, { id: a.id, url: a.downloadUrl, file: /\.apk$/i.test(file) ? file : file + '.apk' });
    }
    catalogCache = { at: Date.now(), map };
    return map;
  } catch (e) {
    if (catalogCache.map) return catalogCache.map; // نُكمل بالنسخة القديمة إن تعذّر الجلب
    console.error('catalog_error', e && e.message);
    throw new HttpError(503, 'catalog_unavailable');
  }
}

// حماية من SSRF: لا نجلب إلا من مضيفين تحددهم أنت (github.com افتراضياً) وعبر https
function upstreamAllowed(raw, env) {
  let u;
  try { u = new URL(raw); } catch { return false; }
  const devHost = env.DEV === '1' && (u.hostname === '127.0.0.1' || u.hostname === 'localhost');
  if (u.protocol !== 'https:' && !devHost) return false;
  const hosts = String(env.UPSTREAM_HOSTS || 'github.com').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  return hosts.some((h) => u.hostname === h || u.hostname.endsWith('.' + h));
}

// ───────────────────────── الإدارة (اختيارية) ─────────────────────────
function requireAdmin(request, env) {
  if (!env.ADMIN_KEY) throw new HttpError(404, 'not_found');
  if (!safeEq(request.headers.get('Authorization') || '', 'Bearer ' + env.ADMIN_KEY)) throw new HttpError(401, 'unauthorized');
}

async function handleAdminReport(request, env) {
  requireAdmin(request, env);
  const since = nowSec() - 30 * 86400;
  const [apps, devices, downloaders, daily] = await db(env).batch([
    db(env).prepare('SELECT app_id, total FROM app_counts ORDER BY total DESC'),
    db(env).prepare('SELECT COUNT(*) AS n FROM devices'),
    db(env).prepare('SELECT COUNT(DISTINCT device_id) AS n FROM downloads'),
    db(env).prepare("SELECT date(created_at, 'unixepoch') AS day, app_id, COUNT(*) AS n FROM downloads WHERE created_at >= ?1 GROUP BY day, app_id ORDER BY day DESC").bind(since),
  ]);
  return json({ ok: true, apps: apps.results, devices: devices.results[0].n, downloaders: downloaders.results[0].n, last30days: daily.results }, 200, {});
}

// يعيد بناء العدّادات من جدول التحميلات (علاج ذاتي إن حدث أي انحراف)
async function handleAdminReconcile(request, env) {
  requireAdmin(request, env);
  await db(env).batch([
    db(env).prepare('DELETE FROM app_counts'),
    db(env).prepare('INSERT INTO app_counts(app_id, total) SELECT app_id, COUNT(*) FROM downloads GROUP BY app_id'),
  ]);
  return json({ ok: true }, 200, {});
}

async function cleanup(env) {
  const now = nowSec();
  await db(env).batch([
    db(env).prepare('DELETE FROM links WHERE last_seen < ?1').bind(now - LINK_TTL),
    db(env).prepare('DELETE FROM rl WHERE exp < ?1').bind(now),
    db(env).prepare('DELETE FROM devices WHERE last_seen < ?1 AND id NOT IN (SELECT device_id FROM downloads)').bind(now - IDLE_DEVICE_TTL),
    db(env).prepare('DELETE FROM links WHERE device_id NOT IN (SELECT id FROM devices)'),
  ]);
}

// ───────────────────────── أدوات مساعدة ─────────────────────────
function db(env) {
  if (!env.DB) throw new HttpError(500, 'not_configured');
  return env.DB;
}

function nowSec() { return Math.floor(Date.now() / 1000); }

function str(v, max) { return typeof v === 'string' ? v.slice(0, max) : ''; }

async function readJson(request) {
  const text = await request.text();
  if (text.length > 2048) throw new HttpError(413, 'too_large');
  try {
    const v = JSON.parse(text || '{}');
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw 0;
    return v;
  } catch { throw new HttpError(400, 'bad_request'); }
}

// الشبكة: عنوان IPv4 كاملاً، أو أول 64 بت من IPv6. لا يُخزَّن أبداً كما هو — يُمرَّر عبر HMAC فقط.
function netKey(request) {
  let ip = (request.headers.get('CF-Connecting-IP') || '').trim() || '0.0.0.0';
  if (/^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(ip)) ip = ip.slice(7);
  if (!ip.includes(':')) return ip;
  const [head, tail = ''] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const parts = ip.includes('::') ? [...h, ...Array(Math.max(8 - h.length - t.length, 0)).fill('0'), ...t] : h;
  return 'v6:' + parts.slice(0, 4).map((x) => x.padStart(4, '0')).join(':');
}

function allowedOrigins(env) {
  const set = new Set();
  try { set.add(new URL(env.SITE_URL).origin); } catch { /* تجاهل */ }
  for (const o of String(env.ALLOWED_ORIGINS || '').split(',')) if (o.trim()) set.add(o.trim().replace(/\/$/, ''));
  return set;
}

function corsHeaders(request, env) {
  const h = { Vary: 'Origin' };
  const origin = request.headers.get('Origin');
  if (origin && allowedOrigins(env).has(origin)) {
    h['Access-Control-Allow-Origin'] = origin;
    h['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
    h['Access-Control-Allow-Headers'] = 'Content-Type';
    h['Access-Control-Max-Age'] = '86400';
  }
  return h;
}

function requireOrigin(request, env) {
  const o = request.headers.get('Origin');
  if (!o || !allowedOrigins(env).has(o)) throw new HttpError(403, 'forbidden');
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      ...extra,
    },
  });
}

function plain(text, status) {
  return new Response(text, {
    status,
    headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
  });
}

function randomHex(bytes) {
  const a = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(a, (b) => b.toString(16).padStart(2, '0')).join('');
}

function safeEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function b64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64url(s) {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}
