/* ══════════════════════════════════════════════════════════════
   متجر تطبيقات OSSAMA SALAM HADI — الواجهة
   بدون أي مكتبة خارجية. كل النصوص تُدرج عبر textContent (لا innerHTML) لمنع XSS.
   ══════════════════════════════════════════════════════════════ */

// ───────────────────────── 0) ثوابت وحالة ─────────────────────────
const PAGE_SIZE = 9;
const COOLDOWN_MS = 7000; // بعد الضغط على تحميل: تُتجاهل النقرات المتكررة خلال هذه المدة
const STATS_EVERY_MS = 45000;
const WATCH_EVERY_MS = 8000;
const WATCH_MAX_MS = 6 * 60 * 1000;
const K = { theme: 'os_theme', did: 'os_did', seen: 'os_seen' };
const TOKEN_RE = /^[0-9a-f]{32}\.[A-Za-z0-9_-]{22}$/;
const ID_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;
const HEX64_RE = /^[a-f0-9]{64}$/i;
const SVG_NS = 'http://www.w3.org/2000/svg';
const REDUCED = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
const MOBILE = window.matchMedia ? matchMedia('(max-width: 640px)') : { matches: false };

const state = {
  apps: [],
  byId: new Map(),
  q: '',
  sort: '', // فارغ = بترتيب apps.json كما وضعه المطوّر
  limit: PAGE_SIZE,
  counts: {}, // appId → عدد
  countsKnown: false,
  seen: new Set(), // التطبيقات التي حمّلها هذا الجهاز (حسب الخادم/الذاكرة المحلية)
  dl: new Map(), // appId → { ts }
  watching: new Set(),
  statsAt: 0,
  opener: null,
};

// ───────────────────────── 1) أدوات عامة ─────────────────────────
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); return true; } catch { return false; } },
  del(k) { try { localStorage.removeItem(k); } catch { /* تجاهل */ } },
};

/** بناء عنصر DOM بأمان (النصوص عبر textContent دائماً) */
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function icon(name, cls = '') {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('class', ('i ' + cls).trim());
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(SVG_NS, 'use');
  use.setAttribute('href', '#i-' + name);
  svg.append(use);
  return svg;
}

const fmtInt = (n) => Number(n || 0).toLocaleString('en-US');

function fmtBytes(n) {
  if (!Number.isFinite(n) || n <= 0) return '';
  if (n >= 1e9) return (n / 1e9).toFixed(1) + ' GB';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + ' MB';
  return Math.max(1, Math.round(n / 1e3)) + ' KB';
}

function fmtDate(s) {
  const d = new Date(s);
  if (!s || isNaN(d)) return '';
  try { return new Intl.DateTimeFormat('ar-IQ-u-nu-latn', { day: 'numeric', month: 'long', year: 'numeric' }).format(d); }
  catch { return d.toISOString().slice(0, 10); }
}

/** توحيد النص العربي للبحث: تشكيل/همزات/ياء/تاء مربوطة/حروف فارسية-كردية */
function norm(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/[\u064B-\u065F\u0670\u0640]/g, '')
    .replace(/[أإآٱ]/g, 'ا').replace(/[ىیي]/g, 'ي').replace(/[ةه]/g, 'ه').replace(/ؤ/g, 'و').replace(/ئ/g, 'ي')
    .replace(/[گکك]/g, 'ك').replace(/چ/g, 'ج').replace(/پ/g, 'ب').replace(/ڤ/g, 'ف').replace(/ژ/g, 'ز')
    .replace(/[٠-٩]/g, (d) => String(d.charCodeAt(0) - 0x0660))
    .replace(/\s+/g, ' ').trim();
}

// المعرّف يُوحَّد تلقائياً إلى أحرف إنجليزية صغيرة وأرقام وشرطة (Weather → weather) كي لا يُهمَل التطبيق بسبب حرف كبير
const normId = (v) => String(v == null ? '' : v).trim().toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
const clean = (v, max) => (typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max) : '');

function safeUrl(v, { allowRelative = false, allowLocalHttp = false } = {}) {
  if (typeof v !== 'string' || !v.trim()) return '';
  try {
    const u = new URL(v.trim(), location.href);
    if (u.protocol === 'https:') return u.href;
    // http مسموح فقط لعنوان الحاسوب المحلي أثناء التطوير (ولا تقبله سياسة CSP الجاهزة أصلاً)
    if (allowLocalHttp && u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1')) return u.href;
    if (allowRelative && u.origin === location.origin && !/^[a-z][a-z0-9+.-]*:/i.test(v.trim())) return u.href;
  } catch { /* تجاهل */ }
  return '';
}

const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function toast(kind, msg, ms = 4600) {
  const box = $('#toasts');
  const map = { ok: 'ok', warn: 'warn', err: 'alert', info: 'info' };
  const el = h('div', { class: 'toast toast--' + kind }, icon(map[kind] || 'info'), h('span', { text: msg }));
  box.append(el);
  while (box.children.length > 3) box.firstElementChild.remove();
  setTimeout(() => { el.classList.add('is-out'); setTimeout(() => el.remove(), 300); }, ms);
}

function placeholder(app) {
  const ch = [...(app.name || '؟')][0] || '؟';
  const esc = ch.replace(/[&<>"']/g, '');
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 96 96"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#22449e"/><stop offset="1" stop-color="#0d1a44"/></linearGradient></defs><rect width="96" height="96" fill="url(#g)"/><text x="48" y="66" font-family="sans-serif" font-size="54" font-weight="700" text-anchor="middle" fill="#f2b94b">${esc}</text></svg>`;
  return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch { /* تجاهل */ }
  try {
    const ta = h('textarea', { class: 'sr', 'aria-hidden': 'true', tabindex: '-1' });
    ta.value = text; document.body.append(ta); ta.select();
    const ok = document.execCommand('copy'); ta.remove(); return ok;
  } catch { return false; }
}

// ───────────────────────── 2) المظهر ─────────────────────────
function applyTheme(t, persist) {
  document.documentElement.setAttribute('data-theme', t);
  if (persist) store.set(K.theme, t);
  const meta = $('meta[name="theme-color"]');
  if (meta) meta.content = t === 'dark' ? '#081230' : '#eef2fb';
  const use = $('#theme-use');
  if (use) use.setAttribute('href', t === 'dark' ? '#i-sun' : '#i-moon'); // الأيقونة = المظهر الذي ستنتقل إليه
  const btn = $('#btn-theme');
  if (btn) btn.setAttribute('aria-label', t === 'dark' ? 'التبديل إلى المظهر الفاتح' : 'التبديل إلى المظهر الداكن');
}

// ───────────────────────── 3) الخصوصية وهوية الجهاز ─────────────────────────
// معرّف الجهاز الموقّع يُحفَظ في ثلاثة أماكن؛ إن مُسح أحدها يُرمَّم من الآخر
const cookie = {
  get(name) {
    const m = document.cookie.split('; ').find((c) => c.startsWith(name + '='));
    return m ? decodeURIComponent(m.slice(name.length + 1)) : null;
  },
  set(name, value, days) {
    document.cookie = `${name}=${encodeURIComponent(value)}; Max-Age=${days * 86400}; Path=/; SameSite=Lax${location.protocol === 'https:' ? '; Secure' : ''}`;
  },
};

const idb = {
  open() {
    return new Promise((res, rej) => {
      const r = indexedDB.open('os-store', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('kv');
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
  },
  async run(mode, fn) {
    const db = await this.open();
    return new Promise((res, rej) => {
      const tx = db.transaction('kv', mode);
      const req = fn(tx.objectStore('kv'));
      tx.oncomplete = () => { db.close(); res(req.result); };
      tx.onerror = tx.onabort = () => { db.close(); rej(tx.error); };
    });
  },
  get(k) { return this.run('readonly', (s) => s.get(k)); },
  set(k, v) { return this.run('readwrite', (s) => s.put(v, k)); },
};

const Identity = {
  async read() {
    let a = null, b = null, c = null;
    try { a = store.get(K.did); } catch { /* تجاهل */ }
    try { c = cookie.get(K.did); } catch { /* تجاهل */ }
    try { b = await idb.get(K.did); } catch { /* تجاهل */ }
    const tok = [a, b, c].find((t) => typeof t === 'string' && TOKEN_RE.test(t)) || null;
    if (tok && (a !== tok || b !== tok || c !== tok)) this.write(tok); // ترميم المخازن الناقصة
    return tok;
  },
  async write(tok) {
    if (!TOKEN_RE.test(tok || '')) return;
    store.set(K.did, tok);
    try { cookie.set(K.did, tok, 400); } catch { /* تجاهل */ }
    try { await idb.set(K.did, tok); } catch { /* تجاهل */ }
  },
};

/**
 * بصمة تقنية خفيفة تُشفَّر (SHA-256) داخل المتصفح قبل الإرسال — لا يستلم الخادم إلا الهاش.
 * لا Canvas ولا Audio ولا قائمة خطوط. وتُعدّ «مفيدة» (q=1) فقط إن توفّر طراز الجهاز (Chrome/Android)،
 * كي لا تُدمج أجهزة مكتبية متشابهة بالتخمين.
 */
let fpPromise = null;
function fingerprint() {
  fpPromise ||= (async () => {
    if (!(window.crypto && crypto.subtle)) return null;
    const n = navigator, s = screen;
    let model = '', pver = '', arch = '', platform = n.platform || '', brand = '';
    try {
      const u = n.userAgentData;
      if (u) {
        platform = u.platform || platform;
        brand = (u.brands || []).map((b) => b.brand).filter((b) => !/not.?a.?brand/i.test(b)).sort().join('/');
        const hi = await u.getHighEntropyValues(['model', 'platformVersion', 'architecture', 'bitness']);
        model = hi.model || ''; pver = String(hi.platformVersion || '').split('.')[0];
        arch = (hi.architecture || '') + (hi.bitness || '');
      }
    } catch { /* المتصفح لا يدعم أو رفض */ }
    let tz = '';
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch { /* تجاهل */ }
    const parts = [
      'm=' + model, 'pv=' + pver, 'ar=' + arch, 'pl=' + platform, 'br=' + brand,
      'sc=' + Math.min(s.width, s.height) + 'x' + Math.max(s.width, s.height),
      'dp=' + (Math.round((window.devicePixelRatio || 1) * 100) / 100),
      'cd=' + s.colorDepth, 'hc=' + (n.hardwareConcurrency || 0), 'dm=' + (n.deviceMemory || 0),
      'tp=' + (n.maxTouchPoints || 0), 'tz=' + tz, 'ln=' + ((n.languages && n.languages[0]) || n.language || ''),
    ];
    const hex = await sha256Hex(parts.join('|'));
    return { f: hex.slice(0, 32), q: model ? 1 : 0 };
  })().catch(() => null);
  return fpPromise;
}

async function identityPayload() {
  const body = {};
  const t = await Identity.read();
  if (t) body.t = t;
  const fp = await fingerprint();
  if (fp) { body.f = fp.f; body.q = fp.q; }
  return body;
}

// ───────────────────────── 4) عميل API ─────────────────────────
const Api = {
  base: '',
  get enabled() { return !!this.base; },
  async call(path, { method = 'GET', body, timeout = 9000 } = {}) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeout);
    try {
      const res = await fetch(this.base + path, {
        method, mode: 'cors', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', signal: ctl.signal,
        headers: body ? { 'Content-Type': 'application/json' } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { const e = new Error(data.error || 'http_' + res.status); e.status = res.status; e.code = data.error; throw e; }
      return data;
    } finally { clearTimeout(timer); }
  },
};

// ───────────────────────── 5) الكتالوج ─────────────────────────
function normalizeApp(a, order) {
  if (!a || typeof a !== 'object') return null;
  const id = normId(a.id);
  const name = clean(a.name, 60);
  const url = safeUrl(a.downloadUrl); // اختياري: الأفضل إخفاؤه (يوضع في متغيّر SOURCES داخل الـ Worker)
  if (!ID_RE.test(id) || !name) { console.warn('[المتجر] تطبيق مُهمَل: id يجب أن يحوي أحرفاً إنجليزية أو أرقاماً، و name مطلوب:', a && a.id); return null; }
  if (id !== String(a.id).trim()) console.info('[المتجر] تم توحيد المعرّف', JSON.stringify(a.id), '←', id);
  const list = (v, max, len) => (Array.isArray(v) ? v.map((x) => clean(x, len)).filter(Boolean).slice(0, max) : []);
  const sizeBytes = Number(a.sizeBytes) > 0 ? Number(a.sizeBytes) : 0;
  const cert = clean(a.certSha256, 100).replace(/[:\s]/g, '');
  const app = {
    id, name, url, order,
    tagline: clean(a.tagline, 140),
    description: clean(a.description, 1200),
    icon: safeUrl(a.icon, { allowRelative: true }),
    version: clean(a.version, 24),
    size: clean(a.size, 20) || fmtBytes(sizeBytes),
    updated: clean(a.updated, 32),
    minAndroid: clean(a.minAndroid, 12),
    sha256: HEX64_RE.test(clean(a.sha256, 80)) ? clean(a.sha256, 80).toLowerCase() : '',
    cert: HEX64_RE.test(cert) ? cert.toLowerCase() : '',
    checked: clean(a.checked, 32),
    changelog: list(a.changelog, 8, 160),
  };
  app.search = norm([app.name, app.tagline, app.description, app.id].join(' '));
  return app;
}

async function loadCatalog() {
  const res = await fetch('apps.json?v=' + Math.floor(Date.now() / 60000), { cache: 'no-cache', credentials: 'omit' });
  if (!res.ok) throw new Error('apps.json ' + res.status);
  const data = await res.json();
  const raw = Array.isArray(data) ? data : data.apps;
  if (!Array.isArray(raw)) throw new Error('apps.json: صيغة غير صحيحة');
  const apps = [], byId = new Map();
  raw.forEach((a, i) => {
    const app = normalizeApp(a, i);
    if (!app) return;
    if (byId.has(app.id)) { console.warn('[المتجر] معرّف مكرّر مُهمَل:', app.id, '— كل تطبيق يحتاج id فريداً وإلا اختلطت عدّاداتها.'); return; }
    byId.set(app.id, app); apps.push(app);
  });
  const api = safeUrl(data && data.api ? String(data.api) : '', { allowLocalHttp: true }).replace(/\/+$/, '');
  return { apps, byId, api };
}

// ───────────────────────── 6) العدّاد الدوّار ─────────────────────────
function odoRender(el, value, animate) {
  const text = fmtInt(value);
  const prev = el.dataset.text;
  if (prev === text) return;
  const sameShape = prev && prev.length === text.length && [...prev].every((c, i) => (c === ',') === (text[i] === ','));
  if (!sameShape) {
    el.textContent = '';
    el.classList.remove('odo--na');
    for (const ch of text) {
      el.append(ch === ','
        ? h('span', { class: 'odo__sep', 'aria-hidden': 'true', text: ',' })
        : h('span', { class: 'odo__col', 'aria-hidden': 'true' }, h('span', { class: 'odo__strip', text: '0\n1\n2\n3\n4\n5\n6\n7\n8\n9' })));
    }
    void el.offsetWidth; // تثبيت الحالة الابتدائية (كل الأعمدة عند 0) قبل التدوير
  }
  el.dataset.text = text;
  el.setAttribute('aria-label', text + ' تحميل');
  const instant = !animate || REDUCED;
  if (instant) el.classList.add('is-instant');
  let i = 0;
  const strips = el.querySelectorAll('.odo__strip');
  for (const ch of text) {
    if (ch === ',') continue;
    const s = strips[i++];
    s.style.setProperty('--delay', instant ? '0ms' : (i * 70) + 'ms');
    s.style.setProperty('--d', ch);
  }
  if (instant) { void el.offsetWidth; el.classList.remove('is-instant'); }
}

function odoNA(el) {
  el.dataset.text = '';
  el.textContent = '—';
  el.classList.add('odo--na');
  el.setAttribute('aria-label', 'عدد التحميلات غير متاح الآن');
}

const rolled = new Set(); // البطاقات التي لعبت حركة التدوير الافتتاحية
function paintCounts(animate) {
  for (const el of $$('[data-odo]')) {
    const id = el.dataset.odo;
    if (!state.countsKnown) { if (!el.dataset.text) odoNA(el); continue; }
    const first = !rolled.has(id); // أول ظهور: حركة التدوير الافتتاحية
    const fresh = !el.dataset.text; // عنصر أُعيد بناؤه (بحث/ترتيب): يُعرض فوراً بلا حركة
    rolled.add(id);
    odoRender(el, state.counts[id] || 0, first ? true : fresh ? false : animate);
  }
  updateHero();
}

// ───────────────────────── 7) العرض ─────────────────────────
function getView() {
  const tokens = norm(state.q).split(' ').filter(Boolean);
  const list = state.apps.filter((a) => tokens.every((t) => a.search.includes(t)));
  const by = {
    new: (a, b) => (Date.parse(b.updated) || 0) - (Date.parse(a.updated) || 0) || a.order - b.order,
    top: (a, b) => (state.counts[b.id] || 0) - (state.counts[a.id] || 0) || a.order - b.order,
    name: (a, b) => a.name.localeCompare(b.name, 'ar') || a.order - b.order,
  };
  return by[state.sort] ? list.sort(by[state.sort]) : list;
}

function dlButton(app, extra = '') {
  return h('button', { class: 'btn btn--cta ' + extra, type: 'button', 'data-dl': app.id, 'data-act': 'download' },
    icon('download', 'btn__ic'),
    h('span', { class: 'btn__label', text: 'تحميل التطبيق' }),
    h('span', { class: 'btn__short', text: 'تحميل' }));
}

function renderCard(app) {
  const img = h('img', { src: app.icon || placeholder(app), alt: '', width: '96', height: '96', decoding: 'async', loading: 'lazy' });
  img.addEventListener('error', () => { img.src = placeholder(app); }, { once: true });

  const badge = h('span', { class: 'seen-badge', title: 'حمّلته على هذا الجهاز', 'data-seen': app.id, hidden: !state.seen.has(app.id) },
    icon('check'), h('span', { class: 'sr', text: 'حمّلته على هذا الجهاز' }));

  const chips = h('div', { class: 'chips' }, h('span', { class: 'chip chip--apk', text: 'APK' }));
  if (app.size) chips.append(h('span', { class: 'chip chip--ltr', text: app.size }));
  if (app.minAndroid) chips.append(h('span', { class: 'chip chip--ltr', text: 'Android ' + app.minAndroid + '+' }));
  if (app.version) chips.append(h('span', { class: 'chip chip--ltr chip--ver', text: 'v' + app.version.replace(/^v/i, '') }));

  const foot = h('div', { class: 'card__foot' });
  if (Api.enabled) {
    foot.append(h('div', { class: 'count', title: 'عدد الأجهزة التي أكملت تحميل هذا التطبيق (كل جهاز يُحتسب مرة واحدة)' },
      h('span', { class: 'odo odo--na', 'data-odo': app.id, role: 'img', 'aria-label': 'عدد التحميلات', text: '—' }),
      h('span', { class: 'count__label', 'aria-hidden': 'true', text: 'تحميل' })));
  }
  foot.append(
    dlButton(app),
    h('button', { class: 'btn btn--link', type: 'button', 'data-act': 'details', 'data-id': app.id, text: 'التفاصيل والتحقق من الملف' }),
  );

  return h('article', { class: 'card', 'aria-labelledby': 't-' + app.id, 'data-card': app.id },
    h('div', { class: 'card__iconwrap' }, h('div', { class: 'card__icon' }, img), badge),
    h('h2', { class: 'card__name', id: 't-' + app.id },
      h('button', { class: 'card__open', type: 'button', 'data-act': 'details', 'data-id': app.id, text: app.name })),
    app.tagline ? h('p', { class: 'card__tag', text: app.tagline }) : null,
    chips,
    foot);
}

function renderGrid() {
  const grid = $('#grid');
  const list = getView();
  grid.textContent = '';
  list.slice(0, state.limit).forEach((a) => grid.append(renderCard(a)));
  const remaining = list.length - state.limit;
  $('#more').hidden = remaining <= 0;
  if (remaining > 0) $('#btn-more span').textContent = `عرض المزيد (${remaining})`;
  const empty = list.length === 0;
  const box = $('#state');
  box.hidden = !empty;
  if (empty && state.apps.length) {
    $('#state-title').textContent = 'لا توجد نتائج مطابقة';
    $('#state-text').textContent = `لم نعثر على تطبيق يطابق «${state.q}». جرّب كلمة أخرى.`;
    const b = $('#state-btn'); b.textContent = 'مسح البحث'; b.dataset.act = 'clear';
  }
  $('#apps').setAttribute('aria-busy', 'false');
  if (Api.enabled) paintCounts(true);
  for (const app of list.slice(0, state.limit)) setDlUi(app.id, phaseOf(app.id));
}

function showSkeleton() {
  const grid = $('#grid');
  grid.textContent = '';
  for (let i = 0; i < 3; i++) {
    grid.append(h('div', { class: 'card card--sk', 'aria-hidden': 'true' },
      h('span', { class: 'sk sk--icon' }), h('span', { class: 'sk sk--l1' }), h('span', { class: 'sk sk--l2' }), h('span', { class: 'sk sk--btn' })));
  }
}

function showFatal(err) {
  console.error('[المتجر] تعذّر تحميل apps.json:', err);
  $('#grid').textContent = '';
  $('#more').hidden = true;
  $('#state').hidden = false;
  $('#state-title').textContent = 'تعذّر تحميل قائمة التطبيقات';
  $('#state-text').textContent = 'تحقق من اتصالك بالإنترنت ثم أعد المحاولة.';
  const b = $('#state-btn'); b.textContent = 'إعادة المحاولة'; b.dataset.act = 'retry';
  $('#apps').setAttribute('aria-busy', 'false');
}

function updateHero() {
  const live = $('#live');
  if (!Api.enabled || !state.countsKnown) { live.hidden = true; return; }
  const total = state.apps.reduce((s, a) => s + (state.counts[a.id] || 0), 0);
  $('#live-text').textContent = `أُكمل ${fmtInt(total)} تحميل حتى الآن`;
  live.hidden = false;
}

function updateStatus(kind) {
  const dot = $('#status .dot'), txt = $('#status-text');
  dot.className = 'dot' + (kind === 'up' ? '' : kind === 'down' ? ' dot--bad' : ' dot--off');
  txt.textContent = { up: 'خدمة العدّاد متصلة', down: 'خدمة العدّاد غير متاحة الآن', pending: 'جارٍ الاتصال بخدمة العدّاد…' }[kind] || 'العدّاد غير مفعّل';
}

// ───────────────────────── 8) الإحصاءات والحالة ─────────────────────────
async function refreshStats() {
  if (!Api.enabled) return;
  try {
    const r = await Api.call('/api/stats', { timeout: 8000 });
    state.counts = r.counts || {}; state.countsKnown = true; state.statsAt = Date.now();
    updateStatus('up');
    paintCounts(true);
  } catch (e) {
    if (!state.countsKnown) { updateStatus('down'); paintCounts(false); }
  }
}

function setSeen(ids) {
  state.seen = new Set(ids.filter((id) => state.byId.has(id)));
  store.set(K.seen, JSON.stringify([...state.seen]));
  for (const b of $$('[data-seen]')) b.hidden = !state.seen.has(b.dataset.seen);
  for (const a of state.apps) setDlUi(a.id, phaseOf(a.id));
}

async function syncIdentity() {
  if (!Api.enabled) return;
  try {
    const payload = await identityPayload();
    if (!payload.t && !(payload.f && payload.q)) return;
    const r = await Api.call('/api/identify', { method: 'POST', body: payload });
    if (r.t) Identity.write(r.t);
    setSeen(r.known ? r.seen : []);
  } catch { /* نبقى على الذاكرة المحلية */ }
}

// ───────────────────────── 9) التحميل ─────────────────────────
function phaseOf(id) {
  const d = state.dl.get(id);
  if (!d) return 'idle';
  return d.phase || 'idle';
}

function setDlUi(id, phase) {
  if (!ID_RE.test(id)) return;
  const long = phase === 'busy' ? 'جارٍ التحضير…' : phase === 'started' ? 'بدأ التحميل ✓' : (state.seen.has(id) ? 'تحميل مرة أخرى' : 'تحميل التطبيق');
  const short = phase === 'busy' ? 'جارٍ…' : phase === 'started' ? 'بدأ ✓' : 'تحميل';
  for (const btn of $$(`[data-dl="${id}"]`)) {
    if (phase === 'busy') btn.setAttribute('aria-busy', 'true'); else btn.removeAttribute('aria-busy');
    $('.btn__label', btn).textContent = long;
    $('.btn__short', btn).textContent = short;
  }
}

function triggerDownload(url) {
  const a = h('a', { href: url, rel: 'noopener', class: 'sr', tabindex: '-1', 'aria-hidden': 'true' });
  document.body.append(a); a.click(); setTimeout(() => a.remove(), 1000);
}

async function startDownload(app) {
  const now = Date.now();
  const cur = state.dl.get(app.id);
  // النظام 1: حارس النقرات — لا طلبات جديدة أثناء فترة التهدئة، فلا يتكرر شيء لا عند الخادم ولا في العدّاد
  if (cur && (cur.phase === 'busy' || now - cur.ts < COOLDOWN_MS)) { toast('info', 'التحميل بدأ بالفعل، تحقق من إشعارات التحميل في هاتفك.'); return; }
  state.dl.set(app.id, { ts: now, phase: 'busy' });
  setDlUi(app.id, 'busy');

  let url = '';
  try {
    if (!Api.enabled) throw new Error('no_api');
    const body = { a: app.id, ...(await identityPayload()) };
    const r = await Api.call('/api/ticket', { method: 'POST', body, timeout: 12000 });
    if (r.t) Identity.write(r.t);
    const tu = new URL(r.u);
    if (tu.origin !== new URL(Api.base).origin || !/^\/dl\/[\w.-]+$/.test(tu.pathname)) throw new Error('bad_ticket_url');
    url = tu.href;
    if (r.seen) {
      if (!state.seen.has(app.id)) setSeen([...state.seen, app.id]);
      toast('info', 'بدأ التحميل. حمّلت هذا التطبيق من جهازك سابقاً، لذلك لن يزيد العدّاد.');
    } else if (r.counted) {
      toast('ok', `بدأ تحميل «${app.name}». سيُحتسب بعد اكتمال وصول الملف.`);
      watchCompletion(app);
    } else {
      toast('warn', 'بدأ التحميل دون احتسابه في العدّاد الآن بسبب كثرة الطلبات من شبكتك.');
    }
  } catch (e) {
    if (!app.url) { // لا رابط احتياطي عمداً (روابط المصدر مخفية داخل الخادم)
      state.dl.set(app.id, { ts: now, phase: 'idle' });
      setDlUi(app.id, 'idle');
      toast('err', e.status === 429 ? 'محاولات كثيرة من شبكتك. حاول بعد دقائق.'
        : Api.enabled ? 'تعذّر بدء التحميل الآن. تحقق من اتصالك وأعد المحاولة بعد قليل.' : 'لم يُضبط رابط تحميل هذا التطبيق بعد.');
      return;
    }
    url = app.url;
    toast(Api.enabled ? 'warn' : 'ok', !Api.enabled ? `بدأ تحميل «${app.name}».`
      : e.status === 429 ? 'محاولات كثيرة؛ سيبدأ التحميل المباشر دون احتسابه.'
      : 'تعذّر الاتصال بعدّاد التحميل؛ سيبدأ التحميل المباشر دون احتسابه.');
  }

  triggerDownload(url);
  state.dl.set(app.id, { ts: now, phase: 'started' });
  setDlUi(app.id, 'started');
  setTimeout(() => { state.dl.set(app.id, { ts: now, phase: 'idle' }); setDlUi(app.id, 'idle'); }, COOLDOWN_MS);
}

/** يستطلع الخادم بلطف حتى يتأكد أن الملف وصل كاملاً، ثم يحدّث العدّاد بحركة التدوير */
function watchCompletion(app) {
  if (state.watching.has(app.id)) return;
  state.watching.add(app.id);
  const t0 = Date.now();
  const check = async () => {
    try {
      const t = await Identity.read();
      if (!t) return false;
      const r = await Api.call('/api/identify', { method: 'POST', body: { t } });
      if (r.known && r.seen.includes(app.id)) return true;
    } catch { /* نحاول لاحقاً */ }
    return false;
  };
  const loop = async () => {
    if (Date.now() - t0 > WATCH_MAX_MS) { state.watching.delete(app.id); return; }
    if (document.visibilityState === 'visible' && (await check())) {
      state.watching.delete(app.id);
      setSeen([...state.seen, app.id]);
      await refreshStats();
      setDlUi(app.id, phaseOf(app.id));
      toast('ok', `اكتمل تحميل «${app.name}» وتم احتسابه. شكراً لك!`);
      const card = $(`[data-card="${app.id}"]`);
      if (card && !REDUCED) { card.classList.add('is-flash'); setTimeout(() => card.classList.remove('is-flash'), 1900); }
      return;
    }
    setTimeout(loop, WATCH_EVERY_MS);
  };
  setTimeout(loop, 5000);
}

// ───────────────────────── 10) نافذة التفاصيل ─────────────────────────
function fact(label, value, ltr = false) { return value ? h('div', { class: 'fact' }, h('dt', { text: label }), h('dd', ltr ? { text: value, dir: 'ltr', class: 'fact__ltr' } : { text: value })) : null; }

function hashRow(label, value) {
  const btn = h('button', { class: 'iconbtn', type: 'button', 'aria-label': 'نسخ ' + label, title: 'نسخ' }, icon('copy'));
  btn.addEventListener('click', async () => { const ok = await copyText(value); toast(ok ? 'ok' : 'err', ok ? 'تم النسخ' : 'تعذّر النسخ'); });
  return h('div', { class: 'hash' }, h('span', { class: 'hash__k', text: label }), h('code', { text: value }), btn);
}

function buildAppSheet(app) {
  const img = h('img', { src: app.icon || placeholder(app), alt: '', width: '62', height: '62', decoding: 'async' });
  img.addEventListener('error', () => { img.src = placeholder(app); }, { once: true });

  const close = h('button', { class: 'iconbtn sheet__close', type: 'button', 'data-close': '', 'aria-label': 'إغلاق' }, icon('x'));
  const head = h('div', { class: 'sheet__head' },
    h('div', { class: 'sheet__niche' }, img),
    h('div', {}, h('h2', { class: 'sheet__name', id: 'app-title', text: app.name }), app.tagline ? h('p', { class: 'sheet__tag', text: app.tagline }) : null));

  const cta = h('div', { class: 'sheet__cta' }, dlButton(app));
  if (state.seen.has(app.id)) {
    cta.append(h('p', { class: 'sheet__hint' }, icon('ok'), h('span', { text: 'حمّلت هذا التطبيق من هذا الجهاز سابقاً. إعادة التحميل لن تزيد العدّاد.' })));
  }

  const count = Api.enabled && state.countsKnown ? fmtInt(state.counts[app.id] || 0) + ' جهاز' : '';
  const facts = h('dl', { class: 'facts' },
    fact('الإصدار', app.version ? 'v' + app.version.replace(/^v/i, '') : '', true),
    fact('حجم الملف', app.size, true),
    fact('يتطلب أندرويد', app.minAndroid ? app.minAndroid + ' فأحدث' : ''),
    fact('آخر تحديث', fmtDate(app.updated)),
    fact('عدد التحميلات', count));

  const body = [head, cta, facts.children.length ? facts : null];
  if (app.description) body.push(h('section', { class: 'block' }, h('h3', { class: 'block__title', text: 'عن التطبيق' }), h('p', { text: app.description })));
  if (app.changelog.length) body.push(h('section', { class: 'block' }, h('h3', { class: 'block__title', text: 'ما الجديد' }), h('ul', {}, app.changelog.map((t) => h('li', { text: t })))));
  if (app.sha256 || app.cert) {
    const v = h('section', { class: 'block' },
      h('h3', { class: 'block__title', text: 'التحقق من الملف' }),
      h('p', { text: 'بعد التحميل احسب بصمة الملف وقارنها بالبصمة أدناه. إذا اختلفتا فلا تثبّت الملف.' }));
    if (app.sha256) v.append(hashRow('SHA-256', app.sha256));
    if (app.cert) v.append(hashRow('شهادة التوقيع', app.cert));
    if (app.checked) v.append(h('p', { class: 'hash__meta', text: 'تاريخ تسجيل البصمة: ' + (fmtDate(app.checked) || app.checked) }));
    body.push(v);
  }
  return h('div', { class: 'sheet__in' }, close, body);
}

function openApp(id, opener) {
  const app = state.byId.get(id);
  if (!app) return;
  const dlg = $('#dlg-app');
  dlg.textContent = '';
  dlg.append(buildAppSheet(app));
  state.opener = opener || document.activeElement;
  if (!dlg.open) dlg.showModal();
  dlg.tabIndex = -1; dlg.focus({ preventScroll: true }); // التركيز على النافذة نفسها لا على زر الإغلاق
  setDlUi(id, phaseOf(id));
  try { history.replaceState(null, '', '#' + id); } catch { /* تجاهل */ }
}

// ───────────────────────── 11) الخصوصية ─────────────────────────
function openPrivacy() {
  const dlg = $('#dlg-privacy');
  state.opener = document.activeElement;
  if (!dlg.open) dlg.showModal();
  dlg.tabIndex = -1; dlg.focus({ preventScroll: true });
}

// ───────────────────────── 12) التهيئة وربط الأحداث ─────────────────────────
function detectInApp() {
  return /FBAN|FBAV|FB_IAB|Instagram|Line\/|Snapchat|TikTok|BytedanceWebview|Telegram|; wv\)/i.test(navigator.userAgent);
}

async function share(url, title, text) {
  try { if (navigator.share) { await navigator.share({ title, text, url }); return; } } catch (e) { if (e && e.name === 'AbortError') return; }
  toast((await copyText(url)) ? 'ok' : 'info', 'تم نسخ الرابط.');
}

function bindUi() {
  applyTheme(document.documentElement.getAttribute('data-theme') || 'dark', false);
  $('#year').textContent = new Date().getFullYear();

  $('#btn-theme').addEventListener('click', () => applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark', true));
  $('#btn-share').addEventListener('click', () => share(location.href.split('#')[0], document.title, 'حمّل تطبيقات أسامة سلام هادي من هنا'));
  $('#btn-privacy').addEventListener('click', openPrivacy);
  $('#foot-privacy').addEventListener('click', openPrivacy);
  $('#inapp-close').addEventListener('click', () => { $('#inapp').hidden = true; });
  if (detectInApp()) $('#inapp').hidden = false;

  // البحث والترتيب
  const q = $('#q'), clear = $('#q-clear');
  const apply = debounce(() => { state.q = q.value; state.limit = PAGE_SIZE; renderGrid(); }, 120);
  q.addEventListener('input', () => { clear.hidden = !q.value; apply(); });
  clear.addEventListener('click', () => { q.value = ''; clear.hidden = true; state.q = ''; state.limit = PAGE_SIZE; renderGrid(); q.focus(); });
  $('#sort').addEventListener('click', (e) => {
    const b = e.target.closest('[data-sort]');
    if (!b) return;
    state.sort = state.sort === b.dataset.sort ? '' : b.dataset.sort; state.limit = PAGE_SIZE;
    $$('#sort [data-sort]').forEach((x) => x.setAttribute('aria-pressed', String(x.dataset.sort === state.sort)));
    renderGrid();
  });
  $('#btn-more').addEventListener('click', () => { state.limit += PAGE_SIZE; renderGrid(); });
  $('#state-btn').addEventListener('click', (e) => {
    const act = e.currentTarget.dataset.act;
    if (act === 'clear') { q.value = ''; clear.hidden = true; state.q = ''; renderGrid(); }
    if (act === 'retry') boot();
  });

  // أزرار البطاقات والنوافذ (تفويض أحداث)
  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-act], [data-close]');
    if (t) {
      if (t.hasAttribute('data-close')) { t.closest('dialog').close(); return; }
      const act = t.dataset.act;
      if (act === 'download') { const app = state.byId.get(t.dataset.dl); if (app) startDownload(app); }
      if (act === 'details') openApp(t.dataset.id, t);
      return;
    }
    // على الجوال: لمس أي مكان في صف التطبيق يفتح تفاصيله (زر التحميل له وظيفته الخاصة)
    const card = e.target.closest('.card[data-card]');
    if (card && MOBILE.matches && !e.target.closest('a, button')) openApp(card.dataset.card, card.querySelector('.card__open'));
  });

  // نوافذ: إغلاق بالنقر على الخلفية + إرجاع التركيز + تنظيف الرابط
  for (const dlg of $$('dialog.sheet')) {
    dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.close(); });
    dlg.addEventListener('close', () => {
      if (dlg.id === 'dlg-app') { try { history.replaceState(null, '', location.pathname + location.search); } catch { /* تجاهل */ } }
      if (state.opener && state.opener.isConnected) state.opener.focus();
    });
  }
  // الصعود للأعلى
  const top = $('#totop');
  let ticking = false;
  window.addEventListener('scroll', () => {
    if (ticking) return; ticking = true;
    requestAnimationFrame(() => { top.hidden = window.scrollY < 700; ticking = false; });
  }, { passive: true });
  top.addEventListener('click', () => window.scrollTo({ top: 0, behavior: REDUCED ? 'auto' : 'smooth' }));

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && Api.enabled && Date.now() - state.statsAt > 15000) refreshStats();
  });
}

let booted = false;
async function boot() {
  $('#state').hidden = true;
  $('#state-btn').hidden = false;
  $('#apps').setAttribute('aria-busy', 'true');
  showSkeleton();
  let cat;
  try { cat = await loadCatalog(); } catch (e) { return showFatal(e); }

  state.apps = cat.apps; state.byId = cat.byId; Api.base = cat.api;

  try { const cached = JSON.parse(store.get(K.seen) || '[]'); if (Array.isArray(cached)) state.seen = new Set(cached.filter((id) => state.byId.has(id))); } catch { /* تجاهل */ }

  $('#tools').hidden = state.apps.length === 0;
  $('#sort').hidden = state.apps.length < 4;
  updateStatus(Api.enabled ? 'pending' : 'off');

  renderGrid();
  if (state.apps.length === 0) {
    $('#state').hidden = false;
    $('#state-title').textContent = 'لا توجد تطبيقات بعد';
    $('#state-text').textContent = 'أضف تطبيقك الأول في ملف apps.json.';
    $('#state-btn').hidden = true;
  }

  if (!booted) {
    booted = true;
    if (Api.enabled) {
      setInterval(() => { if (document.visibilityState === 'visible') refreshStats(); }, STATS_EVERY_MS);
    }
  }
  if (Api.enabled) { refreshStats(); syncIdentity(); }

  let hash = '';
  try { hash = decodeURIComponent(location.hash.slice(1)); } catch { /* رابط تالف */ }
  if (ID_RE.test(hash) && state.byId.has(hash)) openApp(hash);
}

// حماية من التضمين داخل إطار (clickjacking) عند عدم توفّر ترويسات HTTP
if (window.top !== window.self) {
  document.documentElement.style.display = 'none';
  try { window.top.location = window.self.location; } catch { /* محجوب */ }
}

bindUi();
boot();
