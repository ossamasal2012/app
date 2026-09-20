-- ═══════════════════════════════════════════════════════════════
--  قاعدة بيانات عدّاد التحميلات (Cloudflare D1)
--  الصق هذا الملف كاملاً في: D1 ← Console ← Execute
--  (كل أمر في سطر واحد عمداً كي يعمل في لوحة Cloudflare وفي wrangler)
-- ═══════════════════════════════════════════════════════════════

-- الأجهزة: معرّف عشوائي مجهول فقط، بلا أي بيانات شخصية
CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL) WITHOUT ROWID;

-- التحميلات المكتملة: المفتاح (تطبيق + جهاز) هو ما يمنع احتساب الجهاز مرتين إلى الأبد
CREATE TABLE IF NOT EXISTS downloads (app_id TEXT NOT NULL, device_id TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (app_id, device_id)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_downloads_device ON downloads(device_id);
CREATE INDEX IF NOT EXISTS idx_downloads_time ON downloads(created_at);

-- عدّادات جاهزة للقراءة السريعة (تُحدَّث ذرّياً مع كل تحميل جديد فقط)
CREATE TABLE IF NOT EXISTS app_counts (app_id TEXT PRIMARY KEY, total INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;

-- روابط التعرّف بعد مسح بيانات المتصفح: هاش (بصمة تقنية + الشبكة) ← جهاز. لا تُخزَّن أي قيمة خام
CREATE TABLE IF NOT EXISTS links (k TEXT PRIMARY KEY, device_id TEXT NOT NULL, last_seen INTEGER NOT NULL) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_links_device ON links(device_id);
CREATE INDEX IF NOT EXISTS idx_links_seen ON links(last_seen);

-- حدود المعدّل (منع الإغراق والتلاعب)
CREATE TABLE IF NOT EXISTS rl (k TEXT PRIMARY KEY, win INTEGER NOT NULL, n INTEGER NOT NULL, exp INTEGER NOT NULL) WITHOUT ROWID;
