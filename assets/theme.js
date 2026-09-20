// يُطبَّق المظهر المحفوظ قبل أول رسم للصفحة (لمنع وميض الألوان). بدون أي كود مضمَّن كي تبقى سياسة CSP صارمة.
(function () {
  try {
    var t = localStorage.getItem('os_theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (e) { /* التخزين محجوب: نبقى على الافتراضي */ }
})();
