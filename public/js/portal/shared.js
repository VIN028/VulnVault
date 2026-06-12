/**
 * VulnVault Portal — Shared Helpers
 * Exposed globally via window.PortalShared
 * No module bundler required.
 */
(function () {
  'use strict';

  // ── Session Guard ──────────────────────────────────────────────────────────────
  /**
   * Check /api/session and redirect non-management users.
   * @param {Function} onSuccess – called with session object when authenticated management user.
   */
  async function initSessionGuard(onSuccess) {
    try {
      const r = await fetch('/api/session');
      const s = await r.json();
      if (!s.authenticated || !['admin', 'manager', 'pm'].includes(s.role)) {
        window.location.replace(s.authenticated ? '/' : '/login.html');
        return;
      }
      if (typeof onSuccess === 'function') onSuccess(s);
    } catch {
      window.location.replace('/login.html');
    }
  }

  let csrfToken = null;

  async function getCsrfToken() {
    if (csrfToken) return csrfToken;
    const r = await fetch('/api/csrf-token');
    const j = await r.json().catch(function () { return {}; });
    csrfToken = j.token;
    return csrfToken;
  }

  // ── API Fetch ──────────────────────────────────────────────────────────────────
  async function apiFetch(url, method, body) {
    method = method || 'GET';
    body = body || null;

    const headers = { 'Content-Type': 'application/json' };

    if (method !== 'GET') {
      const token = await getCsrfToken();
      if (!token) {
        throw new Error('Missing CSRF token');
      }
      headers['X-CSRF-Token'] = token;
    }

    const opts = { method: method, headers: headers };
    if (body) opts.body = JSON.stringify(body);

    let r;
    try {
      r = await fetch(url, opts);
    } catch (err) {
      throw new Error('Cannot reach VulnVault server. Please make sure the backend is running, then refresh this page.');
    }
    const j = await r.json().catch(function () { return {}; });

    if (!r.ok) {
      if (r.status === 403 && /CSRF/i.test(j.error || '')) {
        csrfToken = null;
      }
      throw new Error(j.error || 'Request failed (' + r.status + ')');
    }

    return j;
  }

  // ── Escaping ───────────────────────────────────────────────────────────────────
  function esc(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  /** Safe only for double-quoted HTML attributes. NOT safe for single-quoted JS strings or onclick event handlers. */
  function escA(s) {
    return (s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /** Safe JSON arg for onclick="..." attributes */
  function jsa(v) {
    return JSON.stringify(v)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /** Only allow http/https URLs — block javascript: and other dangerous schemes */
  function safeUrl(url) {
    if (!url) return '#';
    var s = String(url).trim();
    if (/^https?:\/\//i.test(s)) return s;
    return '#';
  }

  // ── Modal Helpers ──────────────────────────────────────────────────────────────
  function closeModal(e) {
    if (e.target.classList.contains('modal-overlay')) e.target.classList.remove('open');
  }

  function customConfirm(title, message, confirmLabel, variant) {
    confirmLabel = confirmLabel || 'Confirm';
    variant = variant || 'primary';
    return new Promise(function (resolve) {
      var id = 'dlg-' + Date.now();
      var el = document.createElement('div');
      el.className = 'modal-overlay open';
      el.id = id;
      el.innerHTML =
        '<div class="modal" style="max-width:420px">' +
        '<h3 class="modal-title">' + title + '</h3>' +
        '<p style="color:var(--muted);font-size:13px;margin:0 0 24px">' + message + '</p>' +
        '<div class="modal-actions">' +
        '<button class="btn-ghost" id="' + id + '-cancel">Cancel</button>' +
        '<button class="btn-primary" id="' + id + '-ok" style="' + (variant === 'danger' ? 'background:rgba(239,68,68,0.9);' : '') + '">' + esc(confirmLabel) + '</button>' +
        '</div></div>';
      document.body.appendChild(el);
      var cleanup = function (val) { el.remove(); resolve(val); };
      el.querySelector('#' + id + '-ok').onclick = function () { cleanup(true); };
      el.querySelector('#' + id + '-cancel').onclick = function () { cleanup(false); };
      el.addEventListener('click', function (e) { if (e.target === el) cleanup(false); });
    });
  }

  function customPrompt(title, label, defaultValue) {
    defaultValue = defaultValue || '';
    return new Promise(function (resolve) {
      var id = 'dlg-' + Date.now();
      var el = document.createElement('div');
      el.className = 'modal-overlay open';
      el.id = id;
      el.innerHTML =
        '<div class="modal" style="max-width:420px">' +
        '<h3 class="modal-title">' + title + '</h3>' +
        '<div class="form-group"><label>' + label + '</label>' +
        '<input id="' + id + '-inp" value="' + esc(defaultValue) + '">' +
        '</div>' +
        '<div class="modal-actions">' +
        '<button class="btn-ghost" id="' + id + '-cancel">Cancel</button>' +
        '<button class="btn-primary" id="' + id + '-ok">Save</button>' +
        '</div></div>';
      document.body.appendChild(el);
      var inp = el.querySelector('#' + id + '-inp');
      inp.focus(); inp.select();
      var cleanup = function (val) { el.remove(); resolve(val); };
      el.querySelector('#' + id + '-ok').onclick = function () { cleanup(inp.value); };
      el.querySelector('#' + id + '-cancel').onclick = function () { cleanup(null); };
      el.addEventListener('click', function (e) { if (e.target === el) cleanup(null); });
      inp.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') cleanup(inp.value);
        if (e.key === 'Escape') cleanup(null);
      });
    });
  }

  // ── Toast ──────────────────────────────────────────────────────────────────────
  function showToast(msg, type) {
    type = type || 'success';
    var container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      document.body.appendChild(container);
    }
    var icon = type === 'success'
      ? '<svg class="ti" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>'
      : '<svg class="ti" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
    var el = document.createElement('div');
    el.className = 'toast ' + type;
    el.innerHTML = icon + '<span>' + esc(msg) + '</span>';
    container.appendChild(el);
    setTimeout(function () { el.remove(); }, 4000);
  }

  // ── Time Helpers ───────────────────────────────────────────────────────────────
  function timeAgo(dateStr) {
    var s = Math.floor((Date.now() - new Date(dateStr + 'Z').getTime()) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }

  // ── Working-Days Helpers ───────────────────────────────────────────────────────
  // Indonesian public holidays — loaded dynamically from /api/holidays on page load.
  // Seeded with hardcoded 2025-2026 as fallback.
  var idHolidaySet = new Set([
    '2025-01-01', '2025-01-27', '2025-01-28', '2025-01-29', '2025-03-28', '2025-03-29',
    '2025-03-31', '2025-04-01', '2025-04-02', '2025-04-03', '2025-04-04', '2025-04-07',
    '2025-04-18', '2025-04-20', '2025-05-01', '2025-05-12', '2025-05-13', '2025-05-29',
    '2025-06-06', '2025-06-09', '2025-06-27', '2025-08-17', '2025-09-05', '2025-12-25', '2025-12-26',
    '2026-01-01', '2026-01-16', '2026-01-17', '2026-03-19', '2026-03-20', '2026-03-21',
    '2026-03-23', '2026-03-24', '2026-04-03', '2026-05-01', '2026-05-14', '2026-05-26',
    '2026-05-27', '2026-06-17', '2026-08-17', '2026-09-25', '2026-12-25',
  ]);

  /** Fetch holidays from backend and add to the holiday set (non-blocking) */
  function loadHolidays() {
    var thisYear = new Date().getFullYear();
    [thisYear, thisYear + 1].forEach(function (yr) {
      fetch('/api/holidays?year=' + yr)
        .then(function (r) { return r.json(); })
        .then(function (j) { if (j.dates) j.dates.forEach(function (d) { idHolidaySet.add(d); }); })
        .catch(function () { /* ignore */ });
    });
  }

  function workingDaysBetween(startStr, endStr) {
    var start = new Date(startStr);
    var end = new Date(endStr);
    if (isNaN(start) || isNaN(end) || end < start) return { days: 0, holidays: [] };
    var count = 0;
    var skipped = [];
    var cur = new Date(start);
    while (cur <= end) {
      var dow = cur.getDay();
      var iso = cur.toLocaleDateString('en-CA');
      if (dow !== 0 && dow !== 6) {
        if (idHolidaySet.has(iso)) {
          skipped.push(iso);
        } else {
          count++;
        }
      }
      cur.setDate(cur.getDate() + 1);
    }
    return { days: count, holidays: skipped };
  }

  /** Count workdays in a month, excluding weekends and Indonesian public holidays */
  function getWorkdaysInMonth(year, month) {
    var daysInMonth = new Date(year, month + 1, 0).getDate();
    var workdays = 0, holidays = 0;
    for (var d = 1; d <= daysInMonth; d++) {
      var dt = new Date(year, month, d);
      if (dt.getDay() === 0 || dt.getDay() === 6) continue;
      if (idHolidaySet.has(dt.toLocaleDateString('en-CA'))) { holidays++; continue; }
      workdays++;
    }
    return { workdays: workdays, holidays: holidays };
  }

  // ── Notification System ────────────────────────────────────────────────────────
  var _notifOpen = false;

  function toggleNotifDropdown() {
    var dd = document.getElementById('notif-dropdown');
    if (!dd) return;
    _notifOpen = !_notifOpen;
    dd.classList.toggle('open', _notifOpen);
    if (_notifOpen) loadNotifications();
  }

  async function loadNotifications() {
    try {
      var notifs = await apiFetch('/api/notifications');
      var unread = notifs.filter(function (n) { return !n.is_read; }).length;
      var badge = document.getElementById('notif-count');
      if (badge) {
        if (unread > 0) { badge.textContent = unread; badge.style.display = ''; }
        else { badge.style.display = 'none'; }
      }

      var list = document.getElementById('notif-list');
      if (!list) return;
      if (!notifs.length) {
        list.innerHTML = '<div class="notif-empty">No notifications yet</div>';
        return;
      }
      list.innerHTML = notifs.map(function (n) {
        return '<div class="notif-item ' + (n.is_read ? '' : 'unread') + '">' +
          '<div class="notif-item-title">' + esc(n.title) + '</div>' +
          (n.message ? '<div class="notif-item-msg">' + esc(n.message) + '</div>' : '') +
          '<div class="notif-item-time">' + timeAgo(n.created_at) + '</div>' +
          '</div>';
      }).join('');
    } catch (e) {
      var listEl = document.getElementById('notif-list');
      if (listEl) listEl.innerHTML = '<div class="notif-empty">Error: ' + e.message + '</div>';
    }
  }

  async function markAllRead() {
    try {
      await apiFetch('/api/notifications/read', 'PATCH');
      var badge = document.getElementById('notif-count');
      if (badge) badge.style.display = 'none';
      document.querySelectorAll('.notif-item.unread').forEach(function (el) { el.classList.remove('unread'); });
    } catch { /* ignore */ }
  }

  /** Initialize notification polling and outside-click handler */
  function initNotifications() {
    // Close dropdown on outside click
    document.addEventListener('click', function (e) {
      if (_notifOpen && !e.target.closest('.notif-wrapper')) {
        _notifOpen = false;
        var dd = document.getElementById('notif-dropdown');
        if (dd) dd.classList.remove('open');
      }
    });
    // Poll every 30s + initial load
    setInterval(loadNotifications, 30000);
    setTimeout(loadNotifications, 1000);
  }

  // ── Pending Count Badge ────────────────────────────────────────────────────────
  async function loadPendingCount() {
    try {
      var reqs = await apiFetch('/api/project-access-requests');
      var pending = Array.isArray(reqs) ? reqs.filter(function (r) { return r.status === 'pending'; }).length : 0;
      var badge = document.getElementById('nav-badge-requests');
      if (badge) {
        if (pending > 0) { badge.textContent = pending; badge.style.display = ''; }
        else { badge.style.display = 'none'; }
      }
    } catch { /* ignore */ }
  }

  // ── Logout ─────────────────────────────────────────────────────────────────────
  async function logout() {
    try { await apiFetch('/api/logout', 'POST'); } catch { /* ignore */ }
    csrfToken = null;
    window.location.replace('/login.html');
  }

  const _sharedCache = {};
  async function ensureDataLoaded(key, loaderFn) {
    if (_sharedCache[key]) {
      return _sharedCache[key];
    }
    const promise = loaderFn().catch(err => {
      delete _sharedCache[key];
      throw err;
    });
    _sharedCache[key] = promise;
    return promise;
  }

  // ── Expose Globally ────────────────────────────────────────────────────────────
  window.PortalShared = {
    initSessionGuard: initSessionGuard,
    apiFetch: apiFetch,
    esc: esc,
    escA: escA,
    jsa: jsa,
    safeUrl: safeUrl,
    closeModal: closeModal,
    customConfirm: customConfirm,
    customPrompt: customPrompt,
    showToast: showToast,
    timeAgo: timeAgo,
    idHolidaySet: idHolidaySet,
    loadHolidays: loadHolidays,
    workingDaysBetween: workingDaysBetween,
    getWorkdaysInMonth: getWorkdaysInMonth,
    toggleNotifDropdown: toggleNotifDropdown,
    loadNotifications: loadNotifications,
    markAllRead: markAllRead,
    initNotifications: initNotifications,
    loadPendingCount: loadPendingCount,
    logout: logout,
    ensureDataLoaded: ensureDataLoaded,
  };

  // Backward-compatible globals for inline handlers that remain in static HTML.
  window.closeModal = closeModal;
  window.toggleNotifDropdown = toggleNotifDropdown;
  window.markAllRead = markAllRead;
  window.logout = logout;
})();
