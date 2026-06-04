/**
 * VulnVault — IT Audit & SE Portal Logic
 * Scoped specifically to ?team=itaudit
 */
(function () {
  'use strict';

  // ── Shorthand references ───────────────────────────────────────────────────────
  const {
    apiFetch, esc, escA, jsa, safeUrl, closeModal, customConfirm, customPrompt,
    showToast, timeAgo, idHolidaySet, loadHolidays, workingDaysBetween, getWorkdaysInMonth,
    toggleNotifDropdown, loadNotifications, markAllRead, initNotifications, loadPendingCount, logout
  } = window.PortalShared;

  // ── State variables ────────────────────────────────────────────────────────────
  let currentUser = null;
  let _allEngineers = [];
  let _dashboardRows = [];
  let _dashFilter = null;
  let _dashTrendChart = null;
  let _activeProjects = [];
  let _clientGroups = [];
  let _boardProjects = [];
  let _boardStatuses = [];
  let _archivedProjects = [];
  let _clientNameMap = {};

  // Expose filter functions globally
  window.updateDashFilterUI = updateDashFilterUI;
  window.applyDashFilter = applyDashFilter;
  window.loadDashboard = loadDashboard;
  window.navigate = navigate;
  window.filterProjects = filterProjects;
  window.openCreateProject = openCreateProject;
  window.submitNewEntry = submitNewEntry;
  window.validateAndGoToProject = validateAndGoToProject;
  window.switchNeTab = switchNeTab;
  window._filterClientCards = _filterClientCards;
  window._toggleNewClientForm = _toggleNewClientForm;
  window._onEngRefChange = _onEngRefChange;
  window._updateProjectTabState = _updateProjectTabState;
  window._onServiceChange = _onServiceChange;
  window._onResourceCountChange = _onResourceCountChange;
  window.onMandaysParamChanged = onMandaysParamChanged;
  window.onAssessmentInput = onAssessmentInput;
  window._onPastProjectChange = _onPastProjectChange;
  window.addProjectLink = addProjectLink;
  window.removeProjectLink = removeProjectLink;
  window.openBoardSetup = openBoardSetup;
  window.addBoardStatus = addBoardStatus;
  window.saveBoardOrder = saveBoardOrder;
  window.shiftAllocationMonth = shiftAllocationMonth;
  window.filterArchivedProjects = filterArchivedProjects;
  window.openHighlightModal = openHighlightModal;
  window.saveHighlight = saveHighlight;
  window.toggleGroup = toggleGroup;
  window.archiveProjectFromBoard = archiveProjectFromBoard;
  window.restoreProjectFromArchive = restoreProjectFromArchive;

  // ── Init ───────────────────────────────────────────────────────────────────────
  PortalShared.initSessionGuard(function (s) {
    currentUser = s;
    document.getElementById('user-name').textContent = s.displayName || s.username;

    // Set avatar initials
    const initials = getInitials(s.displayName || s.username);
    document.getElementById('user-avatar-initials').textContent = initials;

    PortalShared.loadHolidays();
    initNotifications();
    loadPendingCount();

    const savedTab = localStorage.getItem('vulnvault_itaudit_active_tab') || 'dashboard';
    navigate(savedTab);
  });

  function getInitials(name) {
    if (!name) return '?';
    var parts = name.trim().split(/\s+/);
    if (parts.length >= 2) return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    return parts[0].substring(0, 2).toUpperCase();
  }

  // ── Navigation ─────────────────────────────────────────────────────────────────
  function navigate(section) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const secEl = document.getElementById('section-' + section);
    const navEl = document.getElementById('nav-' + section);
    if (secEl) secEl.classList.add('active');
    if (navEl) navEl.classList.add('active');

    localStorage.setItem('vulnvault_itaudit_active_tab', section);

    if (section === 'dashboard') loadDashboard();
    if (section === 'projects') loadProjects();
    if (section === 'pm-board') loadBoard();
    if (section === 'allocation') loadAllocation();
    if (section === 'archived') loadArchived();
  }

  // ── Dashboard period filter ────────────────────────────────────────────────────
  function initDashFilterUI() {
    const today = new Date();
    const yrSels = ['dash-year-sel', 'dash-quarter-year-sel', 'dash-year-only-sel'];
    yrSels.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.innerHTML = '';
      for (let y = today.getFullYear() - 2; y <= today.getFullYear() + 1; y++) {
        const opt = document.createElement('option');
        opt.value = y;
        opt.textContent = y;
        if (y === today.getFullYear()) opt.selected = true;
        el.appendChild(opt);
      }
    });

    const mSel = document.getElementById('dash-month-sel');
    if (mSel) mSel.value = today.getMonth();

    const startInput = document.getElementById('dash-custom-start');
    const endInput = document.getElementById('dash-custom-end');
    if (startInput && endInput) {
      const lastMonth = new Date(today.getFullYear(), today.getMonth() - 1, today.getDate());
      startInput.value = lastMonth.toISOString().split('T')[0];
      endInput.value = today.toISOString().split('T')[0];
    }
  }

  function updateDashFilterUI() {
    const type = document.getElementById('dash-filter-type').value;
    document.getElementById('dash-filter-month-ui').style.display = type === 'month' ? 'flex' : 'none';
    document.getElementById('dash-filter-quarter-ui').style.display = type === 'quarter' ? 'flex' : 'none';
    document.getElementById('dash-filter-year-ui').style.display = type === 'year' ? 'flex' : 'none';
    document.getElementById('dash-filter-custom-ui').style.display = type === 'custom' ? 'flex' : 'none';
  }

  function applyDashFilter() {
    const type = document.getElementById('dash-filter-type').value;
    let start, end, prevStart, prevEnd, label, deltaLabel;
    const today = new Date(); today.setHours(0, 0, 0, 0);

    if (type === 'month') {
      const y = parseInt(document.getElementById('dash-year-sel').value);
      const m = parseInt(document.getElementById('dash-month-sel').value);
      start = new Date(y, m, 1);
      end = new Date(y, m + 1, 0);
      prevStart = new Date(y, m - 1, 1);
      prevEnd = new Date(y, m, 0);
      label = start.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
      deltaLabel = 'last month';
    } else if (type === 'quarter') {
      const y = parseInt(document.getElementById('dash-quarter-year-sel').value);
      const q = parseInt(document.getElementById('dash-quarter-sel').value);
      start = new Date(y, (q - 1) * 3, 1);
      end = new Date(y, q * 3, 0);
      prevStart = new Date(y, (q - 2) * 3, 1);
      prevEnd = new Date(y, (q - 1) * 3, 0);
      label = `Q${q} ${y}`;
      deltaLabel = 'last quarter';
    } else if (type === 'year') {
      const y = parseInt(document.getElementById('dash-year-only-sel').value);
      start = new Date(y, 0, 1);
      end = new Date(y, 11, 31);
      prevStart = new Date(y - 1, 0, 1);
      prevEnd = new Date(y - 1, 11, 31);
      label = `${y}`;
      deltaLabel = 'last year';
    } else {
      const s = document.getElementById('dash-custom-start').value;
      const e = document.getElementById('dash-custom-end').value;
      if (!s || !e) { showToast('Select start and end dates', 'error'); return; }
      start = new Date(s);
      end = new Date(e);
      if (start > end) { showToast('Start date cannot be after end date', 'error'); return; }
      const diff = end.getTime() - start.getTime();
      prevEnd = new Date(start.getTime() - 86400000);
      prevStart = new Date(prevEnd.getTime() - diff);
      label = `${start.toLocaleDateString('en-US', { day: '2-digit', month: 'short' })} - ${end.toLocaleDateString('en-US', { day: '2-digit', month: 'short', year: 'numeric' })}`;
      deltaLabel = 'prev period';
    }

    _dashFilter = {
      start, end, prevStart, prevEnd, label, deltaLabel,
      refDate: end >= today ? today : end,
      prevRefDate: prevEnd >= today ? today : prevEnd
    };

    loadDashboard(false);
  }

  // ── Dashboard loading & calculation ────────────────────────────────────────────
  async function loadDashboard(fetchState = true) {
    try {
      if (fetchState) {
        [_dashboardRows, _allEngineers] = await Promise.all([
          apiFetch('/api/dashboard/summary?team=itaudit'),
          apiFetch('/api/users/engineers?team=itaudit')
        ]);
        initDashFilterUI();
        applyDashFilter();
        return;
      }

      const rows = _dashboardRows;
      const f = _dashFilter;
      const subEl = document.getElementById('dash-showing-badge');
      if (subEl) subEl.textContent = `Showing: ${f.label}`;

      const allP = rows.filter(r => r.project_id);
      const isPast = (r) => r.is_archived === 1;

      const isStartedIn = (r, start, end) => {
        if (isPast(r)) return false;
        return r.project_id && r.kickoff_date && new Date(r.kickoff_date) >= start && new Date(r.kickoff_date) <= end;
      };

      const isDoneIn = (r, start, end) => {
        return r.project_id && r.final_report_status === 'completed' && r.final_completed_at && new Date(r.final_completed_at) >= start && new Date(r.final_completed_at) <= end;
      };

      const isTotalProject = (r, start, end, refDate) => {
        if (!r.project_id || r.is_archived || !r.kickoff_date || new Date(r.kickoff_date) > refDate) return false;
        const isActiveAtRef = r.final_report_status !== 'completed' || (r.final_completed_at && new Date(r.final_completed_at) > refDate);
        return isActiveAtRef || isDoneIn(r, start, end);
      };

      const isOnTrack = (r, start, end, refDate) => {
        if (!isTotalProject(r, start, end, refDate)) return false;
        if (!r.final_report_date) return true;
        const isCompletedAtRef = r.final_report_status === 'completed' && r.final_completed_at && new Date(r.final_completed_at) <= refDate;
        if (isCompletedAtRef) {
          return new Date(r.final_completed_at) <= new Date(r.final_report_date);
        } else {
          return new Date(r.final_report_date) >= refDate;
        }
      };

      const isOffTrack = (r, start, end, refDate) => {
        if (!isTotalProject(r, start, end, refDate)) return false;
        if (!r.final_report_date) return false;
        const isCompletedAtRef = r.final_report_status === 'completed' && r.final_completed_at && new Date(r.final_completed_at) <= refDate;
        if (isCompletedAtRef) {
          return new Date(r.final_completed_at) > new Date(r.final_report_date);
        } else {
          return new Date(r.final_report_date) < refDate;
        }
      };

      const rangeProjects = allP.filter(r => isTotalProject(r, f.start, f.end, f.refDate));
      const cur = {
        total: rangeProjects.length,
        ontrack: allP.filter(r => isOnTrack(r, f.start, f.end, f.refDate)).length,
        offtrack: allP.filter(r => isOffTrack(r, f.start, f.end, f.refDate)).length,
        staffed: _allEngineers.length
      };

      const prevRangeProjects = allP.filter(r => isTotalProject(r, f.prevStart, f.prevEnd, f.prevRefDate));
      const prev = {
        total: prevRangeProjects.length,
        ontrack: allP.filter(r => isOnTrack(r, f.prevStart, f.prevEnd, f.prevRefDate)).length,
        offtrack: allP.filter(r => isOffTrack(r, f.prevStart, f.prevEnd, f.prevRefDate)).length,
      };

      document.getElementById('kpi-active-audits').textContent = cur.total;
      setKpiDelta('kpi-active-audits-sub', cur.total - prev.total, f.deltaLabel);

      document.getElementById('kpi-ontrack').textContent = cur.ontrack;
      setKpiDelta('kpi-ontrack-sub', cur.ontrack - prev.ontrack, f.deltaLabel);

      document.getElementById('kpi-offtrack').textContent = cur.offtrack;
      setKpiDelta('kpi-offtrack-sub', cur.offtrack - prev.offtrack, f.deltaLabel);

      document.getElementById('kpi-consultants').textContent = cur.staffed;
      document.getElementById('kpi-consultants-sub').textContent = 'Staff in IT Audit team';

      renderDashTrendChart(rows, f.refDate);
      renderDashAllocation(rows, f.refDate);
      renderDashActiveProjects(rows, f.refDate);
      renderDashHighlights(rows);

    } catch (e) {
      showToast('Dashboard error: ' + e.message, 'error');
    }
  }

  function setKpiDelta(id, diff, label) {
    const el = document.getElementById(id);
    if (!el) return;
    if (diff === 0) el.textContent = `equal to ${label}`;
    else if (diff > 0) el.textContent = `+${diff} vs ${label}`;
    else el.textContent = `${diff} vs ${label}`;
  }

  // ── Trend Line Chart ───────────────────────────────────────────────────────────
  function renderDashTrendChart(rows, today) {
    if (typeof Chart === 'undefined') return;
    const labels = [], projectsCount = [];

    for (let i = 5; i >= 0; i--) {
      const d = new Date(today.getFullYear(), today.getMonth() - i, 1);
      labels.push(d.toLocaleDateString('en-US', { month: 'short', year: 'numeric' }));

      const monthRows = rows.filter(r => r.project_id && r.kickoff_date && new Date(r.kickoff_date).getFullYear() === d.getFullYear() && new Date(r.kickoff_date).getMonth() === d.getMonth());
      projectsCount.push(monthRows.length);
    }

    const ctx = document.getElementById('dash-trend-chart');
    if (!ctx) return;
    if (_dashTrendChart) _dashTrendChart.destroy();

    _dashTrendChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'Audits Commenced',
            data: projectsCount,
            borderColor: '#06b6d4',
            backgroundColor: 'rgba(6, 182, 212, 0.05)',
            borderWidth: 2.5,
            pointRadius: 4,
            pointBackgroundColor: '#06b6d4',
            fill: true,
            tension: 0.3
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false
          },
          datalabels: {
            align: 'top',
            anchor: 'end',
            offset: 2,
            color: '#f0f4ff',
            font: { size: 10, weight: 'bold' },
            formatter: (v) => v > 0 ? v : ''
          }
        },
        scales: {
          x: { grid: { color: 'rgba(148,163,184,0.06)' }, ticks: { color: '#64748b', font: { size: 10 } } },
          y: { grid: { color: 'rgba(148,163,184,0.06)' }, ticks: { color: '#64748b', font: { size: 10 }, stepSize: 1 }, beginAtZero: true }
        }
      }
    });
  }

  // ── Allocation preview on Dashboard ────────────────────────────────────────────
  function renderDashAllocation(rows, refDate) {
    const container = document.getElementById('dash-alloc-area');
    if (!container) return;

    const today = new Date(refDate); today.setHours(0, 0, 0, 0);
    const year = today.getFullYear();
    const month = today.getMonth();
    const { workdays } = getWorkdaysInMonth(year, month);

    const engMap = new Map();
    _allEngineers.forEach(e => engMap.set(e.id, { name: e.display_name, used: 0 }));

    rows.forEach(r => {
      if (r.project_id && r.kickoff_date && r.mandays_assessment > 0) {
        const md = _assessmentMandaysInMonth(r, year, month);
        if (md > 0) {
          const hasPic = r.assigned_engineer_id, hasAssist = r.assist_engineer_id;
          const numEng = (hasPic ? 1 : 0) + (hasAssist ? 1 : 0);
          const perPerson = numEng > 0 ? md / numEng : md;
          if (hasPic && engMap.has(r.assigned_engineer_id)) engMap.get(r.assigned_engineer_id).used += perPerson;
          if (hasAssist && engMap.has(r.assist_engineer_id)) engMap.get(r.assist_engineer_id).used += perPerson;
        }
      }
    });

    const list = [...engMap.values()].sort((a, b) => b.used - a.used);

    if (!list.length) {
      container.innerHTML = '<div class="empty-state">No consultants staffed.</div>';
      return;
    }

    container.innerHTML = `
      <div style="display:flex; flex-direction:column; gap:12px;">
        ${list.map(e => {
          const pct = Math.round((e.used / workdays) * 100);
          let barColor = 'green';
          if (pct > 80) barColor = 'yellow';
          if (pct > 100) barColor = 'red';
          const fillWidth = Math.min(100, pct);
          return `
            <div>
              <div style="display:flex; justify-content:space-between; font-size:11px; margin-bottom:4px;">
                <span style="font-weight:600; color:var(--text);">${esc(e.name)}</span>
                <span style="color:var(--muted);">${e.used.toFixed(1)} / ${workdays} d (${pct}%)</span>
              </div>
              <div class="capacity-bar-track" style="height:6px;">
                <div class="capacity-bar-fill ${barColor}" style="width:${fillWidth}%; height:100%;"></div>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;
  }

  // ── Active Audits table on Dashboard ───────────────────────────────────────────
  function renderDashActiveProjects(rows, refDate) {
    const tbody = document.getElementById('dash-active-body');
    if (!tbody) return;

    const activeList = rows.filter(r => r.project_id && !r.is_archived && r.final_report_status !== 'completed');
    if (!activeList.length) {
      tbody.innerHTML = '<tr><td colspan="7"><div class="empty-state">No active audit engagements.</div></td></tr>';
      return;
    }

    const fmt = d => d ? new Date(d).toLocaleDateString('id-ID', { day: 'numeric', month: 'short' }) : '—';
    const sl = { it_audit: 'ITGC Audit', pdp: 'PDP Privacy', maturity_assessment: 'Security Maturity' };

    tbody.innerHTML = activeList.map(p => {
      let badgeHtml = '—';
      if (p.final_report_date) {
        const onTrack = new Date(p.final_report_date) >= refDate;
        badgeHtml = onTrack 
          ? '<span class="badge" style="background:rgba(34,197,94,0.1); color:var(--green)">On Track</span>' 
          : '<span class="badge" style="background:rgba(239,68,68,0.1); color:var(--red)">Delayed</span>';
      }

      return `
        <tr>
          <td><div style="font-weight:600;color:var(--text);">${esc(p.client_name)}</div></td>
          <td><div style="font-weight:500;color:var(--accent2);">${esc(p.project_name)}</div></td>
          <td><span class="badge badge-api">${sl[p.service] || p.service || 'IT Audit'}</span></td>
          <td style="color:var(--muted); font-size:12px;">${fmt(p.final_report_date)}</td>
          <td>${esc(p.engineer_name || '—')}</td>
          <td><span style="color:var(--muted);">—</span></td>
          <td>${badgeHtml}</td>
        </tr>
      `;
    }).join('');
  }

  // ── Highlights rendering ───────────────────────────────────────────────────────
  async function renderDashHighlights(rows) {
    const container = document.getElementById('dash-highlights-area');
    if (!container) return;

    const allP = rows.filter(r => r.project_id && !r.is_archived);
    if (!allP.length) {
      container.innerHTML = '<div class="empty-state" style="grid-column:1/-1;">No highlights available.</div>';
      return;
    }

    try {
      const results = await Promise.all(allP.map(r => apiFetch('/api/projects/' + r.project_id + '/highlight').catch(() => null)));
      const withText = results.filter(r => r && r.highlight_text);

      if (!withText.length) {
        container.innerHTML = '<div class="empty-state" style="grid-column:1/-1;">No highlights documented yet. Document them in the Audit Engagements section.</div>';
        return;
      }

      container.innerHTML = withText.map(h => {
        const proj = allP.find(r => r.project_id === h.id) || {};
        return `
          <div class="kpi-card" style="display:flex; flex-direction:column; gap:8px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <span style="font-weight:700; font-size:13px; color:var(--text);">📝 ${esc(proj.project_name || h.name)}</span>
            </div>
            <div style="font-size:11px; color:var(--muted); font-style:italic;">Client: ${esc(proj.client_name)}</div>
            <p style="font-size:12px; color:var(--text); line-height:1.5; white-space:pre-wrap; margin-top:4px;">${esc(h.highlight_text)}</p>
          </div>
        `;
      }).join('');
    } catch (e) {
      container.innerHTML = `<div class="empty-state" style="grid-column:1/-1;">Failed to load highlights: ${e.message}</div>`;
    }
  }

  // ── Client & Audits Accordion listing ──────────────────────────────────────────
  async function loadProjects() {
    try {
      _clientGroups = await apiFetch('/api/clients/full?team=itaudit');
      renderClientGroups();
    } catch (e) {
      showToast('Failed to load audit records: ' + e.message, 'error');
    }
  }

  function renderClientGroups() {
    const container = document.getElementById('client-groups');
    if (!container) return;

    const q = (document.getElementById('projects-search')?.value || '').toLowerCase();
    const serviceFilter = document.getElementById('projects-service-filter')?.value || '';

    let list = _clientGroups.map(c => {
      let projects = c.projects || [];
      if (q) {
        projects = projects.filter(p => (p.project_name || '').toLowerCase().includes(q) || (c.client_name || '').toLowerCase().includes(q));
      }
      if (serviceFilter) {
        projects = projects.filter(p => p.service === serviceFilter);
      }
      return { ...c, projects };
    });

    if (q || serviceFilter) {
      list = list.filter(c => c.projects.length > 0);
    }

    if (!list.length) {
      container.innerHTML = '<div class="empty-state">No matching clients or engagements found.</div>';
      return;
    }

    const fmt = d => d ? new Date(d).toLocaleDateString('id-ID', { day: 'numeric', month: 'short', year: 'numeric' }) : '—';
    const sl = { it_audit: 'ITGC Audit', pdp: 'PDP Privacy', maturity_assessment: 'Security Maturity' };

    container.innerHTML = list.map(c => {
      const pid = 'cg-' + c.client_id;
      const isExpanded = localStorage.getItem(`cg_exp_${c.client_id}`) === 'true';

      return `
        <div class="client-group">
          <div class="client-group-header" onclick="toggleGroup('${pid}', ${c.client_id})">
            <div style="display:flex; align-items:center; gap:12px; font-weight:700;">
              <svg id="arr-${c.client_id}" class="cg-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:14px; height:14px; transform:${isExpanded ? 'rotate(90deg)' : 'none'};"><polyline points="9 6 15 12 9 18"/></svg>
              <span>${esc(c.client_name)}</span>
              ${c.engagement_reference ? `<span style="font-size:10px; font-weight:600; color:#a5b4fc; background:rgba(99,102,241,0.12); padding:2px 8px; border-radius:6px;">${esc(c.engagement_reference)}</span>` : ''}
              ${c.engagement_info ? `<span style="font-size:11px; color:var(--muted); font-style:italic; font-weight:400;">${esc(c.engagement_info)}</span>` : ''}
            </div>
            <div style="display:flex; align-items:center; gap:12px; font-size:12px; color:var(--muted);">
              <span>${c.projects.length} engagement${c.projects.length !== 1 ? 's' : ''}</span>
            </div>
          </div>
          <div class="client-group-table ${isExpanded ? 'open' : ''}" id="${pid}">
            ${c.projects.length === 0 
              ? `<div style="padding:16px 20px; color:var(--muted); font-size:12px;">No active engagements. Click "New Engagement" to add one.</div>`
              : `<table>
                  <thead>
                    <tr>
                      <th>Engagement</th>
                      <th>Service</th>
                      <th>Lead Consultant</th>
                      <th>Kickoff</th>
                      <th>Target Initial</th>
                      <th>Target Final</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${c.projects.map(p => `
                      <tr>
                        <td style="font-weight:600; color:var(--accent2);">${esc(p.project_name)}</td>
                        <td><span class="badge badge-api">${sl[p.service] || p.service || '—'}</span></td>
                        <td>${esc(p.engineer_name || '—')}</td>
                        <td style="font-size:12px; color:var(--muted);">${fmt(p.kickoff_date)}</td>
                        <td style="font-size:12px; color:var(--muted);">${fmt(p.initial_report_date)}</td>
                        <td style="font-size:12px; color:var(--muted);">${fmt(p.final_report_date)}</td>
                        <td>
                          <div style="display:flex; gap:6px;">
                            <button class="btn-ghost" onclick="openCreateProject(true, ${jsa(p)})" style="padding:4px 8px; font-size:11px; flex:none;">Edit</button>
                            <button class="btn-ghost" onclick="openHighlightModal(${p.project_id}, ${jsa(p.highlight_text)})" style="padding:4px 8px; font-size:11px; flex:none;">Highlight</button>
                          </div>
                        </td>
                      </tr>
                    `).join('')}
                  </tbody>
                </table>`
            }
          </div>
        </div>
      `;
    }).join('');
  }

  function filterProjects() {
    renderClientGroups();
  }

  function toggleGroup(id, clientId) {
    const el = document.getElementById(id);
    const arr = document.getElementById('arr-' + clientId);
    if (!el) return;
    const isOpen = el.classList.toggle('open');
    if (arr) arr.style.transform = isOpen ? 'rotate(90deg)' : 'none';
    localStorage.setItem(`cg_exp_${clientId}`, isOpen ? 'true' : 'false');
  }

  // ── Mandays & Date logic helpers ──────────────────────────────────────────────
  let _picCount = 1;
  function _onResourceCountChange() {
    const count = parseInt(document.getElementById('cp-resource-count').value);
    _picCount = count;
    for (let i = 2; i <= 10; i++) {
      const wrap = document.getElementById(`cp-pic-${i}-wrap`);
      if (wrap) wrap.style.display = i <= count ? 'block' : 'none';
    }
    onMandaysParamChanged();
  }

  function onAssessmentInput() {
    onMandaysParamChanged();
  }

  function onMandaysParamChanged() {
    const startStr = document.getElementById('cp-start-date').value;
    const mdAssessment = parseFloat(document.getElementById('cp-md-assessment').value) || 0;
    const mdInitialReport = parseFloat(document.getElementById('cp-md-initial-report').value) || 1;
    const totalMd = mdAssessment + mdInitialReport;

    if (!startStr) {
      document.getElementById('cp-initial').value = '';
      return;
    }

    const numPic = _picCount;
    const perPersonMd = totalMd / numPic;

    let cur = new Date(startStr);
    let workingDaysAdded = 0;
    const targetDays = Math.ceil(perPersonMd);

    while (workingDaysAdded < targetDays) {
      const iso = cur.toLocaleDateString('en-CA');
      const dow = cur.getDay();
      if (dow !== 0 && dow !== 6 && !idHolidaySet.has(iso)) {
        workingDaysAdded++;
      }
      if (workingDaysAdded < targetDays) {
        cur.setDate(cur.getDate() + 1);
      }
    }

    document.getElementById('cp-initial').value = cur.toLocaleDateString('en-CA');
  }

  function _onPastProjectChange() {
    const isPast = document.getElementById('cp-is-past-project').checked;
    document.getElementById('cp-actual-end-wrap').style.display = isPast ? 'block' : 'none';
  }

  function _onServiceChange() {
    const svc = document.getElementById('cp-service').value;
    document.getElementById('cp-service-custom').style.display = svc === '__other__' ? 'block' : 'none';
  }

  // ── Project Create / Edit Dialog Tabs ──────────────────────────────────────────
  let _activeNeTab = 'client';
  let _selectedClientId = null;
  let _editingProjectId = null;

  function switchNeTab(tab) {
    if (tab === 'project' && !_selectedClientId && !document.getElementById('ne-client-name').value.trim()) {
      showToast('Please select or add a client first', 'error');
      return;
    }
    _activeNeTab = tab;
    document.getElementById('ne-client-section').style.display = tab === 'client' ? 'block' : 'none';
    document.getElementById('ne-project-section').style.display = tab === 'project' ? 'block' : 'none';

    const tabClient = document.getElementById('ne-tab-client');
    const tabProj = document.getElementById('ne-tab-project');
    if (tab === 'client') {
      tabClient.style.background = 'rgba(99,102,241,0.1)'; tabClient.style.color = 'var(--text)'; tabClient.style.opacity = '1';
      tabProj.style.background = 'transparent'; tabProj.style.color = 'var(--muted)'; tabProj.style.opacity = '0.5';
    } else {
      tabProj.style.background = 'rgba(99,102,241,0.1)'; tabProj.style.color = 'var(--text)'; tabProj.style.opacity = '1';
      tabClient.style.background = 'transparent'; tabClient.style.color = 'var(--muted)'; tabClient.style.opacity = '0.5';
    }
  }

  function validateAndGoToProject() {
    const customClientName = document.getElementById('ne-client-name').value.trim();
    if (!_selectedClientId && !customClientName) {
      showToast('Select an existing client or enter a new client name', 'error');
      return;
    }
    switchNeTab('project');
  }

  async function openCreateProject(isEdit = false, proj = null) {
    _editingProjectId = isEdit ? proj.project_id : null;
    _selectedClientId = isEdit ? proj.client_id : null;
    _activeNeTab = 'client';
    _picCount = 1;

    document.getElementById('modal-create-project-title').textContent = isEdit ? 'Edit IT Audit Engagement' : 'New IT Audit Entry';
    document.getElementById('cp-err').style.display = 'none';

    // Populate engineers dropdowns
    const dropdownIds = ['cp-engineer', 'cp-assist', 'cp-engineer-3', 'cp-engineer-4', 'cp-engineer-5', 'cp-engineer-6', 'cp-engineer-7', 'cp-engineer-8', 'cp-engineer-9', 'cp-engineer-10'];
    dropdownIds.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.innerHTML = '<option value="">— Select Consultant —</option>';
      _allEngineers.forEach(eng => {
        const opt = document.createElement('option');
        opt.value = eng.id;
        opt.textContent = eng.display_name;
        el.appendChild(opt);
      });
    });

    // Populate client list
    await loadClientSelectCards();

    // Reset fields
    document.getElementById('cp-name').value = '';
    document.getElementById('cp-regulatory-ref').value = '';
    document.getElementById('cp-audit-scope').value = '';
    document.getElementById('cp-audit-objective').value = '';
    document.getElementById('cp-service').value = 'it_audit';
    document.getElementById('cp-service-custom').value = '';
    document.getElementById('cp-service-custom').style.display = 'none';
    document.getElementById('cp-resource-count').value = '1';
    _onResourceCountChange();

    document.getElementById('cp-audit-period-start').value = '';
    document.getElementById('cp-audit-period-end').value = '';
    document.getElementById('cp-kickoff').value = '';
    document.getElementById('cp-start-date').value = '';
    document.getElementById('cp-md-assessment').value = '10';
    document.getElementById('cp-md-initial-report').value = '3';
    document.getElementById('cp-initial').value = '';
    document.getElementById('cp-is-past-project').checked = false;
    document.getElementById('cp-actual-end').value = '';
    document.getElementById('cp-actual-end-wrap').style.display = 'none';
    document.getElementById('cp-links-container').innerHTML = '';

    // If Edit Mode
    if (isEdit && proj) {
      document.getElementById('ne-tab-bar').style.display = 'none';
      switchNeTab('project');

      document.getElementById('cp-name').value = proj.project_name || '';
      
      const standardServices = ['it_audit', 'pdp', 'maturity_assessment'];
      if (standardServices.includes(proj.service)) {
        document.getElementById('cp-service').value = proj.service;
      } else {
        document.getElementById('cp-service').value = '__other__';
        document.getElementById('cp-service-custom').value = proj.service || '';
        document.getElementById('cp-service-custom').style.display = 'block';
      }

      // Populate audit metadata if present
      if (proj.audit_metadata) {
        try {
          const meta = JSON.parse(proj.audit_metadata);
          document.getElementById('cp-regulatory-ref').value = meta.regulatory_reference || '';
          document.getElementById('cp-audit-scope').value = meta.audit_scope || '';
          document.getElementById('cp-audit-objective').value = meta.audit_objective || '';
          document.getElementById('cp-audit-period-start').value = meta.audit_period_start || '';
          document.getElementById('cp-audit-period-end').value = meta.audit_period_end || '';
        } catch {}
      }

      // Count resources
      let assessorCount = 1;
      const assessorSlots = [
        proj.assigned_engineer_id, proj.assist_engineer_id, proj.engineer_3_id, proj.engineer_4_id,
        proj.engineer_5_id, proj.engineer_6_id, proj.engineer_7_id, proj.engineer_8_id,
        proj.engineer_9_id, proj.engineer_10_id
      ];
      assessorSlots.forEach((id, idx) => {
        if (id) assessorCount = idx + 1;
      });

      document.getElementById('cp-resource-count').value = assessorCount;
      _onResourceCountChange();

      document.getElementById('cp-engineer').value = proj.assigned_engineer_id || '';
      document.getElementById('cp-assist').value = proj.assist_engineer_id || '';
      document.getElementById('cp-engineer-3').value = proj.engineer_3_id || '';
      document.getElementById('cp-engineer-4').value = proj.engineer_4_id || '';
      document.getElementById('cp-engineer-5').value = proj.engineer_5_id || '';
      document.getElementById('cp-engineer-6').value = proj.engineer_6_id || '';
      document.getElementById('cp-engineer-7').value = proj.engineer_7_id || '';
      document.getElementById('cp-engineer-8').value = proj.engineer_8_id || '';
      document.getElementById('cp-engineer-9').value = proj.engineer_9_id || '';
      document.getElementById('cp-engineer-10').value = proj.engineer_10_id || '';

      document.getElementById('cp-kickoff').value = proj.kickoff_date ? proj.kickoff_date.split('T')[0] : '';
      document.getElementById('cp-start-date').value = proj.start_date ? proj.start_date.split('T')[0] : '';
      document.getElementById('cp-md-assessment').value = proj.mandays_assessment || 0;
      document.getElementById('cp-md-initial-report').value = proj.mandays_initial_report || 1;
      
      onMandaysParamChanged();

      if (proj.is_archived) {
        document.getElementById('cp-is-past-project').checked = true;
        _onPastProjectChange();
        document.getElementById('cp-actual-end').value = proj.actual_completed_at ? proj.actual_completed_at.split('T')[0] : '';
      }

      if (proj.project_links) {
        try {
          const links = JSON.parse(proj.project_links);
          populateProjectLinks(links);
        } catch { }
      }
    } else {
      document.getElementById('ne-tab-bar').style.display = 'flex';
      switchNeTab('client');
    }

    document.getElementById('modal-create-project').classList.add('open');
  }

  async function loadClientSelectCards() {
    try {
      const clients = await apiFetch('/api/clients?team=itaudit');
      const listEl = document.getElementById('ne-client-list');
      if (!listEl) return;
      if (!clients.length) {
        listEl.innerHTML = '<div style="padding:20px; text-align:center; color:var(--muted); font-size:12px;">No clients created. Use the form below to create one.</div>';
        return;
      }

      listEl.innerHTML = clients.map(c => `
        <div class="ne-client-card" id="ne-ccard-${c.id}" onclick="selectNeClient(${c.id})" style="border:1px solid var(--border); border-radius:8px; padding:12px 16px; cursor:pointer; background:rgba(255,255,255,0.02); transition:all 0.1s;">
          <div style="font-weight:600; font-size:13px; color:var(--text);">${esc(c.name)}</div>
          ${c.engagement_reference ? `<div style="font-size:11px; color:var(--muted); margin-top:4px;">Reference: ${esc(c.engagement_reference)}</div>` : ''}
        </div>
      `).join('');
    } catch { }
  }

  window.selectNeClient = function(id) {
    _selectedClientId = id;
    document.querySelectorAll('.ne-client-card').forEach(el => {
      el.style.borderColor = 'var(--border)';
      el.style.background = 'rgba(255,255,255,0.02)';
    });
    const sel = document.getElementById('ne-ccard-' + id);
    if (sel) {
      sel.style.borderColor = 'var(--accent)';
      sel.style.background = 'rgba(99,102,241,0.05)';
    }
    document.getElementById('ne-new-client-fields').style.display = 'none';
    document.getElementById('ne-client-name').value = '';
  };

  function _toggleNewClientForm() {
    _selectedClientId = null;
    document.querySelectorAll('.ne-client-card').forEach(el => {
      el.style.borderColor = 'var(--border)';
      el.style.background = 'rgba(255,255,255,0.02)';
    });

    const fields = document.getElementById('ne-new-client-fields');
    const isShowing = fields.style.display === 'block';
    fields.style.display = isShowing ? 'none' : 'block';
    if (!isShowing) document.getElementById('ne-client-name').focus();
  }

  function _filterClientCards() {
    const q = document.getElementById('ne-client-search').value.toLowerCase();
    document.querySelectorAll('.ne-client-card').forEach(card => {
      const txt = card.textContent.toLowerCase();
      card.style.display = txt.includes(q) ? 'block' : 'none';
    });
  }

  function _onEngRefChange() {
    const ref = document.getElementById('ne-engagement-ref').value;
    document.getElementById('ne-engagement-ref-custom').style.display = ref === '__other__' ? 'block' : 'none';
  }

  function _updateProjectTabState() {}

  // ── Links inputs ───────────────────────────────────────────────────────────────
  function addProjectLink(title = '', url = '') {
    const container = document.getElementById('cp-links-container');
    if (!container) return;
    const id = 'link-row-' + Date.now() + Math.random().toString(36).substr(2, 5);
    const div = document.createElement('div');
    div.id = id;
    div.style = 'display:flex;gap:8px;align-items:center;';
    div.innerHTML = `
      <input class="cp-link-title" placeholder="Link Title" value="${escA(title)}" style="flex:1;padding:8px 12px;font-size:12px;">
      <input class="cp-link-url" placeholder="https://..." value="${escA(url)}" style="flex:2;padding:8px 12px;font-size:12px;">
      <button type="button" class="icon-btn" onclick="removeProjectLink('${id}')" style="color:var(--red);flex:none;padding:8px;">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:14px;height:14px;"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
      </button>
    `;
    container.appendChild(div);
  }

  function removeProjectLink(id) {
    document.getElementById(id)?.remove();
  }

  function collectProjectLinks() {
    const links = [];
    document.querySelectorAll('#cp-links-container > div').forEach(row => {
      const title = row.querySelector('.cp-link-title').value.trim();
      const url = row.querySelector('.cp-link-url').value.trim();
      if (title && url) links.push({ title, url });
    });
    return links;
  }

  function populateProjectLinks(links) {
    document.getElementById('cp-links-container').innerHTML = '';
    if (Array.isArray(links)) {
      links.forEach(l => addProjectLink(l.title, l.url));
    }
  }

  // ── Project submission ──────────────────────────────────────────────────────────
  async function submitNewEntry() {
    const errEl = document.getElementById('cp-err');
    errEl.style.display = 'none';

    try {
      const isEdit = _editingProjectId !== null;

      const name = document.getElementById('cp-name').value.trim();
      const svcVal = document.getElementById('cp-service').value;
      const service = svcVal === '__other__' ? document.getElementById('cp-service-custom').value.trim() : svcVal;

      const regulatory_reference = document.getElementById('cp-regulatory-ref').value.trim();
      const audit_scope = document.getElementById('cp-audit-scope').value.trim();
      const audit_objective = document.getElementById('cp-audit-objective').value.trim();
      const audit_period_start = document.getElementById('cp-audit-period-start').value;
      const audit_period_end = document.getElementById('cp-audit-period-end').value;

      const assigned_engineer_id = Number(document.getElementById('cp-engineer').value) || null;
      const assist_engineer_id = Number(document.getElementById('cp-assist').value) || null;
      const engineer_3_id = Number(document.getElementById('cp-engineer-3').value) || null;
      const engineer_4_id = Number(document.getElementById('cp-engineer-4').value) || null;
      const engineer_5_id = Number(document.getElementById('cp-engineer-5').value) || null;
      const engineer_6_id = Number(document.getElementById('cp-engineer-6').value) || null;
      const engineer_7_id = Number(document.getElementById('cp-engineer-7').value) || null;
      const engineer_8_id = Number(document.getElementById('cp-engineer-8').value) || null;
      const engineer_9_id = Number(document.getElementById('cp-engineer-9').value) || null;
      const engineer_10_id = Number(document.getElementById('cp-engineer-10').value) || null;

      const kickoff_date = document.getElementById('cp-kickoff').value || null;
      const start_date = document.getElementById('cp-start-date').value || null;
      const mandays_assessment = parseFloat(document.getElementById('cp-md-assessment').value) || 0;
      const mandays_initial_report = parseFloat(document.getElementById('cp-md-initial-report').value) || 1;
      const initial_report_date = document.getElementById('cp-initial').value || null;

      const is_past_project = document.getElementById('cp-is-past-project').checked ? 1 : 0;
      const actual_end_date = document.getElementById('cp-actual-end').value || null;
      const project_links = collectProjectLinks();

      if (!name) throw new Error('Engagement Name is required.');
      if (!audit_scope) throw new Error('Audit Scope is required.');
      if (!audit_objective) throw new Error('Audit Objective is required.');

      if (!isEdit && !_selectedClientId) {
        const clientName = document.getElementById('ne-client-name').value.trim();
        if (!clientName) throw new Error('Please select or specify a client.');

        const engRefVal = document.getElementById('ne-engagement-ref').value;
        const engagement_reference = engRefVal === '__other__' ? document.getElementById('ne-engagement-ref-custom').value.trim() : engRefVal;
        const engagement_info = document.getElementById('ne-engagement-info').value.trim();

        const cRes = await apiFetch('/api/clients', 'POST', { name: clientName, engagement_reference, engagement_info, team: 'itaudit' });
        _selectedClientId = cRes.id;
      }

      // Serialize audit specific fields into audit_metadata
      const audit_metadata = JSON.stringify({
        audit_scope,
        audit_objective,
        regulatory_reference,
        audit_period_start,
        audit_period_end
      });

      const body = {
        name,
        project_type: 'audit',
        project_method: 'blackbox', // fallback
        assigned_engineer_id, assist_engineer_id, engineer_3_id, engineer_4_id, engineer_5_id, engineer_6_id, engineer_7_id, engineer_8_id, engineer_9_id, engineer_10_id,
        kickoff_date, start_date, mandays_assessment, mandays_initial_report, initial_report_date,
        is_past_project, actual_end_date, project_links,
        team: 'itaudit', service, audit_metadata
      };

      if (isEdit) {
        await apiFetch(`/api/projects/${_editingProjectId}`, 'PUT', body);
        showToast('Engagement updated successfully', 'success');
      } else {
        await apiFetch(`/api/clients/${_selectedClientId}/projects`, 'POST', body);
        showToast('Engagement created successfully', 'success');
      }

      document.getElementById('modal-create-project').classList.remove('open');
      navigate(localStorage.getItem('vulnvault_itaudit_active_tab') || 'dashboard');

    } catch (e) {
      errEl.textContent = e.message;
      errEl.style.display = 'block';
    }
  }

  // ── Kanban Board logic ─────────────────────────────────────────────────────────
  async function loadBoard() {
    const boardEl = document.getElementById('board-container');
    if (!boardEl) return;
    boardEl.innerHTML = '<div class="empty-state">Loading board data...</div>';

    try {
      [_boardProjects, _boardStatuses] = await Promise.all([
        apiFetch('/api/board/projects?team=itaudit'),
        apiFetch('/api/board-statuses?team=itaudit')
      ]);

      renderBoard();
    } catch (e) {
      boardEl.innerHTML = `<div class="empty-state">Error: ${e.message}</div>`;
    }
  }

  function renderBoard() {
    const boardEl = document.getElementById('board-container');
    if (!boardEl) return;
    boardEl.innerHTML = '';

    const statusMap = new Map();
    _boardStatuses.forEach(s => statusMap.set(s.id, { info: s, projects: [] }));
    statusMap.set(-1, { info: { id: -1, name: 'Uncategorized', color: '#64748b' }, projects: [] });

    _boardProjects.forEach(p => {
      const catId = p.board_status_id || -1;
      if (statusMap.has(catId)) statusMap.get(catId).projects.push(p);
      else statusMap.get(-1).projects.push(p);
    });

    const sl = { it_audit: 'ITGC Audit', pdp: 'PDP Privacy', maturity_assessment: 'Security Maturity' };

    [...statusMap.values()].forEach(col => {
      if (col.info.id === -1 && col.projects.length === 0) return;

      const colEl = document.createElement('div');
      colEl.className = 'board-column';
      colEl.style = `flex:0 0 280px; background:rgba(255,255,255,0.01); border:1px solid var(--border); border-radius:12px; display:flex; flex-direction:column; max-height:80vh;`;

      const colHeader = document.createElement('div');
      colHeader.style = `padding:14px 18px; display:flex; align-items:center; justify-content:space-between; border-bottom:1px solid var(--border); font-size:12px; font-weight:700;`;
      colHeader.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="display:block; width:8px; height:8px; border-radius:50%; background:${col.info.color};"></span>
          <span>${esc(col.info.name)}</span>
        </div>
        <span style="color:var(--muted); font-size:11px; font-weight:600; background:rgba(255,255,255,0.05); padding:2px 8px; border-radius:10px;">${col.projects.length}</span>
      `;
      colEl.appendChild(colHeader);

      const cardContainer = document.createElement('div');
      cardContainer.id = `board-col-${col.info.id}`;
      cardContainer.style = `flex:1; overflow-y:auto; padding:12px; display:flex; flex-direction:column; gap:10px; min-height:300px;`;
      cardContainer.ondragover = (e) => e.preventDefault();
      cardContainer.ondrop = (e) => onCardDrop(e, col.info.id);

      col.projects.forEach(p => {
        const card = document.createElement('div');
        card.className = 'board-card';
        card.draggable = true;
        card.ondragstart = (e) => e.dataTransfer.setData('text/plain', p.project_id);
        card.onclick = () => openBoardDetail(p);
        card.style = `padding:14px; background:var(--card); border:1px solid var(--border); border-radius:8px; cursor:grab; transition:all 0.15s;`;
        card.onmouseover = () => { card.style.borderColor = 'rgba(255,255,255,0.2)'; card.style.transform = 'translateY(-2px)'; };
        card.onmouseout = () => { card.style.borderColor = 'var(--border)'; card.style.transform = 'none'; };

        card.innerHTML = `
          <div style="font-size:11px; font-weight:600; color:var(--muted); margin-bottom:4px;">${esc(p.client_name)}</div>
          <div style="font-weight:700; font-size:13px; color:var(--text); margin-bottom:8px; line-height:1.4;">${esc(p.project_name)}</div>
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span class="badge badge-api" style="font-size:9px; padding:2px 6px;">${sl[p.service] || 'Audit'}</span>
            <span style="font-size:10px; color:var(--muted); font-weight:600;">Lead: ${esc(p.engineer_name ? p.engineer_name.split(' ')[0] : '—')}</span>
          </div>
        `;
        cardContainer.appendChild(card);
      });

      colEl.appendChild(cardContainer);
      boardEl.appendChild(colEl);
    });
  }

  async function onCardDrop(e, colId) {
    e.preventDefault();
    const projId = e.dataTransfer.getData('text/plain');
    if (!projId) return;

    try {
      await apiFetch(`/api/projects/${projId}/board-status`, 'PATCH', { board_status_id: colId === -1 ? null : colId });
      loadBoard();
    } catch (err) {
      showToast('Failed to update board status: ' + err.message, 'error');
    }
  }

  // ── Kanban board setup modal ───────────────────────────────────────────────────
  async function openBoardSetup() {
    const listEl = document.getElementById('setup-status-list');
    if (!listEl) return;
    listEl.innerHTML = '<div style="padding:10px; text-align:center;">Loading...</div>';

    try {
      _boardStatuses = await apiFetch('/api/board-statuses?team=itaudit');
      renderSetupList();
      document.getElementById('modal-board-setup').classList.add('open');
    } catch (e) {
      showToast('Failed to load board status list: ' + e.message, 'error');
    }
  }

  function renderSetupList() {
    const listEl = document.getElementById('setup-status-list');
    if (!listEl) return;
    listEl.innerHTML = '';

    if (!_boardStatuses.length) {
      listEl.innerHTML = '<div style="padding:12px; text-align:center; color:var(--muted); font-size:12px;">No custom status columns. Add one below.</div>';
      return;
    }

    _boardStatuses.forEach((s, idx) => {
      const tile = document.createElement('div');
      tile.className = 'status-setup-tile';
      tile.draggable = true;
      tile.ondragstart = (e) => e.dataTransfer.setData('text/plain', idx);
      tile.ondragover = (e) => e.preventDefault();
      tile.ondrop = (e) => reorderStatus(e, idx);
      tile.style = `display:flex; align-items:center; justify-content:space-between; padding:10px 14px; background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:8px; cursor:grab; margin-bottom:6px;`;
      tile.innerHTML = `
        <div style="display:flex; align-items:center; gap:10px; font-size:12px; font-weight:700;">
          <span style="color:var(--muted);">⋮⋮</span>
          <span style="display:block; width:10px; height:10px; border-radius:50%; background:${s.color};"></span>
          <span>${esc(s.name)}</span>
        </div>
        <button class="icon-btn" onclick="deleteBoardStatus(${s.id})" style="color:var(--red); padding:4px;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:13px;height:13px;"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
        </button>
      `;
      listEl.appendChild(tile);
    });
  }

  function reorderStatus(e, targetIdx) {
    e.preventDefault();
    const sourceIdx = parseInt(e.dataTransfer.getData('text/plain'));
    if (isNaN(sourceIdx) || sourceIdx === targetIdx) return;

    const [moved] = _boardStatuses.splice(sourceIdx, 1);
    _boardStatuses.splice(targetIdx, 0, moved);
    renderSetupList();
  }

  async function addBoardStatus() {
    const nameInput = document.getElementById('setup-new-name');
    const colorInput = document.getElementById('setup-new-color');
    const name = nameInput.value.trim();
    const color = colorInput.value;

    if (!name) {
      showToast('Status title cannot be empty', 'error');
      return;
    }

    try {
      const order = _boardStatuses.length;
      await apiFetch('/api/board-statuses', 'POST', { name, color, order_num: order, team: 'itaudit' });
      nameInput.value = '';

      _boardStatuses = await apiFetch('/api/board-statuses?team=itaudit');
      renderSetupList();
      loadBoard();
    } catch (e) {
      showToast('Failed to add board status: ' + e.message, 'error');
    }
  }

  window.deleteBoardStatus = async function(id) {
    const ok = await customConfirm('Delete Column', 'Are you sure you want to delete this status column? Projects in this status will become Uncategorized.', 'Delete Column', 'danger');
    if (!ok) return;

    try {
      await apiFetch(`/api/board-statuses/${id}`, 'DELETE');
      _boardStatuses = await apiFetch('/api/board-statuses?team=itaudit');
      renderSetupList();
      loadBoard();
    } catch (e) {
      showToast('Failed to delete status column: ' + e.message, 'error');
    }
  };

  async function saveBoardOrder() {
    try {
      const ordered_ids = _boardStatuses.map(s => s.id);
      await apiFetch('/api/board-statuses/reorder', 'PUT', { ordered_ids, team: 'itaudit' });
      showToast('Sequence saved successfully');
      document.getElementById('modal-board-setup').classList.remove('open');
      loadBoard();
    } catch (e) {
      showToast('Failed to reorder: ' + e.message, 'error');
    }
  }

  // ── Kanban detail card modal ───────────────────────────────────────────────────
  function openBoardDetail(p) {
    const titleEl = document.getElementById('bd-title');
    const bodyEl = document.getElementById('bd-body');
    if (!titleEl || !bodyEl) return;

    titleEl.textContent = p.project_name;
    const fmt = d => d ? new Date(d).toLocaleDateString('id-ID', { day: 'numeric', month: 'short', year: 'numeric' }) : '—';
    const sl = { it_audit: 'ITGC Audit', pdp: 'PDP Privacy', maturity_assessment: 'Security Maturity' };

    let linksHtml = '<div style="color:var(--muted); font-size:12px;">No resource links uploaded.</div>';
    if (p.project_links) {
      try {
        const arr = JSON.parse(p.project_links);
        if (arr.length) {
          linksHtml = arr.map(l => `
            <a href="${escA(safeUrl(l.url))}" target="_blank" style="display:inline-flex; align-items:center; gap:4px; font-size:12px; color:var(--accent); text-decoration:underline; font-weight:600; margin-right:12px;">
              <span>🔗</span> ${esc(l.title)}
            </a>
          `).join('');
        }
      } catch {}
    }

    let metaHtml = '';
    if (p.audit_metadata) {
      try {
        const meta = JSON.parse(p.audit_metadata);
        metaHtml = `
          <div style="grid-column:1/-1; border-top:1px solid var(--border); padding-top:16px; margin-top:8px;">
            <div style="font-size:11px; color:var(--muted); margin-bottom:8px;">AUDIT DETAILS</div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
              <div><div style="font-size:11px; color:var(--muted)">REGULATION / REFERENCE</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${esc(meta.regulatory_reference || '—')}</div></div>
              <div><div style="font-size:11px; color:var(--muted)">AUDIT PERIOD</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${fmt(meta.audit_period_start)} to ${fmt(meta.audit_period_end)}</div></div>
              <div style="grid-column:1/-1;"><div style="font-size:11px; color:var(--muted)">SCOPE</div><div style="font-size:12px; color:var(--text); margin-top:4px; line-height:1.5; white-space:pre-wrap;">${esc(meta.audit_scope || '—')}</div></div>
              <div style="grid-column:1/-1;"><div style="font-size:11px; color:var(--muted)">OBJECTIVES</div><div style="font-size:12px; color:var(--text); margin-top:4px; line-height:1.5; white-space:pre-wrap;">${esc(meta.audit_objective || '—')}</div></div>
            </div>
          </div>
        `;
      } catch {}
    }

    bodyEl.innerHTML = `
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:20px;">
        <div><div style="font-size:11px; color:var(--muted)">CLIENT</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${esc(p.client_name)}</div></div>
        <div><div style="font-size:11px; color:var(--muted)">SERVICE</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;"><span class="badge badge-api">${sl[p.service] || p.service || 'IT Audit'}</span></div></div>
        <div><div style="font-size:11px; color:var(--muted)">KICK OFF</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${fmt(p.kickoff_date)}</div></div>
        <div><div style="font-size:11px; color:var(--muted)">START DATE</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${fmt(p.start_date)}</div></div>
        <div><div style="font-size:11px; color:var(--muted)">TARGET INITIAL REPORT</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${fmt(p.initial_report_date)}</div></div>
        <div><div style="font-size:11px; color:var(--muted)">TARGET FINAL REPORT</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${fmt(p.final_report_date)}</div></div>
        <div><div style="font-size:11px; color:var(--muted)">AUDIT MANDAYS</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${p.mandays_assessment || 0} hari</div></div>
        <div></div>
        <div style="grid-column:1/-1;"><div style="font-size:11px; color:var(--muted)">LEAD CONSULTANT &amp; PICs</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${esc(p.engineer_name || '—')}</div></div>
      </div>
      ${metaHtml}
      <div style="border-top:1px solid var(--border); padding-top:16px; margin-top:16px;">
        <div style="font-size:11px; color:var(--muted); margin-bottom:8px;">RESOURCE / EVIDENCE LINKS</div>
        <div>${linksHtml}</div>
      </div>
      ${p.board_status_id === -1 ? `
        <div style="border-top:1px solid var(--border); padding-top:16px; margin-top:16px;">
          <button class="btn-primary" onclick="archiveProjectFromBoard(${p.project_id})" style="width:100%; background:rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.3); color:#10b981; justify-content:center;">
            Archive Audit
          </button>
        </div>
      ` : ''}
    `;

    document.getElementById('modal-board-detail').classList.add('open');
  }

  // ── Consultant workload allocation capacity view ────────────────────────────────
  let _allocationMonths = [];
  let _allocationMonthIdx = 0;
  const _monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

  async function loadAllocation() {
    const listEl = document.getElementById('capacity-list');
    if (!listEl) return;
    listEl.innerHTML = '<div class="empty-state">Loading allocation details...</div>';

    try {
      const summary = await apiFetch('/api/dashboard/summary?team=itaudit');
      buildAllocationMonths(summary);
      renderCapacityView(summary);
    } catch (e) {
      listEl.innerHTML = `<div class="empty-state">Error: ${e.message}</div>`;
    }
  }

  function buildAllocationMonths(summary) {
    const months = new Set();
    const today = new Date();

    summary.forEach(r => {
      [r.kickoff_date, r.start_date, r.initial_report_date, r.final_report_date].filter(Boolean).forEach(d => {
        const dt = new Date(d);
        if (!isNaN(dt.getTime())) {
          months.add(`${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}`);
        }
      });
    });

    months.add(`${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}`);
    const next = new Date(today.getFullYear(), today.getMonth() + 1, 1);
    months.add(`${next.getFullYear()}-${String(next.getMonth() + 1).padStart(2, '0')}`);

    _allocationMonths = [...months].sort();
    const curVal = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}`;
    _allocationMonthIdx = Math.max(0, _allocationMonths.indexOf(curVal));
    updateAllocationMonthLabel();
  }

  function updateAllocationMonthLabel() {
    const m = _allocationMonths[_allocationMonthIdx];
    if (!m) return;
    const [y, mon] = m.split('-');
    document.getElementById('capacity-month-label').textContent = `${_monthNames[Number(mon) - 1]} ${y}`;
  }

  function shiftAllocationMonth(dir) {
    const newIdx = _allocationMonthIdx + dir;
    if (newIdx < 0 || newIdx >= _allocationMonths.length) return;
    _allocationMonthIdx = newIdx;
    updateAllocationMonthLabel();
    loadAllocation();
  }

  function renderCapacityView(summary) {
    const listEl = document.getElementById('capacity-list');
    if (!listEl) return;

    const m = _allocationMonths[_allocationMonthIdx];
    if (!m) return;
    const [y, mon] = m.split('-');
    const year = Number(y), month = Number(mon) - 1;
    const { workdays } = getWorkdaysInMonth(year, month);

    const engMap = new Map();
    _allEngineers.forEach(e => engMap.set(e.id, { name: e.display_name, used: 0, projects: [] }));

    summary.forEach(r => {
      if (r.project_id && r.kickoff_date && r.mandays_assessment > 0) {
        const md = _assessmentMandaysInMonth(r, year, month);
        if (md > 0) {
          const hasPic = r.assigned_engineer_id, hasAssist = r.assist_engineer_id;
          const numEng = (hasPic ? 1 : 0) + (hasAssist ? 1 : 0);
          const perPerson = numEng > 0 ? md / numEng : md;

          const pName = `${r.client_name} - ${r.project_name} (${perPerson.toFixed(1)} d)`;

          if (hasPic && engMap.has(r.assigned_engineer_id)) {
            engMap.get(r.assigned_engineer_id).used += perPerson;
            engMap.get(r.assigned_engineer_id).projects.push(pName);
          }
          if (hasAssist && engMap.has(r.assist_engineer_id)) {
            engMap.get(r.assist_engineer_id).used += perPerson;
            engMap.get(r.assist_engineer_id).projects.push(pName);
          }
        }
      }
    });

    const list = [...engMap.values()].sort((a, b) => b.used - a.used);
    if (!list.length) {
      listEl.innerHTML = '<div class="empty-state">No consultants defined for the IT Audit team.</div>';
      return;
    }

    listEl.innerHTML = list.map(e => {
      const pct = Math.round((e.used / workdays) * 100);
      let barClass = 'green';
      if (pct > 80) barClass = 'yellow';
      if (pct > 100) barClass = 'red';
      const fillWidth = Math.min(100, pct);
      const subNotes = e.projects.length ? e.projects.join(', ') : 'No engagements staffed';

      return `
        <div class="capacity-row" style="border-bottom:1px solid var(--border); padding:16px 20px;">
          <div class="capacity-row-top" style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <div style="font-weight:700; color:var(--text);">${esc(e.name)}</div>
            <div style="color:var(--muted); font-size:12px;">Allocated: <strong>${e.used.toFixed(1)} / ${workdays} d</strong> (${pct}%)</div>
          </div>
          <div class="capacity-bar-track" style="height:8px; margin-bottom:8px;">
            <div class="capacity-bar-fill ${barClass}" style="width:${fillWidth}%; height:100%;"></div>
          </div>
          <div style="font-size:11px; color:var(--muted); line-height:1.4;">Engagements: ${esc(subNotes)}</div>
        </div>
      `;
    }).join('');
  }

  function _assessmentMandaysInMonth(r, year, month) {
    const dtStart = r.start_date || r.kickoff_date;
    if (!dtStart || !(r.mandays_assessment > 0)) return 0;

    const ko = new Date(dtStart);
    let curYear = ko.getFullYear();
    let curMonth = ko.getMonth();
    let remaining = r.mandays_assessment;

    while (remaining > 0) {
      const days = getWorkdaysInMonth(curYear, curMonth);
      let avail = 0;
      if (curYear === ko.getFullYear() && curMonth === ko.getMonth()) {
        const overlap = workingDaysBetween(dtStart, new Date(curYear, curMonth + 1, 0).toLocaleDateString('en-CA')).days;
        avail = overlap;
      } else {
        avail = days.workdays;
      }

      const consumed = Math.min(remaining, avail);
      if (curYear === year && curMonth === month) {
        return consumed;
      }
      remaining -= consumed;
      curMonth++;
      if (curMonth > 11) { curMonth = 0; curYear++; }
      if (curYear > year + 2) break;
    }
    return 0;
  }

  // ── Highlight modal logic ──────────────────────────────────────────────────────
  let _hlProjId = null;
  function openHighlightModal(projId, currentText) {
    _hlProjId = projId;
    document.getElementById('hl-text').value = currentText || '';
    document.getElementById('hl-err').style.display = 'none';
    document.getElementById('modal-highlight').classList.add('open');
  }

  async function saveHighlight() {
    const txt = document.getElementById('hl-text').value.trim();
    try {
      await apiFetch(`/api/projects/${_hlProjId}/highlight`, 'PATCH', { highlight_text: txt });
      showToast('Highlight updated successfully');
      document.getElementById('modal-highlight').classList.remove('open');
      loadProjects();
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  // ── Archived projects listing ──────────────────────────────────────────────────
  async function loadArchived() {
    try {
      _archivedProjects = await apiFetch('/api/projects/archived?team=itaudit');
      renderArchivedProjects();
    } catch (e) {
      showToast('Failed to load archived projects: ' + e.message, 'error');
    }
  }

  function renderArchivedProjects() {
    const tbody = document.getElementById('archived-body');
    if (!tbody) return;

    const q = (document.getElementById('archived-search')?.value || '').toLowerCase();
    let list = _archivedProjects;

    if (q) {
      list = list.filter(p => (p.client_name || '').toLowerCase().includes(q) || (p.project_name || '').toLowerCase().includes(q));
    }

    if (!list.length) {
      tbody.innerHTML = '<tr><td colspan="7"><div class="empty-state">No archived audits found.</div></td></tr>';
      return;
    }

    const fmt = d => d ? new Date(d).toLocaleDateString('id-ID', { day: 'numeric', month: 'short', year: 'numeric' }) : '—';
    const sl = { it_audit: 'ITGC Audit', pdp: 'PDP Privacy', maturity_assessment: 'Security Maturity' };

    tbody.innerHTML = list.map(p => {
      let timelineBadge = '—';
      if (p.final_completed_at && p.final_report_date) {
        const onTrack = new Date(p.final_completed_at) <= new Date(p.final_report_date);
        timelineBadge = onTrack 
          ? '<span class="badge" style="background:rgba(34,197,94,0.1); color:var(--green)">On Track</span>' 
          : '<span class="badge" style="background:rgba(239,68,68,0.1); color:var(--red)">Delayed</span>';
      }

      return `
        <tr>
          <td><div style="font-weight:600; color:var(--text);">${esc(p.client_name)}</div></td>
          <td><div style="font-weight:500; color:var(--accent2);">${esc(p.project_name)}</div></td>
          <td><span class="badge badge-api">${sl[p.service] || p.service || '—'}</span></td>
          <td>${esc(p.engineer_name || '—')}</td>
          <td style="font-size:12px; color:var(--muted);">${fmt(p.final_completed_at || p.archived_at)}</td>
          <td>${timelineBadge}</td>
          <td>
            <button class="btn-ghost" onclick="restoreProjectFromArchive(${p.project_id})" style="padding:4px 8px; font-size:11px; font-weight:700; background:rgba(16,185,129,0.1); color:#10b981;">
              Restore
            </button>
          </td>
        </tr>
      `;
    }).join('');
  }

  function filterArchivedProjects() {
    renderArchivedProjects();
  }

  async function restoreProjectFromArchive(id) {
    const ok = await customConfirm('Restore Engagement', 'Restore this engagement back to the Kanban board as uncategorized?', 'Restore');
    if (!ok) return;

    try {
      await apiFetch(`/api/projects/${id}/restore`, 'PATCH');
      showToast('Engagement restored successfully');
      loadArchived();
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  async function archiveProjectFromBoard(id) {
    const ok = await customConfirm('Archive Engagement', 'Archive this engagement? It will be moved to the Archived section.', 'Archive');
    if (!ok) return;

    try {
      await apiFetch(`/api/projects/${id}/archive`, 'PATCH');
      showToast('Engagement archived successfully');
      document.getElementById('modal-board-detail').classList.remove('open');
      loadBoard();
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

})();
