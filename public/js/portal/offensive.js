/**
 * VulnVault — Offensive Security Portal Logic
 * Scoped specifically to ?team=offensive
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
  let _lastAiEstimate = null;
  let _staticEventsBound = false;

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
  window.updateCpMethodOptions = updateCpMethodOptions;
  window.openBoardSetup = openBoardSetup;
  window.addBoardStatus = addBoardStatus;
  window.deleteBoardStatus = deleteBoardStatus;
  window.saveBoardOrder = saveBoardOrder;
  window.shiftAllocationMonth = shiftAllocationMonth;
  window.saveAiApiKey = saveAiApiKey;
  window.clearAiApiKey = clearAiApiKey;
  window.runAiEstimate = runAiEstimate;
  window.useEstimateInProject = useEstimateInProject;
  window.updateAiMethodOptions = updateAiMethodOptions;
  window.updateAiDynamicFields = updateAiDynamicFields;
  window.filterArchivedProjects = filterArchivedProjects;
  window.openRetestModal = openRetestModal;
  window.submitRetest = submitRetest;
  window.openHighlightModal = openHighlightModal;
  window.generateHighlight = generateHighlight;
  window.saveHighlight = saveHighlight;
  window.toggleGroup = toggleGroup;
  window.archiveProjectFromBoard = archiveProjectFromBoard;
  window.restoreProjectFromArchive = restoreProjectFromArchive;

  function runUiAction(action, failureMessage) {
    Promise.resolve()
      .then(action)
      .catch(function (e) {
        showToast(failureMessage + ': ' + e.message, 'error');
      });
  }

  function bindStaticEventListeners() {
    if (_staticEventsBound) return;
    _staticEventsBound = true;

    document.getElementById('btn-new-project')?.addEventListener('click', function () {
      runUiAction(function () { return openCreateProject(false); }, 'Failed to open new project form');
    });
    document.getElementById('btn-board-setup')?.addEventListener('click', function () {
      runUiAction(openBoardSetup, 'Failed to open board setup');
    });
    document.getElementById('btn-add-status')?.addEventListener('click', function () {
      runUiAction(addBoardStatus, 'Failed to add flow');
    });
    document.getElementById('btn-save-board-order')?.addEventListener('click', function () {
      runUiAction(saveBoardOrder, 'Failed to save board sequence');
    });
    document.getElementById('bast-preview-btn')?.addEventListener('click', function () {
      renderBastPreview();
    });
    document.getElementById('bast-generate-btn')?.addEventListener('click', function () {
      runUiAction(generateBastDocx, 'Failed to generate BAST document');
    });
    document.getElementById('modal-bast')?.addEventListener('input', function (e) {
      if (e.target.closest('input, textarea')) renderBastPreview();
    });
    bindNewEntryClientSelection();
  }


  // Bind high-priority static buttons as soon as the deferred script executes.
  bindStaticEventListeners();

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

    bindStaticEventListeners();

    const savedTab = localStorage.getItem('vulnvault_offensive_active_tab') || 'dashboard';
    navigate(savedTab);
  });

  function getInitials(name) {
    if (!name) return '?';
    var parts = name.trim().split(/\s+/);
    if (parts.length >= 2) return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    return parts[0].substring(0, 2).toUpperCase();
  }

  async function ensureEngineersLoaded() {
    _allEngineers = await PortalShared.ensureDataLoaded('engineers_offensive', async () => {
      return apiFetch('/api/users/engineers?team=offensive');
    });
  }

  // ── Navigation ─────────────────────────────────────────────────────────────────
  function navigate(section) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const secEl = document.getElementById('section-' + section);
    const navEl = document.getElementById('nav-' + section);
    if (secEl) secEl.classList.add('active');
    if (navEl) navEl.classList.add('active');

    localStorage.setItem('vulnvault_offensive_active_tab', section);

    if (section === 'dashboard') loadDashboard();
    if (section === 'projects') loadProjects();
    if (section === 'pm-board') loadBoard();
    if (section === 'allocation') loadAllocation();
    if (section === 'ai-mandays') initAiMandaysSection();
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

    // Default custom range
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
          apiFetch('/api/dashboard/summary?team=offensive'),
          apiFetch('/api/users/engineers?team=offensive')
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

      // Metrics in range
      const rangeProjects = allP.filter(r => isTotalProject(r, f.start, f.end, f.refDate));
      const prevRangeProjects = allP.filter(r => isTotalProject(r, f.prevStart, f.prevEnd, f.prevRefDate));
      const curOverdue = rangeProjects.filter(p => p.final_report_status !== 'completed' && p.final_report_date && new Date(p.final_report_date) < new Date()).length;
      const prevOverdue = prevRangeProjects.filter(p => p.final_report_status !== 'completed' && p.final_report_date && new Date(p.final_report_date) < f.prevEnd).length;

      const curRetest = rangeProjects.filter(p => p.retest_status === 'started').length;
      const prevRetest = prevRangeProjects.filter(p => p.retest_status === 'started').length;

      const clientFindings = {};
      rangeProjects.forEach(p => {
        clientFindings[p.client_name] = (clientFindings[p.client_name] || 0) + (p.finding_count || 0);
      });
      let topClientName = '—';
      let topClientCount = 0;
      for (const name in clientFindings) {
        if (clientFindings[name] > topClientCount) {
          topClientCount = clientFindings[name];
          topClientName = name;
        }
      }

      const cur = { total: rangeProjects.length };
      const prev = { total: prevRangeProjects.length };

      // Set values and deltas
      document.getElementById('kpi-active-projects').textContent = cur.total;
      setKpiDelta('kpi-active-projects-sub', cur.total - prev.total, f.deltaLabel);

      document.getElementById('kpi-overdue').textContent = curOverdue;
      setKpiDelta('kpi-overdue-sub', curOverdue - prevOverdue, f.deltaLabel);

      document.getElementById('kpi-retest-pending').textContent = curRetest;
      setKpiDelta('kpi-retest-pending-sub', curRetest - prevRetest, f.deltaLabel);

      const topClientEl = document.getElementById('kpi-top-client');
      if (topClientEl) {
        topClientEl.textContent = topClientCount > 0 ? topClientName : '—';
        topClientEl.title = topClientCount > 0 ? `${topClientName} (${topClientCount} findings)` : '';
      }
      const topClientSubEl = document.getElementById('kpi-top-client-sub');
      if (topClientSubEl) {
        topClientSubEl.textContent = topClientCount > 0 ? `${topClientCount} findings` : 'No findings';
      }

      // Rendering trend line chart
      renderDashTrendChart(rows, f.refDate);
      
      // Render components
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
    const labels = [], projectsCount = [], findingsCount = [];
    
    // Last 6 months trend
    for (let i = 5; i >= 0; i--) {
      const d = new Date(today.getFullYear(), today.getMonth() - i, 1);
      labels.push(d.toLocaleDateString('en-US', { month: 'short', year: 'numeric' }));
      
      const monthRows = rows.filter(r => r.project_id && r.kickoff_date && new Date(r.kickoff_date).getFullYear() === d.getFullYear() && new Date(r.kickoff_date).getMonth() === d.getMonth());
      projectsCount.push(monthRows.length);
      findingsCount.push(monthRows.reduce((sum, p) => sum + (p.finding_count || 0), 0));
    }

    if (typeof Chart === 'undefined') return;
    const ctx = document.getElementById('dash-trend-chart');
    if (!ctx) return;
    if (_dashTrendChart) _dashTrendChart.destroy();

    _dashTrendChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'Projects Started',
            data: projectsCount,
            borderColor: '#6366f1',
            backgroundColor: 'rgba(99, 102, 241, 0.05)',
            borderWidth: 2.5,
            pointRadius: 4,
            pointBackgroundColor: '#6366f1',
            fill: true,
            tension: 0.3
          },
          {
            label: 'Findings Count',
            data: findingsCount,
            borderColor: '#fb7185',
            backgroundColor: 'transparent',
            borderWidth: 2,
            pointRadius: 4,
            pointBackgroundColor: '#fb7185',
            borderDash: [5, 5],
            fill: false,
            tension: 0.3
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: true,
            position: 'top',
            labels: { color: '#94a3b8', font: { size: 10 } }
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
    const monthName = today.toLocaleDateString('en-US', { month: 'short' });

    if (!list.length) {
      container.innerHTML = '<div class="empty-state">No assessors assigned.</div>';
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

  // ── Active Projects table on Dashboard ──────────────────────────────────────────
  function renderDashActiveProjects(rows, refDate) {
    const tbody = document.getElementById('dash-active-body');
    if (!tbody) return;

    const activeList = rows.filter(r => r.project_id && !r.is_archived && r.final_report_status !== 'completed');
    if (!activeList.length) {
      tbody.innerHTML = '<tr><td colspan="8"><div class="empty-state">No active projects running.</div></td></tr>';
      return;
    }

    const fmt = d => d ? new Date(d).toLocaleDateString('id-ID', { day: 'numeric', month: 'short' }) : '—';
    const tl = { web: 'Web', api: 'API', mobile: 'Mobile', infra: 'Infra', phishing: 'Phishing' };
    const ml = { blackbox: 'Black Box', greybox: 'Grey Box', whitebox: 'White Box', external: 'External', internal: 'Internal', combination: 'Combination' };

    tbody.innerHTML = activeList.map(p => {
      const findingsClass = p.finding_count > 0 ? 'finding-count high' : 'finding-count zero';
      
      let badgeHtml = '—';
      if (p.final_report_date) {
        const onTrack = new Date(p.final_report_date) >= refDate;
        badgeHtml = onTrack 
          ? '<span class="badge" style="background:rgba(34,197,94,0.1); color:var(--green)">On Track</span>' 
          : '<span class="badge" style="background:rgba(239,68,68,0.1); color:var(--red)">Overdue</span>';
      }

      return `
        <tr>
          <td><div style="font-weight:600;color:var(--text);">${esc(p.client_name)}</div></td>
          <td><div style="font-weight:500;color:var(--accent);">${esc(p.project_name)}</div></td>
          <td>${esc(p.service || 'VAPT')}</td>
          <td><span class="badge badge-${p.project_type}">${tl[p.project_type] || p.project_type || 'Web'}</span></td>
          <td style="color:var(--muted); font-size:12px;">${ml[p.project_method] || p.project_method || '—'}</td>
          <td style="color:var(--muted); font-size:12px;">${fmt(p.final_report_date)}</td>
          <td>${badgeHtml}</td>
          <td><span class="${findingsClass}">${p.finding_count || 0}</span></td>
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
        container.innerHTML = '<div class="empty-state" style="grid-column:1/-1;">No assessment highlights documented yet. Document them in the Clients &amp; Projects section.</div>';
        return;
      }

      const negKw = ['kendala', 'hambatan', 'terlambat', 'delay', 'masalah', 'gagal', 'overdue', 'block', 'stuck'];
      const posKw = ['selesai', 'sukses', 'berhasil', 'lancar', 'on track', 'clean', 'mitigated'];

      container.innerHTML = withText.map(h => {
        const text = (h.highlight_text || '').toLowerCase();
        const isNeg = negKw.some(k => text.includes(k));
        const isPos = posKw.some(k => text.includes(k));
        const cls = isNeg ? 'negative' : isPos ? 'positive' : 'neutral';
        const icon = isNeg ? '⚠️' : isPos ? '✅' : '📝';
        const proj = allP.find(r => r.project_id === h.id) || {};

        return `
          <div class="kpi-card" style="display:flex; flex-direction:column; gap:8px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <span style="font-weight:700; font-size:13px; color:var(--text);">${icon} ${esc(proj.project_name || h.name)}</span>
              <span style="font-size:10px; color:var(--muted); font-weight:600; text-transform:uppercase;">${cls}</span>
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

  // ── Clients & Projects list ────────────────────────────────────────────────────
  async function loadProjects() {
    try {
      _clientGroups = await apiFetch('/api/clients/full?team=offensive');
      renderClientGroups();
    } catch (e) {
      showToast('Failed to load project records: ' + e.message, 'error');
    }
  }

  function renderClientGroups() {
    const container = document.getElementById('client-groups');
    if (!container) return;

    const q = (document.getElementById('projects-search')?.value || '').toLowerCase();
    const typeFilter = document.getElementById('projects-type-filter')?.value || '';

    // Filter projects inside clients
    let list = _clientGroups.map(c => {
      let projects = c.projects || [];
      if (q) {
        projects = projects.filter(p => (p.project_name || '').toLowerCase().includes(q) || (c.client_name || '').toLowerCase().includes(q));
      }
      if (typeFilter) {
        projects = projects.filter(p => p.project_type === typeFilter);
      }
      return { ...c, projects };
    });

    // Remove clients with no projects if search query is active
    if (q || typeFilter) {
      list = list.filter(c => c.projects.length > 0);
    }

    if (!list.length) {
      container.innerHTML = '<div class="empty-state">No matching clients or projects found.</div>';
      return;
    }

    const fmt = d => d ? new Date(d).toLocaleDateString('id-ID', { day: 'numeric', month: 'short', year: 'numeric' }) : '—';
    const tl = { web: 'Web', api: 'API', mobile: 'Mobile', infra: 'Infra', phishing: 'Phishing' };

    container.innerHTML = list.map(c => {
      const pid = 'cg-' + c.client_id;
      const totalFindings = c.projects.reduce((sum, p) => sum + (p.finding_count || 0), 0);
      const isExpanded = localStorage.getItem(`cg_exp_${c.client_id}`) === 'true';

      return `
        <div class="client-group">
          <div class="client-group-header js-toggle-group" data-pid="${pid}" data-client-id="${c.client_id}">
            <div style="display:flex; align-items:center; gap:12px; font-weight:700;">
              <svg id="arr-${c.client_id}" class="cg-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:14px; height:14px; transform:${isExpanded ? 'rotate(90deg)' : 'none'};"><polyline points="9 6 15 12 9 18"/></svg>
              <span>${esc(c.client_name)}</span>
              ${c.engagement_reference ? `<span style="font-size:10px; font-weight:600; color:#a5b4fc; background:rgba(99,102,241,0.12); padding:2px 8px; border-radius:6px;">${esc(c.engagement_reference)}</span>` : ''}
              ${c.engagement_info ? `<span style="font-size:11px; color:var(--muted); font-style:italic; font-weight:400;">${esc(c.engagement_info)}</span>` : ''}
            </div>
            <div style="display:flex; align-items:center; gap:12px; font-size:12px; color:var(--muted);">
              <span>${c.projects.length} project${c.projects.length !== 1 ? 's' : ''} &bull; Findings: <span class="finding-count ${countColor(totalFindings)}" style="font-size:12px">${totalFindings}</span></span>
            </div>
          </div>
          <div class="client-group-table ${isExpanded ? 'open' : ''}" id="${pid}">
            ${c.projects.length === 0 
              ? `<div style="padding:16px 20px; color:var(--muted); font-size:12px;">No active projects. Click "New Project" to add one.</div>`
              : `<table>
                  <thead>
                    <tr>
                      <th>Project</th>
                      <th>Type</th>
                      <th>Lead / PIC</th>
                      <th>Kickoff</th>
                      <th>Target Initial</th>
                      <th>Target Final</th>
                      <th>Findings</th>
                      <th class="project-actions-heading">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${c.projects.map(p => `
                      <tr>
                        <td style="font-weight:600; color:var(--accent);">${esc(p.project_name)}</td>
                        <td><span class="badge badge-${p.project_type}">${tl[p.project_type] || p.project_type || '—'}</span></td>
                        <td>${esc(p.engineer_name || '—')}</td>
                        <td style="font-size:12px; color:var(--muted);">${fmt(p.kickoff_date)}</td>
                        <td style="font-size:12px; color:var(--muted);">${fmt(p.initial_report_date)}</td>
                        <td style="font-size:12px; color:var(--muted);">${fmt(p.final_report_date)}</td>
                        <td><span class="finding-count ${countColor(p.finding_count)}">${p.finding_count || 0}</span></td>
                        <td class="project-actions-cell">
                          <div class="project-actions">
                            <button class="project-action-btn js-edit-project" data-id="${p.project_id}">Edit</button>
                            <button class="project-action-btn js-open-highlight" data-id="${p.project_id}" data-highlight="${escA(p.highlight_text || '')}">Highlight</button>
                            <button class="project-action-btn project-action-btn--success js-open-retest" data-id="${p.project_id}">Retest</button>
                            ${canGenerateBast() ? `<button class="project-action-btn project-action-btn--accent js-open-bast" data-id="${p.project_id}">BAST</button>` : ''}
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

  function countColor(n) {
    if (!n || n === 0) return 'zero';
    if (n <= 3) return 'low';
    if (n <= 10) return 'mid';
    return 'high';
  }

  function toggleGroup(id, clientId) {
    const el = document.getElementById(id);
    const arr = document.getElementById('arr-' + clientId);
    if (!el) return;
    const isOpen = el.classList.toggle('open');
    if (arr) arr.style.transform = isOpen ? 'rotate(90deg)' : 'none';
    localStorage.setItem(`cg_exp_${clientId}`, isOpen ? 'true' : 'false');
  }

  function canGenerateBast() {
    return currentUser && ['admin', 'pm'].includes(currentUser.role);
  }

  function findProjectById(projectId) {
    for (const client of _clientGroups) {
      const project = (client.projects || []).find(p => Number(p.project_id) === Number(projectId));
      if (project) return { client, project };
    }
    return null;
  }

  let _bastProjectId = null;

  function setBastError(message) {
    const errEl = document.getElementById('bast-err');
    if (!errEl) return;
    errEl.textContent = message || '';
    errEl.style.display = message ? 'block' : 'none';
  }

  function getTodayInputDate() {
    return new Date().toLocaleDateString('en-CA');
  }

  function getBastFormData() {
    return {
      client_pic_name: document.getElementById('bast-client-pic-name')?.value.trim() || '',
      client_company: document.getElementById('bast-client-company')?.value.trim() || '',
      client_company_address: document.getElementById('bast-client-company-address')?.value.trim() || '',
      project_phase: document.getElementById('bast-project-phase')?.value.trim() || '',
      reference_type: document.getElementById('bast-reference-type')?.value.trim() || '',
      report_date: document.getElementById('bast-report-date')?.value || '',
      report_type: document.getElementById('bast-report-type')?.value.trim() || '',
      billing_percentage: document.getElementById('bast-billing-percentage')?.value.trim() || '',
      client_pic_position: document.getElementById('bast-client-pic-position')?.value.trim() || '',
    };
  }

  function validateBastForm(data) {
    const labels = {
      client_pic_name: 'Client PIC Name',
      client_company: 'Client Company',
      client_company_address: 'Client Company Address',
      project_phase: 'Project Phase',
      reference_type: 'Reference Type',
      report_date: 'Report Date',
      report_type: 'Report Type',
      billing_percentage: 'Billing Percentage',
      client_pic_position: 'Client PIC Position',
    };
    return Object.keys(labels)
      .filter(key => !String(data[key] || '').trim())
      .map(key => labels[key]);
  }

  function formatBastPreviewDate(value) {
    if (!value) return '—';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return value;
    return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' });
  }

  function renderBastPreview() {
    const box = document.getElementById('bast-preview-box');
    if (!box) return;
    const data = getBastFormData();
    const clientName = document.getElementById('bast-client-name')?.value || '';
    const serviceType = document.getElementById('bast-service-type')?.value || '';
    const rows = [
      ['CLIENT_NAME', clientName],
      ['CLIENT_PIC_NAME', data.client_pic_name],
      ['CLIENT_COMPANY', data.client_company],
      ['CLIENT_COMPANY_ADDRESS', data.client_company_address],
      ['SERVICE_TYPE', serviceType],
      ['PROJECT_PHASE', data.project_phase],
      ['REFERENCE_TYPE', data.reference_type],
      ['REPORT_DATE', formatBastPreviewDate(data.report_date)],
      ['REPORT_TYPE', data.report_type],
      ['BILLING_PERCENTAGE', data.billing_percentage],
      ['CLIENT_PIC_POSITION', data.client_pic_position],
    ];
    box.innerHTML = rows.map(([key, value]) => `
      <div style="display:grid; grid-template-columns:180px 1fr; gap:10px; padding:7px 0; border-bottom:1px solid rgba(255,255,255,0.05);">
        <div style="font-size:11px; color:var(--muted); font-weight:700;">{{${esc(key)}}}</div>
        <div style="font-size:12px; color:var(--text);">${esc(value || '—')}</div>
      </div>
    `).join('');
  }

  async function loadBastHistory(projectId) {
    const listEl = document.getElementById('bast-history-list');
    if (!listEl) return;
    listEl.innerHTML = '<div style="color:var(--muted); font-size:12px;">Loading history...</div>';
    try {
      const history = await apiFetch(`/api/projects/${projectId}/bast-documents`);
      if (!history.length) {
        listEl.innerHTML = '<div style="color:var(--muted); font-size:12px;">No BAST documents generated yet.</div>';
        return;
      }
      listEl.innerHTML = history.map(item => `
        <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; padding:9px 0; border-bottom:1px solid rgba(255,255,255,0.05);">
          <div style="min-width:0;">
            <div style="font-size:12px; color:var(--text); font-weight:700; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${esc(item.filename)}</div>
            <div style="font-size:11px; color:var(--muted); margin-top:2px;">${esc(item.generated_by_name || 'Unknown')} &bull; ${esc(timeAgo(item.created_at))}</div>
          </div>
          <a href="${escA(item.download_url)}" class="btn-ghost" style="padding:5px 9px; font-size:11px; flex:none;">Download</a>
        </div>
      `).join('');
    } catch (e) {
      listEl.innerHTML = `<div style="color:var(--red); font-size:12px;">Failed to load history: ${esc(e.message)}</div>`;
    }
  }

  async function openBastModal(projectId) {
    if (!canGenerateBast()) {
      showToast('Only PM and Admin can generate BAST documents.', 'error');
      return;
    }
    _bastProjectId = projectId;
    setBastError('');

    const found = findProjectById(projectId);
    const title = document.getElementById('bast-project-title');
    if (title) title.textContent = found ? found.project.project_name : 'Selected project';

    document.getElementById('modal-bast').classList.add('open');
    document.getElementById('bast-history-list').innerHTML = '<div style="color:var(--muted); font-size:12px;">Loading history...</div>';

    try {
      const preview = await apiFetch(`/api/projects/${projectId}/bast/preview`);
      const p = preview.placeholders || {};
      document.getElementById('bast-client-name').value = p.CLIENT_NAME || '';
      document.getElementById('bast-service-type').value = p.SERVICE_TYPE || 'VAPT Services';
      document.getElementById('bast-client-pic-name').value = p.CLIENT_PIC_NAME || '';
      document.getElementById('bast-client-company').value = p.CLIENT_COMPANY || p.CLIENT_NAME || '';
      document.getElementById('bast-client-company-address').value = p.CLIENT_COMPANY_ADDRESS || '';
      document.getElementById('bast-project-phase').value = p.PROJECT_PHASE || 'Final';
      document.getElementById('bast-reference-type').value = p.REFERENCE_TYPE || '';
      document.getElementById('bast-report-date').value = getTodayInputDate();
      document.getElementById('bast-report-type').value = p.REPORT_TYPE || 'Final Report';
      document.getElementById('bast-billing-percentage').value = p.BILLING_PERCENTAGE || '';
      document.getElementById('bast-client-pic-position').value = p.CLIENT_PIC_POSITION || '';
      renderBastPreview();
      await loadBastHistory(projectId);
    } catch (e) {
      setBastError(e.message);
    }
  }

  async function generateBastDocx() {
    if (!_bastProjectId) return;
    const btn = document.getElementById('bast-generate-btn');
    const oldText = btn ? btn.textContent : '';
    const payload = getBastFormData();
    const missing = validateBastForm(payload);
    setBastError('');
    renderBastPreview();
    if (missing.length) {
      const message = `Please complete required field(s): ${missing.join(', ')}`;
      setBastError(message);
      showToast(message, 'error');
      document.getElementById('bast-err')?.scrollIntoView({ block: 'nearest' });
      return;
    }
    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Generating...';
    }
    try {
      const result = await apiFetch(`/api/projects/${_bastProjectId}/generate-bast-docx`, 'POST', payload);
      showToast('BAST document generated.', 'success');
      await loadBastHistory(_bastProjectId);
      const a = document.createElement('a');
      a.href = result.download_url;
      a.download = result.filename || 'BAST.docx';
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (e) {
      setBastError(e.message);
      showToast('BAST generation failed: ' + e.message, 'error');
      document.getElementById('bast-err')?.scrollIntoView({ block: 'nearest' });
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = oldText || 'Generate DOCX';
      }
    }
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
    const isPast = document.getElementById('cp-is-past-project').checked;
    
    // Auto-calculate assessment mandays when dates are changed if assessment is filled
    const mdAssessment = parseFloat(document.getElementById('cp-md-assessment').value) || 0;
    const mdInitialReport = parseFloat(document.getElementById('cp-md-initial-report').value) || 1;
    const totalMd = mdAssessment + mdInitialReport;

    if (!startStr) {
      document.getElementById('cp-initial').value = '';
      return;
    }

    // Allocate mandays distributed over engineers
    const numPic = _picCount;
    const perPersonMd = totalMd / numPic;

    // Calculate report date by running forward 'perPersonMd' working days from startStr
    let cur = new Date(startStr);
    let workingDaysAdded = 0;
    const targetDays = Math.ceil(perPersonMd);

    // Day 1 is the start date itself
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

  function updateCpMethodOptions() {
    const type = document.getElementById('cp-type').value;
    const wrap = document.getElementById('cp-method-wrap');
    const sel = document.getElementById('cp-method');
    if (!wrap || !sel) return;
    if (type === 'phishing') { wrap.style.display = 'none'; return; }
    wrap.style.display = 'block';
    if (type === 'infra') {
      sel.innerHTML = '<option value="external">External</option><option value="internal">Internal</option><option value="combination">Combination</option>';
    } else {
      sel.innerHTML = '<option value="blackbox">Black Box</option><option value="greybox">Grey Box</option><option value="whitebox">White Box</option>';
    }
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

    // Update tab bar styles
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

    document.getElementById('modal-create-project-title').textContent = isEdit ? 'Edit Offensive Project' : 'New Offensive Entry';
    document.getElementById('cp-err').style.display = 'none';
    document.getElementById('modal-create-project').classList.add('open');

    const submitBtn = document.getElementById('cp-btn');
    if (submitBtn) submitBtn.disabled = true;

    try {
      await ensureEngineersLoaded();
      if (submitBtn) submitBtn.disabled = false;
    } catch (e) {
      showToast('Failed to load assessor list: ' + e.message, 'error');
    }

    // Populate engineers dropdowns
    const dropdownIds = ['cp-engineer', 'cp-assist', 'cp-engineer-3', 'cp-engineer-4', 'cp-engineer-5', 'cp-engineer-6', 'cp-engineer-7', 'cp-engineer-8', 'cp-engineer-9', 'cp-engineer-10'];
    dropdownIds.forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      el.innerHTML = '<option value="">— Select Assessor —</option>';
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
    document.getElementById('cp-scope-target').value = '';
    document.getElementById('cp-service').value = 'vapt';
    document.getElementById('cp-service-custom').value = '';
    document.getElementById('cp-service-custom').style.display = 'none';
    document.getElementById('cp-type').value = 'web';
    document.getElementById('cp-resource-count').value = '1';
    _onResourceCountChange();

    document.getElementById('cp-kickoff').value = '';
    document.getElementById('cp-start-date').value = '';
    document.getElementById('cp-md-assessment').value = '5';
    document.getElementById('cp-md-initial-report').value = '2';
    document.getElementById('cp-initial').value = '';
    document.getElementById('cp-is-past-project').checked = false;
    document.getElementById('cp-actual-end').value = '';
    document.getElementById('cp-actual-end-wrap').style.display = 'none';
    document.getElementById('cp-links-container').innerHTML = '';

    // If Edit Mode
    if (isEdit && proj) {
      document.getElementById('ne-tab-bar').style.display = 'none'; // hide tabs on edit
      switchNeTab('project');

      document.getElementById('cp-name').value = proj.project_name || '';
      document.getElementById('cp-scope-target').value = proj.scope_target || '';
      
      const standardServices = ['vapt', 'va', 'firewall_review', 'phishing'];
      if (standardServices.includes(proj.service)) {
        document.getElementById('cp-service').value = proj.service;
      } else {
        document.getElementById('cp-service').value = '__other__';
        document.getElementById('cp-service-custom').value = proj.service || '';
        document.getElementById('cp-service-custom').style.display = 'block';
      }

      document.getElementById('cp-type').value = proj.project_type || 'web';
      updateCpMethodOptions();
      document.getElementById('cp-method').value = proj.project_method || 'blackbox';

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

      // Populate project links
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
      const clients = await apiFetch('/api/clients?team=offensive');
      const listEl = document.getElementById('ne-client-list');
      if (!listEl) return;
      if (!clients.length) {
        listEl.innerHTML = '<div style="padding:20px; text-align:center; color:var(--muted); font-size:12px;">No clients created. Use the form below to create one.</div>';
        return;
      }

      listEl.innerHTML = clients.map(c => `
        <div class="ne-client-card js-select-ne-client" id="ne-ccard-${c.id}" data-id="${c.id}" style="border:1px solid var(--border); border-radius:8px; padding:12px 16px; cursor:pointer; background:rgba(255,255,255,0.02); transition:all 0.1s;">
          <div style="font-weight:600; font-size:13px; color:var(--text);">${esc(c.name)}</div>
          ${c.engagement_reference ? `<div style="font-size:11px; color:var(--muted); margin-top:4px;">Engagement: ${esc(c.engagement_reference)} (${esc(c.engagement_info)})</div>` : ''}
        </div>
      `).join('');
      bindNewEntryClientSelection();
    } catch { }
  }

  function bindNewEntryClientSelection() {
    const listEl = document.getElementById('ne-client-list');
    if (!listEl || listEl.dataset.bound === 'true') return;

    listEl.addEventListener('click', function (e) {
      const card = e.target.closest('.js-select-ne-client');
      if (!card || !listEl.contains(card)) return;
      window.selectNeClient(Number(card.dataset.id));
    });

    listEl.dataset.bound = 'true';
  }

  window.selectNeClient = function(id) {
    _selectedClientId = id;
    document.querySelectorAll('.ne-client-card').forEach(el => {
      el.classList.remove('selected');
    });
    const sel = document.getElementById('ne-ccard-' + id);
    if (sel) {
      sel.classList.add('selected');
    }
    // Collapse new client form
    document.getElementById('ne-new-client-fields').style.display = 'none';
    document.getElementById('ne-client-name').value = '';
  };

  function _toggleNewClientForm() {
    _selectedClientId = null;
    document.querySelectorAll('.ne-client-card').forEach(el => {
      el.classList.remove('selected');
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

  function _updateProjectTabState() {
    // optional logic hooks
  }

  // ── Links inputs ───────────────────────────────────────────────────────────────
  function addProjectLink(title = '', url = '') {
    ProjectFormShared.addProjectLink('cp-links-container', title, url);
  }

  function removeProjectLink(id) {
    document.getElementById(id)?.remove();
  }

  function collectProjectLinks() {
    return ProjectFormShared.collectProjectLinks('cp-links-container');
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

      // Collect project details
      const name = document.getElementById('cp-name').value.trim();
      const scope_target = document.getElementById('cp-scope-target').value.trim();
      
      const svcVal = document.getElementById('cp-service').value;
      const service = svcVal === '__other__' ? document.getElementById('cp-service-custom').value.trim() : svcVal;
      
      const project_type = document.getElementById('cp-type').value;
      const project_method = document.getElementById('cp-method').value;
      
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

      // Validations
      if (!name) throw new Error('Project Name is required.');
      if (!isEdit && !_selectedClientId) {
        // Must create client first
        const clientName = document.getElementById('ne-client-name').value.trim();
        if (!clientName) throw new Error('Please select or specify a client.');
        
        const engRefVal = document.getElementById('ne-engagement-ref').value;
        const engagement_reference = engRefVal === '__other__' ? document.getElementById('ne-engagement-ref-custom').value.trim() : engRefVal;
        const engagement_info = document.getElementById('ne-engagement-info').value.trim();

        // Create client first
        const cRes = await apiFetch('/api/clients', 'POST', { name: clientName, engagement_reference, engagement_info, team: 'offensive' });
        _selectedClientId = cRes.id;
      }

      const body = {
        name, scope_target, project_type, project_method,
        assigned_engineer_id, assist_engineer_id, engineer_3_id, engineer_4_id, engineer_5_id, engineer_6_id, engineer_7_id, engineer_8_id, engineer_9_id, engineer_10_id,
        kickoff_date, start_date, mandays_assessment, mandays_initial_report, initial_report_date,
        is_past_project, actual_end_date, project_links,
        team: 'offensive', service
      };

      if (isEdit) {
        await apiFetch(`/api/projects/${_editingProjectId}`, 'PUT', body);
        showToast('Project updated successfully', 'success');
      } else {
        await apiFetch(`/api/clients/${_selectedClientId}/projects`, 'POST', body);
        showToast('Project created successfully', 'success');
      }

      document.getElementById('modal-create-project').classList.remove('open');
      
      // Reload current tab content
      const tab = localStorage.getItem('vulnvault_offensive_active_tab') || 'dashboard';
      navigate(tab);

    } catch (e) {
      errEl.textContent = e.message;
      errEl.style.display = 'block';
    }
  }

  // ── Kanban Board logic ─────────────────────────────────────────────────────────
  async function loadBoard() {
    closeQuickMoveMenu();
    const boardEl = document.getElementById('board-container');
    if (!boardEl) return;
    boardEl.innerHTML = '<div class="empty-state">Loading board data...</div>';

    try {
      [_boardProjects, _boardStatuses] = await Promise.all([
        apiFetch('/api/board/projects?team=offensive'),
        apiFetch('/api/board-statuses?team=offensive')
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

    // Group projects by status
    const statusMap = new Map();
    _boardStatuses.forEach(s => statusMap.set(s.id, { info: s, projects: [] }));
    
    // Fallback uncategorized (-1)
    statusMap.set(-1, { info: { id: -1, name: 'Uncategorized', color: '#64748b' }, projects: [] });

    _boardProjects.forEach(p => {
      const catId = p.board_status_id || -1;
      if (statusMap.has(catId)) statusMap.get(catId).projects.push(p);
      else statusMap.get(-1).projects.push(p);
    });

    const tl = { web: 'Web', api: 'API', mobile: 'Mobile', infra: 'Infra', phishing: 'Phishing' };

    [...statusMap.values()].forEach(col => {
      // Don't render uncategorized unless it has projects
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

      col.projects.forEach(p => {
        const card = document.createElement('div');
        card.className = 'board-card';
        card.style = `padding:14px; background:var(--card); border:1px solid var(--border); border-radius:8px; cursor:pointer; transition:all 0.15s;`;

        const isTerminal = col.info.is_terminal === 1;
        const isArchiveReady = isTerminal && p.final_report_status === 'completed';

        let badgeHtml = `<span class="badge badge-${p.project_type}" style="font-size:9px; padding:2px 6px;">${tl[p.project_type] || p.project_type || 'Web'}</span>`;
        if (isArchiveReady) {
          badgeHtml += ` <span class="badge badge-archive-ready" style="font-size:9px; padding:2px 6px; margin-left:4px;">Ready to archive</span>`;
        } else if (isTerminal) {
          badgeHtml += ` <span class="badge badge-terminal" style="font-size:9px; padding:2px 6px; margin-left:4px;">Final stage</span>`;
        }

        card.innerHTML = `
          <div class="js-open-board-detail">
            <div style="font-size:11px; font-weight:600; color:var(--muted); margin-bottom:4px;">${esc(p.client_name)}</div>
            <div style="font-weight:700; font-size:13px; color:var(--text); margin-bottom:8px; line-height:1.4;">${esc(p.project_name)}</div>
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <div>
                ${badgeHtml}
              </div>
              <span style="font-size:10px; color:var(--muted); font-weight:600;">PIC: ${esc(p.engineer_name ? p.engineer_name.split(' ')[0] : '—')}</span>
            </div>
          </div>
          <div class="board-card-actions">
            <button
              class="board-card-action js-card-move-menu"
              data-project-id="${p.project_id}"
              type="button"
            >
              Move ▾
            </button>
            ${isArchiveReady ? `
              <button
                class="board-card-action archive js-card-archive"
                data-project-id="${p.project_id}"
                type="button"
              >
                Archive
              </button>
            ` : ''}
          </div>
        `;

        card.addEventListener('click', (e) => {
          const moveBtn = e.target.closest('.js-card-move-menu');
          const archiveBtn = e.target.closest('.js-card-archive');
          if (moveBtn) {
            e.preventDefault();
            e.stopPropagation();
            openQuickMoveMenu(p, moveBtn);
            return;
          }
          if (archiveBtn) {
            e.preventDefault();
            e.stopPropagation();
            archiveProjectFromBoard(Number(archiveBtn.dataset.projectId));
            return;
          }
          openBoardDetail(p);
        });

        cardContainer.appendChild(card);
      });

      colEl.appendChild(cardContainer);
      boardEl.appendChild(colEl);
    });
  }


  // ── Kanban board setup modal ───────────────────────────────────────────────────
  async function openBoardSetup() {
    const btn = document.getElementById('btn-board-setup');
    const oldHtml = btn ? btn.innerHTML : '';
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = 'Loading...';
    }

    const listEl = document.getElementById('setup-status-list');
    if (listEl) {
      listEl.innerHTML = '<div style="padding:10px; text-align:center;">Loading...</div>';
    }

    try {
      _boardStatuses = await apiFetch('/api/board-statuses?team=offensive');
      renderSetupList();
      document.getElementById('modal-board-setup').classList.add('open');
    } catch (e) {
      showToast('Failed to load board status list: ' + e.message, 'error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = oldHtml;
      }
    }
  }

  function renderSetupList() {
    const listEl = document.getElementById('setup-status-list');
    if (!listEl) return;

    if (!listEl.dataset.bound) {
      listEl.addEventListener('change', async function(e) {
        const toggle = e.target.closest('.js-status-terminal');
        if (toggle) {
          const statusId = Number(toggle.dataset.id);
          const is_terminal = toggle.checked ? 1 : 0;
          const status = _boardStatuses.find(s => Number(s.id) === statusId);
          if (!status) return;

          try {
            await apiFetch(`/api/board-statuses/${statusId}`, 'PUT', {
              name: status.name,
              color: status.color,
              team: 'offensive',
              is_terminal: is_terminal
            });
            showToast('Status updated');
            _boardStatuses = await apiFetch('/api/board-statuses?team=offensive');
            renderSetupList();
            loadBoard();
          } catch (err) {
            showToast('Failed to update status: ' + err.message, 'error');
            toggle.checked = !toggle.checked;
          }
        }
      });
      listEl.dataset.bound = 'true';
    }

    BoardShared.renderSetupList(listEl, _boardStatuses, () => {
      renderSetupList();
    });
  }

  function reorderStatus(e, targetIdx) {
    e.preventDefault();
    const sourceIdx = parseInt(e.dataTransfer.getData('text/plain'));
    if (isNaN(sourceIdx) || sourceIdx === targetIdx) return;
    
    // Re-splice status array
    const [moved] = _boardStatuses.splice(sourceIdx, 1);
    _boardStatuses.splice(targetIdx, 0, moved);
    renderSetupList();
  }

  async function addBoardStatus() {
    const nameInput = document.getElementById('setup-new-name');
    const colorInput = document.getElementById('setup-new-color');
    const terminalInput = document.getElementById('setup-new-terminal');
    const name = nameInput.value.trim();
    const color = colorInput ? colorInput.value : '';
    const is_terminal = terminalInput ? (terminalInput.checked ? 1 : 0) : 0;

    if (!name) {
      showToast('Status title cannot be empty', 'error');
      return;
    }
    if (!color) {
      showToast('Default color is required', 'error');
      return;
    }

    const btn = document.getElementById('btn-add-status');
    const oldText = btn ? btn.textContent : '';
    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Adding...';
    }

    try {
      const order = _boardStatuses.length;
      await apiFetch('/api/board-statuses', 'POST', { name, color, sort_order: order, team: 'offensive', is_terminal });
      nameInput.value = '';
      if (terminalInput) terminalInput.checked = false;
      
      // Reload lists
      _boardStatuses = await apiFetch('/api/board-statuses?team=offensive');
      renderSetupList();
      loadBoard();
    } catch (e) {
      showToast('Failed to add board status: ' + e.message, 'error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = oldText;
      }
    }
  }

  async function deleteBoardStatus(id) {
    const ok = await customConfirm('Delete Column', 'Are you sure you want to delete this status column? Projects in this status will become Uncategorized.', 'Delete Column', 'danger');
    if (!ok) return;

    try {
      await apiFetch(`/api/board-statuses/${id}?team=offensive`, 'DELETE');
      _boardStatuses = await apiFetch('/api/board-statuses?team=offensive');
      renderSetupList();
      loadBoard();
    } catch (e) {
      showToast('Failed to delete status column: ' + e.message, 'error');
    }
  }

  async function saveBoardOrder() {
    try {
      const ordered_ids = _boardStatuses.map(s => s.id);
      await apiFetch('/api/board-statuses/reorder', 'PUT', { ordered_ids, team: 'offensive' });
      showToast('Sequence saved successfully');
      document.getElementById('modal-board-setup').classList.remove('open');
      loadBoard();
    } catch (e) {
      showToast('Failed to reorder: ' + e.message, 'error');
    }
  }

  // ── Kanban detail card modal ───────────────────────────────────────────────────
  async function moveBoardProject(projectId, statusId, options = {}) {
    try {
      await apiFetch(`/api/projects/${projectId}/board-status`, 'PATCH', {
        board_status_id: statusId === null ? null : Number(statusId)
      });
      showToast('Project status updated');
      if (options.closeDetailModal !== false) {
        document.getElementById('modal-board-detail')?.classList.remove('open');
      }
      loadBoard();
    } catch (e) {
      showToast('Failed to update status: ' + e.message, 'error');
    }
  }

  function closeQuickMoveMenu() {
    if (window.BoardShared && typeof window.BoardShared.closeFloatingMenu === 'function') {
      window.BoardShared.closeFloatingMenu('.quick-move-menu');
    } else {
      document.querySelector('.quick-move-menu')?.remove();
    }
  }

  function openQuickMoveMenu(project, anchorEl) {
    closeQuickMoveMenu();

    const menu = document.createElement('div');
    menu.className = 'quick-move-menu';

    let optionsHtml = `
      <button class="quick-move-option" data-status-id="null" ${project.board_status_id === null ? 'disabled' : ''}>
        <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#64748b; margin-right:6px;"></span>
        Uncategorized
      </button>
    `;

    optionsHtml += _boardStatuses.map(s => `
      <button
        class="quick-move-option"
        data-status-id="${s.id}"
        ${Number(s.id) === Number(project.board_status_id) ? 'disabled' : ''}
      >
        <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:${escA(s.color)}; margin-right:6px;"></span>
        ${esc(s.name)}
        ${s.is_terminal ? '<small style="margin-left:auto; font-size:9px; background:rgba(255,255,255,0.15); padding:1px 4px; border-radius:4px;">Final</small>' : ''}
      </button>
    `).join('');

    menu.innerHTML = optionsHtml;
    document.body.appendChild(menu);

    menu.addEventListener('click', async (e) => {
      const option = e.target.closest('.quick-move-option');
      if (!option) return;
      e.stopPropagation();

      const statusId = option.dataset.statusId === 'null' ? null : Number(option.dataset.statusId);
      closeQuickMoveMenu();
      await moveBoardProject(project.project_id, statusId, { closeDetailModal: false });
    });

    if (window.BoardShared && typeof window.BoardShared.positionFloatingMenu === 'function') {
      window.BoardShared.positionFloatingMenu(menu, anchorEl);
    } else {
      positionMenu(menu, anchorEl);
    }
  }

  function positionMenu(menu, anchorEl) {
    const rect = anchorEl.getBoundingClientRect();
    let top = rect.bottom + 6;
    let left = rect.left;
    menu.style.top = `${top}px`;
    menu.style.left = `${left}px`;
  }

  // ── Kanban detail card modal ───────────────────────────────────────────────────
  function openBoardDetail(p) {
    const titleEl = document.getElementById('bd-title');
    const bodyEl = document.getElementById('bd-body');
    if (!titleEl || !bodyEl) return;

    titleEl.textContent = p.project_name;
    const fmt = d => d ? new Date(d).toLocaleDateString('id-ID', { day: 'numeric', month: 'short', year: 'numeric' }) : '—';
    const tl = { web: 'Web', api: 'API', mobile: 'Mobile', infra: 'Infra', phishing: 'Phishing' };
    const ml = { blackbox: 'Black Box', greybox: 'Grey Box', whitebox: 'White Box', external: 'External', internal: 'Internal', combination: 'Combination' };

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

    const currentStatus = _boardStatuses.find(s => Number(s.id) === Number(p.board_status_id)) || null;
    const statusName = currentStatus ? currentStatus.name : 'Uncategorized';
    const statusColor = currentStatus ? currentStatus.color : 'var(--muted)';
    const isTerminal = currentStatus?.is_terminal === 1;

    // Uncategorized button
    const uncategorizedActive = p.board_status_id === null || p.board_status_id === undefined;
    let statusButtons = `
      <button
        class="status-action-btn js-move-board-status ${uncategorizedActive ? 'active' : ''}"
        data-project-id="${p.project_id}"
        data-status-id="null"
        ${uncategorizedActive ? 'disabled' : ''}
      >
        <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:var(--muted); margin-right:6px;"></span>
        Uncategorized
      </button>
    `;

    // Statuses buttons
    statusButtons += _boardStatuses.map(s => `
      <button
        class="status-action-btn js-move-board-status ${Number(s.id) === Number(p.board_status_id) ? 'active' : ''}"
        data-project-id="${p.project_id}"
        data-status-id="${s.id}"
        ${Number(s.id) === Number(p.board_status_id) ? 'disabled' : ''}
      >
        <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:${escA(s.color)}; margin-right:6px;"></span>
        ${esc(s.name)}
        ${s.is_terminal ? '<small style="margin-left:4px; font-size:9px; background:rgba(255,255,255,0.15); padding:1px 4px; border-radius:4px;">Final</small>' : ''}
      </button>
    `).join('');

    const isCompleted = p.final_report_status === 'completed';
    const archiveEligible = isCompleted && isTerminal;
    let archiveHtml = '';
    if (archiveEligible) {
      archiveHtml = `
        <div class="archive-panel" style="margin-top:16px;">
          <div style="font-size:11px; font-weight:700; color:#10b981; margin-bottom:4px; text-transform:uppercase;">Ready to archive</div>
          <div style="font-size:12px; color:var(--muted); margin-bottom:12px;">This project is completed and in a final stage.</div>
          <button class="btn-primary js-archive-project-from-board" data-id="${p.project_id}" style="width:100%; background:rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.3); color:#10b981; justify-content:center;">
            Archive Project
          </button>
        </div>
      `;
    } else if (isCompleted && !isTerminal) {
      archiveHtml = `
        <div style="margin-top:16px; color:var(--muted);">
          <div style="font-size:11px; font-weight:700; color:var(--yellow, #eab308); margin-bottom:4px; text-transform:uppercase;">Move to final stage</div>
          <div style="font-size:12px; color:var(--muted);">Move this project to a final board status before archiving.</div>
        </div>
      `;
    } else if (!isCompleted && isTerminal) {
      archiveHtml = `
        <div style="margin-top:16px; color:var(--muted);">
          <div style="font-size:11px; font-weight:700; color:var(--muted); margin-bottom:4px; text-transform:uppercase;">Final stage reached</div>
          <div style="font-size:12px; color:var(--muted);">Complete the final report before archiving this project.</div>
        </div>
      `;
    } else {
      archiveHtml = `
        <div style="margin-top:16px; color:var(--muted);">
          <div style="font-size:11px; font-weight:700; color:var(--muted); margin-bottom:4px; text-transform:uppercase;">Active Project</div>
          <div style="font-size:12px; color:var(--muted);">Complete the final report and move to a final stage to make this project eligible for archiving.</div>
        </div>
      `;
    }

    bodyEl.innerHTML = `
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:20px;">
        <div><div style="font-size:11px; color:var(--muted)">CLIENT</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${esc(p.client_name)}</div></div>
        <div><div style="font-size:11px; color:var(--muted)">SCOPE TYPE</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;"><span class="badge badge-${p.project_type}">${tl[p.project_type] || p.project_type}</span></div></div>
        <div><div style="font-size:11px; color:var(--muted)">METHODOLOGY</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${ml[p.project_method] || p.project_method || '—'}</div></div>
        <div><div style="font-size:11px; color:var(--muted)">SERVICE</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${esc(p.service || 'VAPT')}</div></div>
        <div><div style="font-size:11px; color:var(--muted)">KICK OFF</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${fmt(p.kickoff_date)}</div></div>
        <div><div style="font-size:11px; color:var(--muted)">START DATE</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${fmt(p.start_date)}</div></div>
        <div><div style="font-size:11px; color:var(--muted)">TARGET INITIAL REPORT</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${fmt(p.initial_report_date)}</div></div>
        <div><div style="font-size:11px; color:var(--muted)">TARGET FINAL REPORT</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${fmt(p.final_report_date)}</div></div>
        <div><div style="font-size:11px; color:var(--muted)">MANDAYS ASSESSMENT</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${p.mandays_assessment || 0} hari</div></div>
        <div><div style="font-size:11px; color:var(--muted)">FINDINGS</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;"><span class="finding-count ${countColor(p.finding_count)}">${p.finding_count || 0}</span></div></div>
        <div style="grid-column:1/-1;"><div style="font-size:11px; color:var(--muted)">LEAD ASSESSOR &amp; PICs</div><div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px;">${esc(p.engineer_name || '—')}</div></div>
        <div style="grid-column:1/-1;">
          <div style="font-size:11px; color:var(--muted)">BOARD STATUS</div>
          <div style="font-size:13px; font-weight:600; color:var(--text); margin-top:4px; display:flex; align-items:center; gap:6px;">
            <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:${statusColor};"></span>
            ${esc(statusName)}
            ${isTerminal ? '<span class="badge badge-terminal" style="font-size:9px; padding:1px 6px;">Final Stage</span>' : ''}
          </div>
        </div>
      </div>
      <div style="border-top:1px solid var(--border); padding-top:16px;">
        <div style="font-size:11px; color:var(--muted); margin-bottom:8px;">EVIDENCE / RESOURCE LINKS</div>
        <div>${linksHtml}</div>
      </div>
      <div style="border-top:1px solid var(--border); padding-top:16px; margin-top:16px;">
        <div style="font-size:11px; color:var(--muted); margin-bottom:8px;">MOVE TO STATUS</div>
        <div class="status-action-grid">
          ${statusButtons}
        </div>
      </div>
      <div style="border-top:1px solid var(--border); padding-top:16px; margin-top:16px;">
        ${archiveHtml}
      </div>
    `;

    // Bind local click events to bd-body (once only)
    if (!bodyEl.dataset.bound) {
      bodyEl.addEventListener('click', function(e) {
        const statusBtn = e.target.closest('.js-move-board-status');
        if (statusBtn) {
          const statusId = statusBtn.dataset.statusId === 'null' ? null : Number(statusBtn.dataset.statusId);
          moveBoardProject(Number(statusBtn.dataset.projectId), statusId);
          return;
        }
        const archiveBtn = e.target.closest('.js-archive-project-from-board');
        if (archiveBtn) {
          archiveProjectFromBoard(Number(archiveBtn.dataset.id));
          return;
        }
      });
      bodyEl.dataset.bound = 'true';
    }

    document.getElementById('modal-board-detail').classList.add('open');
  }

  // ── Capacity View — Resource Allocation ─────────────────────────────────────────
  let _allocationMonths = [];
  let _allocationMonthIdx = 0;
  const _monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

  async function loadAllocation() {
    const listEl = document.getElementById('capacity-list');
    if (!listEl) return;
    listEl.innerHTML = '<div class="empty-state">Loading allocation details...</div>';

    try {
      await ensureEngineersLoaded();
      const summary = await apiFetch('/api/dashboard/summary?team=offensive');
      buildAllocationMonths(summary);
      renderCapacityView(summary);
    } catch (e) {
      listEl.innerHTML = `<div class="empty-state">Error: ${e.message}</div>`;
    }
  }

  function buildAllocationMonths(summary) {
    const res = AllocationShared.buildAllocationMonths(summary);
    _allocationMonths = res.allocationMonths;
    _allocationMonthIdx = res.allocationMonthIdx;
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
    
    // Rerender with cached dashboard summary
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
      listEl.innerHTML = '<div class="empty-state">No assessors defined for the Offensive team.</div>';
      return;
    }

    listEl.innerHTML = list.map(e => {
      const pct = Math.round((e.used / workdays) * 100);
      let barClass = 'green';
      if (pct > 80) barClass = 'yellow';
      if (pct > 100) barClass = 'red';
      const fillWidth = Math.min(100, pct);
      const subNotes = e.projects.length ? e.projects.join(', ') : 'No assignments';

      return `
        <div class="capacity-row" style="border-bottom:1px solid var(--border); padding:16px 20px;">
          <div class="capacity-row-top" style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <div style="font-weight:700; color:var(--text);">${esc(e.name)}</div>
            <div style="color:var(--muted); font-size:12px;">Allocated: <strong>${e.used.toFixed(1)} / ${workdays} d</strong> (${pct}%)</div>
          </div>
          <div class="capacity-bar-track" style="height:8px; margin-bottom:8px;">
            <div class="capacity-bar-fill ${barClass}" style="width:${fillWidth}%; height:100%;"></div>
          </div>
          <div style="font-size:11px; color:var(--muted); line-height:1.4;">Projects: ${esc(subNotes)}</div>
        </div>
      `;
    }).join('');
  }

  function _assessmentMandaysInMonth(r, year, month) {
    if (!window.AllocationShared || typeof AllocationShared.assessmentMandaysInMonth !== 'function') {
      return 0;
    }
    return AllocationShared.assessmentMandaysInMonth(r, year, month);
  }

  // ── AI Mandays Estimator section ───────────────────────────────────────────────
  function initAiMandaysSection() {
    const key = localStorage.getItem('vulnvault_gemini_key') || '';
    const statusEl = document.getElementById('ai-key-status');
    const inputEl = document.getElementById('ai-api-key-input');
    const modelEl = document.getElementById('ai-model-select');

    if (modelEl) modelEl.value = localStorage.getItem('vulnvault_gemini_model') || 'gemini-2.5-flash';
    if (key) {
      if (statusEl) { statusEl.textContent = 'Saved'; statusEl.style.background = 'rgba(34,197,94,0.15)'; statusEl.style.color = '#86efac'; }
      if (inputEl) inputEl.placeholder = 'AIzaSy...••••• (Saved)';
    } else {
      if (statusEl) { statusEl.textContent = 'No Key'; statusEl.style.background = 'rgba(239,68,68,0.15)'; statusEl.style.color = '#fca5a5'; }
    }
    updateAiMethodOptions();
    updateAiDynamicFields();
    renderEstimateHistory();
  }

  function saveAiApiKey() {
    const key = document.getElementById('ai-api-key-input').value.trim();
    const model = document.getElementById('ai-model-select').value;
    if (key) localStorage.setItem('vulnvault_gemini_key', key);
    localStorage.setItem('vulnvault_gemini_model', model);
    initAiMandaysSection();
  }

  function clearAiApiKey() {
    localStorage.removeItem('vulnvault_gemini_key');
    localStorage.removeItem('vulnvault_gemini_model');
    document.getElementById('ai-api-key-input').value = '';
    initAiMandaysSection();
  }

  function updateAiMethodOptions() {
    const type = document.getElementById('ai-project-type').value;
    const wrap = document.getElementById('ai-method-wrap');
    const sel = document.getElementById('ai-method');
    if (!wrap || !sel) return;
    if (type === 'phishing') { wrap.style.display = 'none'; return; }
    wrap.style.display = 'block';
    if (type === 'infra') {
      sel.innerHTML = '<option value="external">External</option><option value="internal">Internal</option><option value="combination">Combination</option>';
    } else {
      sel.innerHTML = '<option value="blackbox">Black Box</option><option value="greybox">Grey Box</option><option value="whitebox">White Box</option>';
    }
  }

  function updateAiDynamicFields() {
    const type = document.getElementById('ai-project-type').value;
    const container = document.getElementById('ai-dynamic-fields');
    if (!container) return;

    if (type === 'web' || type === 'mobile') {
      container.innerHTML = `
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
          <div class="form-group"><label>Screen/Page Count *</label><input id="ai-num-pages" type="number" min="1" value="15"></div>
          <div class="form-group"><label>Core Feature Count *</label><input id="ai-num-features" type="number" min="1" value="4"></div>
        </div>
      `;
    } else if (type === 'api') {
      container.innerHTML = `
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
          <div class="form-group"><label>API Endpoints Count *</label><input id="ai-num-endpoints" type="number" min="1" value="12"></div>
          <div class="form-group"><label>Avg HTTP Methods per Endpoint</label>
            <select id="ai-avg-methods">
              <option value="1">1 method (Read-only)</option>
              <option value="2" selected>2 methods (Read &amp; Write)</option>
              <option value="5">5 methods (Full CRUD)</option>
            </select>
          </div>
        </div>
      `;
    } else if (type === 'infra') {
      container.innerHTML = `
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
          <div class="form-group"><label>Infrastructure Target Type *</label>
            <select id="ai-infra-subtype">
              <option value="segmentation">Network Segmentation Pentest</option>
              <option value="external_nonauth" selected>External IP VAPT (Non-Authenticated)</option>
              <option value="external_auth">Internal System VAPT (Authenticated)</option>
              <option value="firewall">Firewall Ruleset Audit</option>
            </select>
          </div>
          <div class="form-group"><label>Targets Count (IPs / Rules) *</label><input id="ai-num-items" type="number" min="1" value="8"></div>
        </div>
      `;
    } else if (type === 'phishing') {
      container.innerHTML = `
        <div class="form-group"><label>Number of Targets (Users) *</label><input id="ai-num-targets" type="number" min="1" value="100"></div>
      `;
    } else {
      container.innerHTML = '';
    }
  }

  async function runAiEstimate() {
    const key = localStorage.getItem('vulnvault_gemini_key');
    const model = localStorage.getItem('vulnvault_gemini_model') || 'gemini-2.5-flash';

    if (!key) {
      showToast('Gemini API Key is required.', 'error');
      return;
    }

    const project_type = document.getElementById('ai-project-type').value;
    const method = document.getElementById('ai-method')?.value || null;
    const description = document.getElementById('ai-description').value.trim();

    const extra = {};
    if (project_type === 'web' || project_type === 'mobile') {
      extra.num_pages = parseInt(document.getElementById('ai-num-pages').value) || 1;
      extra.num_features = parseInt(document.getElementById('ai-num-features').value) || 1;
    } else if (project_type === 'api') {
      extra.num_endpoints = parseInt(document.getElementById('ai-num-endpoints').value) || 1;
      extra.avg_methods = parseInt(document.getElementById('ai-avg-methods').value) || 2;
    } else if (project_type === 'infra') {
      extra.infra_subtype = document.getElementById('ai-infra-subtype').value;
      extra.num_items = parseInt(document.getElementById('ai-num-items').value) || 1;
    } else if (project_type === 'phishing') {
      extra.num_targets = parseInt(document.getElementById('ai-num-targets').value) || 1;
    }

    document.getElementById('ai-error').style.display = 'none';
    document.getElementById('ai-result').style.display = 'none';
    document.getElementById('ai-loading').style.display = 'block';

    try {
      const data = await apiFetch('/api/ai/estimate-mandays', 'POST', { api_key: key, model, project_type, method, description, ...extra });
      _lastAiEstimate = { ...data, project_type, method, description, ...extra };

      document.getElementById('ai-r-kickoff').textContent = data.kickoff_days;
      document.getElementById('ai-r-infogath').textContent = data.infogath_days;
      document.getElementById('ai-r-assessment').textContent = data.assessment_days;
      document.getElementById('ai-r-ir').textContent = data.initial_report_days;
      document.getElementById('ai-r-total').textContent = data.total_days;
      document.getElementById('ai-r-reasoning').textContent = data.reasoning;

      const confEl = document.getElementById('ai-r-confidence');
      if (data.confidence === 'high') { confEl.textContent = '🟢 High Confidence'; confEl.style.background = 'rgba(34,197,94,0.15)'; confEl.style.color = '#86efac'; }
      else if (data.confidence === 'low') { confEl.textContent = '🔴 Low Confidence'; confEl.style.background = 'rgba(239,68,68,0.15)'; confEl.style.color = '#fca5a5'; }
      else { confEl.textContent = '🟡 Medium Confidence'; confEl.style.background = 'rgba(234,179,8,0.15)'; confEl.style.color = '#fde047'; }

      const notesWrap = document.getElementById('ai-r-notes-wrap');
      if (data.notes) {
        document.getElementById('ai-r-notes').textContent = data.notes;
        notesWrap.style.display = 'block';
      } else {
        notesWrap.style.display = 'none';
      }

      document.getElementById('ai-result').style.display = 'block';
      saveEstimateToHistory(_lastAiEstimate);
    } catch (e) {
      document.getElementById('ai-error').textContent = e.message;
      document.getElementById('ai-error').style.display = 'block';
    } finally {
      document.getElementById('ai-loading').style.display = 'none';
    }
  }

  function useEstimateInProject() {
    if (!_lastAiEstimate) return;
    openCreateProject();
    setTimeout(() => {
      document.getElementById('cp-type').value = _lastAiEstimate.project_type || 'web';
      updateCpMethodOptions();
      if (_lastAiEstimate.method) document.getElementById('cp-method').value = _lastAiEstimate.method;
      document.getElementById('cp-md-assessment').value = _lastAiEstimate.assessment_days || 0;
      onAssessmentInput();
    }, 150);
  }

  // ── Highlights editor modal ───────────────────────────────────────────────────
  let _hlProjId = null;
  function openHighlightModal(projId, currentText) {
    _hlProjId = projId;
    document.getElementById('hl-text').value = currentText || '';
    document.getElementById('hl-err').style.display = 'none';
    document.getElementById('modal-highlight').classList.add('open');
  }

  async function generateHighlight() {
    const key = localStorage.getItem('vulnvault_gemini_key');
    if (!key) {
      showToast('Save Gemini API key first', 'error');
      return;
    }
    const btn = document.getElementById('hl-ai-btn');
    btn.disabled = true;
    btn.textContent = 'Thinking...';

    try {
      const notesVal = document.getElementById('hl-text').value.trim();
      const data = await apiFetch(`/api/projects/${_hlProjId}/highlight/generate`, 'POST', {
        api_key: key,
        notes: [notesVal]
      });
      document.getElementById('hl-text').value = data.highlight_text || '';
      showToast('Highlight summary generated!');
    } catch (e) {
      showToast(e.message, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Generate summary with Gemini';
    }
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

  // ── Schedule Retest modal ──────────────────────────────────────────────────────
  let _retestProjId = null;
  function openRetestModal(projId) {
    _retestProjId = projId;
    document.getElementById('retest-err').style.display = 'none';

    // Populate dropdowns
    const devSels = ['retest-engineer', 'retest-assist'];
    devSels.forEach(id => {
      const el = document.getElementById(id);
      el.innerHTML = '<option value="">— Select Assessor —</option>';
      _allEngineers.forEach(eng => {
        const opt = document.createElement('option');
        opt.value = eng.id;
        opt.textContent = eng.display_name;
        el.appendChild(opt);
      });
    });

    document.getElementById('retest-start-date').value = '';
    document.getElementById('retest-end-date').value = '';
    document.getElementById('modal-retest').classList.add('open');
  }

  async function submitRetest() {
    const engineer_id = Number(document.getElementById('retest-engineer').value) || null;
    const assist_id = Number(document.getElementById('retest-assist').value) || null;
    const start = document.getElementById('retest-start-date').value;
    const end = document.getElementById('retest-end-date').value;

    const err = document.getElementById('retest-err');
    err.style.display = 'none';

    if (!engineer_id) { err.textContent = 'Retest Lead Assessor is required.'; err.style.display = 'block'; return; }
    if (!start || !end) { err.textContent = 'Start and End dates are required.'; err.style.display = 'block'; return; }

    try {
      await apiFetch(`/api/projects/${_retestProjId}/retest`, 'POST', {
        retest_engineer_id: engineer_id,
        retest_assist_engineer_id: assist_id,
        retest_start_date: start,
        retest_end_date: end
      });
      showToast('Retest scheduled successfully');
      document.getElementById('modal-retest').classList.remove('open');
      loadProjects();
    } catch (e) {
      err.textContent = e.message;
      err.style.display = 'block';
    }
  }

  // ── Archived list ──────────────────────────────────────────────────────────────
  async function loadArchived() {
    try {
      _archivedProjects = await apiFetch('/api/projects/archived?team=offensive');
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
      tbody.innerHTML = '<tr><td colspan="8"><div class="empty-state">No archived projects found.</div></td></tr>';
      return;
    }

    const fmt = d => d ? new Date(d).toLocaleDateString('id-ID', { day: 'numeric', month: 'short', year: 'numeric' }) : '—';
    const tl = { web: 'Web', api: 'API', mobile: 'Mobile', infra: 'Infra', phishing: 'Phishing' };

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
          <td><div style="font-weight:500; color:var(--accent);">${esc(p.project_name)}</div></td>
          <td><span class="badge badge-${p.project_type}">${tl[p.project_type] || p.project_type || '—'}</span></td>
          <td>${esc(p.engineer_name || '—')}</td>
          <td style="font-size:12px; color:var(--muted);">${fmt(p.final_completed_at || p.archived_at)}</td>
          <td>${timelineBadge}</td>
          <td><span class="finding-count ${countColor(p.finding_count)}">${p.finding_count || 0}</span></td>
          <td>
            <button class="btn-ghost js-restore-project-archive" data-id="${p.project_id}" style="padding:4px 8px; font-size:11px; font-weight:700; background:rgba(16,185,129,0.1); color:#10b981;">
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
    const ok = await customConfirm('Restore Project', 'Restore this project back to the Kanban board as uncategorized?', 'Restore');
    if (!ok) return;

    try {
      await apiFetch(`/api/projects/${id}/restore`, 'PATCH');
      showToast('Project restored successfully');
      loadArchived();
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  async function archiveProjectFromBoard(id) {
    const ok = await customConfirm('Archive Project', 'Archive this project? It will be moved to the Archived section.', 'Archive');
    if (!ok) return;

    try {
      await apiFetch(`/api/projects/${id}/archive`, 'PATCH');
      showToast('Project archived successfully');
      document.getElementById('modal-board-detail').classList.remove('open');
      loadBoard();
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  // AI Estimate History helpers
  function saveEstimateToHistory(est) {
    try {
      const historyStr = localStorage.getItem('vulnvault_estimate_history') || '[]';
      const history = JSON.parse(historyStr);
      
      const newEntry = {
        id: Date.now() + Math.random().toString(36).substr(2, 5),
        timestamp: new Date().toISOString(),
        project_type: est.project_type,
        method: est.method,
        description: est.description || '',
        total_days: est.total_days,
        data: est
      };
      
      history.unshift(newEntry);
      if (history.length > 10) history.pop();
      
      localStorage.setItem('vulnvault_estimate_history', JSON.stringify(history));
      renderEstimateHistory();
    } catch (e) {
      console.error('Failed to save estimate to history:', e);
    }
  }

  function renderEstimateHistory() {
    const listEl = document.getElementById('ai-history-list');
    if (!listEl) return;
    
    try {
      const historyStr = localStorage.getItem('vulnvault_estimate_history') || '[]';
      const history = JSON.parse(historyStr);
      
      if (!history.length) {
        listEl.innerHTML = '<div style="color:var(--muted); font-size:12px; padding:10px 0;">No estimate history saved yet.</div>';
        return;
      }
      
      listEl.innerHTML = history.map(item => {
        const dateStr = new Date(item.timestamp).toLocaleString('id-ID', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
        const typeLabel = item.project_type.toUpperCase();
        const descPreview = item.description ? (item.description.substring(0, 50) + (item.description.length > 50 ? '...' : '')) : 'No description';
        
        return `
          <div class="history-item js-apply-history-estimate" data-id="${item.id}" style="display:flex; justify-content:space-between; align-items:center; padding:10px 14px; background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:8px; cursor:pointer; font-size:12px; transition: background 0.2s;">
            <div style="flex:1; min-width:0; padding-right:12px;">
              <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
                <span class="badge" style="background:rgba(99,102,241,0.1); color:var(--accent); font-size:10px; font-weight:700;">${esc(typeLabel)}</span>
                <span style="color:var(--muted); font-size:10px;">${dateStr}</span>
              </div>
              <div style="color:var(--text); font-weight:500; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${esc(descPreview)}</div>
            </div>
            <div style="flex:none; text-align:right;">
              <div style="font-weight:700; color:var(--text);">${item.total_days} d</div>
              <div style="font-size:10px; color:var(--muted); text-transform:capitalize;">${item.method || 'blackbox'}</div>
            </div>
          </div>
        `;
      }).join('');
    } catch (e) {
      listEl.innerHTML = '<div style="color:var(--red); font-size:12px; padding:10px 0;">Error loading history.</div>';
    }
  }

  function applyHistoryEstimate(id) {
    try {
      const historyStr = localStorage.getItem('vulnvault_estimate_history') || '[]';
      const history = JSON.parse(historyStr);
      const item = history.find(x => x.id === id);
      if (!item) return;
      
      const { data } = item;
      _lastAiEstimate = { ...data };
      
      document.getElementById('ai-project-type').value = item.project_type || 'web';
      updateAiMethodOptions();
      updateAiDynamicFields();
      if (item.method) document.getElementById('ai-method').value = item.method;
      document.getElementById('ai-description').value = item.description || '';
      
      if (data.num_pages && document.getElementById('ai-num-pages')) document.getElementById('ai-num-pages').value = data.num_pages;
      if (data.num_features && document.getElementById('ai-num-features')) document.getElementById('ai-num-features').value = data.num_features;
      if (data.num_endpoints && document.getElementById('ai-num-endpoints')) document.getElementById('ai-num-endpoints').value = data.num_endpoints;
      if (data.avg_methods && document.getElementById('ai-avg-methods')) document.getElementById('ai-avg-methods').value = data.avg_methods;
      if (data.infra_subtype && document.getElementById('ai-infra-subtype')) document.getElementById('ai-infra-subtype').value = data.infra_subtype;
      if (data.num_items && document.getElementById('ai-num-items')) document.getElementById('ai-num-items').value = data.num_items;
      if (data.num_targets && document.getElementById('ai-num-targets')) document.getElementById('ai-num-targets').value = data.num_targets;

      document.getElementById('ai-r-kickoff').textContent = data.kickoff_days;
      document.getElementById('ai-r-infogath').textContent = data.infogath_days;
      document.getElementById('ai-r-assessment').textContent = data.assessment_days;
      document.getElementById('ai-r-ir').textContent = data.initial_report_days;
      document.getElementById('ai-r-total').textContent = data.total_days;
      document.getElementById('ai-r-reasoning').textContent = data.reasoning;
      
      const confEl = document.getElementById('ai-r-confidence');
      if (data.confidence === 'high') { confEl.textContent = '🟢 High Confidence'; confEl.style.background = 'rgba(34,197,94,0.15)'; confEl.style.color = '#86efac'; }
      else if (data.confidence === 'low') { confEl.textContent = '🔴 Low Confidence'; confEl.style.background = 'rgba(239,68,68,0.15)'; confEl.style.color = '#fca5a5'; }
      else { confEl.textContent = '🟡 Medium Confidence'; confEl.style.background = 'rgba(234,179,8,0.15)'; confEl.style.color = '#fde047'; }

      const notesWrap = document.getElementById('ai-r-notes-wrap');
      if (data.notes) {
        document.getElementById('ai-r-notes').textContent = data.notes;
        notesWrap.style.display = 'block';
      } else {
        notesWrap.style.display = 'none';
      }
      
      document.getElementById('ai-result').style.display = 'block';
      showToast('Loaded saved estimate parameters!');
    } catch (e) {
      showToast('Failed to apply history estimate: ' + e.message, 'error');
    }
  }

  // Global click event listener for event delegation
  document.addEventListener('click', function (e) {
    // 1. Toggle group
    const toggleGroupBtn = e.target.closest('.js-toggle-group');
    if (toggleGroupBtn) {
      toggleGroup(toggleGroupBtn.dataset.pid, Number(toggleGroupBtn.dataset.clientId));
      return;
    }

    // 2. Edit project
    const editProjBtn = e.target.closest('.js-edit-project');
    if (editProjBtn) {
      const projId = Number(editProjBtn.dataset.id);
      let foundProj = null;
      for (const c of _clientGroups) {
        const p = c.projects.find(x => x.project_id === projId);
        if (p) { foundProj = p; break; }
      }
      if (foundProj) openCreateProject(true, foundProj);
      return;
    }

    // 3. Highlight project modal
    const hlProjBtn = e.target.closest('.js-open-highlight');
    if (hlProjBtn) {
      openHighlightModal(Number(hlProjBtn.dataset.id), hlProjBtn.dataset.highlight);
      return;
    }

    // 4. Retest project modal
    const retestProjBtn = e.target.closest('.js-open-retest');
    if (retestProjBtn) {
      openRetestModal(Number(retestProjBtn.dataset.id));
      return;
    }

    // 5. BAST modal
    const bastBtn = e.target.closest('.js-open-bast');
    if (bastBtn) {
      openBastModal(Number(bastBtn.dataset.id));
      return;
    }

    // 6. Delete board status

    const deleteBoardStatusBtn = e.target.closest('.js-delete-board-status');
    if (deleteBoardStatusBtn) {
      deleteBoardStatus(Number(deleteBoardStatusBtn.dataset.id));
      return;
    }

    // 7. Archive project from board detail
    const archiveProjBtn = e.target.closest('.js-archive-project-from-board');
    if (archiveProjBtn) {
      archiveProjectFromBoard(Number(archiveProjBtn.dataset.id));
      return;
    }

    // 8. Restore project from archive list
    const restoreProjBtn = e.target.closest('.js-restore-project-archive');
    if (restoreProjBtn) {
      restoreProjectFromArchive(Number(restoreProjBtn.dataset.id));
      return;
    }

    // 9. Remove project link (from shared form link row)
    const removeLinkBtn = e.target.closest('.js-remove-project-link');
    if (removeLinkBtn) {
      document.getElementById(removeLinkBtn.dataset.id)?.remove();
      return;
    }

    // 10. Saved estimate history selection
    const applyHistoryBtn = e.target.closest('.js-apply-history-estimate');
    if (applyHistoryBtn) {
      applyHistoryEstimate(applyHistoryBtn.dataset.id);
      return;
    }
  });

  document.addEventListener('click', (e) => {
    if (!e.target.closest('.quick-move-menu') && !e.target.closest('.js-card-move-menu')) {
      closeQuickMoveMenu();
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeQuickMoveMenu();
  });

  if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
    window.addEventListener('scroll', closeQuickMoveMenu, true);
    window.addEventListener('resize', closeQuickMoveMenu);
  }

})();
