/**
 * VulnVault — Admin Console Logic
 * Unscoped dashboard management logic for administrative roles
 */
(function () {
  'use strict';

  // ── Shorthand references ───────────────────────────────────────────────────────
  const {
    apiFetch, esc, escA, jsa, safeUrl, closeModal, customConfirm, customPrompt,
    showToast, timeAgo, initNotifications, loadPendingCount, logout
  } = window.PortalShared;

  // ── State variables ────────────────────────────────────────────────────────────
  let currentUser = null;
  let _usersList = [];
  let _currentLogType = 'all';
  let _archivedProjects = [];
  let _editingCpwUserId = null;

  // Expose functions globally
  window.navigate = navigate;
  window.loadUsers = loadUsers;
  window.openCreateUser = openCreateUser;
  window._onCuRoleChange = _onCuRoleChange;
  window.submitCreateUser = submitCreateUser;
  window.deleteUser = deleteUser;
  window.openChangePassword = openChangePassword;
  window.submitChangePassword = submitChangePassword;
  window.loadRequests = loadRequests;
  window.reviewProjectRequest = reviewProjectRequest;
  window.reviewRequest = reviewRequest;
  window.filterActivityLog = filterActivityLog;
  window.loadActivityLog = loadActivityLog;
  window.loadArchived = loadArchived;
  window.restoreProjectFromArchive = restoreProjectFromArchive;
  window.runSystemDiagnostics = runSystemDiagnostics;
  window.loadDiagnostics = loadDiagnostics;

  // ── Init ───────────────────────────────────────────────────────────────────────
  PortalShared.initSessionGuard(function (s) {
    currentUser = s;
    document.getElementById('user-name').textContent = s.displayName || s.username;

    // Set avatar initials
    const initials = getInitials(s.displayName || s.username);
    document.getElementById('user-avatar-initials').textContent = initials;

    initNotifications();
    loadPendingCount();

    const savedTab = localStorage.getItem('vulnvault_admin_active_tab') || 'users';
    navigate(savedTab);

    runSystemDiagnostics();
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

    localStorage.setItem('vulnvault_admin_active_tab', section);

    if (section === 'users') loadUsers();
    if (section === 'requests') loadRequests();
    if (section === 'actlog') loadActivityLog('all');
    if (section === 'archived') loadArchived();
    if (section === 'diagnostics') loadDiagnostics();
  }

  // ── Users Section ──────────────────────────────────────────────────────────────
  async function loadUsers() {
    const tbody = document.getElementById('users-body');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="6"><div class="empty-state">Loading user list...</div></td></tr>';

    try {
      _usersList = await apiFetch('/api/users');
      renderUsersTable();
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state">Error: ${e.message}</div></td></tr>`;
    }
  }

  function renderUsersTable() {
    const tbody = document.getElementById('users-body');
    if (!tbody) return;

    if (!_usersList.length) {
      tbody.innerHTML = '<tr><td colspan="6"><div class="empty-state">No users configured.</div></td></tr>';
      return;
    }

    const roleBadges = {
      admin: 'badge-admin',
      manager: 'badge-manager',
      pm: 'badge-pm',
      engineer: 'badge-engineer',
      consultant: 'badge-engineer'
    };

    const teamColors = {
      offensive: '#ef4444',
      itaudit: '#3b82f6'
    };

    tbody.innerHTML = _usersList.map(u => {
      const roleCls = roleBadges[u.role] || 'badge-pending';
      
      const teamBadge = u.team 
        ? `<span class="badge" style="background:rgba(255,255,255,0.05); color:${teamColors[u.team] || 'var(--text)'};">${u.team === 'offensive' ? 'Offensive' : 'IT Audit'}</span>`
        : '<span style="color:var(--muted);">—</span>';

      const fmtDate = u.created_at ? new Date(u.created_at).toLocaleDateString('id-ID', { day: 'numeric', month: 'short', year: 'numeric' }) : '—';

      // Hide delete button for the current logged-in user
      const deleteBtn = currentUser.id === u.id
        ? ''
        : `<button class="btn-ghost" onclick="deleteUser(${u.id})" style="padding:4px 8px; font-size:11px; flex:none; background:rgba(239,68,68,0.1); color:var(--red);">Delete</button>`;

      return `
        <tr>
          <td style="font-weight:600; color:var(--text);">${esc(u.display_name)}</td>
          <td><span style="font-family:monospace; color:var(--accent); font-size:13px;">${esc(u.username)}</span></td>
          <td><span class="badge ${roleCls}">${esc(u.role?.toUpperCase())}</span></td>
          <td>${teamBadge}</td>
          <td style="font-size:12px; color:var(--muted);">${fmtDate}</td>
          <td>
            <div style="display:flex; gap:6px;">
              <button class="btn-ghost" onclick="openChangePassword(${u.id}, ${jsa(u.display_name)})" style="padding:4px 8px; font-size:11px; flex:none;">Reset PW</button>
              ${deleteBtn}
            </div>
          </td>
        </tr>
      `;
    }).join('');
  }

  function openCreateUser() {
    document.getElementById('cu-name').value = '';
    document.getElementById('cu-username').value = '';
    document.getElementById('cu-role').value = 'engineer';
    document.getElementById('cu-password').value = '';
    document.getElementById('cu-err').style.display = 'none';

    _onCuRoleChange();
    document.getElementById('modal-create-user').classList.add('open');
  }

  function _onCuRoleChange() {
    const role = document.getElementById('cu-role').value;
    const teamWrap = document.getElementById('cu-team-wrap');
    const teamAuto = document.getElementById('cu-team-auto');
    const autoLabel = document.getElementById('cu-team-auto-label');

    if (role === 'engineer') {
      teamWrap.style.display = 'none';
      teamAuto.style.display = 'block';
      autoLabel.innerHTML = 'Auto assigned team: <strong style="color:#ef4444">Offensive Security</strong>';
      document.getElementById('cu-team').value = 'offensive';
    } else if (role === 'consultant') {
      teamWrap.style.display = 'none';
      teamAuto.style.display = 'block';
      autoLabel.innerHTML = 'Auto assigned team: <strong style="color:#3b82f6">IT Audit &amp; SE</strong>';
      document.getElementById('cu-team').value = 'itaudit';
    } else {
      teamWrap.style.display = 'block';
      teamAuto.style.display = 'none';
      document.getElementById('cu-team').value = 'offensive';
    }
  }

  async function submitCreateUser() {
    const displayName = document.getElementById('cu-name').value.trim();
    const username = document.getElementById('cu-username').value.trim();
    const role = document.getElementById('cu-role').value;
    const team = document.getElementById('cu-team').value;
    const password = document.getElementById('cu-password').value;

    const err = document.getElementById('cu-err');
    err.style.display = 'none';

    if (!displayName || !username || !password) {
      err.textContent = 'All fields marked with * are required.';
      err.style.display = 'block';
      return;
    }

    try {
      await apiFetch('/api/users', 'POST', { displayName, username, role, team, password });
      showToast('User created successfully');
      document.getElementById('modal-create-user').classList.remove('open');
      loadUsers();
    } catch (e) {
      err.textContent = e.message;
      err.style.display = 'block';
    }
  }

  async function deleteUser(id) {
    const ok = await customConfirm('Delete User', 'Are you sure you want to delete this user? This action is permanent and cannot be undone.', 'Delete', 'danger');
    if (!ok) return;

    try {
      await apiFetch(`/api/users/${id}`, 'DELETE');
      showToast('User account deleted');
      loadUsers();
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  function openChangePassword(id, name) {
    _editingCpwUserId = id;
    document.getElementById('cpw-user-info').textContent = `Resetting password for: ${name}`;
    document.getElementById('cpw-password').value = '';
    document.getElementById('cpw-confirm').value = '';
    document.getElementById('cpw-err').style.display = 'none';
    document.getElementById('modal-cpw').classList.add('open');
  }

  async function submitChangePassword() {
    const password = document.getElementById('cpw-password').value;
    const confirm = document.getElementById('cpw-confirm').value;

    const err = document.getElementById('cpw-err');
    err.style.display = 'none';

    if (!password || !confirm) {
      err.textContent = 'Please enter both password fields.';
      err.style.display = 'block';
      return;
    }

    if (password !== confirm) {
      err.textContent = 'Passwords do not match.';
      err.style.display = 'block';
      return;
    }

    try {
      await apiFetch(`/api/users/${_editingCpwUserId}/password`, 'PATCH', { password });
      showToast('Password updated successfully');
      document.getElementById('modal-cpw').classList.remove('open');
    } catch (e) {
      err.textContent = e.message;
      err.style.display = 'block';
    }
  }

  // ── Access Requests Section ────────────────────────────────────────────────────
  async function loadRequests() {
    const pBody = document.getElementById('project-requests-body');
    const aBody = document.getElementById('access-requests-body');

    if (pBody) pBody.innerHTML = '<tr><td colspan="7"><div class="empty-state">Loading project requests...</div></td></tr>';
    if (aBody) aBody.innerHTML = '<tr><td colspan="5"><div class="empty-state">Loading level requests...</div></td></tr>';

    try {
      const [projReqs, authReqs] = await Promise.all([
        apiFetch('/api/project-access-requests'),
        apiFetch('/api/access-requests')
      ]);

      renderProjectRequests(projReqs);
      renderAccountRequests(authReqs);
    } catch (e) {
      showToast('Failed to load requests: ' + e.message, 'error');
    }
  }

  function renderProjectRequests(reqs) {
    const tbody = document.getElementById('project-requests-body');
    if (!tbody) return;

    if (!reqs || !reqs.length) {
      tbody.innerHTML = '<tr><td colspan="7"><div class="empty-state">No pending project access requests.</div></td></tr>';
      return;
    }

    const fmt = d => d ? new Date(d).toLocaleDateString('id-ID', { day: 'numeric', month: 'short' }) : '—';
    const teamColors = { offensive: '#ef4444', itaudit: '#3b82f6' };

    tbody.innerHTML = reqs.map(r => {
      const teamBadge = r.team 
        ? `<span class="badge" style="background:rgba(255,255,255,0.05); color:${teamColors[r.team]};">${r.team === 'offensive' ? 'Offensive' : 'IT Audit'}</span>`
        : '<span style="color:var(--muted)">—</span>';

      let actions = '—';
      if (r.status === 'pending') {
        actions = `
          <button class="approve-btn" onclick="reviewProjectRequest(${r.id}, 'approved')">Approve</button>
          <button class="reject-btn" onclick="reviewProjectRequest(${r.id}, 'rejected')">Reject</button>
        `;
      } else {
        const cls = r.status === 'approved' ? 'badge-approved' : 'badge-rejected';
        actions = `<span class="badge ${cls}">${r.status.toUpperCase()}</span>`;
      }

      return `
        <tr>
          <td style="font-weight:600;">${esc(r.engineer_name)}</td>
          <td>${esc(r.client_name)}</td>
          <td style="font-weight:500; color:var(--accent);">${esc(r.project_name)}</td>
          <td>${teamBadge}</td>
          <td style="font-size:12px; color:var(--muted);">${fmt(r.created_at)}</td>
          <td><span class="badge badge-${r.status === 'pending' ? 'pending' : r.status}">${r.status.toUpperCase()}</span></td>
          <td><div style="display:flex;">${actions}</div></td>
        </tr>
      `;
    }).join('');
  }

  function renderAccountRequests(reqs) {
    const tbody = document.getElementById('access-requests-body');
    if (!tbody) return;

    if (!reqs || !reqs.length) {
      tbody.innerHTML = '<tr><td colspan="5"><div class="empty-state">No pending account elevational requests.</div></td></tr>';
      return;
    }

    const fmt = d => d ? new Date(d).toLocaleDateString('id-ID', { day: 'numeric', month: 'short' }) : '—';

    tbody.innerHTML = reqs.map(r => {
      let actions = '—';
      if (r.status === 'pending') {
        actions = `
          <button class="approve-btn" onclick="reviewRequest(${r.id}, 'approved')">Approve</button>
          <button class="reject-btn" onclick="reviewRequest(${r.id}, 'rejected')">Reject</button>
        `;
      } else {
        const cls = r.status === 'approved' ? 'badge-approved' : 'badge-rejected';
        actions = `<span class="badge ${cls}">${r.status.toUpperCase()}</span>`;
      }

      return `
        <tr>
          <td style="font-weight:600;">${esc(r.username)}</td>
          <td>Requesting role elevation to: <strong style="color:var(--accent);">${esc(r.requested_role?.toUpperCase())}</strong></td>
          <td style="font-size:12px; color:var(--muted);">${fmt(r.created_at)}</td>
          <td><span class="badge badge-${r.status === 'pending' ? 'pending' : r.status}">${r.status.toUpperCase()}</span></td>
          <td><div style="display:flex;">${actions}</div></td>
        </tr>
      `;
    }).join('');
  }

  async function reviewProjectRequest(id, status) {
    try {
      await apiFetch(`/api/project-access-requests/${id}`, 'PATCH', { status });
      showToast(`Request ${status}`);
      loadRequests();
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  async function reviewRequest(id, status) {
    try {
      await apiFetch(`/api/access-requests/${id}`, 'PATCH', { status });
      showToast(`Role request ${status}`);
      loadRequests();
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  // ── Activity Log Section ───────────────────────────────────────────────────────
  function filterActivityLog(type) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    
    let btnId = 'tab-act-all';
    if (type === 'user') btnId = 'tab-act-user';
    if (type === 'crud') btnId = 'tab-act-crud';
    if (type === 'request') btnId = 'tab-act-request';

    document.getElementById(btnId).classList.add('active');
    loadActivityLog(type);
  }

  async function loadActivityLog(type = 'all') {
    const tbody = document.getElementById('actlog-body');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="4"><div class="empty-state">Loading logs...</div></td></tr>';

    const q = type && type !== 'all' ? `?type=${encodeURIComponent(type)}` : '';

    try {
      const rows = await apiFetch('/api/activity-log' + q);
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="4"><div class="empty-state">No activity logs recorded.</div></td></tr>';
        return;
      }

      const actionsColors = {
        'create_project': '#10b981', 'delete_project': '#ef4444', 'edit_project': '#3b82f6',
        'create_client': '#10b981', 'delete_client': '#ef4444', 'rename_client': '#3b82f6',
        'create_user': '#10b981', 'delete_user': '#ef4444',
        'approve_request': '#10b981', 'reject_request': '#ef4444'
      };

      tbody.innerHTML = rows.map(r => {
        let details = [];
        if (r.client_name) details.push(`Client: ${esc(r.client_name)}`);
        if (r.project_name) details.push(`Project: ${esc(r.project_name)}`);
        const subtext = details.length ? `<br><span style="font-size:11px; color:var(--muted);">${details.join(', ')}</span>` : '';

        const actionColor = actionsColors[r.action] || 'var(--muted)';

        return `
          <tr>
            <td style="font-size:12px; color:var(--muted);">${new Date(r.created_at).toLocaleString()}</td>
            <td style="font-weight:600; color:var(--text);">${esc(r.actor_name || 'System')}</td>
            <td><span class="badge" style="background:rgba(255,255,255,0.05); color:${actionColor};">${r.action?.toUpperCase().replace(/_/g, ' ')}</span></td>
            <td style="font-size:12px; color:var(--text); line-height:1.4;">${esc(r.details || '')}${subtext}</td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state">Error: ${e.message}</div></td></tr>`;
    }
  }

  // ── Unified Project Archive Section ────────────────────────────────────────────
  async function loadArchived() {
    const tbody = document.getElementById('archived-body');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="7"><div class="empty-state">Loading archives...</div></td></tr>';

    try {
      _archivedProjects = await apiFetch('/api/projects/archived');
      renderArchivedTable();
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state">Error: ${e.message}</div></td></tr>`;
    }
  }

  function renderArchivedTable() {
    const tbody = document.getElementById('archived-body');
    if (!tbody) return;

    if (!_archivedProjects.length) {
      tbody.innerHTML = '<tr><td colspan="7"><div class="empty-state">No projects in archive.</div></td></tr>';
      return;
    }

    const fmt = d => d ? new Date(d).toLocaleDateString('id-ID', { day: 'numeric', month: 'short', year: 'numeric' }) : '—';
    const teamColors = { offensive: '#ef4444', itaudit: '#3b82f6' };

    tbody.innerHTML = _archivedProjects.map(p => {
      const teamBadge = p.team 
        ? `<span class="badge" style="background:rgba(255,255,255,0.05); color:${teamColors[p.team]};">${p.team === 'offensive' ? 'Offensive' : 'IT Audit'}</span>`
        : '<span style="color:var(--muted)">—</span>';

      return `
        <tr>
          <td><div style="font-weight:600; color:var(--text);">${esc(p.client_name)}</div></td>
          <td><div style="font-weight:500; color:var(--accent);">${esc(p.project_name)}</div></td>
          <td>${teamBadge}</td>
          <td>${esc(p.service || '—')}</td>
          <td>${esc(p.engineer_name || '—')}</td>
          <td style="font-size:12px; color:var(--muted);">${fmt(p.final_completed_at || p.archived_at)}</td>
          <td>
            <button class="btn-ghost" onclick="restoreProjectFromArchive(${p.project_id})" style="padding:4px 8px; font-size:11px; font-weight:700; background:rgba(16,185,129,0.1); color:#10b981;">
              Restore
            </button>
          </td>
        </tr>
      `;
    }).join('');
  }

  async function restoreProjectFromArchive(id) {
    const ok = await customConfirm('Restore Project', 'Restore this project/engagement back to active Kanban workflows?', 'Restore');
    if (!ok) return;

    try {
      await apiFetch(`/api/projects/${id}/restore`, 'PATCH');
      showToast('Project restored successfully');
      loadArchived();
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  async function runSystemDiagnostics() {
    const banner = document.getElementById('diagnostic-warning-banner');
    const details = document.getElementById('diagnostic-details');
    if (!banner || !details) return;

    try {
      const res = await apiFetch('/api/admin/diagnostics');
      const clientErrors = res.clientMismatches || [];
      const boardErrors = res.boardMismatches || [];
      const userErrors = res.userMismatches || [];

      if (clientErrors.length > 0 || boardErrors.length > 0 || userErrors.length > 0) {
        let html = '<ul style="margin: 0; padding-left: 20px;">';
        clientErrors.forEach(item => {
          html += `<li>Project <strong>${esc(item.name)}</strong> (ID: ${item.id}, team: ${esc(item.project_team || 'offensive')}) has client team mismatch: Client <strong>${esc(item.client_name)}</strong> is team: <strong>${esc(item.client_team || 'offensive')}</strong></li>`;
        });
        boardErrors.forEach(item => {
          html += `<li>Project <strong>${esc(item.name)}</strong> (ID: ${item.id}, team: ${esc(item.project_team || 'offensive')}) has board status team mismatch: Status <strong>${esc(item.status_name)}</strong> is team: <strong>${esc(item.status_team || 'offensive')}</strong></li>`;
        });
        userErrors.forEach(item => {
          html += `<li>Project <strong>${esc(item.name)}</strong> (ID: ${item.id}, team: ${esc(item.project_team || 'offensive')}) has user assignment team mismatch: User <strong>${esc(item.display_name)}</strong> is team: <strong>${esc(item.user_team || 'offensive')}</strong></li>`;
        });
        html += '</ul>';
        details.innerHTML = html;
        banner.style.display = 'block';
      } else {
        banner.style.display = 'none';
        details.innerHTML = '';
      }
    } catch (e) {
      console.error('Failed to run diagnostics:', e);
      banner.style.display = 'block';
      details.innerHTML = `Failed to retrieve diagnostic data: ${esc(e.message)}`;
    }
  }

  async function loadDiagnostics() {
    const container = document.getElementById('diagnostics-root');
    if (!container) return;
    container.innerHTML = '<div class="empty-state">Loading diagnostics...</div>';

    try {
      const [data, caps] = await Promise.all([
        apiFetch('/api/admin/diagnostics'),
        apiFetch('/api/portal-capabilities').catch(() => ({ legacyEnabled: false }))
      ]);
      renderDiagnostics(data, caps.legacyEnabled);
    } catch (e) {
      container.innerHTML = `<div class="empty-state">Error: ${esc(e.message)}</div>`;
    }
  }

  function renderDiagnostics(data, legacyEnabled) {
    const container = document.getElementById('diagnostics-root');
    if (!container) return;

    const clientMismatches = data.clientMismatches || [];
    const boardMismatches = data.boardMismatches || [];
    const userMismatches = data.userMismatches || [];

    const totalMismatches = clientMismatches.length + boardMismatches.length + userMismatches.length;

    let statusText = 'Healthy';
    let statusBg = '#10b981'; // Green
    let statusClass = 'badge-approved';

    if (totalMismatches > 0) {
      statusText = 'Critical';
      statusBg = '#ef4444'; // Red
      statusClass = 'badge-rejected';
    } else if (legacyEnabled) {
      statusText = 'Warning';
      statusBg = '#f59e0b'; // Orange
      statusClass = 'badge-pending';
    }

    const anomalies = [];

    clientMismatches.forEach(m => {
      anomalies.push({
        projectId: m.id,
        projectName: m.name,
        expectedTeam: m.client_team || 'offensive',
        actualTeam: m.project_team || 'offensive',
        type: 'Client Mismatch',
        relatedEntity: `Client: ${m.client_name}`
      });
    });

    boardMismatches.forEach(m => {
      anomalies.push({
        projectId: m.id,
        projectName: m.name,
        expectedTeam: m.project_team || 'offensive',
        actualTeam: m.status_team || 'offensive',
        type: 'Board Status Mismatch',
        relatedEntity: `Status: ${m.status_name}`
      });
    });

    userMismatches.forEach(m => {
      anomalies.push({
        projectId: m.id,
        projectName: m.name,
        expectedTeam: m.project_team || 'offensive',
        actualTeam: m.user_team || 'offensive',
        type: 'User Assignment Mismatch',
        relatedEntity: `User: ${m.display_name} (ID: ${m.user_id})`
      });
    });

    let anomalyTableHtml = '';
    if (anomalies.length > 0) {
      anomalyTableHtml = `
        <div style="margin-top: 30px;">
          <h3 style="font-size: 15px; font-weight: 600; color: var(--text); margin-bottom: 12px;">Detected Scoping Anomalies</h3>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Project ID</th>
                  <th>Project Name</th>
                  <th>Expected Team</th>
                  <th>Actual Team</th>
                  <th>Related Entity / Type</th>
                </tr>
              </thead>
              <tbody>
                ${anomalies.map(a => `
                  <tr>
                    <td style="font-family: monospace; font-size: 13px; color: var(--accent);">${a.projectId}</td>
                    <td style="font-weight: 600; color: var(--text);">${esc(a.projectName)}</td>
                    <td>
                      <span class="badge" style="background: rgba(255,255,255,0.05); color: ${a.expectedTeam === 'offensive' ? '#ef4444' : '#3b82f6'};">
                        ${esc(a.expectedTeam)}
                      </span>
                    </td>
                    <td>
                      <span class="badge" style="background: rgba(255,255,255,0.05); color: ${a.actualTeam === 'offensive' ? '#ef4444' : '#3b82f6'};">
                        ${esc(a.actualTeam)}
                      </span>
                    </td>
                    <td style="font-size: 12px; line-height: 1.4;">
                      <span style="color: var(--muted); font-size: 11px; text-transform: uppercase; font-weight: 700; display: block; margin-bottom: 2px;">${esc(a.type)}</span>
                      <span>${esc(a.relatedEntity)}</span>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      `;
    } else {
      anomalyTableHtml = `
        <div class="empty-state" style="margin-top: 30px; border: 1px dashed var(--border);">
          No data boundary integrity issues detected. All scoped entities are aligned.
        </div>
      `;
    }

    container.innerHTML = `
      <div style="display:flex; align-items:center; justify-content:space-between; background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:12px; padding:16px 20px; margin-bottom:30px;">
        <div>
          <div style="font-weight:600; font-size:15px; color:var(--text);">Overall System Status</div>
          <div style="font-size:12px; color:var(--muted); margin-top:2px;">Last scanned: ${new Date().toLocaleTimeString('id-ID')}</div>
        </div>
        <span class="badge ${statusClass}" style="padding:6px 12px; font-size:12px; font-weight:700; text-transform:uppercase; border-radius:6px; background:${statusBg}; color:#fff;">
          ${statusText}
        </span>
      </div>

      <div class="metrics-grid" style="display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:20px; margin-bottom:30px;">
        <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:12px; padding:20px; display:flex; flex-direction:column; gap:8px;">
          <div style="font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:0.5px; font-weight:600;">Client/Project Mismatch</div>
          <div style="font-size:32px; font-weight:700; color:${clientMismatches.length > 0 ? '#ef4444' : 'var(--text)'};">${clientMismatches.length}</div>
        </div>
        <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:12px; padding:20px; display:flex; flex-direction:column; gap:8px;">
          <div style="font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:0.5px; font-weight:600;">Board Status Mismatch</div>
          <div style="font-size:32px; font-weight:700; color:${boardMismatches.length > 0 ? '#ef4444' : 'var(--text)'};">${boardMismatches.length}</div>
        </div>
        <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border); border-radius:12px; padding:20px; display:flex; flex-direction:column; gap:8px;">
          <div style="font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:0.5px; font-weight:600;">Assignment Team Mismatch</div>
          <div style="font-size:32px; font-weight:700; color:${userMismatches.length > 0 ? '#ef4444' : 'var(--text)'};">${userMismatches.length}</div>
        </div>
      </div>

      ${anomalyTableHtml}
    `;
  }

})();
