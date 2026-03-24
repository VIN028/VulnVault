/* ═══════════════════════════════════════════════════════════════════
   VulnVault — Main Application JavaScript
   Features: Markdown rendering, multi-image POC, paste support
═══════════════════════════════════════════════════════════════════ */

// ─── State ────────────────────────────────────────────────────────────────────
let currentReport = null;
let currentDetailId = null;
let uploadedScreenshotPaths = [];   // Array for multi-image
let selectedSeverity = 'Medium';
let searchDebounceTimer = null;
let loadingStepTimer = null;
let libraryFilters = {
  search: '',
  severity: '',
  sort: 'newest',
  project_id: '',
};


// ─── API Key / Model Management ───────────────────────────────────────────────
const API_KEY_STORAGE = 'vulnvault_gemini_key';
const MODEL_STORAGE   = 'vulnvault_gemini_model';
const DEFAULT_MODEL   = 'gemini-3-flash-preview';

function getApiKey() { return localStorage.getItem(API_KEY_STORAGE) || ''; }
function getModel()  { return localStorage.getItem(MODEL_STORAGE)   || DEFAULT_MODEL; }

function validateApiKeyInput(value) {
  const btn = document.getElementById('apikey-submit');
  btn.disabled = !(value && value.trim().length >= 20);
  const err = document.getElementById('apikey-error');
  if (err) err.style.display = 'none';
}

function saveApiKey() {
  const input = document.getElementById('apikey-input');
  const key   = input.value.trim();
  const err   = document.getElementById('apikey-error');
  if (!key || key.length < 20) {
    err.textContent = 'Please enter a valid Google AI Studio API key.';
    err.style.display = 'block';
    return;
  }
  localStorage.setItem(API_KEY_STORAGE, key);
  localStorage.setItem(MODEL_STORAGE, document.getElementById('apikey-model').value);
  hideApiKeyModal();
  updateAiStatus(true);
  showToast('API key saved!', 'success');
  loadLibrary();
}

function openSettings() {
  const modelEl = document.getElementById('apikey-model');
  document.getElementById('apikey-input').value = getApiKey();
  if (modelEl) modelEl.value = getModel();
  validateApiKeyInput(getApiKey());
  document.getElementById('apikey-overlay').classList.remove('hidden');
}
function hideApiKeyModal() { document.getElementById('apikey-overlay').classList.add('hidden'); }

function toggleApiKeyVis() {
  const input = document.getElementById('apikey-input');
  const icon  = document.getElementById('eye-icon');
  if (input.type === 'password') {
    input.type = 'text';
    icon.innerHTML = `<path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/>`;
  } else {
    input.type = 'password';
    icon.innerHTML = `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>`;
  }
}

function updateAiStatus(hasKey) {
  const dot  = document.querySelector('.status-dot');
  const text = document.getElementById('ai-status-text');
  if (hasKey) {
    dot.style.background = 'var(--accent-green)';
    dot.style.boxShadow  = '0 0 8px var(--accent-green)';
    text.textContent     = getModel().replace('-preview','');
  } else {
    dot.style.background = 'var(--critical)';
    dot.style.boxShadow  = '0 0 8px var(--critical)';
    text.textContent     = 'API Key Missing';
  }
}

async function logoutApp() {
  if (!confirm('Sign out of VulnVault?')) return;
  try {
    await fetch('/api/logout', { method: 'POST' });
  } catch (_) {}
  window.location.href = '/login.html';
}

// ─── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  try {
    const sRes = await fetch('/api/session');
    const s = await sRes.json();
    if (!s.authenticated) {
      window.location.href = '/login.html';
      return;
    }
  } catch {
    window.location.href = '/login.html';
    return;
  }

  const key     = getApiKey();
  const modelEl = document.getElementById('apikey-model');
  if (modelEl) modelEl.value = getModel();

  if (!key) {
    document.getElementById('apikey-overlay').classList.remove('hidden');
    updateAiStatus(false);
  } else {
    document.getElementById('apikey-overlay').classList.add('hidden');
    updateAiStatus(true);
    loadLibrary();
  }

  // ── Drag-and-drop ──
  const zone = document.getElementById('upload-zone');
  zone.addEventListener('dragover',  (e) => { e.preventDefault(); zone.classList.add('dragover'); });
  zone.addEventListener('dragleave', ()  => zone.classList.remove('dragover'));

  // ── Global paste (Ctrl+V) — routes to active view ──
  document.addEventListener('paste', (e) => {
    const items = e.clipboardData?.items;
    if (!items) return;
    const images = Array.from(items).filter(i => i.type.startsWith('image/'));
    if (!images.length) return;
    // Route to whichever view is active
    const activeView = document.querySelector('.view.active')?.id;
    e.preventDefault();
    images.forEach(item => {
      const file = item.getAsFile();
      if (!file) return;
      if (activeView === 'view-ask') handleAskScreenshotFile(file);
      else handleScreenshotFile(file);
    });
  });
});

// ─── Navigation ───────────────────────────────────────────────────────────────
function showView(view) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById(`view-${view}`).classList.add('active');
  document.getElementById(`nav-${view}`).classList.add('active');

  const searchBox  = document.getElementById('search-container');
  const filtersBox = document.getElementById('library-filters');
  const btnNew     = document.querySelector('.btn-generate');

  if (view === 'library') {
    document.getElementById('page-title').textContent    = 'Vulnerability Library';
    document.getElementById('page-subtitle').textContent = 'Browse and manage your saved vulnerability reports';
    searchBox.style.display = '';
    filtersBox.style.display = '';
    btnNew.style.display    = '';
    loadLibrary(libraryFilters.search);
    loadLibraryClientDropdown();
  } else if (view === 'ask') {
    document.getElementById('page-title').textContent    = 'Ask AI';
    document.getElementById('page-subtitle').textContent = 'Upload screenshots — let Gemini identify potential vulnerabilities';
    searchBox.style.display = 'none';
    filtersBox.style.display = 'none';
    btnNew.style.display    = 'none';
  } else if (view === 'clients') {
    document.getElementById('page-title').textContent    = 'Clients';
    document.getElementById('page-subtitle').textContent = 'Group vulnerabilities per client and project';
    searchBox.style.display = 'none';
    filtersBox.style.display = 'none';
    btnNew.style.display    = 'none';
    loadClientsView();
  } else {
    document.getElementById('page-title').textContent    = 'AI Report Generator';
    document.getElementById('page-subtitle').textContent = 'Powered by Gemini — craft a full pentest report in seconds';
    searchBox.style.display = 'none';
    filtersBox.style.display = 'none';
    btnNew.style.display    = 'none';
    loadGenClientDropdown();
  }
}

// ─── Library ──────────────────────────────────────────────────────────────────
async function loadLibrary(searchQuery = '') {
  try {
    libraryFilters.search = searchQuery;
    const params = new URLSearchParams();
    if (libraryFilters.search)   params.set('search',   libraryFilters.search);
    if (libraryFilters.severity)  params.set('severity', libraryFilters.severity);
    if (libraryFilters.sort)      params.set('sort',     libraryFilters.sort);
    if (libraryFilters.project_id) params.set('project_id', libraryFilters.project_id);
    const url = `/api/vulnerabilities${params.toString() ? `?${params}` : ''}`;
    const res  = await fetch(url);
    const data = await res.json();
    renderLibrary(data);
  } catch (err) {
    showToast('Failed to load library', 'error');
  }
}

// ─── Library Client/Project Filter ────────────────────────────────────────────
let _libClients = [];
async function loadLibraryClientDropdown() {
  try {
    const res = await fetch('/api/clients');
    _libClients = await res.json();
    const el = document.getElementById('filter-client');
    if (!el) return;
    el.innerHTML = '<option value="">All Clients</option>' +
      _libClients.map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join('');
  } catch { /* ignore */ }
}
async function handleLibraryClientChange() {
  const clientId = document.getElementById('filter-client')?.value;
  const projEl   = document.getElementById('filter-project');
  projEl.innerHTML = '<option value="">All Projects</option>';
  libraryFilters.project_id = '';
  if (clientId) {
    const res = await fetch(`/api/clients/${clientId}/projects`);
    if (!res.ok) {
      projEl.disabled = true;
      showToast('Failed to load project filters', 'error');
      return;
    }
    const projects = await res.json();
    projEl.innerHTML = '<option value="">All Projects</option>' +
      projects.map(p => `<option value="${p.id}">${escapeHtml(p.name)}</option>`).join('');
    projEl.disabled = false;
  } else {
    projEl.disabled = true;
  }
  loadLibrary(libraryFilters.search);
}

function renderLibrary(vulns) {
  const grid  = document.getElementById('vuln-grid');
  const empty = document.getElementById('empty-state');

  document.getElementById('stat-total').textContent    = vulns.length;
  document.getElementById('stat-critical').textContent = vulns.filter(v => v.severity === 'Critical').length;
  document.getElementById('stat-high').textContent     = vulns.filter(v => v.severity === 'High').length;
  document.getElementById('stat-medium').textContent   = vulns.filter(v => v.severity === 'Medium').length;
  document.getElementById('stat-low').textContent      = vulns.filter(v => v.severity === 'Low' || v.severity === 'Info').length;
  document.getElementById('vuln-count').textContent    = vulns.length;

  if (!vulns.length) {
    grid.innerHTML = '';
    empty.style.display = 'flex';
    return;
  }
  empty.style.display = 'none';
  grid.innerHTML = vulns.map(v => createVulnCard(v)).join('');
}

function createVulnCard(v) {
  const date        = new Date(v.created_at).toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric' });
  const rawDesc     = stripMarkdown(v.description || '');
  const descPreview = rawDesc.length > 140 ? rawDesc.substring(0, 140) + '…' : rawDesc;
  const sev         = v.severity || 'Medium';

  // Count screenshots
  let screenshotCount = 0;
  if (v.screenshot_path) {
    try { screenshotCount = JSON.parse(v.screenshot_path).length; } catch { screenshotCount = 1; }
  }

  return `
    <div class="vuln-card" onclick="openDetail(${v.id})">
      <div class="card-top-bar sev-bar-${sev}"></div>
      <div class="card-inner">
        <div class="card-header">
          <span class="severity-badge sev-${sev}">${sev}</span>
          ${screenshotCount ? `<span class="card-img-count">📷 ${screenshotCount}</span>` : ''}
        </div>
        <div class="card-title">${escapeHtml(v.name)}</div>
        <div class="card-description">${escapeHtml(descPreview)}</div>
        <div class="card-meta">
          <span class="card-date">${date}</span>
          <svg class="card-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:15px;height:15px;flex-shrink:0;"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
        </div>
      </div>
    </div>`;
}

function handleSearch(value) {
  clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(() => loadLibrary(value.trim()), 300);
}

function handleLibraryFilterChange() {
  libraryFilters.severity  = document.getElementById('filter-severity')?.value || '';
  libraryFilters.sort      = document.getElementById('sort-by')?.value || 'newest';
  libraryFilters.project_id = document.getElementById('filter-project')?.value || '';
  loadLibrary((document.getElementById('search-input')?.value || '').trim());
}

// ─── Markdown ─────────────────────────────────────────────────────────────────
function renderMarkdown(text) {
  if (!text) return '';

  // Escape HTML first (safely)
  let html = escapeHtml(text);

  // Headers
  html = html.replace(/^### (.+)$/gm, '<h4 style="margin:.6em 0 .2em;font-size:13px;color:var(--text-primary)">$1</h4>');
  html = html.replace(/^## (.+)$/gm,  '<h3 style="margin:.6em 0 .3em;font-size:14px;color:var(--text-primary)">$1</h3>');

  // Bold + italic
  html = html.replace(/\*\*\*(.+?)\*\*\*/g, '<strong><em>$1</em></strong>');
  html = html.replace(/\*\*(.+?)\*\*/g,    '<strong style="color:var(--text-primary)">$1</strong>');
  html = html.replace(/\*(.+?)\*/g,        '<em>$1</em>');
  html = html.replace(/_(.+?)_/g,          '<em>$1</em>');

  // Inline code
  html = html.replace(/`(.+?)`/g, '<code style="background:rgba(99,102,241,0.15);padding:1px 5px;border-radius:4px;font-family:monospace;font-size:12px">$1</code>');

  // Process lines for lists
  const lines = html.split('\n');
  const out   = [];
  let inBullet = false, inNumber = false;

  for (let line of lines) {
    const bullet = line.match(/^[*\-] (.+)$/);
    const number = line.match(/^\d+\. (.+)$/);

    if (bullet) {
      if (!inBullet) { out.push('<ul class="md-list">'); inBullet = true; }
      out.push(`<li>${bullet[1]}</li>`);
    } else if (number) {
      if (!inNumber) { out.push('<ol class="md-list">'); inNumber = true; }
      out.push(`<li>${number[1]}</li>`);
    } else {
      if (inBullet) { out.push('</ul>'); inBullet = false; }
      if (inNumber) { out.push('</ol>'); inNumber = false; }
      out.push(line === '' ? '<div class="md-gap"></div>' : `<p class="md-p">${line}</p>`);
    }
  }
  if (inBullet) out.push('</ul>');
  if (inNumber) out.push('</ol>');

  return out.join('');
}

// Strip markdown for plain-text previews
function stripMarkdown(text) {
  return (text || '')
    .replace(/\*\*(.+?)\*\*/g, '$1')
    .replace(/\*(.+?)\*/g,     '$1')
    .replace(/`(.+?)`/g,       '$1')
    .replace(/^[*\-] /gm,      '')
    .replace(/^\d+\. /gm,      '')
    .replace(/^#{1,6} /gm,     '');
}

// ─── Section Renderer ─────────────────────────────────────────────────────────
function renderSection({ num, title, content, screenshots, isRefs }) {
  let body = '';

  if (isRefs && content) {
    const refs = content.split('\n').map(r => r.trim()).filter(r => r);
    body = `<div class="references-list">` + refs.map(r => {
      const isUrl = /^https?:\/\//.test(r);
      return `<div class="ref-item">
        <div class="ref-dot"></div>
        ${isUrl
          ? `<a href="${r}" target="_blank" rel="noopener noreferrer">${r}</a>`
          : `<span>${escapeHtml(r)}</span>`}
      </div>`;
    }).join('') + `</div>`;
  } else {
    body = `<div class="section-content md-content">${renderMarkdown(content || '')}</div>`;

    // Multi screenshot grid
    if (screenshots && screenshots.length) {
      body += `<div class="poc-screenshots">
        <div class="poc-label">📸 POC Screenshots (${screenshots.length})</div>
        <div class="poc-img-grid">
          ${screenshots.map((src, i) => `
            <div class="poc-img-wrap">
              <img src="${src}" alt="POC ${i+1}" onclick="openImgFullscreen('${src}')" />
              <span class="poc-img-num">${i+1}</span>
            </div>`).join('')}
        </div>
      </div>`;
    }
  }

  return `
    <div class="report-section">
      <div class="section-header">
        <div class="section-num">${num}</div>
        <div class="section-title">${title}</div>
      </div>
      ${body}
    </div>`;
}

function openImgFullscreen(src) {
  const w = window.open('', '_blank');
  w.document.write(`<html><body style="margin:0;background:#000;display:flex;align-items:center;justify-content:center;min-height:100vh"><img src="${src}" style="max-width:100%;max-height:100vh"/></body></html>`);
}

// Parse screenshot_path — can be single string or JSON array
function parseScreenshots(screenshot_path) {
  if (!screenshot_path) return [];
  try {
    const parsed = JSON.parse(screenshot_path);
    if (Array.isArray(parsed)) return parsed;
    return [parsed];
  } catch {
    return [screenshot_path];
  }
}

// ─── Multi-Image Upload ───────────────────────────────────────────────────────
function selectSeverity(sev) {
  selectedSeverity = sev;
  document.querySelectorAll('.sev-btn').forEach(b => b.classList.toggle('active', b.dataset.sev === sev));
}

function handleDrop(e) {
  e.preventDefault();
  e.currentTarget.classList.remove('dragover');
  const files = Array.from(e.dataTransfer.files).filter(f => f.type.startsWith('image/'));
  files.forEach(f => handleScreenshotFile(f));
}

function handleScreenshot(input) {
  Array.from(input.files).forEach(f => handleScreenshotFile(f));
  input.value = '';   // reset so same files can be picked again
}

async function handleScreenshotFile(file) {
  const formData = new FormData();
  formData.append('screenshot', file);
  try {
    const res  = await fetch('/api/upload', { method: 'POST', body: formData });
    if (!res.ok) throw new Error('Upload failed');
    const data = await res.json();
    uploadedScreenshotPaths.push(data.path);
    renderThumbs();
  } catch {
    showToast('Failed to upload screenshot', 'error');
  }
}

function renderThumbs() {
  const container  = document.getElementById('upload-thumbs');
  const placeholder = document.getElementById('upload-placeholder');

  if (!uploadedScreenshotPaths.length) {
    placeholder.style.display = 'flex';
    container.innerHTML = '';
    return;
  }

  placeholder.style.display = 'none';
  container.innerHTML = `
    <div class="thumb-grid">
      ${uploadedScreenshotPaths.map((p, i) => `
        <div class="thumb-item">
          <img src="${p}" alt="POC ${i+1}" onclick="openImgFullscreen('${p}')" />
          <button class="thumb-remove" onclick="removeThumb(${i}, event)" title="Remove">✕</button>
          <span class="thumb-num">${i+1}</span>
        </div>`).join('')}
      <div class="thumb-add" onclick="document.getElementById('screenshot-input').click()" title="Add more">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
      </div>
    </div>`;
}

function removeThumb(i, e) {
  e.stopPropagation();
  uploadedScreenshotPaths.splice(i, 1);
  renderThumbs();
}

function removeScreenshot(e) {
  e.stopPropagation();
  uploadedScreenshotPaths = [];
  document.getElementById('screenshot-input').value = '';
  renderThumbs();
}

// ─── AI Generator ─────────────────────────────────────────────────────────────
const loadingSteps = [
  'Analyzing vulnerability details...',
  'Crafting description section...',
  'Assessing impact and risks...',
  'Building recommendation steps...',
  'Writing POC narrative...',
  'Compiling references...',
  'Finalizing report...',
];

async function handleGenerate(e) {
  e.preventDefault();
  const apiKey = getApiKey();
  if (!apiKey) { openSettings(); showToast('Please add your Gemini API key first', 'error'); return; }

  const name         = document.getElementById('vuln-name').value.trim();
  const shortDesc    = document.getElementById('short-desc').value.trim();
  const affectedItems = document.getElementById('affected-items').value.trim();
  const pocNotes     = document.getElementById('poc-notes').value.trim();
  const language     = document.getElementById('report-lang').value;
  // Read optional client/project context
  const genClientSel  = document.getElementById('gen-client-select');
  const genProjectSel = document.getElementById('gen-project-select');
  const genClientOpt  = genClientSel?.options[genClientSel?.selectedIndex];
  const genProjectOpt = genProjectSel?.options[genProjectSel?.selectedIndex];
  const client_name   = genClientOpt?.value  ? genClientOpt.text  : '';
  const project_name  = genProjectOpt?.value ? genProjectOpt.text : '';
  const project_id    = genProjectOpt?.value ? Number(genProjectOpt.value) : null;

  showPanel('loading');
  document.getElementById('generate-btn').disabled = true;
  document.getElementById('generate-btn').classList.add('loading');

  let stepIndex = 0;
  const stepEl  = document.getElementById('loading-step');
  stepEl.textContent = loadingSteps[0];
  loadingStepTimer = setInterval(() => {
    stepIndex = (stepIndex + 1) % loadingSteps.length;
    stepEl.textContent = loadingSteps[stepIndex];
  }, 2200);

  try {
    const res = await fetch('/api/ai/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name, short_description: shortDesc,
        affected_items: affectedItems, poc_notes: pocNotes,
        screenshot_paths: uploadedScreenshotPaths,
        language, apiKey, severity: selectedSeverity,
        model: getModel(),
        client_name, project_name, project_id
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Generation failed');
    currentReport = { ...data, severity: data.severity || selectedSeverity, project_id: data.project_id || project_id };
    displayReport(currentReport);
  } catch (err) {
    showPanel('empty');
    showToast(err.message || 'AI generation failed', 'error');
    if (err.message?.includes('API key') || err.message?.includes('invalid')) openSettings();
  } finally {
    clearInterval(loadingStepTimer);
    document.getElementById('generate-btn').disabled = false;
    document.getElementById('generate-btn').classList.remove('loading');
  }
}

function showPanel(which) {
  document.getElementById('preview-empty').style.display   = which === 'empty'   ? 'flex' : 'none';
  document.getElementById('report-loading').style.display  = which === 'loading' ? 'flex' : 'none';
  document.getElementById('report-result').style.display   = which === 'result'  ? 'flex' : 'none';
}

function displayReport(report) {
  showPanel('result');
  const sev   = report.severity || 'Medium';
  const badge = document.getElementById('result-severity-badge');
  badge.textContent = sev;
  badge.className   = `report-severity-badge sev-${sev}`;
  document.getElementById('result-title').textContent     = report.name;
  document.getElementById('result-timestamp').textContent = `Generated ${new Date().toLocaleString()}`;

  const screenshots = parseScreenshots(report.screenshot_path);
  const sections = [
    { num:1, title:'Description',    content: report.description },
    { num:2, title:'Affected Items', content: report.affected_items },
    { num:3, title:'Impact',         content: report.impact },
    { num:4, title:'Recommendation', content: report.recommendation },
    { num:5, title:'POC',            content: report.poc, screenshots },
    { num:6, title:'References',     content: report.references, isRefs: true },
  ];
  document.getElementById('report-sections').innerHTML = sections.map(s => renderSection(s)).join('');
}

async function saveToLibrary() {
  if (!currentReport) return;
  const btn = document.getElementById('btn-save');
  btn.disabled     = true;
  btn.textContent  = 'Saving…';

  // Combine report screenshots with current upload paths if any
  const allScreenshots = uploadedScreenshotPaths.length
    ? uploadedScreenshotPaths
    : parseScreenshots(currentReport.screenshot_path);

  try {
    const payload = {
      ...currentReport,
      screenshot_path: allScreenshots.length ? JSON.stringify(allScreenshots) : null,
    };
    const res = await fetch('/api/vulnerabilities', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('Save failed');
    const saved = await res.json();

    // Auto-assign to project if context was selected
    const projId = currentReport.project_id;
    if (projId && saved?.id) {
      await fetch(`/api/projects/${projId}/assign/${saved.id}`, { method: 'POST' });
      showToast(`"${currentReport.name}" saved & added to project!`, 'success');
    } else {
      showToast(`"${currentReport.name}" saved!`, 'success');
    }

    discardReport();
    document.getElementById('generator-form').reset();
    uploadedScreenshotPaths = [];
    renderThumbs();
    selectSeverity('Medium');
    setTimeout(() => showView('library'), 800);
  } catch {
    showToast('Failed to save vulnerability', 'error');
    btn.disabled = false;
    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:15px;height:15px"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> Save to Library`;
  }
}

function discardReport() {
  currentReport = null;
  showPanel('empty');
  const btn = document.getElementById('btn-save');
  btn.disabled = false;
  btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:15px;height:15px"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> Save to Library`;
}

// ─── Generator Client/Project Dropdowns ───────────────────────────────────────
async function loadGenClientDropdown() {
  try {
    const res = await fetch('/api/clients');
    if (!res.ok) return;
    const clients = await res.json();
    const el = document.getElementById('gen-client-select');
    if (!el) return;
    el.innerHTML = '<option value="">— No client —</option>' +
      clients.map(c => `<option value="${c.id}">${escapeHtml(c.name)}</option>`).join('');
    // Reset project dropdown
    const projEl = document.getElementById('gen-project-select');
    if (projEl) { projEl.innerHTML = '<option value="">— Select client first —</option>'; projEl.disabled = true; }
  } catch { /* ignore */ }
}

async function handleGenClientChange() {
  const clientId = document.getElementById('gen-client-select')?.value;
  const projEl   = document.getElementById('gen-project-select');
  if (!projEl) return;
  if (!clientId) {
    projEl.innerHTML = '<option value="">— Select client first —</option>';
    projEl.disabled = true;
    return;
  }
  try {
    const res = await fetch(`/api/clients/${clientId}/projects`);
    if (!res.ok) throw new Error('Failed to load projects');
    const projects = await res.json();
    projEl.innerHTML = '<option value="">— No project —</option>' +
      projects.map(p => `<option value="${p.id}">${escapeHtml(p.name)}</option>`).join('');
    projEl.disabled = false;
  } catch { projEl.disabled = true; }
}

// ─── Detail Modal ─────────────────────────────────────────────────────────────
async function openDetail(id) {
  try {
    const res = await fetch(`/api/vulnerabilities/${id}`);
    if (!res.ok) throw new Error('Not found');
    const v = await res.json();
    currentDetailId = id;

    const sev    = v.severity || 'Medium';
    const badge  = document.getElementById('modal-severity');
    badge.textContent = sev;
    badge.className   = `modal-severity sev-${sev}`;
    document.getElementById('modal-title').textContent = v.name;
    document.getElementById('modal-date').textContent  = `Saved on ${new Date(v.created_at).toLocaleString()}`;

    const screenshots = parseScreenshots(v.screenshot_path);
    const sections = [
      { num:1, title:'Description',    content: v.description },
      { num:2, title:'Affected Items', content: v.affected_items },
      { num:3, title:'Impact',         content: v.impact },
      { num:4, title:'Recommendation', content: v.recommendation },
      { num:5, title:'POC',            content: v.poc, screenshots },
      { num:6, title:'References',     content: v.references, isRefs: true },
    ];
    document.getElementById('modal-body').innerHTML = sections.map(s => renderSection(s)).join('');
    document.getElementById('detail-modal').classList.add('open');
    document.body.style.overflow = 'hidden';
  } catch {
    showToast('Failed to load vulnerability', 'error');
  }
}

function closeDetailModal(e) {
  if (e && e.target !== e.currentTarget) return;
  document.getElementById('detail-modal').classList.remove('open');
  document.body.style.overflow = '';
  currentDetailId = null;
}

async function deleteVulnerability(id) {
  if (!id || !confirm('Delete this vulnerability?')) return;
  try {
    const res = await fetch(`/api/vulnerabilities/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error();
    closeDetailModal();
    showToast('Vulnerability deleted', 'success');
    loadLibrary();
  } catch {
    showToast('Failed to delete', 'error');
  }
}

// ─── Toast ─────────────────────────────────────────────────────────────────────
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const icons = {
    success: `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`,
    error:   `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
    info:    `<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
  };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `${icons[type] || icons.info}<span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.transition = '0.3s ease';
    toast.style.opacity    = '0';
    toast.style.transform  = 'translateX(20px)';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ─── Utilities ────────────────────────────────────────────────────────────────
function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;')
    .replace(/'/g,  '&#039;');
}

// ═══════════════════════════════════════════════════════════════════
//  ASK AI FEATURE
// ═══════════════════════════════════════════════════════════════════
let askScreenshotPaths = [];
let askAnalysisResult  = null;

// ── Upload Handlers ──
function handleAskDrop(e) {
  e.preventDefault();
  e.currentTarget.classList.remove('dragover');
  const files = Array.from(e.dataTransfer.files).filter(f => f.type.startsWith('image/'));
  files.forEach(f => handleAskScreenshotFile(f));
}

function handleAskScreenshot(input) {
  Array.from(input.files).forEach(f => handleAskScreenshotFile(f));
  input.value = '';
}

async function handleAskScreenshotFile(file) {
  const formData = new FormData();
  formData.append('screenshot', file);
  try {
    const res  = await fetch('/api/upload', { method: 'POST', body: formData });
    if (!res.ok) throw new Error('Upload failed');
    const data = await res.json();
    askScreenshotPaths.push(data.path);
    renderAskThumbs();
  } catch {
    showToast('Failed to upload screenshot', 'error');
  }
}

function renderAskThumbs() {
  const container   = document.getElementById('ask-upload-thumbs');
  const placeholder = document.getElementById('ask-upload-placeholder');
  if (!askScreenshotPaths.length) {
    placeholder.style.display = 'flex';
    container.innerHTML = '';
    return;
  }
  placeholder.style.display = 'none';
  container.innerHTML = `
    <div class="thumb-grid">
      ${askScreenshotPaths.map((p, i) => `
        <div class="thumb-item">
          <img src="${p}" alt="Screenshot ${i+1}" onclick="openImgFullscreen('${p}')" />
          <button class="thumb-remove" onclick="removeAskThumb(${i}, event)" title="Remove">✕</button>
          <span class="thumb-num">${i+1}</span>
        </div>`).join('')}
      <div class="thumb-add" onclick="document.getElementById('ask-screenshot-input').click()" title="Add more">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
      </div>
    </div>`;
}

function removeAskThumb(i, e) {
  e.stopPropagation();
  askScreenshotPaths.splice(i, 1);
  renderAskThumbs();
}

// ── Analyze ──
async function handleAskAI() {
  const apiKey = getApiKey();
  if (!apiKey) { openSettings(); showToast('Please add your Gemini API key first', 'error'); return; }
  if (!askScreenshotPaths.length) { showToast('Please upload at least one screenshot', 'error'); return; }

  const btn = document.getElementById('ask-btn');
  btn.disabled = true;
  btn.classList.add('loading');

  showAskPanel('loading');

  try {
    const res = await fetch('/api/ai/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        screenshot_paths: askScreenshotPaths,
        language: document.getElementById('ask-lang').value,
        apiKey, model: getModel(),
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Analysis failed');
    askAnalysisResult = data;
    displayAskResult(data);
  } catch (err) {
    showAskPanel('empty');
    showToast(err.message || 'Analysis failed', 'error');
  } finally {
    btn.disabled = false;
    btn.classList.remove('loading');
  }
}

function showAskPanel(which) {
  document.getElementById('ask-empty').style.display   = which === 'empty'   ? 'flex'  : 'none';
  document.getElementById('ask-loading').style.display = which === 'loading' ? 'flex'  : 'none';
  document.getElementById('ask-result').style.display  = which === 'result'  ? 'flex'  : 'none';
}

function displayAskResult(data) {
  showAskPanel('result');

  // Verdict badge
  const verdictEl = document.getElementById('ask-verdict');
  if (data.is_vulnerability) {
    verdictEl.className   = 'ask-verdict vuln';
    verdictEl.innerHTML   = '⚠️ Vulnerability Detected';
  } else {
    verdictEl.className   = 'ask-verdict no-vuln';
    verdictEl.innerHTML   = '✅ No Vulnerability Found';
  }

  // Confidence
  document.getElementById('ask-confidence').textContent = `${data.confidence} Confidence`;

  // Name + fields
  document.getElementById('ask-result-name').textContent  = data.name || '—';
  document.getElementById('ask-desc').textContent         = data.short_description || '—';
  document.getElementById('ask-impact').textContent       = data.impact || '—';
  document.getElementById('ask-rec').textContent          = data.recommendation || '—';

  // Hide impact & rec if not a vulnerability
  document.getElementById('ask-impact-wrap').style.display = data.is_vulnerability ? '' : 'none';
  document.getElementById('ask-rec-wrap').style.display    = data.is_vulnerability ? '' : 'none';

  // Show Generate button only if it IS a vulnerability
  document.getElementById('ask-actions').style.display = data.is_vulnerability ? 'flex' : 'none';
}

// ── Parse to Generator ──
function parseToGenerate() {
  if (!askAnalysisResult) return;
  const r = askAnalysisResult;

  // Switch to generator view
  showView('generate');

  // Pre-fill the form
  document.getElementById('vuln-name').value    = r.name  || '';
  document.getElementById('short-desc').value   = `${r.short_description || ''}\n\nImpact: ${r.impact || ''}\n\nRecommendation: ${r.recommendation || ''}`.trim();
  document.getElementById('affected-items').value = '';
  document.getElementById('poc-notes').value    = '';

  // Transfer screenshots to generator
  uploadedScreenshotPaths = [...(r.screenshot_paths || askScreenshotPaths)];
  renderThumbs();

  // Reset severity to Medium (user can change)
  selectSeverity('Medium');

  showToast('Loaded into Generator — add details and generate!', 'success');
}

// ── Reset ──
function resetAsk() {
  askScreenshotPaths = [];
  askAnalysisResult  = null;
  document.getElementById('ask-screenshot-input').value = '';
  renderAskThumbs();
  showAskPanel('empty');
}

// ═══════════════════════════════════════════════════════════════════
// CLIENTS / PROJECTS FEATURE
// ═══════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════
//  CLIENTS — 3-Column Drill-Down
// ═══════════════════════════════════════════════════════════════════
const clientsState = {
  clients: [],
  selectedClient: null,
  projects: [],
  selectedProject: null,
  findings: [],
  allLibrary: [],
  pickerAddedIds: new Set(),
};

const SEV_COLOR = { Critical:'#ef4444', High:'#f97316', Medium:'#eab308', Low:'#22c55e', Info:'#06b6d4' };

async function loadClientsView() {
  try {
    const [cRes, vRes] = await Promise.all([
      fetch('/api/clients'),
      fetch('/api/vulnerabilities?sort=severity_desc'),
    ]);
    if (!cRes.ok || !vRes.ok) throw new Error('Failed to load client data');
    clientsState.clients  = await cRes.json();
    clientsState.allLibrary = await vRes.json();
    renderClientList();
    // Re-select previously selected client if still exists
    if (clientsState.selectedClient) {
      const still = clientsState.clients.find(c => c.id === clientsState.selectedClient.id);
      if (still) selectClient(still, false);
      else resetDrillDown();
    } else {
      resetDrillDown();
    }
  } catch (err) {
    showToast('Failed to load clients', 'error');
  }
}

function resetDrillDown() {
  clientsState.selectedClient  = null;
  clientsState.selectedProject = null;
  clientsState.findings = [];
  renderClientList();
  setCol('projects', false);
  setCol('findings', false);
  updateBreadcrumb();
  document.getElementById('project-list').innerHTML = '<div class="drill-empty">Select a client first.</div>';
  document.getElementById('findings-list').innerHTML = '<div class="drill-empty">Select a project first.</div>';
}

function setCol(col, active) {
  const el = document.getElementById(`col-${col}`);
  if (!el) return;
  if (active) { el.classList.remove('drill-col--dim'); el.classList.add('active'); }
  else        { el.classList.add('drill-col--dim');    el.classList.remove('active'); }
  if (col === 'projects') document.getElementById('btn-add-project').disabled = !active;
  if (col === 'findings') {
    document.getElementById('btn-add-finding').disabled = !active;
    document.getElementById('btn-gen-pdf').disabled     = !active;
  }
}

function updateBreadcrumb() {
  const c  = clientsState.selectedClient;
  const p  = clientsState.selectedProject;
  document.getElementById('crumb-sep-1').style.display       = c ? '' : 'none';
  document.getElementById('crumb-project-name').style.display = c ? '' : 'none';
  document.getElementById('crumb-project-name').textContent   = c ? c.name : '';
  document.getElementById('crumb-sep-2').style.display       = p ? '' : 'none';
  document.getElementById('crumb-findings-name').style.display = p ? '' : 'none';
  document.getElementById('crumb-findings-name').textContent   = p ? p.name : '';
  // Highlight active crumb
  document.getElementById('crumb-clients').className = c ? 'crumb' : 'crumb active';
  if (document.getElementById('crumb-project-name'))
    document.getElementById('crumb-project-name').className = p ? 'crumb' : 'crumb active';
}

function drillTo(level) {
  if (level === 'clients') resetDrillDown();
  if (level === 'projects') {
    clientsState.selectedProject = null;
    clientsState.findings = [];
    renderProjectList();
    setCol('findings', false);
    document.getElementById('findings-list').innerHTML = '<div class="drill-empty">Select a project first.</div>';
    updateBreadcrumb();
  }
}

// ── Client CRUD ──
function renderClientList() {
  const el = document.getElementById('client-list');
  if (!clientsState.clients.length) {
    el.innerHTML = '<div class="drill-empty">No clients yet.<br><span>Click New Client to add one.</span></div>';
    return;
  }
  el.innerHTML = clientsState.clients.map(c => `
    <div class="drill-item ${clientsState.selectedClient?.id === c.id ? 'selected' : ''}" onclick="selectClient(${JSON.stringify(c).replace(/"/g,'&quot;')})">
      <div class="drill-item-body">
        <div class="drill-item-name">${escapeHtml(c.name)}</div>
      </div>
      <div class="drill-item-actions">
        <button class="drill-item-btn" title="Rename" onclick="renameClient(event,${c.id},'${escapeHtml(c.name).replace(/'/g,"\'")}')">✏️</button>
        <button class="drill-item-btn danger" title="Delete" onclick="deleteClient(event,${c.id})">🗑</button>
      </div>
    </div>`).join('');
}

async function selectClient(client, reload = true) {
  clientsState.selectedClient  = client;
  clientsState.selectedProject = null;
  clientsState.findings = [];
  renderClientList();
  document.getElementById('projects-col-title').textContent = client.name;
  setCol('projects', true);
  setCol('findings', false);
  document.getElementById('findings-list').innerHTML = '<div class="drill-empty">Select a project first.</div>';
  updateBreadcrumb();
  if (reload) await refreshProjects();
}

async function refreshProjects() {
  const res  = await fetch(`/api/clients/${clientsState.selectedClient.id}/projects`);
  if (!res.ok) throw new Error('Failed to load projects');
  clientsState.projects = await res.json();
  renderProjectList();
}

async function promptAddClient() {
  const name = prompt('Client name:');
  if (!name?.trim()) return;
  try {
    const res = await fetch('/api/clients', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ name: name.trim() }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    showToast('Client added', 'success');
    await loadClientsView();
    const c = clientsState.clients.find(x => x.id === data.id);
    if (c) selectClient(c);
  } catch(e) { showToast(e.message || 'Failed', 'error'); }
}

async function renameClient(e, id, currentName) {
  e.stopPropagation();
  const name = prompt('New name:', currentName);
  if (!name?.trim() || name.trim() === currentName) return;
  try {
    const res = await fetch(`/api/clients/${id}`, {
      method:'PUT', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ name: name.trim() }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    showToast('Renamed', 'success');
    if (clientsState.selectedClient?.id === id) clientsState.selectedClient.name = name.trim();
    await loadClientsView();
    if (clientsState.selectedClient?.id === id) selectClient(clientsState.selectedClient, false);
  } catch(e) { showToast(e.message || 'Failed', 'error'); }
}

async function deleteClient(e, id) {
  e.stopPropagation();
  if (!confirm('Delete this client and all its projects?')) return;
  try {
    const res  = await fetch(`/api/clients/${id}`, { method:'DELETE' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    showToast('Client deleted', 'success');
    if (clientsState.selectedClient?.id === id) resetDrillDown();
    else await loadClientsView();
  } catch(e) { showToast(e.message || 'Failed', 'error'); }
}

// ── Project CRUD ──
function renderProjectList() {
  const el = document.getElementById('project-list');
  if (!clientsState.projects.length) {
    el.innerHTML = '<div class="drill-empty">No projects.<br><span>Click New Project to add one.</span></div>';
    return;
  }
  el.innerHTML = clientsState.projects.map(p => `
    <div class="drill-item ${clientsState.selectedProject?.id === p.id ? 'selected' : ''}" onclick="selectProject(${JSON.stringify(p).replace(/"/g,'&quot;')})">
      <div class="drill-item-body">
        <div class="drill-item-name">${escapeHtml(p.name)}</div>
      </div>
      <div class="drill-item-actions">
        <button class="drill-item-btn" title="Rename" onclick="renameProject(event,${p.id},'${escapeHtml(p.name).replace(/'/g,"\'")}')">✏️</button>
        <button class="drill-item-btn danger" title="Delete" onclick="deleteProject(event,${p.id})">🗑</button>
      </div>
    </div>`).join('');
}

async function selectProject(project) {
  clientsState.selectedProject = project;
  renderProjectList();
  document.getElementById('findings-col-title').textContent = project.name;
  setCol('findings', true);
  updateBreadcrumb();
  await refreshFindings();
}

async function refreshFindings() {
  const res = await fetch(`/api/projects/${clientsState.selectedProject.id}/findings`);
  if (!res.ok) throw new Error('Failed to load findings');
  clientsState.findings = await res.json();
  renderFindingsList();
}

async function promptAddProject() {
  if (!clientsState.selectedClient) { showToast('Select a client first', 'error'); return; }
  const name = prompt('Project name:');
  if (!name?.trim()) return;
  try {
    const res = await fetch(`/api/clients/${clientsState.selectedClient.id}/projects`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ name: name.trim() }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    showToast('Project added', 'success');
    await refreshProjects();
    const p = clientsState.projects.find(x => x.id === data.id);
    if (p) selectProject(p);
  } catch(e) { showToast(e.message || 'Failed', 'error'); }
}

async function renameProject(e, id, currentName) {
  e.stopPropagation();
  const name = prompt('New name:', currentName);
  if (!name?.trim() || name.trim() === currentName) return;
  try {
    const res = await fetch(`/api/projects/${id}`, {
      method:'PUT', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ name: name.trim() }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    showToast('Renamed', 'success');
    if (clientsState.selectedProject?.id === id) clientsState.selectedProject.name = name.trim();
    await refreshProjects();
    updateBreadcrumb();
  } catch(e) { showToast(e.message || 'Failed', 'error'); }
}

async function deleteProject(e, id) {
  e.stopPropagation();
  if (!confirm('Delete this project?')) return;
  try {
    const res  = await fetch(`/api/projects/${id}`, { method:'DELETE' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    showToast('Project deleted', 'success');
    if (clientsState.selectedProject?.id === id) {
      clientsState.selectedProject = null;
      clientsState.findings = [];
      setCol('findings', false);
      document.getElementById('findings-list').innerHTML = '<div class="drill-empty">Select a project first.</div>';
      updateBreadcrumb();
    }
    await refreshProjects();
  } catch(e) { showToast(e.message || 'Failed', 'error'); }
}

// ── Findings ──
function renderFindingsList() {
  const el = document.getElementById('findings-list');
  if (!clientsState.findings.length) {
    el.innerHTML = '<div class="drill-empty">No findings yet.<br><span>Click Add Finding to pick from library.</span></div>';
    return;
  }
  el.innerHTML = clientsState.findings.map(v => {
    const sc = SEV_COLOR[v.severity] || '#6366f1';
    return `
      <div class="finding-item">
        <div class="finding-sev-bar" style="background:${sc}"></div>
        <div class="finding-body">
          <div class="finding-name">${escapeHtml(v.name)}</div>
          <div class="finding-sev">${v.severity}</div>
        </div>
        <button class="finding-remove" title="Remove from project" onclick="removeFromProject(${v.id})">✕</button>
      </div>`;
  }).join('');
}

async function removeFromProject(vulnId) {
  if (!clientsState.selectedProject) return;
  try {
    const res = await fetch(`/api/projects/${clientsState.selectedProject.id}/assign/${vulnId}`, { method:'DELETE' });
    if (!res.ok) throw new Error((await res.json()).error);
    showToast('Removed from project', 'success');
    await refreshFindings();
  } catch(e) { showToast(e.message || 'Failed', 'error'); }
}

// ── Library Picker Modal ──
let pickerAllVulns = [];
function openLibraryPicker() {
  if (!clientsState.selectedProject) return;
  pickerAllVulns = clientsState.allLibrary;
  clientsState.pickerAddedIds = new Set(clientsState.findings.map(f => f.id));
  document.getElementById('picker-search').value = '';
  renderPickerList(pickerAllVulns);
  document.getElementById('library-picker-modal').classList.add('open');
  document.body.style.overflow = 'hidden';
}
function closeLibraryPicker(e) {
  if (e && e.target !== e.currentTarget) return;
  document.getElementById('library-picker-modal').classList.remove('open');
  document.body.style.overflow = '';
}
function filterPickerList(q) {
  const filtered = pickerAllVulns.filter(v =>
    v.name.toLowerCase().includes(q.toLowerCase()) ||
    (v.description || '').toLowerCase().includes(q.toLowerCase())
  );
  renderPickerList(filtered);
}
function renderPickerList(vulns) {
  const el = document.getElementById('picker-list');
  if (!vulns.length) { el.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:20px">No vulnerabilities found.</p>'; return; }
  el.innerHTML = vulns.map(v => {
    const sc      = SEV_COLOR[v.severity] || '#6366f1';
    const added   = clientsState.pickerAddedIds.has(v.id);
    const rawDesc = (v.description || '').replace(/\*\*?(.+?)\*\*?/g,'$1').replace(/#+\s/g,'').slice(0,80);
    return `
      <div class="picker-item">
        <span class="picker-item-sev" style="background:${sc}20;color:${sc};border:1px solid ${sc}40">${v.severity}</span>
        <div class="picker-item-info">
          <div class="picker-item-name">${escapeHtml(v.name)}</div>
          ${rawDesc ? `<div class="picker-item-desc">${escapeHtml(rawDesc)}…</div>` : ''}
        </div>
        <button class="picker-item-add ${added?'added':''}" id="pick-btn-${v.id}" onclick="addFindingToProject(${v.id})" title="${added?'Already added':'Add to project'}">
          ${added ? '✓' : '+'}
        </button>
      </div>`;
  }).join('');
}
async function addFindingToProject(vulnId) {
  if (clientsState.pickerAddedIds.has(vulnId)) return;
  try {
    const res = await fetch(`/api/projects/${clientsState.selectedProject.id}/assign/${vulnId}`, { method:'POST' });
    if (!res.ok) throw new Error((await res.json()).error);
    clientsState.pickerAddedIds.add(vulnId);
    const btn = document.getElementById(`pick-btn-${vulnId}`);
    if (btn) { btn.classList.add('added'); btn.textContent = '✓'; }
    await refreshFindings();
    showToast('Added to project', 'success');
  } catch(e) { showToast(e.message || 'Failed', 'error'); }
}

// ── PDF Report ──
function generateProjectReport() {
  if (!clientsState.selectedProject) { showToast('Select a project first', 'error'); return; }
  const url = `/api/projects/${clientsState.selectedProject.id}/report`;
  window.open(url, '_blank');
}

// ── DOCX Report ──
