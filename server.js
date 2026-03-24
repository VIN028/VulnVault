require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const db = require('./database');
const auth = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Behind Render / other reverse proxies (correct client IP, HTTPS awareness)
app.set('trust proxy', 1);

// Initialize DB on startup
db.getDb();

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ─── Auth (public) ───────────────────────────────────────────────────────────
app.get('/api/session', (req, res) => auth.sessionStatus(req, res));
app.post('/api/login', (req, res) => auth.login(req, res));
app.post('/api/logout', (req, res) => auth.logout(req, res));

// Everything under /api below requires a valid session cookie (except routes above)
app.use(auth.requireApiAuth);

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer config for screenshot uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `poc_${Date.now()}${ext}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp|bmp/;
    const ext = allowed.test(path.extname(file.originalname).toLowerCase());
    if (ext) cb(null, true);
    else cb(new Error('Only image files are allowed'));
  },
});

// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  db.countVulnerabilities((err, row) => {
    if (err) return res.status(500).json({ status: 'error', message: err.message });
    res.json({ status: 'ok', count: row.count });
  });
});

// ─── Vulnerability Routes ─────────────────────────────────────────────────────
app.get('/api/vulnerabilities', (req, res) => {
  const { search, severity, sort, project_id } = req.query;
  db.listVulnerabilities(
    {
      search:     (search   || '').trim(),
      severity:   (severity || '').trim(),
      sort:       (sort     || 'newest').trim(),
      project_id: project_id ? Number(project_id) : null,
    },
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.get('/api/vulnerabilities/:id', (req, res) => {
  db.getVulnerabilityById(req.params.id, (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Vulnerability not found' });
    res.json(row);
  });
});

app.post('/api/vulnerabilities', (req, res) => {
  const { name, description, affected_items, impact, recommendation, poc, references, screenshot_path, severity } = req.body;
  if (!name) return res.status(400).json({ error: 'Vulnerability name is required' });
  db.saveVulnerability(
    { name, description, affected_items, impact, recommendation, poc, references, screenshot_path, severity },
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      db.getVulnerabilityById(result.id, (err2, row) => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.status(201).json(row);
      });
    }
  );
});

app.delete('/api/vulnerabilities/:id', (req, res) => {
  db.deleteVulnerability(req.params.id, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (result.changes === 0) return res.status(404).json({ error: 'Vulnerability not found' });
    res.json({ message: 'Deleted successfully' });
  });
});

// ─── Client / Project Grouping Routes ────────────────────────────────────────
app.get('/api/clients', (req, res) => {
  db.getClients((err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/clients', (req, res) => {
  const name = (req.body?.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Client name is required' });
  db.createClient(name, (err, result) => {
    if (err) {
      if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Client already exists' });
      return res.status(500).json({ error: err.message });
    }
    db.getClients((err2, rows) => {
      if (err2) return res.status(500).json({ error: err2.message });
      const created = rows.find(r => r.id === result.id);
      res.status(201).json(created || { id: result.id, name });
    });
  });
});

app.delete('/api/clients/:id', (req, res) => {
  const clientId = Number(req.params.id);
  if (!Number.isInteger(clientId) || clientId < 1) {
    return res.status(400).json({ error: 'Invalid client id' });
  }
  db.deleteClient(clientId, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!result?.changes) return res.status(404).json({ error: 'Client not found' });
    res.json({ message: 'Client deleted successfully' });
  });
});

app.get('/api/clients/:clientId/projects', (req, res) => {
  const clientId = Number(req.params.clientId);
  if (!Number.isInteger(clientId) || clientId < 1) {
    return res.status(400).json({ error: 'Invalid client id' });
  }
  db.getProjectsByClient(clientId, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/clients/:clientId/projects', (req, res) => {
  const clientId = Number(req.params.clientId);
  const name = (req.body?.name || '').trim();
  if (!Number.isInteger(clientId) || clientId < 1) {
    return res.status(400).json({ error: 'Invalid client id' });
  }
  if (!name) return res.status(400).json({ error: 'Project name is required' });
  db.createProject(clientId, name, (err, result) => {
    if (err) {
      if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Project already exists for this client' });
      return res.status(500).json({ error: err.message });
    }
    db.getProjectsByClient(clientId, (err2, rows) => {
      if (err2) return res.status(500).json({ error: err2.message });
      const created = rows.find(r => r.id === result.id);
      res.status(201).json(created || { id: result.id, client_id: clientId, name });
    });
  });
});

app.delete('/api/projects/:projectId', (req, res) => {
  const projectId = Number(req.params.projectId);
  if (!Number.isInteger(projectId) || projectId < 1) {
    return res.status(400).json({ error: 'Invalid project id' });
  }
  db.deleteProject(projectId, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!result?.changes) return res.status(404).json({ error: 'Project not found' });
    res.json({ message: 'Project deleted successfully' });
  });
});

app.get('/api/projects/:projectId/vulnerabilities', (req, res) => {
  const projectId = Number(req.params.projectId);
  if (!Number.isInteger(projectId) || projectId < 1) {
    return res.status(400).json({ error: 'Invalid project id' });
  }
  db.getProjectVulnerabilityIds(projectId, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows.map(r => r.vulnerability_id));
  });
});

app.put('/api/projects/:projectId/vulnerabilities', (req, res) => {
  const projectId = Number(req.params.projectId);
  const ids = Array.isArray(req.body?.vulnerability_ids) ? req.body.vulnerability_ids : [];
  const normalizedIds = [...new Set(ids.map(v => Number(v)).filter(v => Number.isInteger(v) && v > 0))];
  if (!Number.isInteger(projectId) || projectId < 1) {
    return res.status(400).json({ error: 'Invalid project id' });
  }
  db.setProjectVulnerabilities(projectId, normalizedIds, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Project vulnerabilities updated', count: result?.count || 0 });
  });
});

app.get('/api/projects/:projectId/export', (req, res) => {
  const projectId = Number(req.params.projectId);
  if (!Number.isInteger(projectId) || projectId < 1) {
    return res.status(400).json({ error: 'Invalid project id' });
  }
  db.getProjectExportData(projectId, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!rows.length) return res.status(404).json({ error: 'Project not found' });

    const first = rows[0];
    const vulnerabilities = rows.filter(r => r.id).map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description,
      affected_items: r.affected_items,
      impact: r.impact,
      recommendation: r.recommendation,
      poc: r.poc,
      references: r.references,
      screenshot_path: r.screenshot_path,
      severity: r.severity,
      created_at: r.created_at,
      updated_at: r.updated_at,
    }));

    res.json({
      client: { id: first.client_id, name: first.client_name },
      project: { id: first.project_id, name: first.project_name },
      vulnerabilities,
      generated_at: new Date().toISOString(),
    });
  });
});

// ─── Client / Project — rename + single-vuln management + report ─────────────

app.put('/api/clients/:id', (req, res) => {
  const id   = Number(req.params.id);
  const name = (req.body?.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Name is required' });
  db.renameClient(id, name, (err, result) => {
    if (err) {
      if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Client name already exists' });
      return res.status(500).json({ error: err.message });
    }
    if (!result.changes) return res.status(404).json({ error: 'Client not found' });
    res.json({ id, name });
  });
});

app.put('/api/projects/:id', (req, res) => {
  const id   = Number(req.params.id);
  const name = (req.body?.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Name is required' });
  db.renameProject(id, name, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!result.changes) return res.status(404).json({ error: 'Project not found' });
    res.json({ id, name });
  });
});

// Full vulnerability details for a project
app.get('/api/projects/:projectId/findings', (req, res) => {
  const projectId = Number(req.params.projectId);
  if (!Number.isInteger(projectId) || projectId < 1)
    return res.status(400).json({ error: 'Invalid project id' });
  db.getProjectFullVulnerabilities(projectId, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Add single vulnerability to project
app.post('/api/projects/:projectId/assign/:vulnId', (req, res) => {
  const projectId = Number(req.params.projectId);
  const vulnId    = Number(req.params.vulnId);
  if (!Number.isInteger(projectId) || projectId < 1 || !Number.isInteger(vulnId) || vulnId < 1) {
    return res.status(400).json({ error: 'Invalid project or vulnerability id' });
  }
  db.addVulnerabilityToProject(projectId, vulnId, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Vulnerability added to project' });
  });
});

// Remove single vulnerability from project
app.delete('/api/projects/:projectId/assign/:vulnId', (req, res) => {
  const projectId = Number(req.params.projectId);
  const vulnId    = Number(req.params.vulnId);
  if (!Number.isInteger(projectId) || projectId < 1 || !Number.isInteger(vulnId) || vulnId < 1) {
    return res.status(400).json({ error: 'Invalid project or vulnerability id' });
  }
  db.removeVulnerabilityFromProject(projectId, vulnId, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Vulnerability removed from project' });
  });
});

// HTML Pentest Report (open in new tab → print to PDF)
app.get('/api/projects/:projectId/report', (req, res) => {
  const projectId = Number(req.params.projectId);
  if (!Number.isInteger(projectId) || projectId < 1)
    return res.status(400).json({ error: 'Invalid project id' });

  db.getProjectExportData(projectId, (err, rows) => {
    if (err) return res.status(500).send('Database error');
    if (!rows.length) return res.status(404).send('Project not found');

    const first = rows[0];
    const vulns = rows.filter(r => r.id);
    const date  = new Date().toLocaleDateString('id-ID', { day: '2-digit', month: 'long', year: 'numeric' });

    const sevColor = { Critical: '#ef4444', High: '#f97316', Medium: '#eab308', Low: '#22c55e', Info: '#06b6d4' };

    const vulnHtml = vulns.map((v, i) => {
      let screenshots = [];
      try { screenshots = JSON.parse(v.screenshot_path); if (!Array.isArray(screenshots)) screenshots = [v.screenshot_path]; }
      catch { if (v.screenshot_path) screenshots = [v.screenshot_path]; }

      const sc = sevColor[v.severity] || '#6366f1';
      const sections = [
        ['Description', v.description],
        ['Affected Items', v.affected_items],
        ['Impact', v.impact],
        ['Recommendation', v.recommendation],
        ['Proof of Concept (POC)', v.poc],
        ['References', v.references],
      ];

      return `
        <div class="finding">
          <div class="finding-header" style="border-left:4px solid ${sc}">
            <div class="finding-num">${i + 1}</div>
            <div class="finding-info">
              <span class="sev-badge" style="background:${sc}20;color:${sc};border:1px solid ${sc}40">${v.severity}</span>
              <h3>${escHtml(v.name)}</h3>
            </div>
          </div>
          ${sections.filter(([, c]) => c).map(([title, content]) => `
            <div class="section">
              <div class="section-title">${title}</div>
              <div class="section-body">${escHtml(content).replace(/\n/g, '<br>')}</div>
            </div>`).join('')}
          ${screenshots.length ? `
            <div class="section">
              <div class="section-title">Screenshots</div>
              <div class="screenshots">${screenshots.map(s => `<img src="${s}" alt="POC" />`).join('')}</div>
            </div>` : ''}
        </div>`;
    }).join('');

    function escHtml(t) {
      return (t || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    const html = `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Pentest Report — ${escHtml(first.project_name)}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono&display=swap');
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Inter',sans-serif;background:#fff;color:#1e293b;line-height:1.6;font-size:13px}
  .cover{min-height:100vh;display:flex;flex-direction:column;justify-content:center;padding:60px;background:linear-gradient(135deg,#0f1729 0%,#1e1b4b 100%);color:#fff;page-break-after:always}
  .cover-badge{display:inline-flex;align-items:center;gap:8px;background:rgba(99,102,241,.2);border:1px solid rgba(99,102,241,.4);border-radius:20px;padding:6px 16px;font-size:12px;font-weight:600;color:#a5b4fc;margin-bottom:32px;width:fit-content}
  .cover h1{font-size:42px;font-weight:800;letter-spacing:-1px;line-height:1.2;margin-bottom:12px}
  .cover h2{font-size:20px;font-weight:500;color:#94a3b8;margin-bottom:48px}
  .cover-meta{display:grid;grid-template-columns:1fr 1fr;gap:16px;max-width:480px}
  .cover-meta-item label{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;display:block;margin-bottom:2px}
  .cover-meta-item span{font-size:14px;font-weight:600;color:#e2e8f0}
  .toc{padding:48px 60px;page-break-after:always}
  .toc h2{font-size:20px;font-weight:700;margin-bottom:24px;padding-bottom:12px;border-bottom:2px solid #e2e8f0}
  .toc-item{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #f1f5f9}
  .toc-item:last-child{border:none}
  .toc-sev{font-size:11px;font-weight:700;padding:3px 10px;border-radius:20px}
  .findings{padding:60px}
  .finding{margin-bottom:48px;page-break-inside:avoid}
  .finding-header{display:flex;align-items:center;gap:16px;padding:16px 20px;background:#f8fafc;border-radius:8px;margin-bottom:20px}
  .finding-num{width:32px;height:32px;background:#1e293b;color:#fff;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14px;flex-shrink:0}
  .finding-info{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
  .finding-info h3{font-size:16px;font-weight:700;color:#0f172a}
  .sev-badge{font-size:11px;font-weight:700;padding:3px 10px;border-radius:20px;white-space:nowrap}
  .section{margin-bottom:16px}
  .section-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#6366f1;margin-bottom:6px}
  .section-body{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:12px 16px;color:#374151;line-height:1.8}
  .screenshots img{max-width:100%;margin:8px 0;border:1px solid #e2e8f0;border-radius:6px;page-break-inside:avoid}
  .stats{display:flex;gap:16px;margin:20px 0;flex-wrap:wrap}
  .stat{text-align:center;flex:1;min-width:80px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px}
  .stat-num{font-size:28px;font-weight:800;line-height:1}
  .stat-label{font-size:11px;color:#64748b;margin-top:4px;text-transform:uppercase;letter-spacing:.04em}
  @media print{
    .cover{-webkit-print-color-adjust:exact;print-color-adjust:exact}
    .finding{page-break-inside:avoid}
  }
</style>
</head>
<body>

<div class="cover">
  <div class="cover-badge">🛡️ Penetration Test Report</div>
  <h1>${escHtml(first.project_name)}</h1>
  <h2>${escHtml(first.client_name)}</h2>
  <div class="cover-meta">
    <div class="cover-meta-item"><label>Client</label><span>${escHtml(first.client_name)}</span></div>
    <div class="cover-meta-item"><label>Project</label><span>${escHtml(first.project_name)}</span></div>
    <div class="cover-meta-item"><label>Report Date</label><span>${date}</span></div>
    <div class="cover-meta-item"><label>Total Findings</label><span>${vulns.length}</span></div>
  </div>
</div>

<div class="toc">
  <h2>Table of Contents</h2>
  <div class="stats">
    ${['Critical','High','Medium','Low','Info'].map(s => {
      const cnt = vulns.filter(v => v.severity === s).length;
      return `<div class="stat"><div class="stat-num" style="color:${sevColor[s]}">${cnt}</div><div class="stat-label">${s}</div></div>`;
    }).join('')}
  </div>
  ${vulns.map((v, i) => `
    <div class="toc-item">
      <span>${i+1}. ${escHtml(v.name)}</span>
      <span class="toc-sev" style="background:${sevColor[v.severity] || '#6366f1'}20;color:${sevColor[v.severity] || '#6366f1'}">${v.severity}</span>
    </div>`).join('')}
</div>

<div class="findings">
  ${vulnHtml || '<p style="color:#64748b;font-style:italic">No findings have been added to this project yet.</p>'}
</div>

<script>window.onload=()=>{window.print();}</script>
</body>
</html>`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  });
});

// ─── Screenshot Upload ────────────────────────────────────────────────────────
app.post('/api/upload', upload.single('screenshot'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  res.json({
    filename: req.file.filename,
    path: `/uploads/${req.file.filename}`,
    size: req.file.size,
  });
});

// ─── Ask AI — Image-Based Vulnerability Analysis ──────────────────────────────
app.post('/api/ai/analyze', async (req, res) => {
  const { screenshot_paths, apiKey, model, language } = req.body;
  const screenshotPaths = Array.isArray(screenshot_paths) ? screenshot_paths : [];

  if (!apiKey || apiKey.trim().length < 10) {
    return res.status(401).json({ error: 'Google AI Studio API key is required.' });
  }
  if (!screenshotPaths.length) {
    return res.status(400).json({ error: 'At least one screenshot is required for analysis.' });
  }

  const geminiModel = model || 'gemini-2.5-pro';
  const lang = language === 'en' ? 'English' : 'Bahasa Indonesia';

  const systemInstruction = `You are a senior cybersecurity penetration tester performing visual triage of screenshots from security tools (Burp Suite, browser dev tools, Shodan, etc.).

Your job is to analyze EVERYTHING visible in the screenshot — not just the obvious payload or primary action. Look at:
- HTTP request/response headers (look for Server, X-Powered-By, version strings, etc.)
- Status codes and what they reveal
- Cookies and session tokens
- Error messages and what they disclose
- URL structure, parameters, and endpoints
- HTML responses and embedded metadata
- Any version numbers, server banners, or technology fingerprints
- Configuration files, directory listings, or sensitive paths exposed
- Security headers that are MISSING (HSTS, CSP, X-Frame-Options, etc.)

When the primary action (e.g., an attack attempt) is BLOCKED but the response still reveals sensitive information (e.g., Server header reveals web server type and version), focus on what the response DISCLOSES — that is often the actual vulnerability worth reporting.

Pick the MOST SIGNIFICANT finding. If there are multiple, pick the one with the highest security impact.

Respond in ${lang} with valid JSON containing EXACTLY these keys:
{
  "is_vulnerability": true or false,
  "confidence": "High|Medium|Low",
  "name": "standardized vulnerability name (e.g. 'Web Server Version Disclosure', 'Missing Security Headers', 'Information Disclosure via Server Header')",
  "short_description": "3-4 sentences. Describe WHAT you see in the screenshot, WHAT the vulnerability is, and WHY it matters. Be specific — mention actual values like header names, server versions, status codes, or paths seen in the image.",
  "impact": "2-3 sentences on practical security impact. What can an attacker do with this information?",
  "recommendation": "2-3 sentences with specific remediation. Mention actual config changes or header names."
}

Be thorough and specific. Reference actual values you can see in the screenshot.`;

  try {
    const genAI = new GoogleGenerativeAI(apiKey.trim());
    const aiModel = genAI.getGenerativeModel({
      model: geminiModel,
      systemInstruction,
      generationConfig: {
        temperature: 0.4,
        maxOutputTokens: 2048,
      },
    });

    const parts = [{ text: 'Analyze the attached screenshot(s) for security vulnerabilities. Respond ONLY with valid JSON.' }];

    for (const sp of screenshotPaths) {
      const absolutePath = path.join(__dirname, sp.replace(/^\//, ''));
      if (fs.existsSync(absolutePath)) {
        const imageBuffer = fs.readFileSync(absolutePath);
        const base64Image = imageBuffer.toString('base64');
        const ext = path.extname(absolutePath).replace('.', '').toLowerCase();
        const mimeType = ext === 'jpg' ? 'image/jpeg' : `image/${ext}`;
        parts.push({ inlineData: { mimeType, data: base64Image } });
      }
    }

    const result = await aiModel.generateContent(parts);
    let text = result.response.text().trim();

    console.log('[Ask AI] Raw response:', text.substring(0, 500));

    // Strip markdown code fences (```json ... ``` or ``` ... ```)
    text = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();

    // Aggressively extract JSON: find first { and last }
    const firstBrace = text.indexOf('{');
    const lastBrace  = text.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
      text = text.substring(firstBrace, lastBrace + 1);
    }

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (parseErr) {
      console.error('[Ask AI] JSON parse error:', parseErr.message);
      console.error('[Ask AI] Text was:', text.substring(0, 300));
      return res.status(500).json({ error: 'AI returned invalid response. Please try again.' });
    }

    res.json({
      is_vulnerability: parsed.is_vulnerability ?? true,
      confidence:       parsed.confidence || 'Medium',
      name:             parsed.name || '',
      short_description: parsed.short_description || '',
      impact:           parsed.impact || '',
      recommendation:   parsed.recommendation || '',
      screenshot_paths: screenshotPaths,
    });

  } catch (error) {
    console.error('Analyze error:', error.message);
    if (error.message?.includes('API_KEY_INVALID') || error.message?.includes('API key not valid')) {
      return res.status(401).json({ error: 'Invalid API key.' });
    }
    if (error.message?.includes('quota') || error.message?.includes('RESOURCE_EXHAUSTED')) {
      return res.status(429).json({ error: 'API quota exceeded. Please try another model.' });
    }
    res.status(500).json({ error: error.message || 'Analysis failed.' });
  }
});

// ─── AI Generation via Gemini ─────────────────────────────────────────────────
// API key is provided per-request from the frontend (stored in user's browser localStorage)
app.post('/api/ai/generate', async (req, res) => {
  const { name, short_description, affected_items, poc_notes, screenshot_paths, language, apiKey, model,
          client_name, project_name, project_id } = req.body;
  // Support both single path (legacy) and array
  const screenshotPaths = Array.isArray(screenshot_paths)
    ? screenshot_paths
    : (screenshot_paths ? [screenshot_paths] : []);

  if (!name || !short_description) {
    return res.status(400).json({ error: 'Vulnerability name and description are required' });
  }
  if (!apiKey || apiKey.trim().length < 10) {
    return res.status(401).json({ error: 'Google AI Studio API key is required. Please configure it in the app settings.' });
  }

  const geminiModel = model || 'gemini-2.5-pro';
  const lang = language === 'en' ? 'English' : 'Bahasa Indonesia';
  const isID = language !== 'en';

  // Build client/project context string if provided
  const clientCtx = client_name && project_name
    ? `\n\nCONTEXT: This vulnerability was found during the "${project_name}" penetration test engagement for client "${client_name}". Ensure all descriptions, impacts, and recommendations are relevant and specific to this client and project engagement. Do NOT use generic company names — always reference "${client_name}" when mentioning the affected party.`
    : '';

  const systemInstruction = `You are an expert cybersecurity penetration tester writing professional vulnerability reports in ${lang}.

Your response must be valid JSON with EXACTLY these keys:
{
  "name": "string",
  "description": "string",
  "affected_items": "string",
  "impact": "string",
  "recommendation": "string",
  "poc": "string",
  "references": "string",
  "severity": "Critical|High|Medium|Low|Info"
}

Follow these EXACT format templates for each section:

=== DESCRIPTION ===
Write exactly 2 paragraphs. First paragraph explains what the vulnerability is, where it was found, and technical details. Second paragraph explains how it was discovered (tool/method/technique).
No bullet points. Plain paragraphs only.

=== AFFECTED ITEMS ===
Use this exact structure (skip a field if not applicable):
URL / IP: [value]
Port: [value if applicable]
Endpoint: [value]
Parameter: [value if applicable]
Component: [value if applicable]

=== IMPACT ===
${isID
  ? 'Start with: "Dampak dari temuan ini dapat mengakibatkan beberapa hal diantaranya:"'
  : 'Start with: "The impact of this finding may include the following:"'}
Then write a bullet list using "- " prefix for each impact item. Minimum 3 bullets, maximum 6.

=== RECOMMENDATION ===
${isID
  ? 'Start with a short sentence like "Untuk mengatasi kerentanan ini, kami menyarankan untuk..."'
  : 'Start with a short sentence like "To remediate this vulnerability, we recommend..."'}
Then provide remediation steps. Can be bullet points or short paragraphs. Be specific and actionable.

=== POC ===
${isID
  ? 'Start with: "Untuk membuktikan kerentanan ini, kami melakukan langkah-langkah berikut:"'
  : 'Start with: "To reproduce this vulnerability, perform the following steps:"'}
Then write numbered steps using "1. ", "2. ", etc. Each step should be clear and reproducible.
${isID ? 'If screenshots were attached, reference them in the relevant steps.' : 'If screenshots are provided, reference them in the relevant steps.'}

=== REFERENCES ===
List relevant references using "- " prefix, one per line. Include OWASP, CWE, CVE, or official documentation URLs where applicable. Minimum 2 references.

=== NAME ===
Polish the user-provided vulnerability name into a professional, standardized pentest finding title.
Keep it concise (max 8 words), use proper capitalization.
Example: "sql injection" → "SQL Injection on Login Form"

=== SEVERITY ===
IMPORTANT: The user has already selected the severity as "${req.body.severity || 'Medium'}". You MUST use exactly this value in the JSON. Do NOT change or reassess it.

Be thorough and professional. Output only valid JSON.`;

  const userPrompt = `Generate a complete vulnerability report for:

Vulnerability Name (raw input, polish it): ${name}
User-Selected Severity (USE THIS EXACTLY): ${req.body.severity || 'Medium'}
Short Description: ${short_description}
Affected Items: ${affected_items || 'Not specified'}
POC Notes: ${poc_notes || 'Not specified'}
${screenshotPaths.length ? `${screenshotPaths.length} POC screenshot(s) are attached. Use them to enrich the POC section.` : ''}

Return only valid JSON as described.${clientCtx}`;

  try {
    const genAI = new GoogleGenerativeAI(apiKey.trim());
    const model = genAI.getGenerativeModel({
      model: geminiModel,
      systemInstruction,
      generationConfig: {
        responseMimeType: 'application/json',
        temperature: 0.7,
        maxOutputTokens: 4096,
      },
    });

    const parts = [{ text: userPrompt }];

    // Attach all screenshots (multimodal)
    for (const sp of screenshotPaths) {
      const absolutePath = path.join(__dirname, sp.replace(/^\//, ''));
      if (fs.existsSync(absolutePath)) {
        const imageBuffer = fs.readFileSync(absolutePath);
        const base64Image = imageBuffer.toString('base64');
        const ext = path.extname(absolutePath).replace('.', '').toLowerCase();
        const mimeType = ext === 'jpg' ? 'image/jpeg' : `image/${ext}`;
        parts.push({ inlineData: { mimeType, data: base64Image } });
      }
    }

    const result = await model.generateContent(parts);
    const text = result.response.text();

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      // Try to extract JSON from response
      const match = text.match(/\{[\s\S]*\}/);
      if (match) parsed = JSON.parse(match[0]);
      else return res.status(500).json({ error: 'AI returned invalid response. Please try again.' });
    }

    const screenshotPathValue = screenshotPaths.length
      ? (screenshotPaths.length === 1 ? screenshotPaths[0] : JSON.stringify(screenshotPaths))
      : null;

    res.json({
      name:           parsed.name           || name,
      description:   parsed.description    || '',
      affected_items: parsed.affected_items || affected_items || '',
      impact:         parsed.impact         || '',
      recommendation: parsed.recommendation || '',
      poc:            parsed.poc            || poc_notes || '',
      references:     parsed.references     || '',
      screenshot_path: screenshotPathValue,
      severity:       req.body.severity     || parsed.severity || 'Medium',
      project_id:     project_id            || null,
    });

  } catch (error) {
    console.error('Gemini error:', error.message);
    if (error.message?.includes('API_KEY_INVALID') || error.message?.includes('API key not valid')) {
      return res.status(401).json({ error: 'Invalid Google AI Studio API key. Please check your key and try again.' });
    }
    if (error.message?.includes('quota') || error.message?.includes('RESOURCE_EXHAUSTED')) {
      return res.status(429).json({ error: 'API quota exceeded. Please wait and try again.' });
    }
    res.status(500).json({ error: error.message || 'AI generation failed. Please try again.' });
  }
});

// ─── Static + SPA (browser must be logged in, except login page + css/js) ─────
app.use(auth.requirePageAuth);
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ─── Catch-all: Serve SPA ────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🛡️  VulnVault — Vulnerability Management App`);
  console.log(`✅ Server running at http://localhost:${PORT}`);
  console.log(`📁 Database: vulnerabilities.db`);
  console.log(`🤖 AI: Google Gemini 2.5 Pro (key provided by user)\n`);
});
