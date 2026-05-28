require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { execFile } = require('child_process');
const { randomUUID } = require('crypto');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const db = require('./database');
const auth = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Gemini Model Fallback Chain ──────────────────────────────────────────────
const GEMINI_MODELS = [
  'gemini-3.5-flash',
  'gemini-3.1-flash-lite',
  'gemini-3-flash-preview',
  'gemini-2.5-flash',
  'gemini-2.5-flash-lite',
  'gemini-2.0-flash-lite',
];

/**
 * Try generating with each model in GEMINI_MODELS until one succeeds.
 * Skips quickly on 404/not-found. 30s timeout per model.
 * @param {string} apiKey
 * @param {object} modelConfig  – { systemInstruction, generationConfig }
 * @param {Array}  parts        – content parts to send
 * @returns {Promise<{text: string, model: string}>}
 */
async function callGeminiWithFallback(apiKey, modelConfig, parts) {
  const genAI = new GoogleGenerativeAI(apiKey.trim());
  let lastError = null;
  const PER_MODEL_TIMEOUT = 30000; // 30s max per model

  for (const modelName of GEMINI_MODELS) {
    const t0 = Date.now();
    try {
      const model = genAI.getGenerativeModel({
        model: modelName,
        ...modelConfig,
      });

      // Race between generation and timeout
      const result = await Promise.race([
        model.generateContent(parts),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error(`Timeout after ${PER_MODEL_TIMEOUT/1000}s`)), PER_MODEL_TIMEOUT)
        ),
      ]);

      const text = result.response.text();
      console.log(`[AI] ✅ ${modelName} succeeded in ${Date.now() - t0}ms`);
      return { text, model: modelName };
    } catch (err) {
      const msg = err?.message || '';
      const elapsed = Date.now() - t0;
      console.warn(`[AI] ❌ ${modelName} failed (${elapsed}ms): ${msg.substring(0, 150)}`);

      // Don't retry on auth errors — they affect all models
      if (msg.includes('API_KEY_INVALID') || msg.includes('API key not valid')) {
        throw err;
      }
      lastError = err;
      // Continue to next model immediately (no delay needed — errors are fast for 404/quota)
    }
  }

  // All models failed
  throw lastError || new Error('All AI models failed. Please try again later.');
}

// Behind reverse proxies (correct client IP, HTTPS awareness)
app.set('trust proxy', 1);

// Initialize DB on startup
db.getDb();

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const rateLimit = require('express-rate-limit');

// ─── Auth (public) ───────────────────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,       // 1 minute window
  max: 5,                     // 5 attempts per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please wait 1 minute before trying again.' },
});
app.get('/api/session', (req, res) => auth.sessionStatus(req, res));
app.post('/api/login', loginLimiter, (req, res) => auth.login(req, res));
app.post('/api/logout', (req, res) => auth.logout(req, res));

// ── Public Holidays (Google Calendar API with in-memory cache) ─────────────────
const _holidayCache = new Map(); // year -> { fetchedAt, dates: Set<string> }
const HOLIDAY_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours
const GCAL_CALENDAR_ID = 'id.indonesian%23holiday%40group.v.calendar.google.com';

// Hardcoded fallback if API key is not configured
const ID_HOLIDAYS_FALLBACK = new Set([
  '2025-01-01','2025-01-27','2025-01-28','2025-01-29','2025-03-28','2025-03-29',
  '2025-03-31','2025-04-01','2025-04-02','2025-04-03','2025-04-04','2025-04-07',
  '2025-04-18','2025-04-20','2025-05-01','2025-05-12','2025-05-13','2025-05-29',
  '2025-06-06','2025-06-09','2025-06-27','2025-08-17','2025-09-05','2025-12-25','2025-12-26',
  '2026-01-01','2026-01-16','2026-01-17','2026-03-19','2026-03-20','2026-03-21',
  '2026-03-23','2026-03-24','2026-04-03','2026-05-01','2026-05-14','2026-05-26',
  '2026-05-27','2026-06-17','2026-08-17','2026-09-25','2026-12-25',
]);
const SCHEDULE_POLICY_VERSION = 'id-holiday-working-days-v1';

async function fetchHolidaysFromGoogle(year) {
  const apiKey = process.env.GOOGLE_CALENDAR_API_KEY;
  if (!apiKey) return null; // no key configured

  const timeMin = encodeURIComponent(`${year}-01-01T00:00:00Z`);
  const timeMax = encodeURIComponent(`${year}-12-31T23:59:59Z`);
  const url = `https://www.googleapis.com/calendar/v3/calendars/${GCAL_CALENDAR_ID}/events?key=${apiKey}&timeMin=${timeMin}&timeMax=${timeMax}&singleEvents=true&maxResults=100`;

  const https = require('https');
  return new Promise((resolve) => {
    https.get(url, (r) => {
      let d = '';
      r.on('data', c => d += c);
      r.on('end', () => {
        try {
          const json = JSON.parse(d);
          if (!json.items) return resolve(null);
          const dates = new Set(
            json.items.map(e => (e.start?.date || e.start?.dateTime || '').slice(0, 10)).filter(Boolean)
          );
          resolve(dates);
        } catch { resolve(null); }
      });
    }).on('error', () => resolve(null));
  });
}

async function getHolidaysSet(year) {
  const cached = _holidayCache.get(year);
  if (cached && Date.now() - cached.fetchedAt < HOLIDAY_CACHE_TTL) {
    return { source: cached.source, dates: cached.dates };
  }
  const googleDates = await fetchHolidaysFromGoogle(year);
  if (googleDates) {
    _holidayCache.set(year, { fetchedAt: Date.now(), dates: googleDates, source: 'google' });
    return { source: 'google', dates: googleDates };
  }
  const fallback = new Set([...ID_HOLIDAYS_FALLBACK].filter(d => d.startsWith(`${year}-`)));
  _holidayCache.set(year, { fetchedAt: Date.now(), dates: fallback, source: 'fallback' });
  return { source: 'fallback', dates: fallback };
}

function isValidDateString(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(new Date(`${value}T00:00:00`).getTime());
}

function toLocalDate(value) {
  return new Date(`${value}T00:00:00`);
}

function toDateStringLocal(date) {
  return date.toLocaleDateString('en-CA');
}

async function addWorkingDays(dateStr, days, { includeStart = true } = {}) {
  if (!isValidDateString(dateStr)) return null;
  const total = Number(days);
  if (!Number.isInteger(total) || total < 1) return null;

  const d = toLocalDate(dateStr);
  let counted = includeStart ? 0 : -1;
  const excluded = [];

  while (counted < total) {
    if (counted >= 0 || !includeStart) {
      const day = d.getDay();
      const dateKey = toDateStringLocal(d);
      const { dates: holidays } = await getHolidaysSet(d.getFullYear());
      if (day !== 0 && day !== 6 && !holidays.has(dateKey)) {
        counted++;
        if (counted >= total) break;
      } else if (day !== 0 && day !== 6 && holidays.has(dateKey)) {
        excluded.push(dateKey);
      }
    }
    d.setDate(d.getDate() + 1);
  }

  return { date: toDateStringLocal(d), excluded_holidays: [...new Set(excluded)] };
}

async function calculateSchedule(input) {
  const startDate = input.start_date;
  const assessmentDays = Number(input.assessment_days || 0);
  const initialReportDays = Number(input.initial_report_days || 1);
  const remediationDays = Number(input.remediation_days ?? 60);
  const retestDays = Number(input.retest_days ?? 2);
  const finalReportDays = Number(input.final_report_days ?? 1);

  if (!isValidDateString(startDate)) {
    throw new Error('start_date must be YYYY-MM-DD');
  }
  for (const [name, value] of [
    ['assessment_days', assessmentDays],
    ['initial_report_days', initialReportDays],
    ['remediation_days', remediationDays],
    ['retest_days', retestDays],
    ['final_report_days', finalReportDays],
  ]) {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`${name} must be a non-negative integer`);
    }
  }
  if (assessmentDays + initialReportDays < 1) {
    throw new Error('assessment_days + initial_report_days must be at least 1');
  }

  const initial = await addWorkingDays(startDate, assessmentDays + initialReportDays, { includeStart: true });
  const finalSpan = remediationDays + retestDays + finalReportDays;
  const final = finalSpan > 0
    ? await addWorkingDays(initial.date, finalSpan, { includeStart: false })
    : { date: initial.date, excluded_holidays: [] };

  return {
    initial_report_date: initial.date,
    final_report_date: final.date,
    excluded_holidays: [...new Set([...initial.excluded_holidays, ...final.excluded_holidays])],
    schedule_policy_version: SCHEDULE_POLICY_VERSION,
  };
}

async function calculateFinalReportDate(initialReportDate) {
  const result = await addWorkingDays(initialReportDate, 63, { includeStart: false });
  return result ? result.date : null;
}

app.get('/api/holidays', async (req, res) => {
  const year = parseInt(req.query.year) || new Date().getFullYear();
  if (year < 2020 || year > 2035) return res.status(400).json({ error: 'Invalid year' });

  const { source, dates } = await getHolidaysSet(year);
  return res.json({ year, source, dates: [...dates] });
});

// Everything under /api below requires a valid session cookie (except routes above)
app.use(auth.requireApiAuth);

app.post('/api/schedule/calculate', async (req, res) => {
  try {
    const result = await calculateSchedule(req.body || {});
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});


// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
const generatedReportsDir = path.join(__dirname, 'generated_reports');
if (!fs.existsSync(generatedReportsDir)) {
  fs.mkdirSync(generatedReportsDir, { recursive: true });
}

const reportTemplateEnPath = path.join(__dirname, 'templates', 'initial_report_en.docx');
const reportGeneratorScript = path.join(__dirname, 'tools', 'report_generator_docx.py');

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

// ─── Current User ─────────────────────────────────────────────────────────────
app.get('/api/me', (req, res) => {
  const s = req.session;
  if (!s) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ userId: s.userId, username: s.username, displayName: s.displayName, role: s.role });
});

// ─── User Management (PM + Manager + Admin) ───────────────────────────────────
const mgmtRoles = auth.MANAGEMENT_ROLES;

app.get('/api/users', auth.requireRole(...mgmtRoles), (req, res) => {
  db.getAllUsers((err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/users/engineers', auth.requireRole(...mgmtRoles), (req, res) => {
  db.getAllEngineers((err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/users', auth.requireRole(...mgmtRoles), (req, res) => {
  let { username, display_name, role, password, team } = req.body;
  if (!username || !display_name || !role || !password) {
    return res.status(400).json({ error: 'username, display_name, role, and password are required.' });
  }
  const allowedRoles = ['engineer', 'consultant', 'pm', 'manager'];
  // Only admin can create other admins
  if (role === 'admin' && req.session.role !== 'admin') {
    return res.status(403).json({ error: 'Only admin can create another admin.' });
  }
  if (!allowedRoles.includes(role) && role !== 'admin') {
    return res.status(400).json({ error: 'Invalid role. Must be engineer, consultant, pm, manager, or admin.' });
  }
  // Auto-assign team based on role
  if (role === 'engineer') team = 'offensive';
  else if (role === 'consultant') team = 'itaudit';
  else if (!team || (team !== 'offensive' && team !== 'itaudit')) {
    return res.status(400).json({ error: 'Team is required for this role. Must be offensive or itaudit.' });
  }
  db.createUser({ username, display_name, role, password, team }, (err, id) => {
    if (err) {
      if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Username already exists.' });
      return res.status(500).json({ error: err.message });
    }
    db.writeActivityLog({ type:'user', actorId: req.session.userId, action:'create_user', details:`Created user @${username} (${role}, ${team})` });
    res.status(201).json({ id, username, display_name, role, team });
  });
});

app.delete('/api/users/:id', auth.requireRole(...mgmtRoles), (req, res) => {
  const targetId = Number(req.params.id);
  // Prevent self-deletion
  if (targetId === req.session.userId) {
    return res.status(400).json({ error: 'Cannot delete your own account.' });
  }
  db.deleteUser(targetId, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    db.writeActivityLog({ type:'user', actorId: req.session.userId, engineerId: targetId, action:'deactivate_user', details:`Deactivated user ID ${targetId}` });
    res.json({ ok: true });
  });
});

// ─── Password Change ─────────────────────────────────────────────────────────
const bcrypt = require('bcryptjs');
app.patch('/api/users/:id/password', (req, res) => {
  const targetId = Number(req.params.id);
  const { old_password, new_password } = req.body;
  const s = req.session;

  if (!new_password || new_password.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  }

  // Self-change: require old password
  // Management changing others: no old password needed
  const isSelf = targetId === s.userId;
  const isManagement = mgmtRoles.includes(s.role);

  if (!isSelf && !isManagement) {
    return res.status(403).json({ error: 'You can only change your own password.' });
  }

  db.getUserById(targetId, async (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found.' });

    // If changing own password, verify old password
    if (isSelf) {
      if (!old_password) return res.status(400).json({ error: 'Current password is required.' });
      const ok = await bcrypt.compare(old_password, user.password_hash);
      if (!ok) return res.status(401).json({ error: 'Current password is incorrect.' });
    }

    const hash = await bcrypt.hash(new_password, 10);
    db.changePassword(targetId, hash, (err2, result) => {
      if (err2) return res.status(500).json({ error: err2.message });
      db.writeActivityLog({ type:'user', actorId: s.userId, action:'change_password', details:`Password changed for user ID ${targetId}` });
      res.json({ ok: true });
    });
  });
});

// ─── Dashboard (PM + Manager + Admin) ─────────────────────────────────────────
app.get('/api/dashboard/summary', auth.requireRole(...mgmtRoles), (req, res) => {
  db.getDashboardSummary((err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ─── Access Requests ──────────────────────────────────────────────────────────
app.get('/api/access-requests', (req, res) => {
  const s = req.session;
  if (auth.DELIVERY_ROLES.includes(s.role)) {
    db.getAccessRequests({ requesterId: s.userId }, (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  } else if (mgmtRoles.includes(s.role)) {
    db.getAccessRequests({}, (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
});

app.post('/api/access-requests', auth.requireRole(...auth.DELIVERY_ROLES), (req, res) => {
  const { target_engineer_id } = req.body;
  if (!target_engineer_id) return res.status(400).json({ error: 'target_engineer_id is required.' });
  db.createAccessRequest(
    { requesterId: req.session.userId, targetEngineerId: Number(target_engineer_id) },
    (err, id) => {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ id, status: 'pending' });
    }
  );
});

app.patch('/api/access-requests/:id', auth.requireRole('admin', 'manager', 'pm'), (req, res) => {
  const { status } = req.body;
  if (!['approved', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'status must be approved or rejected.' });
  }
  db.updateAccessRequest({ id: Number(req.params.id), status, reviewedBy: req.session.userId }, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ ok: true, status });
  });
});

// ─── Project Access Requests (engineer → PM/Manager) ─────────────────────────
// GET /api/project-access-requests — engineer sees own; mgmt sees all pending
app.get('/api/project-access-requests', (req, res) => {
  const s = req.session;
  const filter = auth.DELIVERY_ROLES.includes(s.role) ? { engineerId: s.userId } : {};
  db.getProjectAccessRequests(filter, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// GET /api/projects/all — projects the engineer/consultant can REQUEST (only unassigned & matching team)
app.get('/api/projects/all', (req, res) => {
  db.getAllProjects((err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    if (auth.DELIVERY_ROLES.includes(req.session?.role)) {
      const uid = Number(req.session.userId);
      const role = req.session.role;
      rows = rows.filter(p => {
        const projectTeam = p.team || 'offensive';
        // Enforce team policy for requestable projects only.
        const isCorrectTeam = (role === 'consultant') ? projectTeam === 'itaudit' : projectTeam === 'offensive';
        if (!isCorrectTeam) return false;

        const assignmentSlots = [
          p.assigned_engineer_id,
          p.assist_engineer_id,
          p.engineer_3_id,
          p.engineer_4_id,
          p.engineer_5_id,
          p.engineer_6_id,
          p.engineer_7_id,
          p.engineer_8_id,
          p.engineer_9_id,
          p.engineer_10_id,
        ];
        const alreadyAssigned = assignmentSlots.some(v => Number(v) === uid);
        const hasOpenSlot = assignmentSlots.some(v => !v);
        return !alreadyAssigned && hasOpenSlot;
      });
    }
    res.json(rows);
  });
});

// POST /api/project-access-requests — engineer submits request
app.post('/api/project-access-requests', auth.requireRole(...auth.DELIVERY_ROLES), (req, res) => {
  const { project_id, message } = req.body;
  if (!project_id) return res.status(400).json({ error: 'project_id is required.' });
  db.createProjectAccessRequest(
    { engineerId: req.session.userId, projectId: Number(project_id), message },
    (err, id) => {
      if (err) {
        if (err.message === 'Project or engineer not found') return res.status(404).json({ error: err.message });
        if (err.message === 'Project resource slots are full' || err.message === 'Engineer is already assigned to this project') {
          return res.status(409).json({ error: err.message });
        }
        if (/archived|inactive|delivery users|team mismatch/i.test(err.message || '')) {
          return res.status(400).json({ error: err.message });
        }
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({ id, status: 'pending' });
    }
  );
});

// PATCH /api/project-access-requests/:id — PM/Manager approves or rejects (auto-assigns on approve)
app.patch('/api/project-access-requests/:id', auth.requireRole('admin', 'manager', 'pm'), (req, res) => {
  const { status } = req.body;
  if (!['approved', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'status must be approved or rejected.' });
  }
  db.updateProjectAccessRequest({ id: Number(req.params.id), status, reviewedBy: req.session.userId }, (err) => {
    if (err) {
      if (err.message === 'Project resource slots are full') {
        return res.status(409).json({ error: err.message });
      }
      if (err.message === 'Engineer is already assigned to this project') {
        return res.status(409).json({ error: err.message });
      }
      if (err.message === 'Cannot approve access request for an archived project') {
        return res.status(400).json({ error: err.message });
      }
      if (err.message === 'Engineer is inactive') {
        return res.status(400).json({ error: err.message });
      }
      if (err.message === 'Team mismatch: engineer and project teams do not match') {
        return res.status(400).json({ error: err.message });
      }
      if (err.message === 'Access request is not pending') {
        return res.status(409).json({ error: err.message });
      }
      if (err.message === 'Access request not found' || err.message === 'Project not found' || err.message === 'Engineer not found') {
        return res.status(404).json({ error: err.message });
      }
      return res.status(500).json({ error: err.message });
    }
    // Log the action + send notification to engineer
    db.getDb().get(
      `SELECT par.engineer_id, par.project_id, p.name AS project_name
       FROM project_access_requests par
       JOIN projects p ON p.id = par.project_id
       WHERE par.id=?`,
      [Number(req.params.id)],
      (e, row) => {
        if (row) {
          db.writeActivityLog({
            type: 'project_request',
            actorId: req.session.userId,
            engineerId: row.engineer_id,
            projectId: row.project_id,
            action: status,
            details: `Project access request ${status} by ${req.session.username}`
          });
          // Notify the requesting engineer
          db.createNotification({
            userId: row.engineer_id,
            type: 'access_request',
            title: status === 'approved' ? 'Access Request Approved' : 'Access Request Rejected',
            message: `Your request to join project "${row.project_name}" has been ${status} by ${req.session.displayName || req.session.username}.`
          });
        }
      }
    );
    res.json({ ok: true, status });
  });
});

// GET /api/activity-log — PM/Manager/Admin only, optional ?type=user|crud|project_request
app.get('/api/activity-log', auth.requireRole('admin','manager','pm'), (req, res) => {
  const type = req.query.type || null;
  db.getActivityLog(type, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ─── Notifications ────────────────────────────────────────────────────────────
app.get('/api/notifications', (req, res) => {
  db.getNotifications(req.session.userId, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.patch('/api/notifications/read', (req, res) => {
  db.markNotificationsRead(req.session.userId, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ ok: true });
  });
});

// ─── Vulnerability Routes ─────────────────────────────────────────────────────
app.get('/api/vulnerabilities', (req, res) => {
  const { search, severity, sort, project_id } = req.query;
  const s = req.session;
  // The library is global for all roles
  const engineerId = null;
  const projectId = project_id ? Number(project_id) : null;
  if (project_id && (!Number.isInteger(projectId) || projectId < 1)) {
    return res.status(400).json({ error: 'Invalid project id' });
  }

  const list = () => {
    db.listVulnerabilities(
      {
        search:     (search   || '').trim(),
        severity:   (severity || '').trim(),
        sort:       (sort     || 'newest').trim(),
        project_id: projectId,
        owner_engineer_id: engineerId,
      },
      (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
      }
    );
  };

  if (projectId && auth.DELIVERY_ROLES.includes(s?.role)) {
    db.checkProjectAccess(s.userId, s.role, projectId, (err, hasAccess) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!hasAccess) return res.status(403).json({ error: 'Forbidden: You do not have access to this project.' });
      list();
    });
    return;
  }

  list();
});

app.get('/api/vulnerabilities/:id', (req, res) => {
  db.getVulnerabilityById(req.params.id, (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Vulnerability not found' });
    res.json(row);
  });
});

function validateBilingualPayload(payload) {
  if (payload === undefined || payload === null || payload === '') return null;
  if (typeof payload === 'string') {
    try {
      const parsed = JSON.parse(payload);
      if (parsed && typeof parsed === 'object') {
        return payload;
      }
      throw new Error('Bilingual payload must resolve to a JSON object');
    } catch (e) {
      throw new Error('Invalid JSON format in bilingual payload: ' + e.message);
    }
  }
  if (typeof payload === 'object') {
    try {
      return JSON.stringify(payload);
    } catch (e) {
      throw new Error('Failed to serialize bilingual payload: ' + e.message);
    }
  }
  throw new Error('Bilingual payload must be a JSON string or object');
}

app.post('/api/vulnerabilities', (req, res) => {
  const { name, description, affected_items, impact, recommendation, poc, references, screenshot_path, severity, bilingual_payload, cvss_score, cvss_vector } = req.body;
  if (!name) return res.status(400).json({ error: 'Vulnerability name is required' });

  let validatedBilingualPayload = null;
  try {
    validatedBilingualPayload = validateBilingualPayload(bilingual_payload);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  const owner_engineer_id = auth.DELIVERY_ROLES.includes(req.session?.role) ? req.session.userId : null;
  db.saveVulnerability(
    { name, description, affected_items, impact, recommendation, poc, references, screenshot_path, severity, bilingual_payload: validatedBilingualPayload, owner_engineer_id, cvss_score, cvss_vector },
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      db.getVulnerabilityById(result.id, (err2, row) => {
        if (err2) return res.status(500).json({ error: err2.message });
        res.status(201).json(row);
      });
    }
  );
});

app.put('/api/vulnerabilities/:id', (req, res) => {
  const id = Number(req.params.id);
  const { name, severity, description, affected_items, impact, recommendation, poc, screenshot_path, bilingual_payload, cvss_score, cvss_vector } = req.body;
  if (!name) return res.status(400).json({ error: 'Vulnerability name is required' });

  const hasBilingualPayload = Object.prototype.hasOwnProperty.call(req.body, 'bilingual_payload');
  let validatedBilingualPayload;
  if (hasBilingualPayload) {
    try {
      validatedBilingualPayload = validateBilingualPayload(bilingual_payload);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  }

  db.updateVulnerability(id, { name, severity, description, affected_items, impact, recommendation, poc, screenshot_path, cvss_score, cvss_vector, bilingual_payload: validatedBilingualPayload }, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!result.changes) return res.status(404).json({ error: 'Vulnerability not found' });
    db.getVulnerabilityById(id, (err2, row) => {
      if (err2) return res.status(500).json({ error: err2.message });
      res.json(row);
    });
  });
});

app.delete('/api/vulnerabilities/:id', (req, res) => {
  // First fetch the vulnerability to get screenshot paths for cleanup
  db.getVulnerabilityById(req.params.id, (fetchErr, vuln) => {
    if (fetchErr) return res.status(500).json({ error: fetchErr.message });
    if (!vuln) return res.status(404).json({ error: 'Vulnerability not found' });

    // Clean up screenshot files from disk
    if (vuln.screenshot_path) {
      let paths = [];
      try { paths = JSON.parse(vuln.screenshot_path); if (!Array.isArray(paths)) paths = [vuln.screenshot_path]; }
      catch { paths = [vuln.screenshot_path]; }
      for (const p of paths) {
        const absPath = path.join(__dirname, p.replace(/^\//, ''));
        if (fs.existsSync(absPath)) {
          try { fs.unlinkSync(absPath); } catch (e) { console.warn('[cleanup] Failed to delete:', absPath, e.message); }
        }
      }
    }

    db.deleteVulnerability(req.params.id, (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      if (result.changes === 0) return res.status(404).json({ error: 'Vulnerability not found' });
      res.json({ message: 'Deleted successfully' });
    });
  });
});

// ─── Client / Project Grouping Routes ────────────────────────────────────────
app.get('/api/clients', (req, res) => {
  const s = req.session;
  if (auth.DELIVERY_ROLES.includes(s?.role)) {
    if (s.role === 'consultant') {
      db.getClientsByConsultant(s.userId, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
      });
    } else {
      db.getClientsByEngineer(s.userId, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
      });
    }
  } else {
    db.getClients((err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  }
});

app.post('/api/clients', (req, res) => {
  // Only management roles can create clients
  if (!auth.MANAGEMENT_ROLES.includes(req.session?.role)) return res.status(403).json({ error: 'Unauthorized to create clients. Ask your PM to create and assign you.' });
  const name = (req.body?.name || '').trim();
  const engagement_reference = (req.body?.engagement_reference || '').trim() || null;
  const engagement_info = (req.body?.engagement_info || '').trim() || null;
  const team = (req.body?.team || 'offensive').trim();
  if (!name) return res.status(400).json({ error: 'Client name is required' });
  db.createClient(name, { engagement_reference, engagement_info, team }, (err, result) => {
    if (err) {
      if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Client already exists in this team' });
      return res.status(500).json({ error: err.message });
    }
    db.writeActivityLog({ type:'crud', actorId: req.session.userId, action:'create_client', details:`Created client "${name}" (${team})` });
    db.getClients((err2, rows) => {
      if (err2) return res.status(500).json({ error: err2.message });
      const created = rows.find(r => r.id === result.id);
      res.status(201).json(created || { id: result.id, name, team });
    });
  });
});

// ─── Engagements ──────────────────────────────────────────────────────────────
app.get('/api/clients/:clientId/engagements', auth.requireRole('admin','manager','pm'), (req, res) => {
  const clientId = Number(req.params.clientId);
  db.getEngagementsByClient(clientId, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/engagements', auth.requireRole('admin','manager','pm'), (req, res) => {
  db.getAllEngagements((err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/clients/:clientId/engagements', auth.requireRole('admin','manager','pm'), (req, res) => {
  const clientId = Number(req.params.clientId);
  const { engagement_reference, engagement_info } = req.body;
  db.createEngagement(clientId, { engagement_reference, engagement_info }, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ id: result.id, client_id: clientId, engagement_reference, engagement_info });
  });
});

app.delete('/api/clients/:id', (req, res) => {
  if (!auth.MANAGEMENT_ROLES.includes(req.session?.role)) return res.status(403).json({ error: 'Unauthorized to delete clients.' });
  const clientId = Number(req.params.id);
  if (!Number.isInteger(clientId) || clientId < 1) {
    return res.status(400).json({ error: 'Invalid client id' });
  }
  db.deleteClient(clientId, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!result?.changes) return res.status(404).json({ error: 'Client not found' });
    db.writeActivityLog({ type:'crud', actorId: req.session.userId, action:'delete_client', details:`Deleted client ID ${clientId}` });
    res.json({ message: 'Client deleted successfully' });
  });
});

// GET /api/clients/full — all clients with their projects (LEFT JOIN) for portal accordion
// ⚠ MUST be defined BEFORE /api/clients/:clientId routes to avoid "full" matching as :clientId
app.get('/api/clients/full', auth.requireRole('admin','manager','pm'), (req, res) => {
  db.getClientsWithProjects((err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/clients/:clientId/projects', (req, res) => {
  const clientId = Number(req.params.clientId);
  if (!Number.isInteger(clientId) || clientId < 1) {
    return res.status(400).json({ error: 'Invalid client id' });
  }
  db.getProjectsByClient(clientId, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    if (auth.DELIVERY_ROLES.includes(req.session?.role)) {
      const uid = Number(req.session.userId);
      const role = req.session.role;
      rows = rows.filter(p => {
        const isAssigned =
          Number(p.assigned_engineer_id) === uid ||
          Number(p.assist_engineer_id) === uid ||
          Number(p.engineer_3_id) === uid ||
          Number(p.engineer_4_id) === uid ||
          Number(p.engineer_5_id) === uid ||
          Number(p.engineer_6_id) === uid ||
          Number(p.engineer_7_id) === uid ||
          Number(p.engineer_8_id) === uid ||
          Number(p.engineer_9_id) === uid ||
          Number(p.engineer_10_id) === uid ||
          Number(p.retest_pic_id) === uid ||
          Number(p.retest_assist_id) === uid;

        if (role === 'consultant') {
          return isAssigned && p.team === 'itaudit';
        } else {
          return isAssigned && p.team === 'offensive';
        }
      });
    }
    res.json(rows);
  });
});

app.post('/api/clients/:clientId/projects', async (req, res) => {
  // Only management roles can create projects
  if (!auth.MANAGEMENT_ROLES.includes(req.session?.role)) return res.status(403).json({ error: 'Unauthorized to create projects. Ask your PM to create and assign you.' });
  const clientId = Number(req.params.clientId);
  let { name, project_type, project_method, assigned_engineer_id, assist_engineer_id, engineer_3_id, engineer_4_id, engineer_5_id, engineer_6_id, engineer_7_id, engineer_8_id, engineer_9_id, engineer_10_id, kickoff_date, initial_report_date, final_report_date, project_links, start_date, mandays_initial_report, mandays_assessment, team, service, is_past_project, actual_end_date } = req.body;
  const trimName = (name || '').trim();
  if (!Number.isInteger(clientId) || clientId < 1) {
    return res.status(400).json({ error: 'Invalid client id' });
  }
  if (!trimName) return res.status(400).json({ error: 'Project name is required' });
  
  let schedule_policy_version = null;
  if (start_date && (Number(mandays_assessment) > 0 || Number(mandays_initial_report) > 0)) {
    try {
      const schedule = await calculateSchedule({
        start_date,
        assessment_days: Number(mandays_assessment) || 0,
        initial_report_days: Number(mandays_initial_report) || 1,
        remediation_days: 60,
        retest_days: 2,
        final_report_days: 1,
      });
      initial_report_date = schedule.initial_report_date;
      final_report_date = final_report_date || schedule.final_report_date;
      schedule_policy_version = schedule.schedule_policy_version;
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  } else if (initial_report_date && !final_report_date) {
    final_report_date = await calculateFinalReportDate(initial_report_date) || final_report_date;
    schedule_policy_version = SCHEDULE_POLICY_VERSION;
  }
  
  let initial_report_status = 'pending';
  let final_report_status = 'pending';
  let initial_completed_at = null;
  let final_completed_at = null;
  let initial_completed_by = null;
  let final_completed_by = null;
  let is_archived = 0;
  let archived_at = null;
  if (is_past_project && actual_end_date) {
    initial_report_status = 'completed';
    final_report_status = 'completed';
    initial_completed_at = actual_end_date;
    final_completed_at = actual_end_date;
    initial_completed_by = req.session.displayName || req.session.username;
    final_completed_by = req.session.displayName || req.session.username;
    is_archived = 1;
    archived_at = new Date().toISOString();
  }

  db.createProject(clientId, trimName, { project_type, project_method: project_method || 'blackbox', assigned_engineer_id, assist_engineer_id, engineer_3_id, engineer_4_id, engineer_5_id, engineer_6_id, engineer_7_id, engineer_8_id, engineer_9_id, engineer_10_id, kickoff_date, initial_report_date, final_report_date, initial_report_status, final_report_status, initial_completed_at, final_completed_at, initial_completed_by, final_completed_by, is_archived, archived_at, project_links: project_links ? JSON.stringify(project_links) : null, start_date, mandays_initial_report, mandays_assessment, team, service, schedule_policy_version }, (err, result) => {
    if (err) {
      if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Project already exists for this client' });
      if (/assigned user|duplicate engineer|invalid assignment/i.test(err.message || '')) return res.status(400).json({ error: err.message });
      return res.status(500).json({ error: err.message });
    }
    db.writeActivityLog({ type:'crud', actorId: req.session.userId, projectId: result.id, action:'create_project', details:`Created project "${trimName}" in client ID ${clientId}` });
    db.getProjectsByClient(clientId, (err2, rows) => {
      if (err2) return res.status(500).json({ error: err2.message });
      const created = rows.find(r => r.id === result.id);
      res.status(201).json(created || { id: result.id, client_id: clientId, name: trimName });
    });
  });
});

app.get('/api/projects/archived', auth.requireRole('admin', 'manager', 'pm'), (req, res) => {
  db.getArchivedProjects((err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.patch('/api/projects/:id/archive', auth.requireRole('admin', 'manager', 'pm'), (req, res) => {
  const id = Number(req.params.id);
  db.getProjectById(id, (err, proj) => {
    if (err || !proj) return res.status(404).json({ error: 'Project not found' });

    const isCompleted = proj.final_report_status === 'completed';
    if (!isCompleted) {
      return res.status(400).json({ error: 'Cannot archive active project. Complete final report first.' });
    }

    db.archiveProject(id, (err2, result) => {
      if (err2) return res.status(500).json({ error: err2.message });
      if (!result?.changes) return res.status(404).json({ error: 'Project not found' });
      db.writeActivityLog({ type:'crud', actorId: req.session.userId, projectId: id, action:'archive_project', details:`Archived project "${proj.name}"` });
      res.json({ message: 'Project archived successfully' });
    });
  });
});

app.patch('/api/projects/:id/restore', auth.requireRole('admin', 'manager', 'pm'), (req, res) => {
  const id = Number(req.params.id);
  db.restoreProject(id, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!result?.changes) return res.status(404).json({ error: 'Project not found' });
    db.writeActivityLog({ type:'crud', actorId: req.session.userId, projectId: id, action:'restore_project', details:`Restored project ID ${id}` });
    res.json({ message: 'Project restored successfully' });
  });
});

app.delete('/api/projects/:projectId', (req, res) => {
  if (!auth.MANAGEMENT_ROLES.includes(req.session?.role)) return res.status(403).json({ error: 'Unauthorized to delete projects.' });
  const projectId = Number(req.params.projectId);
  if (!Number.isInteger(projectId) || projectId < 1) {
    return res.status(400).json({ error: 'Invalid project id' });
  }
  db.deleteProject(projectId, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!result?.changes) return res.status(404).json({ error: 'Project not found' });
    db.writeActivityLog({ type:'crud', actorId: req.session.userId, projectId, action:'delete_project', details:`Deleted project ID ${projectId}` });
    res.json({ message: 'Project deleted successfully' });
  });
});


app.get('/api/projects/:projectId/vulnerabilities', auth.requireProjectAccess('projectId'), (req, res) => {
  const projectId = Number(req.params.projectId);
  if (!Number.isInteger(projectId) || projectId < 1) {
    return res.status(400).json({ error: 'Invalid project id' });
  }
  db.getProjectVulnerabilityIds(projectId, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows.map(r => r.vulnerability_id));
  });
});

app.put('/api/projects/:projectId/vulnerabilities', auth.requireProjectAccess('projectId'), (req, res) => {
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

function parseJsonMaybe(value, fallback = null) {
  if (!value) return fallback;
  try { return JSON.parse(value); } catch { return fallback; }
}

function parseListText(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(v => String(v).trim()).filter(Boolean);
  return String(value)
    .split(/\r?\n|;|,/)
    .map(line => line.replace(/^[-*•\d.]+\s*/, '').trim())
    .filter(Boolean);
}

function parseScreenshots(value) {
  if (!value) return [];
  const parsed = parseJsonMaybe(value, null);
  if (Array.isArray(parsed)) return parsed.filter(Boolean);
  if (parsed) return [parsed];
  return [value];
}

function pickLanguagePayload(row, language = 'en') {
  const payload = parseJsonMaybe(row.bilingual_payload, null);
  const localized = payload?.[language] || null;
  return {
    name: localized?.name || row.name || '',
    description: localized?.description || row.description || '',
    affected_items: localized?.affected_items || row.affected_items || '',
    impact: localized?.impact || row.impact || '',
    recommendation: localized?.recommendation || row.recommendation || '',
    poc: localized?.poc || row.poc || '',
    references: localized?.references || row.references || '',
    // severity, cvss_score, cvss_vector are NOT taken from bilingual_payload
    // because the user can edit them directly in VulnVault — row.* is the source of truth.
  };
}

function normalizeSeverityForTemplate(severity) {
  if (!severity) return 'Medium';
  if (severity === 'Info') return 'Informational';
  return severity;
}

function cvssFallback(severity) {
  const normalized = normalizeSeverityForTemplate(severity);
  const fallback = {
    Critical: { score: '9.8', vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    High: { score: '8.1', vector: 'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N' },
    Medium: { score: '6.5', vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N' },
    Low: { score: '3.7', vector: 'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N' },
    Informational: { score: '0.0', vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N' },
  };
  return fallback[normalized] || fallback.Medium;
}

function parseCvssVector(raw) {
  if (!raw) return '';
  // Strip prefix like 'CVSS:3.1/' or 'CVSS:3.0/' → keep only the vector part
  return String(raw).replace(/^CVSS:\d+\.\d+\//i, '').trim();
}

function firstUrlOrFirstItem(text, fallback) {
  const value = String(text || '');
  const urlMatch = value.match(/https?:\/\/[^\s,;]+/i);
  if (urlMatch) return urlMatch[0];
  const items = parseListText(value);
  return items[0] || fallback || '';
}

function formatReportDate(dateValue) {
  const date = dateValue ? new Date(dateValue) : new Date();
  if (Number.isNaN(date.getTime())) return new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' });
  return date.toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' });
}

function projectMethodLabel(method) {
  const value = String(method || '').toLowerCase();
  if (value.includes('white')) return 'White-Box Testing';
  if (value.includes('black')) return 'Black-Box Testing';
  return 'Grey-Box Testing';
}

function safeFilename(value) {
  return String(value || 'report')
    .replace(/[^a-z0-9._-]+/gi, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 120) || 'report';
}

function buildInitialReportData(rows, language = 'en') {
  const first = rows[0];
  const vulns = rows.filter(row => row.id);
  const clientName = first.client_name || 'Client';
  const projectName = first.project_name || 'Application';
  const reportDate = formatReportDate(first.initial_report_date || first.start_date || first.kickoff_date);
  const testingPeriod = first.start_date && first.initial_report_date
    ? `${formatReportDate(first.start_date)} - ${formatReportDate(first.initial_report_date)}`
    : (first.kickoff_date && first.initial_report_date
      ? `${formatReportDate(first.kickoff_date)} - ${formatReportDate(first.initial_report_date)}`
      : reportDate);
  const scopes = [
    {
      scope_name: first.project_type ? String(first.project_type).replace(/\b\w/g, c => c.toUpperCase()) : 'Application',
      scope_target: projectName,
      scope_area: 'External',
    },
  ];

  return {
    client_name: clientName,
    client_nick: clientName.replace(/^PT\s+/i, '').split(/\s+/)[0] || clientName,
    application_name: projectName,
    document_title: `Penetration Test Report for ${projectName}`,
    document_number: `CISO-VAPT-${String(first.project_id).padStart(3, '0')}/${new Date().getFullYear()}.EN`,
    document_date: reportDate,
    report_type: 'Initial Report',
    testing_period: testingPeriod,
    testing_approach: projectMethodLabel(first.project_method),
    pentester_name: reqSafeDisplayNamePlaceholder(),
    pentester_certifications: '-',
    scopes,
    findings: vulns.map((row, idx) => {
      const localized = pickLanguagePayload(row, language);
      const severity = normalizeSeverityForTemplate(row.severity || 'Medium');
      const fallback = cvssFallback(severity);
      const realScore = row.cvss_score ? String(row.cvss_score).trim() : '';
      const realVector = row.cvss_vector ? parseCvssVector(row.cvss_vector) : '';
      const affectedItems = parseListText(localized.affected_items);
      const screenshotPaths = parseScreenshots(row.screenshot_path);
      return {
        finding_number: idx + 1,
        severity,
        finding_name: localized.name,
        finding_title: localized.name,
        target: firstUrlOrFirstItem(localized.affected_items, projectName),
        status: 'New',
        cvss_score: realScore || fallback.score,
        cvss_vector: realVector || fallback.vector,
        finding_date: formatReportDate(row.created_at),
        description: localized.description,
        impact: localized.impact,
        affected_items: affectedItems.length ? affectedItems : [firstUrlOrFirstItem(localized.affected_items, projectName)],
        poc_description: localized.poc,
        poc_images: screenshotPaths.map((imagePath, imageIdx) => ({
          image_path: path.resolve(__dirname, imagePath.replace(/^\//, '')),
          figure_caption: `${localized.name} evidence ${imageIdx + 1}`,
        })),
        recommendation: localized.recommendation,
        references: parseListText(localized.references),
      };
    }),
  };
}

function reqSafeDisplayNamePlaceholder() {
  return 'Cisometric Security Team';
}

function findPythonBinary() {
  const candidates = [
    process.env.PYTHON_BIN,
    path.join(__dirname, '.venv', 'bin', 'python3'),
    '/Users/vincentius/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3',
    'python3',
  ].filter(Boolean);
  return candidates.find(candidate => candidate === 'python3' || fs.existsSync(candidate)) || 'python3';
}

function runDocxGenerator({ dataPath, outputPath }) {
  return new Promise((resolve, reject) => {
    execFile(
      findPythonBinary(),
      [reportGeneratorScript, '--template', reportTemplateEnPath, '--data', dataPath, '--out', outputPath],
      { cwd: __dirname, timeout: 120000, maxBuffer: 1024 * 1024 * 10 },
      (error, stdout, stderr) => {
        if (error) {
          error.message = `${error.message}${stderr ? `\n${stderr}` : ''}`;
          return reject(error);
        }
        try {
          return resolve(JSON.parse(stdout));
        } catch {
          return reject(new Error(`Generator returned invalid JSON: ${stdout || stderr}`));
        }
      }
    );
  });
}

app.get('/api/projects/:projectId/export', auth.requireProjectAccess('projectId'), (req, res) => {
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

// ─── Generate DOCX Report (EN) from Project Data ────────────────────────────
app.post('/api/projects/:projectId/generate-report-docx', auth.requireProjectAccess('projectId'), async (req, res) => {
  const projectId = Number(req.params.projectId);
  if (!Number.isInteger(projectId) || projectId < 1) {
    return res.status(400).json({ error: 'Invalid project id' });
  }

  // Verify template exists
  if (!fs.existsSync(reportTemplateEnPath)) {
    return res.status(500).json({ error: 'Report template not found on server. Please contact admin.' });
  }

  db.getProjectExportData(projectId, async (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!rows.length) return res.status(404).json({ error: 'Project not found or has no data' });

    try {
      const reportData = buildInitialReportData(rows, 'en');

      // Write temp JSON for the Python generator
      const tempId = `report_${projectId}_${Date.now()}`;
      const dataPath = path.join(generatedReportsDir, `${tempId}.json`);
      const outputPath = path.join(generatedReportsDir, `${tempId}.docx`);
      fs.writeFileSync(dataPath, JSON.stringify(reportData, null, 2));

      // Call Python generator
      const result = await runDocxGenerator({ dataPath, outputPath });

      // Clean up temp JSON
      try { fs.unlinkSync(dataPath); } catch {}

      if (!fs.existsSync(outputPath)) {
        return res.status(500).json({ error: 'Generator did not produce output file' });
      }

      // Build download filename
      const clientName = safeFilename(rows[0].client_name || 'Client');
      const projectName = safeFilename(rows[0].project_name || 'Project');
      const downloadName = `Initial_Report_EN_${clientName}_${projectName}.docx`;

      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
      res.setHeader('Content-Disposition', `attachment; filename="${downloadName}"`);

      const fileStream = fs.createReadStream(outputPath);
      fileStream.pipe(res);
      fileStream.on('end', () => {
        // Clean up generated DOCX after sending
        try { fs.unlinkSync(outputPath); } catch {}
      });
      fileStream.on('error', (streamErr) => {
        try { fs.unlinkSync(outputPath); } catch {}
        if (!res.headersSent) {
          res.status(500).json({ error: 'Failed to stream report file' });
        }
      });
    } catch (genErr) {
      console.error('[DOCX Generator Error]', genErr.message);
      return res.status(500).json({ error: `Report generation failed: ${genErr.message}` });
    }
  });
});

// ─── Client / Project — rename + single-vuln management + report ─────────────

app.put('/api/clients/:id', (req, res) => {
  if (!auth.MANAGEMENT_ROLES.includes(req.session?.role)) return res.status(403).json({ error: 'Unauthorized to edit clients.' });
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

app.put('/api/projects/:id', async (req, res) => {
  if (!auth.MANAGEMENT_ROLES.includes(req.session?.role)) return res.status(403).json({ error: 'Unauthorized to edit projects.' });
  const id   = Number(req.params.id);
  let { name, project_type, project_method, assigned_engineer_id, assist_engineer_id, engineer_3_id, engineer_4_id, engineer_5_id, engineer_6_id, engineer_7_id, engineer_8_id, engineer_9_id, engineer_10_id, kickoff_date, initial_report_date, final_report_date, project_links, start_date, mandays_initial_report, mandays_assessment, team, service } = req.body;
  const trimName = (name || '').trim();
  if (!trimName) return res.status(400).json({ error: 'Name is required' });
  
  let schedule_policy_version = null;
  if (start_date && (Number(mandays_assessment) > 0 || Number(mandays_initial_report) > 0)) {
    try {
      const schedule = await calculateSchedule({
        start_date,
        assessment_days: Number(mandays_assessment) || 0,
        initial_report_days: Number(mandays_initial_report) || 1,
        remediation_days: 60,
        retest_days: 2,
        final_report_days: 1,
      });
      initial_report_date = schedule.initial_report_date;
      final_report_date = final_report_date || schedule.final_report_date;
      schedule_policy_version = schedule.schedule_policy_version;
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  } else if (initial_report_date && !final_report_date) {
    final_report_date = await calculateFinalReportDate(initial_report_date) || final_report_date;
    schedule_policy_version = SCHEDULE_POLICY_VERSION;
  }
  
  db.updateProject(id, { name: trimName, project_type, project_method, assigned_engineer_id, assist_engineer_id, engineer_3_id, engineer_4_id, engineer_5_id, engineer_6_id, engineer_7_id, engineer_8_id, engineer_9_id, engineer_10_id, kickoff_date, initial_report_date, final_report_date, project_links: project_links ? JSON.stringify(project_links) : null, start_date, mandays_initial_report, mandays_assessment, team, service, schedule_policy_version }, (err, result) => {
    if (err) {
      if (/assigned user|duplicate engineer|invalid assignment/i.test(err.message || '')) return res.status(400).json({ error: err.message });
      return res.status(500).json({ error: err.message });
    }
    if (!result.changes) return res.status(404).json({ error: 'Project not found' });
    db.writeActivityLog({ type:'crud', actorId: req.session.userId, projectId: id, action:'edit_project', details:`Updated project ID ${id}: name="${trimName}", PIC=${assigned_engineer_id||'none'}, Assist=${assist_engineer_id||'none'}` });
    res.json({ id, name: trimName, project_type, project_method, assigned_engineer_id, assist_engineer_id, engineer_3_id, engineer_4_id, engineer_5_id, engineer_6_id, engineer_7_id, engineer_8_id, engineer_9_id, engineer_10_id, kickoff_date, initial_report_date, final_report_date, start_date, mandays_initial_report, mandays_assessment, team, service, schedule_policy_version });
  });
});

app.patch('/api/projects/:id/reports', auth.requireRole('engineer', 'consultant', 'admin', 'manager', 'pm'), auth.requireProjectAccess('id'), (req, res) => {
  const id   = Number(req.params.id);
  const { link_report_en, link_report_id } = req.body;
  
  const urlRegex = /^https?:\/\//i;
  if (link_report_en && !urlRegex.test(link_report_en)) {
    return res.status(400).json({ error: 'English report link must be a valid URL starting with http:// or https://' });
  }
  if (link_report_id && !urlRegex.test(link_report_id)) {
    return res.status(400).json({ error: 'Indonesian report link must be a valid URL starting with http:// or https://' });
  }

  db.updateProjectReports(id, { link_report_en, link_report_id }, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!result.changes) return res.status(404).json({ error: 'Project not found' });
    db.writeActivityLog({ type:'crud', actorId: req.session.userId, projectId: id, action:'edit_project', details:`Updated report links for project ID ${id}` });
    // Notify management when report links are saved
    db.getProjectById(id, (e, proj) => {
      if (!e && proj) {
        db.notifyManagement({
          type: 'report_links',
          title: '📎 Report Links Updated',
          message: `${req.session.displayName || req.session.username} updated report links for "${proj.name}".`
        });
      }
    });
    res.json({ id, link_report_en, link_report_id });
  });
});

app.patch('/api/projects/:id/status', auth.requireRole('engineer', 'consultant', 'admin', 'manager', 'pm'), auth.requireProjectAccess('id'), (req, res) => {
  const id = Number(req.params.id);
  const { initial_report_status, final_report_status } = req.body;
  if (!initial_report_status && !final_report_status) return res.json({ ok: true });

  const role   = req.session?.role;
  const userId = req.session?.userId;
  const isPM   = ['admin','manager','pm'].includes(role);

  // If trying to mark FINAL report done — enforce retest access control
  if (final_report_status === 'completed') {
    db.getProjectById(id, (err, proj) => {
      if (err || !proj) return res.status(404).json({ error: 'Project not found' });
      // Must have retest started before final report can be marked done
      if (proj.retest_status !== 'started' && !isPM)
        return res.status(403).json({ error: 'Final Report can only be completed after PM starts the Retest phase.' });
      // Engineer must be the retest PIC (or management)
      if (!isPM && Number(proj.retest_pic_id) !== Number(userId))
        return res.status(403).json({ error: 'Only the Retest PIC can complete the Final Report.' });
      // Allowed — proceed
      doStatusUpdate();
    });
  } else {
    doStatusUpdate();
  }

  function doStatusUpdate() {
    // Build completed_by + completed_at updates
    const completedBy = {};
    const now = new Date().toISOString();
    if (initial_report_status === 'completed') {
      completedBy.initial_completed_by = req.session.displayName || req.session.username;
      completedBy.initial_completed_at = now;
    }
    if (final_report_status === 'completed') {
      completedBy.final_completed_by = req.session.displayName || req.session.username;
      completedBy.final_completed_at = now;
    }
    db.updateProjectReportStatus(id, { initial_report_status, final_report_status, ...completedBy }, (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!result.changes) return res.status(404).json({ error: 'Project not found' });
      db.getProjectById(id, (err, proj) => {
        if (!err && proj) {
          let msg = '';
          if (initial_report_status === 'completed') msg = `Initial Report completed for project ${proj.name}`;
          if (final_report_status === 'completed') msg = `Final Report completed for project ${proj.name}`;
          if (msg) {
            db.writeActivityLog({ type: 'project', actorId: req.session.userId, projectId: id, action: 'report_completed', details: msg }, () => {});
            db.notifyManagement({
              type: 'report_completed',
              title: initial_report_status === 'completed' ? '📋 Initial Report Completed' : '📗 Final Report Completed',
              message: `${req.session.displayName || req.session.username} completed the ${initial_report_status === 'completed' ? 'Initial' : 'Final'} Report for "${proj.name}".`
            });
          }
        }
      });
      res.json({ ok: true });
    });
  }
});

// Start Retest — PM/Manager only
app.post('/api/projects/:id/retest', auth.requireRole('pm', 'admin', 'manager'), (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid project id' });
  const { retest_pic_id, retest_assist_id, retest_start_date, retest_end_date } = req.body;
  if (!retest_pic_id) return res.status(400).json({ error: 'Retest PIC is required' });
  if (!retest_start_date || !retest_end_date) return res.status(400).json({ error: 'Retest start and end dates are required' });

  // Guard: initial report must be completed before retest can start
  db.getProjectById(id, (err0, proj0) => {
    if (err0 || !proj0) return res.status(404).json({ error: 'Project not found' });
    if (proj0.initial_report_status !== 'completed')
      return res.status(400).json({ error: 'Cannot start Retest until the Initial Report is marked as completed.' });

    db.startRetest(id, { retest_pic_id: Number(retest_pic_id), retest_assist_id: retest_assist_id ? Number(retest_assist_id) : null, retest_start_date, retest_end_date }, (err, result) => {
      if (err) {
        if (/assigned user|duplicate engineer|invalid assignment/i.test(err.message || '')) return res.status(400).json({ error: err.message });
        return res.status(500).json({ error: err.message });
      }
      if (!result.changes) return res.status(404).json({ error: 'Project not found' });

      db.getProjectById(id, (err2, proj) => {
        if (!err2 && proj) {
          db.writeActivityLog({ type: 'project', actorId: req.session.userId, projectId: id, action: 'start_retest', details: `Retest started for project "${proj.name}"` }, () => {});
          db.notifyManagement({ type: 'retest_started', title: '🔁 Retest Started', message: `PM started retest for "${proj.name}". Final report expected ${retest_end_date}.` });
          // Notify retest PIC engineer directly
          if (retest_pic_id) {
            db.createNotification({
              userId: Number(retest_pic_id),
              type: 'retest_assigned',
              title: '🔁 You are assigned as Retest PIC',
              message: `You have been assigned as Retest PIC for "${proj.name}". Retest runs ${retest_start_date} → ${retest_end_date}. Please complete the Final Report when done.`
            }, () => {});
          }
          if (retest_assist_id) {
            db.createNotification({
              userId: Number(retest_assist_id),
              type: 'retest_assigned',
              title: '🔁 You are assigned as Retest Assist',
              message: `You have been assigned as Retest Assist for "${proj.name}". Retest runs ${retest_start_date} → ${retest_end_date}.`
            }, () => {});
          }
        }
      });
      res.json({ ok: true });
    });
  });
});

// Full vulnerability details for a project
app.get('/api/projects/:projectId/findings', auth.requireProjectAccess('projectId'), (req, res) => {
  const projectId = Number(req.params.projectId);
  if (!Number.isInteger(projectId) || projectId < 1)
    return res.status(400).json({ error: 'Invalid project id' });
  db.getProjectFullVulnerabilities(projectId, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ── Project Highlights ─────────────────────────────────────────────────────────
app.get('/api/projects/:id/highlight', auth.requireRole('pm','admin','manager'), (req, res) => {
  const id = Number(req.params.id);
  db.getProjectHighlight(id, (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Project not found' });
    res.json({ id: row.id, name: row.name, highlight_notes: row.highlight_notes ? JSON.parse(row.highlight_notes) : [], highlight_text: row.highlight_text || '' });
  });
});

app.put('/api/projects/:id/highlight', auth.requireRole('pm','admin','manager'), (req, res) => {
  const id = Number(req.params.id);
  const { highlight_notes, highlight_text } = req.body;
  db.updateProjectHighlight(id, {
    highlight_notes: highlight_notes ? JSON.stringify(highlight_notes) : null,
    highlight_text: highlight_text || null
  }, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!result.changes) return res.status(404).json({ error: 'Project not found' });
    db.writeActivityLog({ type:'crud', actorId: req.session.userId, projectId: id, action:'update_highlight', details:`Updated highlight for project ID ${id}` });
    res.json({ ok: true });
  });
});

app.post('/api/projects/:id/highlight/generate', auth.requireRole('pm','admin','manager'), async (req, res) => {
  const id = Number(req.params.id);
  const { api_key, model, notes, project_name, client_name, project_type, kickoff_date, initial_report_date, final_report_date } = req.body;
  if (!api_key) return res.status(400).json({ error: 'API key is required' });
  if (!notes || !notes.length) return res.status(400).json({ error: 'At least one highlight note is required' });

  const notesList = Array.isArray(notes) ? notes.filter(n => n.trim()) : [];
  if (!notesList.length) return res.status(400).json({ error: 'Notes cannot be empty' });

  const prompt = `Kamu adalah asisten project manager untuk perusahaan cybersecurity. Tugas kamu adalah membuat highlight ringkas (2-4 kalimat) untuk laporan progress project.

Data Project:
- Nama Klien: ${client_name || 'N/A'}
- Nama Project: ${project_name || 'N/A'}
- Jenis: ${project_type || 'N/A'}
- Kickoff: ${kickoff_date || 'N/A'}
- Target Initial Report: ${initial_report_date || 'N/A'}
- Final Report: ${final_report_date || 'N/A'}

Poin-poin highlight dari PM:
${notesList.map((n, i) => `${i + 1}. ${n}`).join('\n')}

Buatlah satu paragraf highlight yang profesional dalam Bahasa Indonesia. Jika ada poin kendala atau masalah, tolong sebutkan secara jelas. Jika project berjalan lancar atau selesai lebih awal, highlight hal positif tersebut. Gunakan bahasa formal dan ringkas.`;

  try {
    const { text, model: usedModel } = await callGeminiWithFallback(api_key, {}, [{ text: prompt }]);
    console.log(`[Highlight] Used model: ${usedModel}`);
    res.json({ highlight_text: text.trim() });
  } catch (e) {
    const msg = e?.message || 'AI generation failed';
    fs.appendFileSync(path.join(__dirname, 'ai_error.log'), `[${new Date().toISOString()}] highlight: ${msg}\n`);
    res.status(500).json({ error: msg.includes('API key') ? 'Invalid API key' : msg });
  }
});

// ── Board Statuses (Kanban) ────────────────────────────────────────────────────
app.get('/api/board-statuses', auth.requireRole(...mgmtRoles), (req, res) => {
  const team = req.query.team;
  db.getBoardStatuses(team, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/board-statuses', auth.requireRole(...mgmtRoles), (req, res) => {
  const { name, color, sort_order, team } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Status name is required.' });
  db.createBoardStatus({ name: name.trim(), color, sort_order, team }, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    db.writeActivityLog({ type: 'crud', actorId: req.session.userId, action: 'create_board_status', details: `Created board status "${name.trim()}" for team "${team || 'offensive'}"` });
    res.status(201).json({ id: result.id, name: name.trim(), color: color || '#6366f1', sort_order: sort_order ?? 0, team });
  });
});

app.put('/api/board-statuses/reorder', auth.requireRole(...mgmtRoles), (req, res) => {
  const { ordered_ids, team } = req.body;
  if (!Array.isArray(ordered_ids)) return res.status(400).json({ error: 'ordered_ids array is required.' });
  db.reorderBoardStatuses(ordered_ids.map(Number), team, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ ok: true });
  });
});

app.put('/api/board-statuses/:id', auth.requireRole(...mgmtRoles), (req, res) => {
  const id = Number(req.params.id);
  const { name, color, sort_order } = req.body;
  db.updateBoardStatus(id, { name: name?.trim(), color, sort_order }, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!result.changes) return res.status(404).json({ error: 'Status not found' });
    res.json({ ok: true });
  });
});

app.delete('/api/board-statuses/:id', auth.requireRole(...mgmtRoles), (req, res) => {
  const id = Number(req.params.id);
  db.deleteBoardStatus(id, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!result.changes) return res.status(404).json({ error: 'Status not found' });
    db.writeActivityLog({ type: 'crud', actorId: req.session.userId, action: 'delete_board_status', details: `Deleted board status ID ${id}` });
    res.json({ ok: true });
  });
});

app.patch('/api/projects/:id/board-status', auth.requireRole(...mgmtRoles), (req, res) => {
  const id = Number(req.params.id);
  const { board_status_id } = req.body;

  const isClosed = (board_status_id === -1);

  db.getProjectById(id, (err, proj) => {
    if (err || !proj) return res.status(404).json({ error: 'Project not found' });

    if (isClosed && proj.final_report_status !== 'completed') {
      return res.status(400).json({ error: 'Complete final report first' });
    }

    db.updateProjectBoardStatus(id, board_status_id, (err2, result) => {
      if (err2) return res.status(500).json({ error: err2.message });
      if (!result.changes) return res.status(404).json({ error: 'Project not found' });
      res.json({ ok: true, isClosed, final_completed_at: proj.final_completed_at });
    });
  });
});

app.get('/api/board/projects', auth.requireRole(...mgmtRoles), (req, res) => {
  db.getProjectsForBoard((err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ── AI Mandays Estimator ───────────────────────────────────────────────────────
app.post('/api/ai/estimate-mandays', auth.requireRole('pm','admin','manager'), async (req, res) => {
  const {
    api_key, model, project_type, method, description,
    // Web / Mobile
    num_pages, num_features,
    // API
    num_endpoints, avg_methods,
    // Infra
    infra_subtype, num_items,
    // Phishing
    num_targets
  } = req.body;
  if (!api_key) return res.status(400).json({ error: 'API key is required' });
  if (!project_type) return res.status(400).json({ error: 'Project type is required' });


  const typeLabel = {
    web: 'Web Application', api: 'API / REST', mobile: 'Mobile Application',
    infra: 'Infrastructure / Network', phishing: 'Phishing Simulation'
  }[project_type] || project_type;

  const methodLabel = {
    blackbox: 'Black Box', greybox: 'Grey Box', whitebox: 'White Box',
    external: 'External', internal: 'Internal', combination: 'Combination'
  }[method] || method || 'Grey Box';

  const infraLabel = {
    segmentation: 'Segmentation Pentest',
    external_nonauth: 'Network VAPT (Non-Authenticated)',
    external_auth: 'Network VAPT (Authenticated)',
    firewall: 'Firewall Ruleset Review'
  }[infra_subtype] || infra_subtype || '';

  // Build input-specific section of the prompt
  let inputSection = '';
  if (project_type === 'web' || project_type === 'mobile') {
    inputSection = `
Pages: ${num_pages || 0}
Features/Functions: ${num_features || 0}
Method: ${methodLabel}`;
  } else if (project_type === 'api') {
    inputSection = `
Number of Endpoints: ${num_endpoints || 0}
Average HTTP Methods per Endpoint: ${avg_methods || 2}
Total Pentest Items: ${(num_endpoints || 0) * (avg_methods || 2)}
Method: ${methodLabel}`;
  } else if (project_type === 'infra') {
    inputSection = `
VAPT Sub-type: ${infraLabel}
Number of Items (IP/Subnet/Ruleset): ${num_items || 0}
Method: ${methodLabel}`;
  } else if (project_type === 'phishing') {
    inputSection = `Number of Target Users: ${num_targets || 'Not specified'}`;
  }

  const prompt = `You are a Senior Cyber Security Project Manager following exact internal mandays guidelines.

=== OFFICIAL MANDAYS GUIDELINES ===

WEB APPLICATION (GrayBox baseline):
- Pre & Post: FIXED 5 mandays (do NOT include in assessment_days)
- Testing formula: (features × 4 hours) + (pages / 4 hours) = total hours ÷ 8 = assessment days
- Method multipliers on testing hours: Black Box ×1.25 | Grey Box ×1.0 | White Box ×0.80
- Round UP to nearest integer

MOBILE APPLICATION (GrayBox baseline):
- Pre & Post: FIXED 5 mandays (do NOT include in assessment_days)
- Testing formula: (features × 4 hours) + (pages × 2 hours) = total hours ÷ 8 = assessment days
- Method multipliers: Black Box ×1.25 | Grey Box ×1.0 | White Box ×0.80
- Round UP to nearest integer

API APPLICATION:
- Total pentest items = num_endpoints × avg_http_methods
- Hours per item: Grey Box = 2h | Black Box = 2.5h | White Box = 1.5h
- assessment days = CEIL(total items × hours_per_item / 8)

NETWORK VAPT (Infrastructure):
- Segmentation PT: 4 hours per subnet/segment
- Non-Authenticated VAPT: 2 hours per IP/hostname
- Authenticated VAPT: 3 hours per IP/hostname
- Firewall Ruleset Review: 1 hour per 4 rulesets = CEIL(num_items / 4) hours
- assessment days = CEIL(total hours / 8)

PHISHING SIMULATION:
- Fixed: 3 to 5 days total (use description to determine complexity)

IMPORTANT: assessment_days = testing phase days ONLY. Do NOT add Pre & Post (5 days) or Kickoff (1 day).

=== PM INPUT ===
Scope Type: ${typeLabel}
${inputSection}
Description: ${description || 'None'}

=== TASK ===
Apply the exact formula above. Show the step-by-step calculation in "reasoning" (in Bahasa Indonesia).
Return only valid JSON:
{
  "assessment_days": <integer, ceil result of formula above>,
  "confidence": "high",
  "reasoning": "<show the formula and numbers clearly, e.g.: features(5)×4=20jam + pages(20)/4=5jam = 25jam ÷ 8 = 3.125 → dibulatkan naik = 4 hari>",
  "notes": "<any scope clarifications or assumptions>"
}`;

  try {
    const { text: rawText, model: usedModel } = await callGeminiWithFallback(api_key, {
      generationConfig: {
        temperature: 0.2,
        maxOutputTokens: 1024,
        responseMimeType: "application/json"
      }
    }, [{ text: prompt }]);

    console.log(`[AI Estimator] Used model: ${usedModel}`);

    let text = rawText.trim();
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      text = jsonMatch[0];
    } else {
      text = text.replace(/```json\n?/gi, '').replace(/```\n?/g, '').trim();
    }
    
    let aiResult;
    try {
      aiResult = JSON.parse(text);
    } catch (parseErr) {
      console.error('Failed to parse AI response:', text);
      throw new Error('AI returned an invalid format. Please try again.');
    }

    const assessmentDays = Math.max(1, Math.ceil(Number(aiResult.assessment_days)));
    res.json({
      kickoff_days: 1,
      infogath_days: 5,
      assessment_days: assessmentDays,
      initial_report_days: 1,
      total_days: 1 + 5 + assessmentDays + 1,
      confidence: aiResult.confidence || 'medium',
      reasoning: aiResult.reasoning || '',
      notes: aiResult.notes || null
    });
  } catch (e) {
    console.error('[AI Estimator] Error:', e.message);
    const msg = e?.message || 'AI request failed';
    if (msg.includes('API_KEY_INVALID') || msg.includes('API key not valid')) {
      return res.status(401).json({ error: 'API key tidak valid. Periksa kembali key di Google AI Studio.' });
    }
    res.status(500).json({ error: `AI request failed: ${msg}` });
  }
});


// Add single vulnerability to project
app.post('/api/projects/:projectId/assign/:vulnId', auth.requireProjectAccess('projectId'), (req, res) => {
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
app.delete('/api/projects/:projectId/assign/:vulnId', auth.requireProjectAccess('projectId'), (req, res) => {
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
app.get('/api/projects/:projectId/report', auth.requireProjectAccess('projectId'), (req, res) => {
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
              <div class="screenshots">${screenshots.map(s => `<img src="${escHtml(s)}" alt="POC" />`).join('')}</div>
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

    const { text: rawText, model: usedModel } = await callGeminiWithFallback(apiKey, {
      systemInstruction,
      generationConfig: { temperature: 0.4, maxOutputTokens: 2048 },
    }, parts);

    console.log(`[Ask AI] Used model: ${usedModel}`);
    let text = rawText.trim();

    // Strip markdown code fences
    text = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();

    // Aggressively extract JSON
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
      return res.status(500).json({
        error: `AI returned unparseable response. Raw: ${text.substring(0, 200)}`
      });
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


  // Build client/project context string if provided
  const clientCtx = client_name && project_name
    ? `\n\nCONTEXT: This vulnerability was found during the "${project_name}" penetration test engagement for client "${client_name}". Ensure all descriptions, impacts, and recommendations are relevant and specific to this client and project engagement. Do NOT use generic company names — always reference "${client_name}" when mentioning the affected party.`
    : '';

  const systemInstruction = `You are an expert cybersecurity penetration tester writing professional vulnerability reports.

You MUST output a single JSON object with TWO top-level keys: "en" (English) and "id" (Bahasa Indonesia).
Each key contains the SAME vulnerability report in its respective language.

Your response must be valid JSON with EXACTLY this structure:
{
  "en": {
    "name": "string",
    "description": "string",
    "affected_items": "string",
    "impact": "string",
    "recommendation": "string",
    "poc": "string",
    "references": "string",
    "severity": "Critical|High|Medium|Low|Info"
  },
  "id": {
    "name": "string",
    "description": "string",
    "affected_items": "string",
    "impact": "string",
    "recommendation": "string",
    "poc": "string",
    "references": "string",
    "severity": "Critical|High|Medium|Low|Info"
  }
}

Follow these EXACT format templates for each section (apply to both languages):

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

=== IMPACT (English) ===
Start with: "The impact of this finding may include the following:"
Then write a bullet list using "- " prefix for each impact item. Minimum 3 bullets, maximum 6.

=== IMPACT (Indonesian) ===
Start with: "Dampak dari temuan ini dapat mengakibatkan beberapa hal diantaranya:"
Then write a bullet list using "- " prefix for each impact item. Minimum 3 bullets, maximum 6.

=== RECOMMENDATION (English) ===
Start with a short sentence like "To remediate this vulnerability, we recommend..."
Then provide remediation steps. Be specific and actionable.

=== RECOMMENDATION (Indonesian) ===
Start with a short sentence like "Untuk mengatasi kerentanan ini, kami menyarankan untuk..."
Then provide remediation steps. Be specific and actionable.

=== POC (English) ===
Start with: "To reproduce this vulnerability, perform the following steps:"
Then write numbered steps using "1. ", "2. ", etc. Each step should be clear and reproducible.
If screenshots are provided, reference them in the relevant steps.

=== POC (Indonesian) ===
Start with: "Untuk membuktikan kerentanan ini, kami melakukan langkah-langkah berikut:"
Then write numbered steps using "1. ", "2. ", etc.
If screenshots were attached, reference them in the relevant steps.

=== REFERENCES ===
List relevant references using "- " prefix, one per line. Include OWASP, CWE, CVE, or official documentation URLs where applicable. Minimum 2 references.

=== NAME ===
Polish the user-provided vulnerability name into a professional, standardized pentest finding title.
Keep it concise (max 8 words), use proper capitalization.
Example: "sql injection" → "SQL Injection on Login Form"
In the "id" section, translate the name to Indonesian if appropriate, or keep English technical terms.

=== SEVERITY ===
IMPORTANT: The user has already selected the severity. You MUST use exactly this value in BOTH the "en" and "id" objects. Do NOT change or reassess it.

Be thorough and professional. Output ONLY valid JSON — no markdown fences, no extra text.`;

  const userPrompt = `Generate a complete bilingual (EN + ID) vulnerability report for:

Vulnerability Name (raw input, polish it): ${name}
User-Selected Severity (USE THIS EXACTLY): ${req.body.severity || 'Medium'}
Short Description: ${short_description}
Affected Items: ${affected_items || 'Not specified'}
POC Notes: ${poc_notes || 'Not specified'}
${screenshotPaths.length ? `${screenshotPaths.length} POC screenshot(s) are attached. Use them to enrich the POC section.` : ''}

Return only valid JSON as described.${clientCtx}`;

  try {
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

    const { text: rawText, model: usedModel } = await callGeminiWithFallback(apiKey, {
      systemInstruction,
      generationConfig: {
        responseMimeType: 'application/json',
        temperature: 0.7,
        maxOutputTokens: 8192,
      },
    }, parts);

    console.log(`[AI Generate] Used model: ${usedModel} (${rawText.length} chars)`);

    let parsed;
    try {
      parsed = JSON.parse(rawText);
    } catch (parseErr) {
      // Try to extract JSON from response
      const match = rawText.match(/\{[\s\S]*\}/);
      if (match) {
        try { parsed = JSON.parse(match[0]); } catch {}
      }
      if (!parsed) {
        console.error('[AI Generate] JSON parse failed:', parseErr.message, '| Raw:', rawText.substring(0, 300));
        return res.status(500).json({ error: 'AI response terpotong. Coba lagi (report terlalu panjang).' });
      }
    }

    const screenshotPathValue = screenshotPaths.length
      ? (screenshotPaths.length === 1 ? screenshotPaths[0] : JSON.stringify(screenshotPaths))
      : null;

    const en = parsed.en || parsed;
    const id = parsed.id || parsed;

    res.json({
      name:           en.name || name,
      severity:       req.body.severity || en.severity || 'Medium',
      screenshot_path: screenshotPathValue,
      project_id:     project_id || null,
      en: {
        name:           en.name           || name,
        description:    en.description    || '',
        affected_items: en.affected_items || affected_items || '',
        impact:         en.impact         || '',
        recommendation: en.recommendation || '',
        poc:            en.poc            || poc_notes || '',
        references:     en.references     || '',
        severity:       req.body.severity || en.severity || 'Medium',
      },
      id: {
        name:           id.name           || name,
        description:    id.description    || '',
        affected_items: id.affected_items || affected_items || '',
        impact:         id.impact         || '',
        recommendation: id.recommendation || '',
        poc:            id.poc            || poc_notes || '',
        references:     id.references     || '',
        severity:       req.body.severity || id.severity || 'Medium',
      },
    });

  } catch (error) {
    console.error('Gemini error:', error.message);
    if (error.message?.includes('API_KEY_INVALID') || error.message?.includes('API key not valid')) {
      return res.status(401).json({ error: 'Invalid Google AI Studio API key. Please check your key and try again.' });
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
  console.log(`🤖 AI: Gemini Auto-Fallback (${GEMINI_MODELS.length} models)\n`);
});
