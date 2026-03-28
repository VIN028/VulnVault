const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('./database');

const COOKIE_NAME = 'vv_session';
const MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const MANAGEMENT_ROLES = ['admin', 'manager', 'pm'];
const ENGINEER_ROLES   = ['engineer'];

function getSecret() {
  const s = process.env.SESSION_SECRET;
  if (!s || String(s).length < 16) {
    console.warn('[auth] Set SESSION_SECRET in .env (at least 16 random characters) for production.');
  }
  return s || 'dev-only-change-me-please-16chars';
}

// ─── Cookie / Token ──────────────────────────────────────────────────────────
function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i === -1) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    try { out[k] = decodeURIComponent(v); } catch { out[k] = v; }
  });
  return out;
}

function signPayload(payload) {
  const data = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', getSecret()).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const dot = raw.lastIndexOf('.');
  if (dot === -1) return null;
  const data = raw.slice(0, dot);
  const sig  = raw.slice(dot + 1);
  const expected = crypto.createHmac('sha256', getSecret()).update(data).digest('base64url');
  if (sig.length !== expected.length) return null;
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'utf8'), Buffer.from(expected, 'utf8'))) return null;
  } catch { return null; }
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (payload.exp && payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

function getSessionFromReq(req) {
  const cookies = parseCookies(req.headers.cookie);
  return verifyToken(cookies[COOKIE_NAME]);
}

function setSessionCookie(res, req, payload) {
  const token  = signPayload({ ...payload, exp: Date.now() + MAX_AGE_MS });
  const xfProto = (req.headers['x-forwarded-proto'] || '').toLowerCase();
  const secure = process.env.FORCE_SECURE_COOKIE === '1' || req.secure || xfProto === 'https';
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true, sameSite: 'lax', secure, maxAge: MAX_AGE_MS, path: '/',
  });
}

// ─── Middleware ──────────────────────────────────────────────────────────────
const PUBLIC_API_ROUTES = new Set(['/api/login', '/api/logout', '/api/session', '/api/health']);

function requireApiAuth(req, res, next) {
  if (!req.path.startsWith('/api')) return next();
  if (PUBLIC_API_ROUTES.has(req.path)) return next();
  const session = getSessionFromReq(req);
  if (!session) return res.status(401).json({ error: 'Unauthorized', authenticated: false });
  req.session = session; // attach session to request
  next();
}

/** Role-based middleware factory. requireRole('admin') or requireRole('pm','manager') */
function requireRole(...roles) {
  return (req, res, next) => {
    const session = req.session || getSessionFromReq(req);
    if (!session) return res.status(401).json({ error: 'Unauthorized' });
    if (!roles.includes(session.role)) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}

/** Redirect unauthenticated page requests; also redirect engineers ↔ portal */
function requirePageAuth(req, res, next) {
  if (req.method !== 'GET') return next();
  const p = req.path.split('?')[0];

  // Always allow public static assets and the login page itself
  if (p === '/login.html') return next();
  if (p.startsWith('/css/') || p.startsWith('/js/')) return next();

  const session = getSessionFromReq(req);

  // No session → go to login
  if (!session) {
    if (p.startsWith('/uploads/')) return res.status(401).send('Unauthorized');
    return res.redirect(302, '/login.html');
  }

  const isEngineer = session.role === 'engineer';

  // Engineers landing on portal → main app
  if (!isEngineer && p === '/') return res.redirect(302, '/portal.html');
  // Management roles landing on main app → portal
  if (isEngineer && p === '/portal.html') return res.redirect(302, '/');

  // Always allow portal itself once logged in as management
  return next();
}

// ─── Login / Logout / Session ─────────────────────────────────────────────────
function login(req, res) {
  const username = (req.body?.username || '').trim();
  const password = (req.body?.password || '');

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  db.getUserByUsername(username, async (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }
    setSessionCookie(res, req, {
      userId:      user.id,
      username:    user.username,
      displayName: user.display_name,
      role:        user.role,
    });
    res.json({ ok: true, role: user.role, displayName: user.display_name });
  });
}

function logout(req, res) {
  res.clearCookie(COOKIE_NAME, { path: '/' });
  res.json({ ok: true });
}

function sessionStatus(req, res) {
  const session = getSessionFromReq(req);
  if (!session) return res.json({ authenticated: false });
  res.json({
    authenticated: true,
    userId:      session.userId,
    username:    session.username,
    displayName: session.displayName,
    role:        session.role,
  });
}

module.exports = {
  requireApiAuth,
  requirePageAuth,
  requireRole,
  login,
  logout,
  sessionStatus,
  getSessionFromReq,
  MANAGEMENT_ROLES,
  ENGINEER_ROLES,
};
