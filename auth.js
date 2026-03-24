const crypto = require('crypto');

const COOKIE_NAME = 'vv_session';
const MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

function getSecret() {
  const s = process.env.SESSION_SECRET;
  if (!s || String(s).length < 16) {
    console.warn('[auth] Set SESSION_SECRET in .env (at least 16 random characters) for production.');
  }
  return s || 'dev-only-change-me-please-16chars';
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i === -1) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    try {
      out[k] = decodeURIComponent(v);
    } catch {
      out[k] = v;
    }
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
  const sig = raw.slice(dot + 1);
  const expected = crypto.createHmac('sha256', getSecret()).update(data).digest('base64url');
  if (sig.length !== expected.length) return null;
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'utf8'), Buffer.from(expected, 'utf8'))) return null;
  } catch {
    return null;
  }
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (payload.exp && payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function getSessionFromReq(req) {
  const cookies = parseCookies(req.headers.cookie);
  return verifyToken(cookies[COOKIE_NAME]);
}

function getCredentials() {
  return {
    user: (process.env.APP_LOGIN_USER || '').trim(),
    pass: (process.env.APP_LOGIN_PASSWORD || '').trim(),
  };
}

function requireApiAuth(req, res, next) {
  if (!req.path.startsWith('/api')) return next();
  if (req.path === '/api/login' && req.method === 'POST') return next();
  if (req.path === '/api/session' && req.method === 'GET') return next();
  if (req.path === '/api/logout' && req.method === 'POST') return next();
  // Uptime / load balancer (Render, etc.) — no secrets exposed
  if (req.path === '/api/health' && req.method === 'GET') return next();
  if (!getSessionFromReq(req)) {
    return res.status(401).json({ error: 'Unauthorized', authenticated: false });
  }
  next();
}

/** Block app shell and uploads for guests (GET only). Public: login page + static assets. */
function requirePageAuth(req, res, next) {
  if (req.method !== 'GET') return next();
  const p = req.path.split('?')[0];
  if (p === '/login.html') return next();
  if (p.startsWith('/css/') || p.startsWith('/js/')) return next();
  if (getSessionFromReq(req)) return next();
  if (p.startsWith('/uploads/')) {
    return res.status(401).send('Unauthorized');
  }
  return res.redirect(302, '/login.html');
}

function login(req, res) {
  const username = (req.body?.username || req.body?.user || '').trim();
  const password = (req.body?.password || '').trim();
  const { user, pass } = getCredentials();
  if (!user || !pass) {
    return res.status(503).json({
      error: 'Login is not configured. Set APP_LOGIN_USER and APP_LOGIN_PASSWORD in .env.',
    });
  }
  const okUser = username === user;
  const okPass = password === pass && pass.length > 0;
  if (!okUser || !okPass) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  const token = signPayload({ u: username, exp: Date.now() + MAX_AGE_MS });
  const secure = process.env.NODE_ENV === 'production' || process.env.FORCE_SECURE_COOKIE === '1';
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: secure,
    maxAge: MAX_AGE_MS,
    path: '/',
  });
  res.json({ ok: true });
}

function logout(req, res) {
  res.clearCookie(COOKIE_NAME, { path: '/' });
  res.json({ ok: true });
}

function sessionStatus(req, res) {
  res.json({ authenticated: !!getSessionFromReq(req) });
}

module.exports = {
  requireApiAuth,
  requirePageAuth,
  login,
  logout,
  sessionStatus,
  getSessionFromReq,
};
