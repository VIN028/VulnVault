const test = require('node:test');
const assert = require('node:assert');
const sqlite3 = require('sqlite3').verbose();
const { startServer, stopServer, makeRequest, authenticatedRequest } = require('../helpers/request');
const { login } = require('../helpers/auth');
const { seedDatabase } = require('../helpers/seed');

test.describe('Observability & Security Audit Boundary Tests', () => {
  let port;
  let dbPath;
  let cookie;

  test.before(async () => {
    // Start server with LEGACY_PORTAL_SUNSET_DATE defined
    const server = await startServer({
      LEGACY_PORTAL_SUNSET_DATE: '2026-07-01',
      ENABLE_LEGACY_PORTAL: 'false'
    });
    port = server.port;
    dbPath = server.dbPath;
    await seedDatabase(dbPath);

    // Login as admin
    const authRes = await login(port, 'admin', 'Cisometric123@');
    cookie = authRes.cookie;
  });

  test.after(() => {
    stopServer();
  });

  test('Database indices must be created correctly', () => {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        const db = new sqlite3.Database(dbPath, (err) => {
          if (err) return reject(err);
          db.all("SELECT name FROM sqlite_master WHERE type = 'index'", [], (queryErr, rows) => {
            if (queryErr) {
              db.close(() => reject(queryErr));
              return;
            }
            const indexNames = rows.map(r => r.name);
            const requiredIndices = [
              'idx_projects_team',
              'idx_projects_client_id',
              'idx_projects_board_status_id',
              'idx_clients_team',
              'idx_users_team',
              'idx_board_statuses_team',
              'idx_project_access_requests_status'
            ];
            for (const required of requiredIndices) {
              assert.ok(indexNames.includes(required), `Missing index: ${required}`);
            }
            db.close((closeErr) => {
              if (closeErr) reject(closeErr);
              else resolve();
            });
          });
        });
      }, 1000);
    });
  });

  test('Capabilities endpoint returns sunset metadata', async () => {
    const res = await authenticatedRequest(port, cookie, 'GET', '/api/portal-capabilities');
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.legacySunsetDate, '2026-07-01');
    assert.strictEqual(res.body.legacyEnabled, false);
  });

  test('CSRF token mismatch should be logged as security event', async () => {
    // Make a state changing request without header token
    const res = await makeRequest(port, {
      path: '/api/clients',
      method: 'POST'
    }, { name: 'Mismatched CSRF Client', team: 'offensive' }, cookie);

    assert.strictEqual(res.statusCode, 403);

    // Verify it is logged in security log
    const logRes = await authenticatedRequest(port, cookie, 'GET', '/api/activity-log?type=security');
    assert.strictEqual(logRes.statusCode, 200);
    const securityLogs = logRes.body;
    const hasCsrfLog = securityLogs.some(log => log.action === 'csrf_validation_failed');
    assert.ok(hasCsrfLog, 'CSRF failure security event not logged.');
  });

  test('Invalid team value should trigger team_validation_failed security log', async () => {
    const res = await authenticatedRequest(port, cookie, 'POST', '/api/clients', {
      name: 'Invalid Team Client',
      team: 'invalid_team_name'
    });
    assert.strictEqual(res.statusCode, 400);

    const logRes = await authenticatedRequest(port, cookie, 'GET', '/api/activity-log?type=security');
    assert.strictEqual(logRes.statusCode, 200);
    const securityLogs = logRes.body;
    const hasTeamLog = securityLogs.some(log => log.action === 'team_validation_failed');
    assert.ok(hasTeamLog, 'Team validation failure event not logged.');
  });

  test('Attempt to modify project team results in project_team_change_rejected security log', async () => {
    // Project ID 201 exists. Attempt to PUT and change team.
    const res = await authenticatedRequest(port, cookie, 'PUT', '/api/projects/201', {
      name: 'Modified Project Name',
      team: 'itaudit',
      project_type: 'web',
      project_method: 'blackbox'
    });
    assert.strictEqual(res.statusCode, 400);

    const logRes = await authenticatedRequest(port, cookie, 'GET', '/api/activity-log?type=security');
    assert.strictEqual(logRes.statusCode, 200);
    const securityLogs = logRes.body;
    const hasChangeLog = securityLogs.some(log => log.action === 'project_team_change_rejected');
    assert.ok(hasChangeLog, 'Project team change rejection security event not logged.');
  });

  test('Invalid legacy portal access is redirected and logged', async () => {
    const res = await makeRequest(port, {
      path: '/portal-legacy.html',
      method: 'GET'
    }, null, cookie);

    // Express auth middleware redirects (302) to /portal.html
    assert.strictEqual(res.statusCode, 302);
    assert.ok(res.headers.location.includes('/portal.html'));

    const logRes = await authenticatedRequest(port, cookie, 'GET', '/api/activity-log?type=security');
    assert.strictEqual(logRes.statusCode, 200);
    const securityLogs = logRes.body;
    const hasLegacyLog = securityLogs.some(log => log.action === 'invalid_legacy_access_attempt');
    assert.ok(hasLegacyLog, 'Invalid legacy access attempt not logged.');
  });
});
