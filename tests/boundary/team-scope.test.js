const test = require('node:test');
const assert = require('node:assert');
const { startServer, stopServer, authenticatedRequest } = require('../helpers/request');
const { login } = require('../helpers/auth');
const { seedDatabase } = require('../helpers/seed');

test.describe('Team Scoping Boundary Tests', () => {
  let port;
  let dbPath;
  let cookie;

  test.before(async () => {
    const server = await startServer();
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

  test('GET /api/clients/full?team=offensive should not contain any itaudit projects', async () => {
    const res = await authenticatedRequest(port, cookie, 'GET', '/api/clients/full?team=offensive');
    assert.strictEqual(res.statusCode, 200);
    const clients = res.body;
    for (const c of clients) {
      if (c.project_id && c.team !== 'offensive' && c.team !== null) {
        assert.fail(`Found itaudit project in offensive list: ${JSON.stringify(c)}`);
      }
    }
  });

  test('GET /api/clients/full?team=itaudit should not contain any offensive projects', async () => {
    const res = await authenticatedRequest(port, cookie, 'GET', '/api/clients/full?team=itaudit');
    assert.strictEqual(res.statusCode, 200);
    const clients = res.body;
    for (const c of clients) {
      if (c.project_id && c.team !== 'itaudit') {
        assert.fail(`Found non-itaudit project in itaudit list: ${JSON.stringify(c)}`);
      }
    }
  });

  test('POST /api/clients/:id/projects should reject when client and project teams mismatch', async () => {
    // client 102 is 'itaudit'. Try to create 'offensive' project under it
    const res = await authenticatedRequest(port, cookie, 'POST', '/api/clients/102/projects', {
      name: 'Mismatched Project',
      team: 'offensive',
      project_type: 'web',
      project_method: 'blackbox'
    });
    assert.strictEqual(res.statusCode, 400);
  });
});
