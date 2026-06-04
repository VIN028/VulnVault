const test = require('node:test');
const assert = require('node:assert');
const { startServer, stopServer, authenticatedRequest } = require('../helpers/request');
const { login } = require('../helpers/auth');
const { seedDatabase } = require('../helpers/seed');

test.describe('Board Status Boundary Tests', () => {
  let port;
  let dbPath;
  let cookie;

  test.before(async () => {
    const server = await startServer();
    port = server.port;
    dbPath = server.dbPath;
    await seedDatabase(dbPath);
    const authRes = await login(port, 'admin', 'Cisometric123@');
    cookie = authRes.cookie;
  });

  test.after(() => {
    stopServer();
  });

  test('PUT /api/board-statuses/reorder should reject if ordered_ids contain statuses from other teams', async () => {
    // Status 302 belongs to itaudit. Trying to reorder it as 'offensive'
    const res = await authenticatedRequest(port, cookie, 'PUT', '/api/board-statuses/reorder', {
      ordered_ids: [301, 302],
      team: 'offensive'
    });
    assert.strictEqual(res.statusCode, 400);
  });

  test('DELETE /api/board-statuses/:id?team=offensive should reject if status is IT Audit', async () => {
    // Status 302 belongs to itaudit. Trying to delete as 'offensive'
    const res = await authenticatedRequest(port, cookie, 'DELETE', '/api/board-statuses/302?team=offensive');
    assert.strictEqual(res.statusCode, 400);
  });
});
