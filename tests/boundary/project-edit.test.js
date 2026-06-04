const test = require('node:test');
const assert = require('node:assert');
const { startServer, stopServer, authenticatedRequest } = require('../helpers/request');
const { login } = require('../helpers/auth');
const { seedDatabase } = require('../helpers/seed');

test.describe('Project Edit Boundary Tests', () => {
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

  test('PUT /api/projects/:id should reject attempts to change the project team', async () => {
    // Project 201 is offensive. Try to change to itaudit
    const res = await authenticatedRequest(port, cookie, 'PUT', '/api/projects/201', {
      name: 'Project Offensive Edited',
      team: 'itaudit',
      project_type: 'web',
      project_method: 'blackbox'
    });
    assert.strictEqual(res.statusCode, 400);
  });

  test('PATCH /api/projects/:id/board-status should reject mismatched team board status', async () => {
    // Project 201 is offensive. Status 302 is itaudit.
    const res = await authenticatedRequest(port, cookie, 'PATCH', '/api/projects/201/board-status', {
      board_status_id: 302
    });
    assert.strictEqual(res.statusCode, 400);
  });
});
