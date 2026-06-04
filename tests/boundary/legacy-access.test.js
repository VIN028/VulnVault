const test = require('node:test');
const assert = require('node:assert');
const { startServer, stopServer, makeRequest } = require('../helpers/request');
const { login } = require('../helpers/auth');
const { seedDatabase } = require('../helpers/seed');

test.describe('Legacy Portal Access Tests', () => {
  test('GET /portal-legacy.html should redirect to /portal.html if ENABLE_LEGACY_PORTAL is false', async () => {
    // Start server with ENABLE_LEGACY_PORTAL=false
    const server = await startServer({ ENABLE_LEGACY_PORTAL: 'false' });
    const { port, dbPath } = server;
    await seedDatabase(dbPath);

    // Login as admin
    const authRes = await login(port, 'admin', 'Cisometric123@');
    
    const res = await makeRequest(port, {
      path: '/portal-legacy.html',
      method: 'GET'
    }, null, authRes.cookie);

    stopServer();

    assert.strictEqual(res.statusCode, 302);
    assert.ok(res.headers.location.includes('/portal.html'));
  });

  test('GET /portal-legacy.html should redirect to /portal.html if user is not admin', async () => {
    // Start server with ENABLE_LEGACY_PORTAL=true
    const server = await startServer({ ENABLE_LEGACY_PORTAL: 'true' });
    const { port, dbPath } = server;
    await seedDatabase(dbPath);

    // Login as non-admin PM user
    const authRes = await login(port, 'pm', 'Cisometric123@');

    const res = await makeRequest(port, {
      path: '/portal-legacy.html',
      method: 'GET'
    }, null, authRes.cookie);

    stopServer();

    assert.strictEqual(res.statusCode, 302);
    assert.ok(res.headers.location.includes('/portal.html'));
  });
});
