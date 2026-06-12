const test = require('node:test');
const assert = require('node:assert');
const { startServer, stopServer, authenticatedRequest } = require('../helpers/request');
const { login } = require('../helpers/auth');
const { seedDatabase } = require('../helpers/seed');

test.describe('BAST Generation Boundary Tests', () => {
  let port;
  let dbPath;
  let adminCookie;
  let managerCookie;

  test.before(async () => {
    const server = await startServer();
    port = server.port;
    dbPath = server.dbPath;
    await seedDatabase(dbPath);

    const adminAuth = await login(port, 'admin', 'Cisometric123@');
    adminCookie = adminAuth.cookie;

    const managerAuth = await login(port, 'manager', 'Cisometric123@');
    managerCookie = managerAuth.cookie;
  });

  test.after(() => {
    stopServer();
  });

  test('GET /api/projects/:id/bast/preview returns automatic BAST fields for offensive projects', async () => {
    const res = await authenticatedRequest(port, adminCookie, 'GET', '/api/projects/201/bast/preview');
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.placeholders.CLIENT_NAME, 'Client Offensive');
    assert.strictEqual(res.body.placeholders.SERVICE_TYPE, 'VAPT Services');
  });

  test('BAST generation is restricted to admin and PM roles', async () => {
    const res = await authenticatedRequest(port, managerCookie, 'POST', '/api/projects/201/generate-bast-docx', {
      client_pic_name: 'Budi Santoso',
      client_company: 'PT Client Offensive',
      client_company_address: 'Jl. Sudirman No. 1, Jakarta',
      project_phase: 'Final',
      reference_type: 'Final Report',
      report_date: '2026-06-12',
      report_type: 'Final Report',
      billing_percentage: '100%',
      client_pic_position: 'IT Security Manager',
    });
    assert.strictEqual(res.statusCode, 403);
  });

  test('POST /api/projects/:id/generate-bast-docx creates history and downloadable DOCX', async () => {
    const generateRes = await authenticatedRequest(port, adminCookie, 'POST', '/api/projects/201/generate-bast-docx', {
      client_pic_name: 'Budi Santoso',
      client_company: 'PT Client Offensive',
      client_company_address: 'Jl. Sudirman No. 1, Jakarta',
      project_phase: 'Final',
      reference_type: 'Final Report',
      report_date: '2026-06-12',
      report_type: 'Final Report',
      billing_percentage: '100%',
      client_pic_position: 'IT Security Manager',
    });

    assert.strictEqual(generateRes.statusCode, 201, JSON.stringify(generateRes.body));
    assert.ok(generateRes.body.id);
    assert.match(generateRes.body.download_url, /\/api\/bast-documents\/\d+\/download/);

    const historyRes = await authenticatedRequest(port, adminCookie, 'GET', '/api/projects/201/bast-documents');
    assert.strictEqual(historyRes.statusCode, 200);
    assert.ok(historyRes.body.some(item => item.id === generateRes.body.id));

    const downloadRes = await authenticatedRequest(port, adminCookie, 'GET', generateRes.body.download_url);
    assert.strictEqual(downloadRes.statusCode, 200);
    assert.match(downloadRes.headers['content-type'], /wordprocessingml\.document/);
  });

  test('BAST generation rejects IT Audit projects', async () => {
    const res = await authenticatedRequest(port, adminCookie, 'GET', '/api/projects/202/bast/preview');
    assert.strictEqual(res.statusCode, 400);
  });
});
