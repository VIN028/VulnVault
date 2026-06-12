const test = require('node:test');
const assert = require('node:assert');
const { startServer, stopServer, authenticatedRequest } = require('../helpers/request');
const { login } = require('../helpers/auth');
const { seedDatabase } = require('../helpers/seed');
const sqlite3 = require('sqlite3').verbose();

function getDbConnection(dbPath) {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath, (err) => {
      if (err) reject(err);
      else resolve(db);
    });
  });
}

function runQuery(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

test.describe('Regression Tests for VulnVault', () => {
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

    // Seed additional regression projects
    const db = await getDbConnection(dbPath);
    try {
      await runQuery(db, 'PRAGMA foreign_keys = OFF');
      
      // 1. Insert a completed project under Client Offensive (id 101)
      await runQuery(db, `
        INSERT INTO projects (id, client_id, name, team, board_status_id, project_type, project_method, is_archived, final_report_status, mandays_initial_report, mandays_assessment)
        VALUES (203, 101, 'Completed Project', 'offensive', 301, 'web', 'blackbox', 0, 'completed', 1, 0)
      `);

      // 2. Insert an archived project under Client Offensive (id 101)
      await runQuery(db, `
        INSERT INTO projects (id, client_id, name, team, board_status_id, project_type, project_method, is_archived, final_report_status, mandays_initial_report, mandays_assessment)
        VALUES (204, 101, 'Archived Project', 'offensive', 301, 'web', 'blackbox', 1, 'pending', 1, 0)
      `);

      // 3. Insert an overdue project (target dates in the past, but not completed) under Client Offensive (id 101)
      await runQuery(db, `
        INSERT INTO projects (id, client_id, name, team, board_status_id, project_type, project_method, is_archived, final_report_status, initial_report_date, final_report_date, mandays_initial_report, mandays_assessment)
        VALUES (205, 101, 'Overdue Project', 'offensive', 301, 'web', 'blackbox', 0, 'pending', '2020-01-01', '2020-01-02', 1, 0)
      `);

      await runQuery(db, 'PRAGMA foreign_keys = ON');
    } finally {
      await new Promise((resolve) => db.close(resolve));
    }
  });

  test.after(() => {
    stopServer();
  });

  test('GET /api/clients/full?team=offensive should return client with projects.length === 2 (only active ones: Project Offensive and Overdue Project)', async () => {
    // There are 4 projects under client 101:
    // - id 201 (active, pending)
    // - id 203 (inactive, completed)
    // - id 204 (inactive, archived)
    // - id 205 (active, pending, overdue)
    // Thus, only 2 active projects should be returned for Client Offensive.
    const res = await authenticatedRequest(port, cookie, 'GET', '/api/clients/full?team=offensive');
    assert.strictEqual(res.statusCode, 200);

    const clients = res.body;
    const clientOffensive = clients.find(c => c.client_id === 101);
    assert.ok(clientOffensive);
    assert.ok(Array.isArray(clientOffensive.projects));
    
    // projects.length should be exactly 2 (id 201 and id 205) because id 203 (completed) and id 204 (archived) are filtered out.
    assert.strictEqual(clientOffensive.projects.length, 2);

    const projectIds = clientOffensive.projects.map(p => p.project_id);
    assert.ok(projectIds.includes(201));
    assert.ok(projectIds.includes(205));
    assert.ok(!projectIds.includes(203));
    assert.ok(!projectIds.includes(204));
  });

  test('GET /api/board/projects?team=offensive contains project_id and project_name', async () => {
    const res = await authenticatedRequest(port, cookie, 'GET', '/api/board/projects?team=offensive');
    assert.strictEqual(res.statusCode, 200);

    const projects = res.body;
    assert.ok(Array.isArray(projects));
    assert.ok(projects.length >= 1);

    for (const p of projects) {
      assert.ok('project_id' in p, 'Should contain project_id field');
      assert.ok('project_name' in p, 'Should contain project_name field');
      // Backward compatibility checks
      assert.ok('id' in p, 'Should contain id field');
      assert.ok('name' in p, 'Should contain name field');
    }
  });

  test('PATCH /api/projects/:id/board-status returns 200 for a valid project ID and valid status', async () => {
    // Move project 201 to board status 303 (valid offensive status)
    const res = await authenticatedRequest(port, cookie, 'PATCH', '/api/projects/201/board-status', {
      board_status_id: 303
    });
    assert.strictEqual(res.statusCode, 200);
  });

  test('PATCH /api/projects/:id/board-status returns 400 Invalid project ID for invalid ID formats', async () => {
    // Invalid ID: non-integer string
    const res1 = await authenticatedRequest(port, cookie, 'PATCH', '/api/projects/abc/board-status', {
      board_status_id: 303
    });
    assert.strictEqual(res1.statusCode, 400);
    assert.strictEqual(res1.body.error, 'Invalid project ID');

    // Invalid ID: less than 1 (0)
    const res2 = await authenticatedRequest(port, cookie, 'PATCH', '/api/projects/0/board-status', {
      board_status_id: 303
    });
    assert.strictEqual(res2.statusCode, 400);
    assert.strictEqual(res2.body.error, 'Invalid project ID');

    // Invalid ID: negative integer
    const res3 = await authenticatedRequest(port, cookie, 'PATCH', '/api/projects/-5/board-status', {
      board_status_id: 303
    });
    assert.strictEqual(res3.statusCode, 400);
    assert.strictEqual(res3.body.error, 'Invalid project ID');
  });

  test('Project overdue initial/final target dates remains visible as long as final_report_status !== completed', async () => {
    // Project 205 is overdue (initial_report_date and final_report_date are in 2020)
    // But it is not completed (final_report_status is 'pending')
    // It should appear in both clients full and board projects
    
    // Check in GET /api/clients/full?team=offensive
    const clientsRes = await authenticatedRequest(port, cookie, 'GET', '/api/clients/full?team=offensive');
    const clients = clientsRes.body;
    const clientOff = clients.find(c => c.client_id === 101);
    const hasOverdueInClients = clientOff.projects.some(p => p.project_id === 205);
    assert.ok(hasOverdueInClients, 'Overdue project 205 should be visible in clients full list');

    // Check in GET /api/board/projects?team=offensive
    const boardRes = await authenticatedRequest(port, cookie, 'GET', '/api/board/projects?team=offensive');
    const boardProjects = boardRes.body;
    const hasOverdueInBoard = boardProjects.some(p => p.project_id === 205);
    assert.ok(hasOverdueInBoard, 'Overdue project 205 should be visible on the board');
  });

  test('PATCH /api/projects/:id/highlight successfully saves highlight', async () => {
    const res = await authenticatedRequest(port, cookie, 'PATCH', '/api/projects/201/highlight', {
      highlight_text: 'Patched Highlight Content',
      highlight_notes: ['note 1', 'note 2']
    });
    assert.strictEqual(res.statusCode, 200);

    const getRes = await authenticatedRequest(port, cookie, 'GET', '/api/projects/201/highlight');
    assert.strictEqual(getRes.statusCode, 200);
    assert.strictEqual(getRes.body.highlight_text, 'Patched Highlight Content');
    assert.deepStrictEqual(getRes.body.highlight_notes, ['note 1', 'note 2']);
  });

  test('PUT /api/projects/:id/highlight still successfully saves highlight', async () => {
    const res = await authenticatedRequest(port, cookie, 'PUT', '/api/projects/201/highlight', {
      highlight_text: 'Put Highlight Content',
      highlight_notes: ['note 3']
    });
    assert.strictEqual(res.statusCode, 200);

    const getRes = await authenticatedRequest(port, cookie, 'GET', '/api/projects/201/highlight');
    assert.strictEqual(getRes.statusCode, 200);
    assert.strictEqual(getRes.body.highlight_text, 'Put Highlight Content');
    assert.deepStrictEqual(getRes.body.highlight_notes, ['note 3']);
  });

  test('Invalid project ID on highlight endpoints replies with 400 Invalid project ID', async () => {
    const resGet = await authenticatedRequest(port, cookie, 'GET', '/api/projects/abc/highlight');
    assert.strictEqual(resGet.statusCode, 400);
    assert.strictEqual(resGet.body.error, 'Invalid project ID');

    const resPut = await authenticatedRequest(port, cookie, 'PUT', '/api/projects/0/highlight', {
      highlight_text: 'test'
    });
    assert.strictEqual(resPut.statusCode, 400);
    assert.strictEqual(resPut.body.error, 'Invalid project ID');

    const resPatch = await authenticatedRequest(port, cookie, 'PATCH', '/api/projects/-1/highlight', {
      highlight_text: 'test'
    });
    assert.strictEqual(resPatch.statusCode, 400);
    assert.strictEqual(resPatch.body.error, 'Invalid project ID');

    const resGen = await authenticatedRequest(port, cookie, 'POST', '/api/projects/abc/highlight/generate', {
      api_key: 'test',
      notes: ['test']
    });
    assert.strictEqual(resGen.statusCode, 400);
    assert.strictEqual(resGen.body.error, 'Invalid project ID');
  });

  test('Frontend Offensive and IT Audit do not use /highlight-ai', () => {
    const fs = require('fs');
    const path = require('path');
    const offContent = fs.readFileSync(path.join(__dirname, '../../public/js/portal/offensive.js'), 'utf8');
    const auditContent = fs.readFileSync(path.join(__dirname, '../../public/js/portal/itaudit.js'), 'utf8');
    
    assert.ok(!offContent.includes('/highlight-ai'), 'Offensive frontend should not call /highlight-ai');
    assert.ok(!auditContent.includes('/highlight-ai'), 'IT Audit frontend should not call /highlight-ai');
  });
});
