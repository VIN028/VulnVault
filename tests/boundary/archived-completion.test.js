const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const { startServer, stopServer, authenticatedRequest } = require('../helpers/request');
const { login } = require('../helpers/auth');
const { seedDatabase } = require('../helpers/seed');

test.describe('Archived Projects Completion Date and Sorting Tests', () => {
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

  test('create past project and assert completion date is correctly saved and displayed in archived list', async () => {
    // 1. Create a project with is_past_project = 1 and actual_end_date = '2026-05-20'
    const newProjectRes = await authenticatedRequest(port, cookie, 'POST', '/api/clients/101/projects', {
      name: 'Simulated Past Project',
      scope_target: 'past test targets',
      project_type: 'web',
      project_method: 'blackbox',
      team: 'offensive',
      is_past_project: 1,
      actual_end_date: '2026-05-20'
    });
    assert.strictEqual(newProjectRes.statusCode, 201);
    
    // 2. Fetch the archived projects list
    const archivedRes = await authenticatedRequest(port, cookie, 'GET', '/api/projects/archived?team=offensive');
    assert.strictEqual(archivedRes.statusCode, 200);
    
    const archivedList = archivedRes.body;
    
    // 3. Find our past project and assert it has final_completed_at = '2026-05-20'
    const foundProject = archivedList.find(p => p.project_name === 'Simulated Past Project');
    assert.ok(foundProject, 'Simulated past project should be found in archived list');
    assert.strictEqual(foundProject.final_completed_at, '2026-05-20');
    assert.ok(foundProject.archived_at, 'archived_at should be populated');
    
    // 4. Assert sorting of the archived projects
    // To thoroughly test the COALESCE sorting, let's create a second past project completed on a later date.
    const secondProjectRes = await authenticatedRequest(port, cookie, 'POST', '/api/clients/101/projects', {
      name: 'Later Past Project',
      scope_target: 'later past targets',
      project_type: 'web',
      project_method: 'blackbox',
      team: 'offensive',
      is_past_project: 1,
      actual_end_date: '2026-06-10'
    });
    assert.strictEqual(secondProjectRes.statusCode, 201);

    const reArchivedRes = await authenticatedRequest(port, cookie, 'GET', '/api/projects/archived?team=offensive');
    const reArchivedList = reArchivedRes.body;

    const firstIdx = reArchivedList.findIndex(p => p.project_name === 'Later Past Project');
    const secondIdx = reArchivedList.findIndex(p => p.project_name === 'Simulated Past Project');
    
    assert.ok(firstIdx < secondIdx, 'Archived projects should be sorted by final_completed_at DESC (Later Past Project before Simulated Past Project)');
  });

  test('frontend scripts fallback check to ensure backward compatibility', () => {
    // Verify that the fallback is still present in offensive.js and itaudit.js
    const offJs = fs.readFileSync('public/js/portal/offensive.js', 'utf8');
    const itJs = fs.readFileSync('public/js/portal/itaudit.js', 'utf8');

    assert.ok(offJs.includes('p.final_completed_at || p.archived_at'), 'offensive.js should have fallback to p.archived_at');
    assert.ok(itJs.includes('p.final_completed_at || p.archived_at'), 'itaudit.js should have fallback to p.archived_at');
  });
});
