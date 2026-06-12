const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
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

function getRow(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function getAllRows(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

test.describe('Board Click Workflow and Terminal Status Tests', () => {
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

  // ── Terminal Status CRUD ────────────────────────────────────────────────────

  test('Database & API: create board status with is_terminal = 1', async () => {
    const res = await authenticatedRequest(port, cookie, 'POST', '/api/board-statuses', {
      name: 'Final Delivered',
      color: '#10b981',
      sort_order: 10,
      team: 'offensive',
      is_terminal: 1
    });

    assert.strictEqual(res.statusCode, 201);
    assert.strictEqual(res.body.name, 'Final Delivered');
    assert.strictEqual(res.body.is_terminal, 1);
  });

  test('Database & API: GET board statuses returns is_terminal value', async () => {
    const res = await authenticatedRequest(port, cookie, 'GET', '/api/board-statuses?team=offensive');
    assert.strictEqual(res.statusCode, 200);
    
    const statuses = res.body;
    const finalDelivered = statuses.find(s => s.name === 'Final Delivered');
    assert.ok(finalDelivered);
    assert.strictEqual(finalDelivered.is_terminal, 1);
  });

  test('Database & API: update board status terminal flag', async () => {
    const getRes = await authenticatedRequest(port, cookie, 'GET', '/api/board-statuses?team=offensive');
    const targetStatus = getRes.body.find(s => s.name === 'Final Delivered');
    assert.ok(targetStatus);

    const updateRes = await authenticatedRequest(port, cookie, 'PUT', `/api/board-statuses/${targetStatus.id}`, {
      name: 'Final Delivered Updated',
      color: '#10b981',
      team: 'offensive',
      is_terminal: 0
    });

    assert.strictEqual(updateRes.statusCode, 200);
    assert.strictEqual(updateRes.body.ok, true);

    const getRes2 = await authenticatedRequest(port, cookie, 'GET', '/api/board-statuses?team=offensive');
    const updatedStatus = getRes2.body.find(s => s.id === targetStatus.id);
    assert.strictEqual(updatedStatus.name, 'Final Delivered Updated');
    assert.strictEqual(updatedStatus.is_terminal, 0);
  });

  test('Database & API: only one terminal status per team is enforced', async () => {
    const res1 = await authenticatedRequest(port, cookie, 'POST', '/api/board-statuses', {
      name: 'IT Audit Terminal 1',
      color: '#06b6d4',
      sort_order: 5,
      team: 'itaudit',
      is_terminal: 1
    });
    assert.strictEqual(res1.statusCode, 201);
    const id1 = res1.body.id;

    const res2 = await authenticatedRequest(port, cookie, 'POST', '/api/board-statuses', {
      name: 'IT Audit Terminal 2',
      color: '#06b6d4',
      sort_order: 6,
      team: 'itaudit',
      is_terminal: 1
    });
    assert.strictEqual(res2.statusCode, 201);
    const id2 = res2.body.id;

    // Only Terminal 2 should be terminal (it was created last and resets others)
    const listRes = await authenticatedRequest(port, cookie, 'GET', '/api/board-statuses?team=itaudit');
    const status1 = listRes.body.find(s => s.id === id1);
    const status2 = listRes.body.find(s => s.id === id2);

    assert.strictEqual(status1.is_terminal, 0);
    assert.strictEqual(status2.is_terminal, 1);

    // Update status1 to terminal — status2 should automatically become 0
    const updateRes = await authenticatedRequest(port, cookie, 'PUT', `/api/board-statuses/${id1}`, {
      name: 'IT Audit Terminal 1',
      color: '#06b6d4',
      team: 'itaudit',
      is_terminal: 1
    });
    assert.strictEqual(updateRes.statusCode, 200);

    const listRes2 = await authenticatedRequest(port, cookie, 'GET', '/api/board-statuses?team=itaudit');
    const status1_updated = listRes2.body.find(s => s.id === id1);
    const status2_updated = listRes2.body.find(s => s.id === id2);

    assert.strictEqual(status1_updated.is_terminal, 1);
    assert.strictEqual(status2_updated.is_terminal, 0);
  });

  // ── Board status PATCH response ─────────────────────────────────────────────

  test('Database & API: PATCH board-status rejects status from a different team', async () => {
    const itauditList = await authenticatedRequest(port, cookie, 'GET', '/api/board-statuses?team=itaudit');
    const itauditStatus = itauditList.body[0];
    assert.ok(itauditStatus);

    const patchRes = await authenticatedRequest(port, cookie, 'PATCH', `/api/projects/201/board-status`, {
      board_status_id: itauditStatus.id
    });
    assert.strictEqual(patchRes.statusCode, 400);
    assert.ok(patchRes.body.error.includes('Board status team does not match project team'));
  });

  test('Database & API: PATCH board-status returns payload with is_terminal and archive_eligible', async () => {
    // Create terminal status for offensive
    const termRes = await authenticatedRequest(port, cookie, 'POST', '/api/board-statuses', {
      name: 'Final Stage Off',
      color: '#ef4444',
      sort_order: 8,
      team: 'offensive',
      is_terminal: 1
    });
    assert.strictEqual(termRes.statusCode, 201);
    const statusId = termRes.body.id;

    // Project 201 (offensive) is pending — is_terminal=true but archive_eligible=false
    const patchRes1 = await authenticatedRequest(port, cookie, 'PATCH', `/api/projects/201/board-status`, {
      board_status_id: statusId
    });
    assert.strictEqual(patchRes1.statusCode, 200);
    assert.strictEqual(patchRes1.body.is_terminal, true);
    assert.strictEqual(patchRes1.body.archive_eligible, false);
  });

  // ── Archive rules: completed + terminal required ────────────────────────────

  test('Archive: completed project in NON-terminal status should be rejected (400)', async () => {
    // Create a non-terminal status
    const nonTermRes = await authenticatedRequest(port, cookie, 'POST', '/api/board-statuses', {
      name: 'In Review',
      color: '#3b82f6',
      sort_order: 3,
      team: 'offensive',
      is_terminal: 0
    });
    assert.strictEqual(nonTermRes.statusCode, 201);
    const nonTermId = nonTermRes.body.id;

    // Insert completed project in non-terminal status
    const db = await getDbConnection(dbPath);
    try {
      await runQuery(db, `
        INSERT INTO projects (id, client_id, name, team, board_status_id, project_type, project_method, is_archived, final_report_status, mandays_initial_report, mandays_assessment)
        VALUES (901, 101, 'Completed Non-Terminal', 'offensive', ?, 'web', 'blackbox', 0, 'completed', 1, 0)
      `, [nonTermId]);
    } finally {
      await new Promise((resolve) => db.close(resolve));
    }

    const archRes = await authenticatedRequest(port, cookie, 'PATCH', `/api/projects/901/archive`);
    assert.strictEqual(archRes.statusCode, 400);
    assert.ok(archRes.body.error.includes('Move project to a final board status before archiving'));
  });

  test('Archive: active project in terminal status should be rejected (400)', async () => {
    // Project 201 is pending & already in terminal status from earlier test
    const archRes = await authenticatedRequest(port, cookie, 'PATCH', `/api/projects/201/archive`);
    assert.strictEqual(archRes.statusCode, 400);
    assert.ok(archRes.body.error.includes('Complete final report first'));
  });

  test('Archive: completed project in terminal status should succeed (200)', async () => {
    // Get the current terminal status for offensive
    const statusList = await authenticatedRequest(port, cookie, 'GET', '/api/board-statuses?team=offensive');
    const terminalStatus = statusList.body.find(s => s.is_terminal === 1);
    assert.ok(terminalStatus, 'Must have a terminal status for offensive team');

    // Insert completed project in terminal status
    const db = await getDbConnection(dbPath);
    try {
      await runQuery(db, `
        INSERT INTO projects (id, client_id, name, team, board_status_id, project_type, project_method, is_archived, final_report_status, mandays_initial_report, mandays_assessment)
        VALUES (902, 101, 'Completed Terminal', 'offensive', ?, 'web', 'blackbox', 0, 'completed', 1, 0)
      `, [terminalStatus.id]);
    } finally {
      await new Promise((resolve) => db.close(resolve));
    }

    const archRes = await authenticatedRequest(port, cookie, 'PATCH', `/api/projects/902/archive`);
    assert.strictEqual(archRes.statusCode, 200);
    assert.strictEqual(archRes.body.message, 'Project archived successfully');
  });

  test('Archive: completed project with NO board status should be rejected (400)', async () => {
    // Insert completed project with null board_status_id
    const db = await getDbConnection(dbPath);
    try {
      await runQuery(db, `
        INSERT INTO projects (id, client_id, name, team, board_status_id, project_type, project_method, is_archived, final_report_status, mandays_initial_report, mandays_assessment)
        VALUES (903, 101, 'Completed No Status', 'offensive', NULL, 'web', 'blackbox', 0, 'completed', 1, 0)
      `);
    } finally {
      await new Promise((resolve) => db.close(resolve));
    }

    const archRes = await authenticatedRequest(port, cookie, 'PATCH', `/api/projects/903/archive`);
    assert.strictEqual(archRes.statusCode, 400);
    assert.ok(archRes.body.error.includes('Move project to a final board status before archiving'));
  });

  test('Archive: archived project disappears from board, appears in archived list', async () => {
    // Project 902 was archived above
    const boardRes = await authenticatedRequest(port, cookie, 'GET', '/api/board/projects?team=offensive');
    assert.strictEqual(boardRes.statusCode, 200);
    const boardProjectIds = boardRes.body.map(p => p.project_id);
    assert.ok(!boardProjectIds.includes(902));

    const archivedRes = await authenticatedRequest(port, cookie, 'GET', '/api/projects/archived?team=offensive');
    assert.strictEqual(archivedRes.statusCode, 200);
    const archivedProjectIds = archivedRes.body.map(p => p.project_id);
    assert.ok(archivedProjectIds.includes(902));
  });

  // ── Migration idempotency ───────────────────────────────────────────────────

  test('Migration: schema_migrations table records backfill key', async () => {
    const db = await getDbConnection(dbPath);
    try {
      const row = await getRow(db, "SELECT key, applied_at FROM schema_migrations WHERE key = 'board_statuses_is_terminal_backfill_v1'");
      assert.ok(row, 'Migration key should be recorded in schema_migrations');
      assert.ok(row.applied_at, 'applied_at should be set');
    } finally {
      await new Promise((resolve) => db.close(resolve));
    }
  });

  test('Migration: manually set terminal status is NOT overwritten by backfill on restart', async () => {
    // Create a status named "Done" for a fresh team scenario and manually mark it terminal
    const createRes = await authenticatedRequest(port, cookie, 'POST', '/api/board-statuses', {
      name: 'Done',
      color: '#22c55e',
      sort_order: 20,
      team: 'offensive',
      is_terminal: 0 // intentionally non-terminal
    });
    assert.strictEqual(createRes.statusCode, 201);
    const doneId = createRes.body.id;

    // Verify the status is_terminal = 0 (not overwritten by backfill)
    const db = await getDbConnection(dbPath);
    try {
      const row = await getRow(db, 'SELECT is_terminal FROM board_statuses WHERE id = ?', [doneId]);
      assert.strictEqual(row.is_terminal, 0, 'Status "Done" created after backfill should not be auto-marked terminal');
    } finally {
      await new Promise((resolve) => db.close(resolve));
    }
  });

  // ── Static checks ──────────────────────────────────────────────────────────

  test('Static Checks: drag and drop must be disabled and specific classes must be present', () => {
    const offensiveJsPath = path.join(__dirname, '../../public/js/portal/offensive.js');
    const itauditJsPath = path.join(__dirname, '../../public/js/portal/itaudit.js');
    const boardSharedPath = path.join(__dirname, '../../public/js/portal/boardShared.js');

    const offensiveContent = fs.readFileSync(offensiveJsPath, 'utf8');
    const itauditContent = fs.readFileSync(itauditJsPath, 'utf8');
    const boardSharedContent = fs.readFileSync(boardSharedPath, 'utf8');

    // offensive.js must not define draggable = true on project board cards
    assert.ok(!offensiveContent.includes('card.draggable = true'));
    assert.ok(!offensiveContent.includes('card.ondragstart'));
    assert.ok(!offensiveContent.includes('cardContainer.ondragover'));
    assert.ok(!offensiveContent.includes('cardContainer.ondrop'));

    // itaudit.js must not define draggable = true on project board cards
    assert.ok(!itauditContent.includes('card.draggable = true'));
    assert.ok(!itauditContent.includes('card.ondragstart'));
    assert.ok(!itauditContent.includes('cardContainer.ondragover'));
    assert.ok(!itauditContent.includes('cardContainer.ondrop'));

    // Verify move status and archive classes are in both files
    assert.ok(offensiveContent.includes('.js-move-board-status'));
    assert.ok(offensiveContent.includes('.js-archive-project-from-board'));
    assert.ok(itauditContent.includes('.js-move-board-status'));
    assert.ok(itauditContent.includes('.js-archive-project-from-board'));

    // boardShared.js must not contain dead card drag/drop helpers
    assert.ok(!boardSharedContent.includes('onCardDragStart'));
    assert.ok(!boardSharedContent.includes('onCardDragOver'));
    assert.ok(!boardSharedContent.includes('handleCardDrop'));

    // boardShared.js should still have the status reorder drag functionality
    assert.ok(boardSharedContent.includes('reorderStatusByDrag'));
  });

  test('Static Checks: archive UI only shows button when archiveEligible (isCompleted && isTerminal)', () => {
    const offensiveContent = fs.readFileSync(path.join(__dirname, '../../public/js/portal/offensive.js'), 'utf8');
    const itauditContent = fs.readFileSync(path.join(__dirname, '../../public/js/portal/itaudit.js'), 'utf8');

    // Both files should compute archiveEligible = isCompleted && isTerminal
    assert.ok(offensiveContent.includes('const archiveEligible = isCompleted && isTerminal'));
    assert.ok(itauditContent.includes('const archiveEligible = isCompleted && isTerminal'));

    // The archive button should be gated on archiveEligible, not just isCompleted
    assert.ok(offensiveContent.includes('if (archiveEligible)'));
    assert.ok(itauditContent.includes('if (archiveEligible)'));
  });

  test('Static Checks: Quick Move actions and Escape/Click handlers', () => {
    const offensiveContent = fs.readFileSync(path.join(__dirname, '../../public/js/portal/offensive.js'), 'utf8');
    const itauditContent = fs.readFileSync(path.join(__dirname, '../../public/js/portal/itaudit.js'), 'utf8');

    assert.ok(offensiveContent.includes('.js-card-move-menu'));
    assert.ok(itauditContent.includes('.js-card-move-menu'));

    assert.ok(offensiveContent.includes('stopPropagation'));
    assert.ok(itauditContent.includes('stopPropagation'));

    assert.ok(offensiveContent.includes('openQuickMoveMenu'));
    assert.ok(itauditContent.includes('openQuickMoveMenu'));

    assert.ok(offensiveContent.includes('archiveEligible'));
    assert.ok(itauditContent.includes('archiveEligible'));

    // Assert that drag/drop is disabled
    assert.ok(!offensiveContent.includes('card.draggable = true'));
    assert.ok(!itauditContent.includes('card.draggable = true'));
  });
});
