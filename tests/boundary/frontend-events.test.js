const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');

test('frontend files migrated main buttons from inline onclick to addEventListener', () => {
  const offHtml = fs.readFileSync('public/portal-offensive.html', 'utf8');
  const itHtml = fs.readFileSync('public/portal-itaudit.html', 'utf8');

  // Verify elements have IDs and type button
  assert.match(offHtml, /id="btn-new-project"/);
  assert.match(offHtml, /id="btn-board-setup"/);
  assert.match(itHtml, /id="btn-new-project"/);
  assert.match(itHtml, /id="btn-board-setup"/);

  // Verify inline click handlers for these are gone
  assert.ok(!/onclick="openCreateProject\(\)"/.test(offHtml));
  assert.ok(!/onclick="openBoardSetup\(\)"/.test(offHtml));
  assert.ok(!/onclick="openCreateProject\(\)"/.test(itHtml));
  assert.ok(!/onclick="openBoardSetup\(\)"/.test(itHtml));
});

test('shared.js defines ensureDataLoaded and backward-compatible globals', () => {
  const shared = fs.readFileSync('public/js/portal/shared.js', 'utf8');
  assert.match(shared, /ensureDataLoaded/);
  assert.match(shared, /window\.closeModal\s*=/);
  assert.match(shared, /window\.toggleNotifDropdown\s*=/);
  assert.match(shared, /window\.markAllRead\s*=/);
  assert.match(shared, /window\.logout\s*=/);
});

test('portal scripts define ensureEngineersLoaded and guard Chart.js', () => {
  const offJs = fs.readFileSync('public/js/portal/offensive.js', 'utf8');
  const itJs = fs.readFileSync('public/js/portal/itaudit.js', 'utf8');

  // Verify they register listeners for the new buttons
  assert.match(offJs, /btn-new-project/);
  assert.match(offJs, /btn-board-setup/);
  assert.match(itJs, /btn-new-project/);
  assert.match(itJs, /btn-board-setup/);

  // Verify ensureEngineersLoaded is present
  assert.match(offJs, /ensureEngineersLoaded/);
  assert.match(itJs, /ensureEngineersLoaded/);

  // Verify Chart.js guard
  assert.match(offJs, /typeof Chart === 'undefined'/);
  assert.match(itJs, /typeof Chart === 'undefined'/);
});
