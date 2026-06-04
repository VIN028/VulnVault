const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');

test('engineer app defines CSRF-aware apiRequest helper', () => {
  const src = fs.readFileSync('public/js/app.js', 'utf8');
  assert.match(src, /function getCsrfToken|async function getCsrfToken/);
  assert.match(src, /X-CSRF-Token/);
});

test('legacy portal apiFetch sends CSRF token for state-changing requests', () => {
  const src = fs.readFileSync('public/portal-legacy.html', 'utf8');
  assert.match(src, /getLegacyCsrfToken/);
  assert.match(src, /X-CSRF-Token/);
});
