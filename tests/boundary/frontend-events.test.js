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

test('admin create user form posts display_name expected by the API', () => {
  const adminJs = fs.readFileSync('public/js/portal/admin.js', 'utf8');

  assert.match(adminJs, /const display_name = document\.getElementById\('cu-name'\)\.value\.trim\(\);/);
  assert.match(adminJs, /apiFetch\('\/api\/users', 'POST', \{ display_name, username, role, team, password \}\)/);
  assert.ok(!/apiFetch\('\/api\/users', 'POST', \{ displayName,/.test(adminJs));
});

test('offensive.js and itaudit.js client selection events and class visual states', () => {
  const offJs = fs.readFileSync('public/js/portal/offensive.js', 'utf8');
  const itJs = fs.readFileSync('public/js/portal/itaudit.js', 'utf8');

  // Verify static constraints first
  // 1. offensive.js has listener for #ne-client-list
  assert.match(offJs, /document\.getElementById\('ne-client-list'\)/);
  assert.match(offJs, /bindNewEntryClientSelection/);

  // 2. itaudit.js has listener for #ne-client-list
  assert.match(itJs, /document\.getElementById\('ne-client-list'\)/);
  assert.match(itJs, /bindNewEntryClientSelection/);

  // 3. .js-select-ne-client does not only rely on document.addEventListener
  // Check that the global click listener in both files does not handle js-select-ne-client
  const offGlobalDelegationCheck = offJs.match(/document\.addEventListener\('click'[\s\S]+?\);/);
  const itGlobalDelegationCheck = itJs.match(/document\.addEventListener\('click'[\s\S]+?\);/);

  assert.ok(offGlobalDelegationCheck, 'offensive.js should have a global click listener');
  assert.ok(itGlobalDelegationCheck, 'itaudit.js should have a global click listener');

  assert.ok(!offGlobalDelegationCheck[0].includes('js-select-ne-client'), 'offensive.js global click listener should not handle js-select-ne-client');
  assert.ok(!itGlobalDelegationCheck[0].includes('js-select-ne-client'), 'itaudit.js global click listener should not handle js-select-ne-client');

  // Simulated browser test in node environment for offensive.js and itaudit.js
  const runSimulatedPortalTest = (portalJsContent) => {
    const mockWindow = {
      PortalShared: {
        initSessionGuard: (cb) => {
          cb({ displayName: 'Test User', username: 'testuser' });
        },
        loadHolidays: () => {},
        initNotifications: () => {},
        loadPendingCount: () => {},
        ensureDataLoaded: (key, cb) => cb(),
        apiFetch: () => Promise.resolve([]),
        esc: (x) => x,
        escA: (x) => x,
        jsa: (x) => x,
        safeUrl: (x) => x,
        closeModal: () => {},
        customConfirm: () => Promise.resolve(true),
        customPrompt: () => Promise.resolve(''),
        showToast: () => {},
        timeAgo: () => '',
        idHolidaySet: () => false,
        workingDaysBetween: () => 0,
        getWorkdaysInMonth: () => 0,
        toggleNotifDropdown: () => {},
        loadNotifications: () => {},
        markAllRead: () => {},
        logout: () => {}
      },
      localStorage: {
        getItem: () => 'dashboard',
        setItem: () => {}
      }
    };

    const mockDocument = {
      elements: {},
      listeners: {},
      addEventListener(event, cb) {
        if (!this.listeners[event]) this.listeners[event] = [];
        this.listeners[event].push(cb);
      },
      getElementById(id) {
        if (!this.elements[id]) {
          this.elements[id] = {
            id: id,
            classList: {
              classes: new Set(),
              add(cls) { this.classes.add(cls); },
              remove(cls) { this.classes.delete(cls); },
              contains(cls) { return this.classes.has(cls); }
            },
            style: {},
            addEventListener: (event, cb) => {
              if (!this.elements[id].listeners) this.elements[id].listeners = {};
              if (!this.elements[id].listeners[event]) this.elements[id].listeners[event] = [];
              this.elements[id].listeners[event].push(cb);
            },
            dataset: {},
            value: '',
            focus: () => {}
          };
        }
        return this.elements[id];
      },
      querySelectorAll(selector) {
        if (selector === '.ne-client-card') {
          return Object.values(this.elements).filter(el => el.id && el.id.startsWith('ne-ccard-'));
        }
        return [];
      }
    };

    const oldWindow = global.window;
    const oldDocument = global.document;
    const oldLocalStorage = global.localStorage;
    const oldPortalShared = global.PortalShared;
    global.window = mockWindow;
    global.document = mockDocument;
    global.localStorage = mockWindow.localStorage;
    global.PortalShared = mockWindow.PortalShared;

    try {
      const vm = require('node:vm');
      vm.runInThisContext(portalJsContent, { filename: 'portal.js' });

      // Assert selectNeClient window-level function was defined
      assert.equal(typeof mockWindow.selectNeClient, 'function');
      assert.equal(typeof mockWindow.validateAndGoToProject, 'function');

      const listEl = mockDocument.getElementById('ne-client-list');
      assert.ok(listEl.listeners?.click?.length > 0, 'ne-client-list should have a registered click listener');

      // Setup cards
      const card1 = mockDocument.getElementById('ne-ccard-1');
      card1.dataset.id = '1';
      card1.classList.add('ne-client-card');
      card1.classList.add('js-select-ne-client');

      const card2 = mockDocument.getElementById('ne-ccard-2');
      card2.dataset.id = '2';
      card2.classList.add('ne-client-card');
      card2.classList.add('js-select-ne-client');

      // Test selectNeClient directly sets class selected
      mockWindow.selectNeClient(1);
      assert.ok(card1.classList.contains('selected'));
      assert.ok(!card2.classList.contains('selected'));

      // Test event delegation on list click
      const clickEvent = {
        target: card2,
      };
      card2.closest = (sel) => {
        if (sel === '.js-select-ne-client') return card2;
        return null;
      };
      listEl.contains = (el) => el === card2;

      // Trigger list listener
      listEl.listeners.click[0](clickEvent);
      assert.ok(!card1.classList.contains('selected'));
      assert.ok(card2.classList.contains('selected'));

      // Test validateAndGoToProject switches tab to project details
      const neProjectSection = mockDocument.getElementById('ne-project-section');
      neProjectSection.style.display = 'none';

      mockWindow.validateAndGoToProject();
      assert.equal(neProjectSection.style.display, 'block');
    } finally {
      global.window = oldWindow;
      global.document = oldDocument;
      global.localStorage = oldLocalStorage;
      global.PortalShared = oldPortalShared;
    }

  };

  runSimulatedPortalTest(offJs);
  runSimulatedPortalTest(itJs);
});
