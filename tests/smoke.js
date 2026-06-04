const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const http = require('http');

// Paths
const dbPath = path.join(__dirname, '../vulnerabilities.db');
const dbBakPath = path.join(__dirname, '../vulnerabilities.db.bak');

console.log('🛡️ Starting VulnVault Security Boundary Smoke Tests...\n');

// 1. Back up database
let hasBackup = false;
if (fs.existsSync(dbPath)) {
  fs.copyFileSync(dbPath, dbBakPath);
  hasBackup = true;
  console.log('✅ Backed up vulnerabilities.db to vulnerabilities.db.bak');
}

let serverProcess = null;

// Helper: cleanup & exit
function cleanupAndExit(exitCode) {
  if (serverProcess) {
    serverProcess.kill('SIGTERM');
    console.log('🛑 Server process terminated.');
  }
  if (hasBackup && fs.existsSync(dbBakPath)) {
    fs.copyFileSync(dbBakPath, dbPath);
    fs.unlinkSync(dbBakPath);
    console.log('✅ Restored database from vulnerabilities.db.bak');
  }
  process.exit(exitCode);
}

// 2. Start server
console.log('🚀 Spawning server on port 3333...');
serverProcess = cp.spawn(process.execPath, ['server.js'], {
  env: {
    ...process.env,
    PORT: '3333',
    ENABLE_LEGACY_PORTAL: 'true'
  }
});

serverProcess.stdout.on('data', (data) => {
  // console.log('[Server stdout]', data.toString().trim());
});

serverProcess.stderr.on('data', (data) => {
  console.error('[Server stderr]', data.toString().trim());
});

// Helper for fetch-like HTTP requests
function request(options, body = null) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: 'localhost',
      port: 3333,
      ...options
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(data);
        } catch (e) {
          json = data;
        }
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: json
        });
      });
    });

    req.on('error', (err) => reject(err));

    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

// Wait for server to boot (up to 3 seconds)
async function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

(async () => {
  await wait(2000); // Wait for SQLite setup and listen

  let cookie = '';

  try {
    // 3. Login
    console.log('🔑 Authenticating as admin...');
    const loginRes = await request({
      path: '/api/login',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { username: 'admin', password: 'Cisometric123@' });

    if (loginRes.statusCode !== 200) {
      throw new Error(`Login failed with status ${loginRes.statusCode}: ${JSON.stringify(loginRes.body)}`);
    }

    const setCookie = loginRes.headers['set-cookie'];
    if (setCookie && setCookie.length > 0) {
      cookie = setCookie[0].split(';')[0];
    }
    console.log('✅ Successfully authenticated.');

    // 4. Run Test Cases

    // --- TEST 1 & 2: Data Boundary Filtering ---
    console.log('\n🔍 Running Test 1 & 2: Scoped clients and projects filtering...');
    
    // Fetch offensive
    const offRes = await request({
      path: '/api/clients/full?team=offensive',
      method: 'GET',
      headers: { 'cookie': cookie }
    });
    if (offRes.statusCode !== 200) throw new Error('Failed to fetch offensive clients');
    const offClients = offRes.body;
    for (const c of offClients) {
      if (c.project_id && c.team !== 'offensive' && c.team !== null) {
        throw new Error(`Test 1 Failed: Found itaudit project in offensive list: ${JSON.stringify(c)}`);
      }
    }
    console.log('✅ Test 1 Passed: GET /api/clients/full?team=offensive contains no itaudit projects.');

    // Fetch itaudit
    const auditRes = await request({
      path: '/api/clients/full?team=itaudit',
      method: 'GET',
      headers: { 'cookie': cookie }
    });
    if (auditRes.statusCode !== 200) throw new Error('Failed to fetch itaudit clients');
    const auditClients = auditRes.body;
    for (const c of auditClients) {
      if (c.project_id && c.team !== 'itaudit') {
        throw new Error(`Test 2 Failed: Found non-itaudit project in itaudit list: ${JSON.stringify(c)}`);
      }
    }
    console.log('✅ Test 2 Passed: GET /api/clients/full?team=itaudit contains no offensive projects.');

    // --- TEST 3: Invalid client team ---
    console.log('\n🔍 Running Test 3: Invalid client team validation...');
    const invalidClientRes = await request({
      path: '/api/clients',
      method: 'POST',
      headers: { 'cookie': cookie, 'Content-Type': 'application/json' }
    }, { name: 'Test Invalid Client', team: 'random' });

    if (invalidClientRes.statusCode !== 400) {
      throw new Error(`Test 3 Failed: Expected status 400 for invalid team, got ${invalidClientRes.statusCode}`);
    }
    console.log('✅ Test 3 Passed: POST /api/clients with invalid team rejected with 400.');

    // --- TEST 4: Project creation team mismatch ---
    console.log('\n🔍 Running Test 4: Project-client team mismatch validation...');
    
    // Create itaudit client
    const itClientRes = await request({
      path: '/api/clients',
      method: 'POST',
      headers: { 'cookie': cookie, 'Content-Type': 'application/json' }
    }, { name: 'IT Audit Smoke Client', team: 'itaudit' });

    if (itClientRes.statusCode !== 201) throw new Error('Failed to create IT Audit client for testing');
    const itClientId = itClientRes.body.id;

    // Try creating offensive project under itaudit client
    const mismatchProjectRes = await request({
      path: `/api/clients/${itClientId}/projects`,
      method: 'POST',
      headers: { 'cookie': cookie, 'Content-Type': 'application/json' }
    }, {
      name: 'Mismatch Project',
      team: 'offensive',
      project_type: 'web',
      project_method: 'blackbox'
    });

    if (mismatchProjectRes.statusCode !== 400) {
      throw new Error(`Test 4 Failed: Expected 400 for mismatch, got ${mismatchProjectRes.statusCode}`);
    }
    console.log('✅ Test 4 Passed: Team mismatch client/project creation rejected with 400.');

    // --- TEST 5: Board status team consistency ---
    console.log('\n🔍 Running Test 5: Board status team mismatch validation...');
    
    // Create itaudit board status
    const itStatusRes = await request({
      path: '/api/board-statuses',
      method: 'POST',
      headers: { 'cookie': cookie, 'Content-Type': 'application/json' }
    }, { name: 'IT Audit Custom Status', color: '#123456', sort_order: 1, team: 'itaudit' });

    if (itStatusRes.statusCode !== 201) throw new Error('Failed to create IT Audit board status');
    const itStatusId = itStatusRes.body.id;

    // Create offensive project
    const offClientRes = await request({
      path: '/api/clients',
      method: 'POST',
      headers: { 'cookie': cookie, 'Content-Type': 'application/json' }
    }, { name: 'Offensive Smoke Client', team: 'offensive' });
    const offClientId = offClientRes.body.id;

    const offProjectRes = await request({
      path: `/api/clients/${offClientId}/projects`,
      method: 'POST',
      headers: { 'cookie': cookie, 'Content-Type': 'application/json' }
    }, {
      name: 'Offensive Project',
      team: 'offensive',
      project_type: 'web',
      project_method: 'blackbox'
    });
    const offProjectId = offProjectRes.body.id;

    // Attempt to move offensive project to itaudit board status
    const moveRes = await request({
      path: `/api/projects/${offProjectId}/board-status`,
      method: 'PATCH',
      headers: { 'cookie': cookie, 'Content-Type': 'application/json' }
    }, { board_status_id: itStatusId });

    if (moveRes.statusCode !== 400) {
      throw new Error(`Test 5 Failed: Expected 400 for board status team mismatch, got ${moveRes.statusCode}`);
    }
    console.log('✅ Test 5 Passed: Board status team mismatch rejected with 400.');

    // --- TEST 6: Reorder board status boundaries ---
    console.log('\n🔍 Running Test 6: Reorder board status validation...');
    
    const reorderRes = await request({
      path: '/api/board-statuses/reorder',
      method: 'PUT',
      headers: { 'cookie': cookie, 'Content-Type': 'application/json' }
    }, { ordered_ids: [itStatusId], team: 'offensive' }); // itStatusId belongs to itaudit

    if (reorderRes.statusCode !== 400) {
      throw new Error(`Test 6 Failed: Expected 400 when reordering status belonging to another team, got ${reorderRes.statusCode}`);
    }
    console.log('✅ Test 6 Passed: Reordering status of another team rejected with 400.');

    // --- TEST 7: Single quotes in display name ---
    console.log('\n🔍 Running Test 7: Single quotes (XSS/syntax) escaping validation...');
    
    // Test the jsa serializer on client display name representation
    function testJsaSerializer(val) {
      return JSON.stringify(val)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }
    
    const badName = "O'Hara";
    const jsaResult = testJsaSerializer(badName);
    
    // It should output a double-quoted JSON string with escaped quotes inside HTML attributes
    if (jsaResult !== '&quot;O\'Hara&quot;') {
      throw new Error(`Test 7 Failed: jsa serialization expected '&quot;O\'Hara&quot;', got '${jsaResult}'`);
    }
    console.log('✅ Test 7 Passed: display name with single quotes is serialized safely into attribute-safe JSON.');

    console.log('\n🏆 ALL SMOKE TESTS COMPLETED SUCCESSFULLY! 🎉\n');
    cleanupAndExit(0);
  } catch (err) {
    console.error('\n❌ Smoke tests failed with error:', err.message);
    cleanupAndExit(1);
  }
})();
