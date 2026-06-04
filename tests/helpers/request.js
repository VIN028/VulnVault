const cp = require('child_process');
const http = require('http');
const path = require('path');
const fs = require('fs');
const { randomUUID } = require('crypto');

let serverProcess = null;
let testDbDir = null;
let testDbPath = null;
let serverPort = null;

async function startServer(customEnv = {}) {
  // Find a port
  serverPort = 4000 + Math.floor(Math.random() * 1000) + process.pid % 1000;
  testDbDir = path.join(__dirname, `../../tmp/test-dir-${randomUUID()}`);

  // Ensure tmp directory exists
  if (!fs.existsSync(testDbDir)) {
    fs.mkdirSync(testDbDir, { recursive: true });
  }

  testDbPath = path.join(testDbDir, 'vulnerabilities.db');

  // Copy initial DB to test DB
  const srcDb = path.join(__dirname, '../../vulnerabilities.db');
  if (fs.existsSync(srcDb)) {
    fs.copyFileSync(srcDb, testDbPath);
  }

  serverProcess = cp.spawn(process.execPath, ['server.js'], {
    env: {
      ...process.env,
      PORT: String(serverPort),
      DB_DIR: testDbDir,
      ENABLE_LEGACY_PORTAL: 'true',
      ...customEnv
    }
  });

  // Wait for server to boot
  await new Promise((resolve) => {
    serverProcess.stdout.on('data', (data) => {
      if (data.toString().includes('Server running')) {
        resolve();
      }
    });
    // Fallback timeout
    setTimeout(resolve, 1500);
  });

  return { port: serverPort, dbPath: testDbPath };
}

function stopServer() {
  if (serverProcess) {
    serverProcess.kill('SIGTERM');
    serverProcess = null;
  }
  if (testDbPath && fs.existsSync(testDbPath)) {
    try { fs.unlinkSync(testDbPath); } catch {}
    testDbPath = null;
  }
  if (testDbDir && fs.existsSync(testDbDir)) {
    try {
      if (fs.rmSync) {
        fs.rmSync(testDbDir, { recursive: true, force: true });
      } else {
        fs.rmdirSync(testDbDir, { recursive: true });
      }
    } catch {}
    testDbDir = null;
  }
}

function makeRequest(port, options, body = null, cookie = '') {
  return new Promise((resolve, reject) => {
    const headers = { ...options.headers };
    if (cookie) {
      headers['cookie'] = cookie;
    }
    const postData = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;
    if (postData) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(postData);
    }

    const req = http.request({
      hostname: 'localhost',
      port: port,
      ...options,
      headers: headers
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

    req.on('error', reject);
    if (postData) {
      req.write(postData);
    }
    req.end();
  });
}

// Stateful request helper that fetches CSRF token if needed
async function authenticatedRequest(port, cookie, method, path, body = null) {
  const headers = {};
  const stateChanging = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase());

  if (stateChanging) {
    // 1. Fetch CSRF token first
    const csrfRes = await makeRequest(port, {
      path: '/api/csrf-token',
      method: 'GET'
    }, null, cookie);

    if (csrfRes.statusCode === 200 && csrfRes.body && csrfRes.body.token) {
      headers['X-CSRF-Token'] = csrfRes.body.token;
    }
  }

  // 2. Make the actual request
  return makeRequest(port, {
    path,
    method,
    headers
  }, body, cookie);
}

module.exports = { startServer, stopServer, makeRequest, authenticatedRequest };
