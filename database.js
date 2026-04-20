const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_DIR = process.env.DB_DIR || __dirname;
const DB_PATH = path.join(DB_DIR, 'vulnerabilities.db');
const SALT_ROUNDS = 10;
const DEFAULT_PASSWORD = 'Cisometric123@';

let db;

function getDb() {
  if (!db) {
    db = new sqlite3.Database(DB_PATH, (err) => {
      if (err) {
        console.error('Error opening database:', err.message);
      } else {
        console.log('Connected to SQLite database.');
        initializeDb();
      }
    });
  }
  return db;
}

function initializeDb() {
  const createTable = `
    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      affected_items TEXT,
      impact TEXT,
      recommendation TEXT,
      poc TEXT,
      vuln_references TEXT,
      screenshot_path TEXT,
      severity TEXT DEFAULT 'Medium',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      is_template INTEGER DEFAULT 0,
      bilingual_payload TEXT,
      owner_engineer_id INTEGER
    )
  `;
  db.run(createTable, (err) => {
    if (err) {
      console.error('Error creating table:', err.message);
    } else {
      console.log('Vulnerabilities table ready.');
      db.run(`ALTER TABLE vulnerabilities ADD COLUMN bilingual_payload TEXT`, () => {});
      db.run(`ALTER TABLE vulnerabilities ADD COLUMN owner_engineer_id INTEGER`, () => {});
    }
  });

  db.run(`
    CREATE TABLE IF NOT EXISTS clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS projects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      project_type TEXT DEFAULT 'web',
      assigned_engineer_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(client_id, name)
    )
  `, () => {
    db.run(`ALTER TABLE projects ADD COLUMN project_type TEXT DEFAULT 'web'`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN assigned_engineer_id INTEGER`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN assist_engineer_id INTEGER`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN kickoff_date TEXT`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN initial_report_date TEXT`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN final_report_date TEXT`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN link_report_en TEXT`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN link_report_id TEXT`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN initial_report_status TEXT DEFAULT 'pending'`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN final_report_status TEXT DEFAULT 'pending'`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN initial_completed_by TEXT`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN final_completed_by TEXT`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN initial_completed_at TEXT`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN final_completed_at TEXT`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN project_links TEXT`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN mandays_kickoff INTEGER DEFAULT 1`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN mandays_infogath INTEGER DEFAULT 5`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN retest_status TEXT DEFAULT 'none'`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN retest_start_date TEXT`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN retest_end_date TEXT`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN retest_pic_id INTEGER`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN retest_assist_id INTEGER`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN project_method TEXT DEFAULT 'blackbox'`, () => {});
    db.run(`ALTER TABLE projects ADD COLUMN mandays_assessment INTEGER DEFAULT 0`, () => {});
  });

  db.run(`
    CREATE TABLE IF NOT EXISTS project_vulnerabilities (
      project_id INTEGER NOT NULL,
      vulnerability_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(project_id, vulnerability_id)
    )
  `);

  // Initialize project access requests table
  setTimeout(initProjectAccessRequests, 200);
  // Initialize activity log table
  setTimeout(initActivityLog, 300);
  // Initialize notifications table
  setTimeout(initNotifications, 400);


  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','manager','pm','engineer')),
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (!err) seedDefaultUsers();
  });

  db.run(`
    CREATE TABLE IF NOT EXISTS access_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      requester_id INTEGER NOT NULL,
      target_engineer_id INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
      reviewed_by INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      reviewed_at DATETIME,
      UNIQUE(requester_id, target_engineer_id)
    )
  `);
}

async function seedDefaultUsers() {
  const defaults = [
    { username: 'admin',   display_name: 'Admin',   role: 'admin'   },
    { username: 'manager', display_name: 'Manager', role: 'manager' },
    { username: 'pm',      display_name: 'PM',      role: 'pm'      },
  ];

  for (const u of defaults) {
    db.get('SELECT id FROM users WHERE username = ?', [u.username], async (err, row) => {
      if (!row) {
        const hash = await bcrypt.hash(DEFAULT_PASSWORD, SALT_ROUNDS);
        db.run(
          'INSERT INTO users (username, display_name, role, password_hash) VALUES (?,?,?,?)',
          [u.username, u.display_name, u.role, hash],
          (e) => { if (!e) console.log(`[auth] Seeded user: ${u.username}`); }
        );
      }
    });
  }
}


// ─── User management ──────────────────────────────────────────────────────────
function getUserByUsername(username, callback) {
  getDb().get('SELECT * FROM users WHERE username = ?', [username], callback);
}

function getAllUsers(callback) {
  getDb().all(
    'SELECT id, username, display_name, role, created_at FROM users ORDER BY role, username',
    callback
  );
}

function createUser({ username, display_name, role, password }, callback) {
  bcrypt.hash(password, SALT_ROUNDS, (err, hash) => {
    if (err) return callback(err);
    getDb().run(
      'INSERT INTO users (username, display_name, role, password_hash) VALUES (?,?,?,?)',
      [username, display_name, role, hash],
      function(e) { callback(e, this?.lastID); }
    );
  });
}

function deleteUser(id, callback) {
  const db = getDb();
  db.serialize(() => {
    // Unassign from projects where they are PIC or Assist
    db.run('UPDATE projects SET assigned_engineer_id = NULL WHERE assigned_engineer_id = ?', [id]);
    db.run('UPDATE projects SET assist_engineer_id = NULL WHERE assist_engineer_id = ?', [id]);
    // Clean up access requests
    db.run('DELETE FROM access_requests WHERE requester_id = ? OR target_engineer_id = ?', [id, id]);
    db.run('DELETE FROM project_access_requests WHERE engineer_id = ?', [id]);
    // Finally delete the user
    db.run('DELETE FROM users WHERE id = ?', [id], callback);
  });
}

function getUserById(id, callback) {
  getDb().get('SELECT id, username, display_name, role, password_hash FROM users WHERE id = ?', [id], callback);
}

function changePassword(id, newPasswordHash, callback) {
  getDb().run('UPDATE users SET password_hash = ? WHERE id = ?', [newPasswordHash, id], function(err) {
    callback(err, { changes: this?.changes });
  });
}

function getAllEngineers(callback) {
  getDb().all(
    'SELECT id, username, display_name FROM users WHERE role = ? ORDER BY display_name',
    ['engineer'],
    callback
  );
}

// ─── Access requests ──────────────────────────────────────────────────────────
function getAccessRequests(filter, callback) {
  const db = getDb();
  if (filter.requesterId) {
    db.all(
      `SELECT ar.*, u.display_name AS target_name
       FROM access_requests ar JOIN users u ON u.id = ar.target_engineer_id
       WHERE ar.requester_id = ? ORDER BY ar.created_at DESC`,
      [filter.requesterId], callback
    );
  } else {
    db.all(
      `SELECT ar.*, u.display_name AS target_name, r.display_name AS requester_name
       FROM access_requests ar
       JOIN users u ON u.id = ar.target_engineer_id
       JOIN users r ON r.id = ar.requester_id
       WHERE ar.status = 'pending' ORDER BY ar.created_at DESC`,
      callback
    );
  }
}

function createAccessRequest({ requesterId, targetEngineerId }, callback) {
  getDb().run(
    'INSERT OR IGNORE INTO access_requests (requester_id, target_engineer_id) VALUES (?,?)',
    [requesterId, targetEngineerId],
    function(e) { callback(e, this?.lastID); }
  );
}

function updateAccessRequest({ id, status, reviewedBy }, callback) {
  getDb().run(
    `UPDATE access_requests SET status = ?, reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP WHERE id = ?`,
    [status, reviewedBy, id],
    callback
  );
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
function getDashboardSummary(callback) {
  getDb().all(`
    SELECT c.id AS client_id, c.name AS client_name,
           p.id AS project_id, p.name AS project_name,
           p.project_type, p.assigned_engineer_id, p.assist_engineer_id,
           p.kickoff_date, p.initial_report_date, p.final_report_date,
           p.initial_report_status, p.final_report_status,
           p.initial_completed_by, p.final_completed_by,
           p.initial_completed_at, p.final_completed_at,
           p.mandays_kickoff, p.mandays_infogath,
           p.retest_status, p.retest_start_date, p.retest_end_date,
           p.retest_pic_id, p.retest_assist_id,
           u.display_name AS engineer_name,
           u2.display_name AS assist_engineer_name,
           u3.display_name AS retest_pic_name,
           u4.display_name AS retest_assist_name,
           (SELECT COUNT(*) FROM project_vulnerabilities pv WHERE pv.project_id = p.id) AS finding_count
    FROM clients c
    JOIN projects p ON p.client_id = c.id
    LEFT JOIN users u  ON u.id  = p.assigned_engineer_id
    LEFT JOIN users u2 ON u2.id = p.assist_engineer_id
    LEFT JOIN users u3 ON u3.id = p.retest_pic_id
    LEFT JOIN users u4 ON u4.id = p.retest_assist_id
    ORDER BY c.name, p.name
  `, callback);
}

// Engineers only see clients where they have an assigned project
function getClientsByEngineer(engineerId, callback) {
  getDb().all(`
    SELECT DISTINCT c.id, c.name, c.created_at
    FROM clients c
    JOIN projects p ON p.client_id = c.id
    WHERE p.assigned_engineer_id = ?
       OR p.assist_engineer_id = ?
       OR p.retest_pic_id = ?
       OR p.retest_assist_id = ?
    ORDER BY c.name
  `, [engineerId, engineerId, engineerId, engineerId], callback);
}

// All clients with their projects (LEFT JOIN so empty clients appear too)
function getClientsWithProjects(callback) {
  getDb().all(`
    SELECT c.id AS client_id, c.name AS client_name,
           p.id AS project_id, p.name AS project_name, p.project_type,
           p.kickoff_date, p.initial_report_date, p.final_report_date,
           p.initial_report_status, p.final_report_status,
           p.assigned_engineer_id,
           p.assist_engineer_id,
           p.link_report_en, p.link_report_id, p.project_links,
           p.project_method, p.mandays_kickoff, p.mandays_infogath, p.mandays_assessment,
           p.retest_status, p.retest_start_date, p.retest_end_date,
           p.retest_pic_id, p.retest_assist_id,
           u.display_name AS engineer_name,
           u2.display_name AS assist_engineer_name,
           u3.display_name AS retest_pic_name,
           u4.display_name AS retest_assist_name,
           (SELECT COUNT(*) FROM project_vulnerabilities pv WHERE pv.project_id = p.id) AS finding_count
    FROM clients c
    LEFT JOIN projects p ON p.client_id = c.id
    LEFT JOIN users u ON u.id = p.assigned_engineer_id
    LEFT JOIN users u2 ON u2.id = p.assist_engineer_id
    LEFT JOIN users u3 ON u3.id = p.retest_pic_id
    LEFT JOIN users u4 ON u4.id = p.retest_assist_id
    ORDER BY c.name, p.name
  `, callback);
}


// ─── Activity Log ─────────────────────────────────────────────────────────────
function initActivityLog() {
  getDb().run(`
    CREATE TABLE IF NOT EXISTS activity_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      actor_id INTEGER,
      engineer_id INTEGER,
      project_id INTEGER,
      action TEXT NOT NULL,
      details TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

function writeActivityLog({ type, actorId, engineerId, projectId, action, details }, callback) {
  getDb().run(
    'INSERT INTO activity_log (type, actor_id, engineer_id, project_id, action, details) VALUES (?,?,?,?,?,?)',
    [type, actorId||null, engineerId||null, projectId||null, action, details||null],
    callback || (() => {})
  );
}

function getActivityLog(type, callback) {
  if (typeof type === 'function') { callback = type; type = null; } // handle old 1-arg call
  const params = [];
  let where = '';
  if (type) {
    where = 'WHERE al.type = ?';
    params.push(type);
  }
  getDb().all(`
    SELECT al.*, 
           actor.display_name AS actor_name,
           eng.display_name AS engineer_name,
           p.name AS project_name,
           c.name AS client_name
    FROM activity_log al
    LEFT JOIN users actor ON actor.id = al.actor_id
    LEFT JOIN users eng ON eng.id = al.engineer_id
    LEFT JOIN projects p ON p.id = al.project_id
    LEFT JOIN clients c ON c.id = p.client_id
    ${where}
    ORDER BY al.created_at DESC
    LIMIT 200
  `, params, callback);
}

// ─── Project Access Requests (engineer → PM approval) ─────────────────────────
function initProjectAccessRequests() {
  getDb().run(`
    CREATE TABLE IF NOT EXISTS project_access_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      engineer_id INTEGER NOT NULL,
      project_id INTEGER NOT NULL,
      message TEXT,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
      reviewed_by INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      reviewed_at DATETIME,
      UNIQUE(engineer_id, project_id)
    )
  `);
}

function getAllProjects(callback) {
  getDb().all(`
    SELECT p.id, p.name, p.project_type, p.client_id, p.assigned_engineer_id, p.assist_engineer_id,
           p.kickoff_date, p.initial_report_date, p.final_report_date,
           p.link_report_en, p.link_report_id,
           c.name AS client_name
    FROM projects p JOIN clients c ON c.id = p.client_id
    ORDER BY c.name, p.name
  `, callback);
}

function getProjectAccessRequests(filter, callback) {
  const db = getDb();
  if (filter.engineerId) {
    db.all(`
      SELECT par.*, p.name AS project_name, c.name AS client_name
      FROM project_access_requests par
      JOIN projects p ON p.id = par.project_id
      JOIN clients c ON c.id = p.client_id
      WHERE par.engineer_id = ?
      ORDER BY par.created_at DESC
    `, [filter.engineerId], callback);
  } else {
    db.all(`
      SELECT par.*, p.name AS project_name, c.name AS client_name,
             u.display_name AS engineer_name
      FROM project_access_requests par
      JOIN projects p ON p.id = par.project_id
      JOIN clients c ON c.id = p.client_id
      JOIN users u ON u.id = par.engineer_id
      WHERE par.status = 'pending'
      ORDER BY par.created_at DESC
    `, callback);
  }
}

function createProjectAccessRequest({ engineerId, projectId, message }, callback) {
  // Upsert: if request already exists and was rejected/approved, reset to pending
  getDb().run(
    `INSERT INTO project_access_requests (engineer_id, project_id, message, status)
     VALUES (?,?,?,'pending')
     ON CONFLICT(engineer_id, project_id) DO UPDATE SET
       status='pending', message=excluded.message, created_at=CURRENT_TIMESTAMP, reviewed_at=NULL, reviewed_by=NULL
     WHERE status != 'pending'`,
    [engineerId, projectId, message || null],
    function(e) { callback(e, this?.lastID); }
  );
}

function updateProjectAccessRequest({ id, status, reviewedBy }, callback) {
  const db = getDb();
  db.run(
    `UPDATE project_access_requests SET status=?, reviewed_by=?, reviewed_at=CURRENT_TIMESTAMP WHERE id=?`,
    [status, reviewedBy, id],
    (err) => {
      if (err || status !== 'approved') return callback(err);
      // On approval, assign engineer to the project
      db.get('SELECT project_id, engineer_id FROM project_access_requests WHERE id=?', [id], (e, row) => {
        if (e || !row) return callback(e);
        db.get('SELECT assigned_engineer_id, assist_engineer_id FROM projects WHERE id=?', [row.project_id], (err2, proj) => {
          if (err2 || !proj) return callback(err2);
          if (!proj.assigned_engineer_id) {
            db.run('UPDATE projects SET assigned_engineer_id=? WHERE id=?', [row.engineer_id, row.project_id], callback);
          } else {
            db.run('UPDATE projects SET assist_engineer_id=? WHERE id=?', [row.engineer_id, row.project_id], callback);
          }
        });
      });
    }
  );
}

function listVulnerabilities(options, callback) {
  const db = getDb();
  const search    = (options?.search    || '').trim();
  const severity  = (options?.severity  || '').trim();
  const sort      = (options?.sort      || 'newest').trim();
  const projectId = options?.project_id ? Number(options.project_id) : null;
  const params = [];

  // When filtering by project, join on the junction table
  const fromClause = projectId
    ? `FROM vulnerabilities v JOIN project_vulnerabilities pv ON pv.vulnerability_id = v.id AND pv.project_id = ?`
    : `FROM vulnerabilities v`;
  if (projectId) params.push(projectId);

  const where = [];
  const ownerId = options?.owner_engineer_id ? Number(options.owner_engineer_id) : null;
  if (ownerId) {
    where.push('v.owner_engineer_id = ?');
    params.push(ownerId);
  }
  if (search) {
    where.push('(v.name LIKE ? OR v.description LIKE ? OR v.affected_items LIKE ?)');
    const like = `%${search}%`;
    params.push(like, like, like);
  }
  if (severity) {
    where.push('v.severity = ?');
    params.push(severity);
  }

  let orderBy = 'v.created_at DESC';
  const sevCase = `CASE v.severity WHEN 'Critical' THEN 5 WHEN 'High' THEN 4 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 2 WHEN 'Info' THEN 1 ELSE 0 END`;
  if (sort === 'oldest')       orderBy = 'v.created_at ASC';
  else if (sort === 'severity_desc') orderBy = `${sevCase} DESC, v.created_at DESC`;
  else if (sort === 'severity_asc')  orderBy = `${sevCase} ASC,  v.created_at DESC`;
  else if (sort === 'name_asc')  orderBy = 'v.name COLLATE NOCASE ASC, v.created_at DESC';
  else if (sort === 'name_desc') orderBy = 'v.name COLLATE NOCASE DESC, v.created_at DESC';

  const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  db.all(
    `SELECT v.id, v.name, v.description, v.affected_items, v.impact, v.recommendation, v.poc,
            v.vuln_references as "references", v.screenshot_path, v.severity, v.created_at, v.updated_at
     ${fromClause}
     ${whereClause}
     ORDER BY ${orderBy}`,
    params,
    callback
  );
}

function getAllVulnerabilities(callback) {
  listVulnerabilities({}, callback);
}

function getVulnerabilityById(id, callback) {
  const db = getDb();
  db.get(
    `SELECT id, name, description, affected_items, impact, recommendation, poc,
            vuln_references as "references", screenshot_path, severity, created_at, updated_at
     FROM vulnerabilities WHERE id = ?`,
    [id], callback
  );
}

function saveVulnerability(data, callback) {
  const db = getDb();
  const {
    name, description, affected_items, impact,
    recommendation, poc, screenshot_path, severity,
    bilingual_payload, owner_engineer_id
  } = data;
  const references = data.references || data.vuln_references || '';
  db.run(
    `INSERT INTO vulnerabilities 
      (name, description, affected_items, impact, recommendation, poc, vuln_references, screenshot_path, severity, bilingual_payload, owner_engineer_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [name, description, affected_items, impact, recommendation, poc, references, screenshot_path || null, severity || 'Medium', bilingual_payload || null, owner_engineer_id || null],
    function (err) {
      if (err) return callback(err);
      callback(null, { id: this.lastID });
    }
  );
}

function updateVulnerability(id, data, callback) {
  const db = getDb();
  const { name, description, affected_items, impact, recommendation, poc, screenshot_path, severity } = data;
  db.run(
    `UPDATE vulnerabilities SET name=?, description=?, affected_items=?, impact=?, recommendation=?, poc=?, screenshot_path=?, severity=? WHERE id=?`,
    [name, description || null, affected_items || null, impact || null, recommendation || null, poc || null, screenshot_path || null, severity || 'Medium', id],
    function(err) {
      if (err) return callback(err);
      callback(null, { changes: this.changes });
    }
  );
}

function deleteVulnerability(id, callback) {
  const db = getDb();
  db.run('DELETE FROM vulnerabilities WHERE id = ?', [id], function (err) {
    if (err) return callback(err);
    callback(null, { changes: this.changes });
  });
}

function searchVulnerabilities(query, callback) {
  listVulnerabilities({ search: query }, callback);
}

function countVulnerabilities(callback) {
  const db = getDb();
  db.get('SELECT COUNT(*) as count FROM vulnerabilities', [], callback);
}

function getClients(callback) {
  const db = getDb();
  db.all('SELECT id, name, created_at FROM clients ORDER BY name COLLATE NOCASE ASC', [], callback);
}

function createClient(name, callback) {
  const db = getDb();
  db.run('INSERT INTO clients (name) VALUES (?)', [name], function (err) {
    if (err) return callback(err);
    callback(null, { id: this.lastID });
  });
}

function deleteClient(clientId, callback) {
  const db = getDb();
  db.serialize(() => {
    db.run(
      `DELETE FROM project_vulnerabilities
       WHERE project_id IN (SELECT id FROM projects WHERE client_id = ?)`,
      [clientId]
    );
    db.run('DELETE FROM projects WHERE client_id = ?', [clientId]);
    db.run('DELETE FROM clients WHERE id = ?', [clientId], function (err) {
      if (err) return callback(err);
      callback(null, { changes: this.changes });
    });
  });
}

function getProjectsByClient(clientId, callback) {
  const db = getDb();
  db.all(
    `SELECT p.id, p.client_id, p.name, p.project_type,
            p.assigned_engineer_id, p.assist_engineer_id, p.kickoff_date,
            p.initial_report_date, p.final_report_date,
            p.initial_report_status, p.final_report_status,
            p.link_report_en, p.link_report_id, p.project_links,
            p.created_at,
            p.retest_status, p.retest_start_date, p.retest_end_date,
            p.retest_pic_id, p.retest_assist_id,
            u.display_name AS engineer_name,
            u2.display_name AS assist_engineer_name
     FROM projects p
     LEFT JOIN users u ON u.id = p.assigned_engineer_id
     LEFT JOIN users u2 ON u2.id = p.assist_engineer_id
     WHERE p.client_id = ?
     ORDER BY p.name COLLATE NOCASE ASC`,
    [clientId],
    callback
  );
}

function createProject(clientId, name, opts, callback) {
  // Handle legacy 2-arg call: createProject(clientId, name, callback)
  if (typeof opts === 'function') { callback = opts; opts = {}; }
  const db = getDb();
  const { project_type, project_method, assigned_engineer_id, assist_engineer_id, kickoff_date, initial_report_date, final_report_date, project_links, mandays_kickoff, mandays_infogath, mandays_assessment } = opts || {};
  db.run(
    `INSERT INTO projects (client_id, name, project_type, project_method, assigned_engineer_id, assist_engineer_id, kickoff_date, initial_report_date, final_report_date, project_links, mandays_kickoff, mandays_infogath, mandays_assessment)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [clientId, name, project_type || 'web', project_method || 'blackbox', assigned_engineer_id || null, assist_engineer_id || null, kickoff_date || null, initial_report_date || null, final_report_date || null, project_links || null, mandays_kickoff ?? 1, mandays_infogath ?? 5, mandays_assessment ?? 0],
    function (err) {
      if (err) return callback(err);
      callback(null, { id: this.lastID });
    }
  );
}

function deleteProject(projectId, callback) {
  const db = getDb();
  db.serialize(() => {
    db.run('DELETE FROM project_vulnerabilities WHERE project_id = ?', [projectId]);
    db.run('DELETE FROM projects WHERE id = ?', [projectId], function (err) {
      if (err) return callback(err);
      callback(null, { changes: this.changes });
    });
  });
}

function getProjectVulnerabilityIds(projectId, callback) {
  const db = getDb();
  db.all(
    'SELECT vulnerability_id FROM project_vulnerabilities WHERE project_id = ? ORDER BY created_at DESC',
    [projectId],
    callback
  );
}

function setProjectVulnerabilities(projectId, vulnerabilityIds, callback) {
  const db = getDb();
  db.serialize(() => {
    db.run('DELETE FROM project_vulnerabilities WHERE project_id = ?', [projectId], (err) => {
      if (err) return callback(err);
      if (!vulnerabilityIds.length) return callback(null, { count: 0 });

      const stmt = db.prepare(
        'INSERT OR IGNORE INTO project_vulnerabilities (project_id, vulnerability_id) VALUES (?, ?)'
      );
      for (const vulnId of vulnerabilityIds) {
        stmt.run([projectId, vulnId]);
      }
      stmt.finalize((finalizeErr) => {
        if (finalizeErr) return callback(finalizeErr);
        callback(null, { count: vulnerabilityIds.length });
      });
    });
  });
}

function getProjectExportData(projectId, callback) {
  const db = getDb();
  db.all(
    `SELECT
      c.id as client_id,
      c.name as client_name,
      p.id as project_id,
      p.name as project_name,
      v.id, v.name, v.description, v.affected_items, v.impact, v.recommendation, v.poc,
      v.vuln_references as "references", v.screenshot_path, v.severity, v.created_at, v.updated_at
    FROM projects p
    JOIN clients c ON c.id = p.client_id
    LEFT JOIN project_vulnerabilities pv ON pv.project_id = p.id
    LEFT JOIN vulnerabilities v ON v.id = pv.vulnerability_id
    WHERE p.id = ?
    ORDER BY
      CASE v.severity
        WHEN 'Critical' THEN 5
        WHEN 'High' THEN 4
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 2
        WHEN 'Info' THEN 1
        ELSE 0
      END DESC,
      v.created_at DESC`,
    [projectId],
    callback
  );
}

function renameClient(id, name, callback) {
  const db = getDb();
  db.run('UPDATE clients SET name = ? WHERE id = ?', [name, id], function (err) {
    if (err) return callback(err);
    callback(null, { changes: this.changes });
  });
}

function getProjectById(id, callback) {
  getDb().get('SELECT * FROM projects WHERE id = ?', [id], callback);
}

function renameProject(id, name, callback) {
  const db = getDb();
  db.run('UPDATE projects SET name = ? WHERE id = ?', [name, id], function (err) {
    if (err) return callback(err);
    callback(null, { changes: this.changes });
  });
}

function updateProject(id, { name, project_type, project_method, assigned_engineer_id, assist_engineer_id, kickoff_date, initial_report_date, final_report_date, project_links, mandays_kickoff, mandays_infogath, mandays_assessment }, callback) {
  const db = getDb();
  db.run(
    `UPDATE projects SET
       name = ?,
       project_type = ?,
       project_method = ?,
       assigned_engineer_id = ?,
       assist_engineer_id = ?,
       kickoff_date = ?,
       initial_report_date = ?,
       final_report_date = ?,
       project_links = ?,
       mandays_kickoff = ?,
       mandays_infogath = ?,
       mandays_assessment = ?
     WHERE id = ?`,
    [name, project_type || 'web', project_method || 'blackbox', assigned_engineer_id || null, assist_engineer_id || null, kickoff_date || null, initial_report_date || null, final_report_date || null, project_links || null, mandays_kickoff ?? 1, mandays_infogath ?? 5, mandays_assessment ?? 0, id],
    function(err) {
      if (err) return callback(err);
      callback(null, { changes: this.changes });
    }
  );
}

function updateProjectReports(id, { link_report_en, link_report_id }, callback) {
  getDb().run(
    `UPDATE projects SET link_report_en = ?, link_report_id = ? WHERE id = ?`,
    [link_report_en || null, link_report_id || null, id],
    function(err) { callback(err, { changes: this?.changes }); }
  );
}

function updateProjectReportStatus(id, statuses, callback) {
  const { initial_report_status, final_report_status, initial_completed_by, final_completed_by, initial_completed_at, final_completed_at } = statuses;
  let updates = [];
  let params = [];
  if (initial_report_status) {
    updates.push('initial_report_status = ?');
    params.push(initial_report_status);
  }
  if (final_report_status) {
    updates.push('final_report_status = ?');
    params.push(final_report_status);
  }
  if (initial_completed_by) {
    updates.push('initial_completed_by = ?');
    params.push(initial_completed_by);
  }
  if (final_completed_by) {
    updates.push('final_completed_by = ?');
    params.push(final_completed_by);
  }
  if (initial_completed_at) {
    updates.push('initial_completed_at = ?');
    params.push(initial_completed_at);
  }
  if (final_completed_at) {
    updates.push('final_completed_at = ?');
    params.push(final_completed_at);
  }
  if (updates.length === 0) return callback(null, { changes: 0 });
  
  params.push(id);
  const q = `UPDATE projects SET ${updates.join(', ')} WHERE id = ?`;
  getDb().run(q, params, function (err) { callback(err, { changes: this?.changes }); });
}

function startRetest(id, { retest_pic_id, retest_assist_id, retest_start_date, retest_end_date }, callback) {
  getDb().run(
    `UPDATE projects SET
       retest_status = 'started',
       retest_pic_id = ?,
       retest_assist_id = ?,
       retest_start_date = ?,
       retest_end_date = ?,
       final_report_date = ?
     WHERE id = ?`,
    [retest_pic_id || null, retest_assist_id || null, retest_start_date || null, retest_end_date || null, retest_end_date || null, id],
    function (err) { callback(err, { changes: this?.changes }); }
  );
}

function addVulnerabilityToProject(projectId, vulnId, callback) {
  const db = getDb();
  db.run(
    'INSERT OR IGNORE INTO project_vulnerabilities (project_id, vulnerability_id) VALUES (?, ?)',
    [projectId, vulnId],
    function (err) {
      if (err) return callback(err);
      callback(null, { changes: this.changes });
    }
  );
}

function removeVulnerabilityFromProject(projectId, vulnId, callback) {
  const db = getDb();
  db.run(
    'DELETE FROM project_vulnerabilities WHERE project_id = ? AND vulnerability_id = ?',
    [projectId, vulnId],
    function (err) {
      if (err) return callback(err);
      callback(null, { changes: this.changes });
    }
  );
}

function getProjectFullVulnerabilities(projectId, callback) {
  const db = getDb();
  db.all(
    `SELECT v.id, v.name, v.description, v.affected_items, v.impact, v.recommendation, v.poc,
            v.vuln_references as "references", v.screenshot_path, v.severity, v.created_at, v.updated_at
     FROM project_vulnerabilities pv
     JOIN vulnerabilities v ON v.id = pv.vulnerability_id
     WHERE pv.project_id = ?
     ORDER BY
       CASE v.severity
         WHEN 'Critical' THEN 5 WHEN 'High' THEN 4 WHEN 'Medium' THEN 3
         WHEN 'Low' THEN 2 WHEN 'Info' THEN 1 ELSE 0
       END DESC, pv.created_at DESC`,
    [projectId],
    callback
  );
}

// ─── Notifications ────────────────────────────────────────────────────────────
function initNotifications() {
  getDb().run(`
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT,
      is_read INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

function createNotification({ userId, type, title, message }, callback) {
  getDb().run(
    'INSERT INTO notifications (user_id, type, title, message) VALUES (?,?,?,?)',
    [userId, type, title, message || null],
    callback || (() => {})
  );
}

/** Notify all management users (admin, manager, pm) */
function notifyManagement({ type, title, message }, callback) {
  const db = getDb();
  db.all("SELECT id FROM users WHERE role IN ('admin','manager','pm')", [], (err, rows) => {
    if (err || !rows?.length) return (callback || (() => {}))();
    const stmt = db.prepare('INSERT INTO notifications (user_id, type, title, message) VALUES (?,?,?,?)');
    for (const r of rows) stmt.run([r.id, type, title, message || null]);
    stmt.finalize(callback || (() => {}));
  });
}

function getNotifications(userId, callback) {
  getDb().all(
    'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
    [userId], callback
  );
}

function markNotificationsRead(userId, callback) {
  getDb().run(
    'UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0',
    [userId],
    function(err) { callback(err, { changes: this?.changes }); }
  );
}

module.exports = {
  getDb,
  // Vulnerabilities
  listVulnerabilities,
  getAllVulnerabilities,
  getVulnerabilityById,
  saveVulnerability,
  updateVulnerability,
  deleteVulnerability,
  searchVulnerabilities,
  countVulnerabilities,
  // Clients
  getClients,
  createClient,
  deleteClient,
  renameClient,
  // Projects
  getProjectsByClient,
  createProject,
  deleteProject,
  renameProject,
  getProjectById,
  updateProject,
  updateProjectReports,
  updateProjectReportStatus,
  startRetest,
  getProjectVulnerabilityIds,
  setProjectVulnerabilities,
  addVulnerabilityToProject,
  removeVulnerabilityFromProject,
  getProjectFullVulnerabilities,
  getProjectExportData,
  // Users (multi-role auth)
  getUserByUsername,
  getAllUsers,
  createUser,
  deleteUser,
  getAllEngineers,
  // Access requests
  getAccessRequests,
  createAccessRequest,
  updateAccessRequest,
  // Dashboard
  getDashboardSummary,
  getClientsByEngineer,
  getAllProjects,
  getProjectAccessRequests,
  createProjectAccessRequest,
  updateProjectAccessRequest,
  // Activity log
  writeActivityLog,
  getActivityLog,
  // Clients with projects
  getClientsWithProjects,
  // User management extras
  getUserById,
  changePassword,
  // Notifications
  createNotification,
  notifyManagement,
  getNotifications,
  markNotificationsRead,
};

