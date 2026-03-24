const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = path.join(__dirname, 'vulnerabilities.db');

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
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `;
  db.run(createTable, (err) => {
    if (err) {
      console.error('Error creating table:', err.message);
    } else {
      console.log('Vulnerabilities table ready.');
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
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(client_id, name)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS project_vulnerabilities (
      project_id INTEGER NOT NULL,
      vulnerability_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(project_id, vulnerability_id)
    )
  `);
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
    recommendation, poc, screenshot_path, severity
  } = data;
  const references = data.references || data.vuln_references || '';
  db.run(
    `INSERT INTO vulnerabilities 
      (name, description, affected_items, impact, recommendation, poc, vuln_references, screenshot_path, severity)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [name, description, affected_items, impact, recommendation, poc, references, screenshot_path || null, severity || 'Medium'],
    function (err) {
      if (err) return callback(err);
      callback(null, { id: this.lastID });
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
    'SELECT id, client_id, name, created_at FROM projects WHERE client_id = ? ORDER BY name COLLATE NOCASE ASC',
    [clientId],
    callback
  );
}

function createProject(clientId, name, callback) {
  const db = getDb();
  db.run('INSERT INTO projects (client_id, name) VALUES (?, ?)', [clientId, name], function (err) {
    if (err) return callback(err);
    callback(null, { id: this.lastID });
  });
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

function renameProject(id, name, callback) {
  const db = getDb();
  db.run('UPDATE projects SET name = ? WHERE id = ?', [name, id], function (err) {
    if (err) return callback(err);
    callback(null, { changes: this.changes });
  });
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

module.exports = {
  getDb,
  listVulnerabilities,
  getAllVulnerabilities,
  getVulnerabilityById,
  saveVulnerability,
  deleteVulnerability,
  searchVulnerabilities,
  countVulnerabilities,
  getClients,
  createClient,
  deleteClient,
  renameClient,
  getProjectsByClient,
  createProject,
  deleteProject,
  renameProject,
  getProjectVulnerabilityIds,
  setProjectVulnerabilities,
  addVulnerabilityToProject,
  removeVulnerabilityFromProject,
  getProjectFullVulnerabilities,
  getProjectExportData,
};
