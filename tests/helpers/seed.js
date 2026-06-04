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

async function seedDatabase(dbPath) {
  const db = await getDbConnection(dbPath);

  try {
    // Disable foreign keys temporarily
    await runQuery(db, 'PRAGMA foreign_keys = OFF');

    // Clean tables
    await runQuery(db, 'DELETE FROM clients');
    await runQuery(db, 'DELETE FROM projects');
    await runQuery(db, 'DELETE FROM board_statuses');

    // Seed board statuses
    await runQuery(db, `
      INSERT INTO board_statuses (id, name, color, sort_order, team) VALUES
      (301, 'Offensive Status 1', '#ff0000', 0, 'offensive'),
      (302, 'IT Audit Status 1', '#0000ff', 0, 'itaudit'),
      (303, 'Offensive Status 2', '#ff00ff', 1, 'offensive')
    `);

    // Seed clients
    await runQuery(db, `
      INSERT INTO clients (id, name, team) VALUES
      (101, 'Client Offensive', 'offensive'),
      (102, 'Client IT Audit', 'itaudit')
    `);

    // Seed projects
    await runQuery(db, `
      INSERT INTO projects (id, client_id, name, team, board_status_id, project_type, project_method, is_archived, mandays_initial_report, mandays_assessment) VALUES
      (201, 101, 'Project Offensive', 'offensive', 301, 'web', 'blackbox', 0, 1, 0),
      (202, 102, 'Project IT Audit', 'itaudit', 302, 'web', 'blackbox', 0, 1, 0)
    `);

    await runQuery(db, 'PRAGMA foreign_keys = ON');
  } finally {
    await new Promise((resolve) => db.close(resolve));
  }
}

module.exports = { seedDatabase };
