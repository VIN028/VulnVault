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
        db.run('PRAGMA foreign_keys = ON');
        initializeDb();
      }
    });
  }
  return db;
}

function migrateProjectVulnerabilitiesConstraints() {
  db.get(
    `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'project_vulnerabilities'`,
    (err, row) => {
      if (err) {
        console.error('[Migration] Failed to inspect project_vulnerabilities:', err.message);
        return;
      }
      if (!row?.sql || row.sql.includes('FOREIGN KEY')) return;

      console.log('[Migration] Rebuilding project_vulnerabilities with foreign keys...');

      const rollback = (migrationErr) => {
        db.run('ROLLBACK', () => {
          db.run('PRAGMA foreign_keys = ON');
          console.error('[Migration] Failed to rebuild project_vulnerabilities:', migrationErr.message);
        });
      };

      db.run('PRAGMA foreign_keys = OFF', (pragmaErr) => {
        if (pragmaErr) {
          console.error('[Migration] Failed to disable foreign keys:', pragmaErr.message);
          return;
        }

        db.run('BEGIN IMMEDIATE TRANSACTION', (beginErr) => {
          if (beginErr) return rollback(beginErr);

          db.run('DROP TABLE IF EXISTS project_vulnerabilities_new', (cleanupErr) => {
            if (cleanupErr) return rollback(cleanupErr);

            db.run(
              `CREATE TABLE project_vulnerabilities_new (
              project_id INTEGER NOT NULL,
              vulnerability_id INTEGER NOT NULL,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
              PRIMARY KEY(project_id, vulnerability_id),
              FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
              FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
            )`,
              (createErr) => {
                if (createErr) return rollback(createErr);

                db.run(
                  `INSERT OR IGNORE INTO project_vulnerabilities_new (project_id, vulnerability_id, created_at)
                   SELECT pv.project_id, pv.vulnerability_id, COALESCE(pv.created_at, CURRENT_TIMESTAMP)
                   FROM project_vulnerabilities pv
                   JOIN projects p ON p.id = pv.project_id
                   JOIN vulnerabilities v ON v.id = pv.vulnerability_id`,
                  (insertErr) => {
                    if (insertErr) return rollback(insertErr);

                    db.run('DROP TABLE project_vulnerabilities', (dropErr) => {
                      if (dropErr) return rollback(dropErr);

                      db.run('ALTER TABLE project_vulnerabilities_new RENAME TO project_vulnerabilities', (renameErr) => {
                        if (renameErr) return rollback(renameErr);

                        db.run('COMMIT', (commitErr) => {
                          db.run('PRAGMA foreign_keys = ON');
                          if (commitErr) {
                            console.error('[Migration] Failed to commit project_vulnerabilities rebuild:', commitErr.message);
                            return;
                          }
                          console.log('[Migration] project_vulnerabilities foreign keys enabled.');
                        });
                      });
                    });
                  }
                );
              }
            );
          });
        });
      });
    }
  );
}

function migrateProjectsConstraints() {
  db.get(
    `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'projects'`,
    (err, row) => {
      if (err) {
        console.error('[Migration] Failed to inspect projects:', err.message);
        return;
      }
      if (!row?.sql || row.sql.includes('FOREIGN KEY (client_id)')) return;

      console.log('[Migration] Rebuilding projects with client foreign key...');

      const rollback = (migrationErr) => {
        db.run('ROLLBACK', () => {
          db.run('PRAGMA foreign_keys = ON');
          console.error('[Migration] Failed to rebuild projects:', migrationErr.message);
        });
      };

      db.run('PRAGMA foreign_keys = OFF', (pragmaErr) => {
        if (pragmaErr) {
          console.error('[Migration] Failed to disable foreign keys:', pragmaErr.message);
          return;
        }

        db.run('BEGIN IMMEDIATE TRANSACTION', (beginErr) => {
          if (beginErr) return rollback(beginErr);

          db.run('DROP TABLE IF EXISTS projects_new', (cleanupErr) => {
            if (cleanupErr) return rollback(cleanupErr);

            db.run(
              `CREATE TABLE projects_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                project_type TEXT DEFAULT 'web',
                assigned_engineer_id INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                assist_engineer_id INTEGER,
                kickoff_date TEXT,
                initial_report_date TEXT,
                final_report_date TEXT,
                link_report_en TEXT,
                link_report_id TEXT,
                initial_report_status TEXT DEFAULT 'pending',
                final_report_status TEXT DEFAULT 'pending',
                initial_completed_by TEXT,
                final_completed_by TEXT,
                initial_completed_at TEXT,
                final_completed_at TEXT,
                project_links TEXT,
                mandays_kickoff INTEGER DEFAULT 1,
                mandays_infogath INTEGER DEFAULT 5,
                retest_status TEXT DEFAULT 'none',
                retest_start_date TEXT,
                retest_end_date TEXT,
                retest_pic_id INTEGER,
                retest_assist_id INTEGER,
                project_method TEXT DEFAULT 'blackbox',
                mandays_assessment INTEGER DEFAULT 0,
                highlight_notes TEXT,
                highlight_text TEXT,
                board_status_id INTEGER,
                team TEXT DEFAULT 'offensive',
                service TEXT,
                engineer_3_id INTEGER,
                engineer_4_id INTEGER,
                engineer_5_id INTEGER,
                engineer_6_id INTEGER,
                engineer_7_id INTEGER,
                engineer_8_id INTEGER,
                engineer_9_id INTEGER,
                engineer_10_id INTEGER,
                start_date TEXT,
                mandays_initial_report INTEGER DEFAULT 1,
                is_archived INTEGER DEFAULT 0,
                archived_at TEXT,
                schedule_policy_version TEXT,
                UNIQUE(client_id, name),
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
              )`,
              (createErr) => {
                if (createErr) return rollback(createErr);

                db.run(
                  `INSERT OR IGNORE INTO projects_new (
                    id, client_id, name, project_type, assigned_engineer_id, created_at,
                    assist_engineer_id, kickoff_date, initial_report_date, final_report_date,
                    link_report_en, link_report_id, initial_report_status, final_report_status,
                    initial_completed_by, final_completed_by, initial_completed_at, final_completed_at,
                    project_links, mandays_kickoff, mandays_infogath, retest_status,
                    retest_start_date, retest_end_date, retest_pic_id, retest_assist_id,
                    project_method, mandays_assessment, highlight_notes, highlight_text,
                    board_status_id, team, service, engineer_3_id, engineer_4_id, engineer_5_id,
                    engineer_6_id, engineer_7_id, engineer_8_id, engineer_9_id, engineer_10_id,
                    start_date, mandays_initial_report, is_archived, archived_at, schedule_policy_version
                  )
                  SELECT
                    p.id, p.client_id, p.name, COALESCE(p.project_type, 'web'), p.assigned_engineer_id, p.created_at,
                    p.assist_engineer_id, p.kickoff_date, p.initial_report_date, p.final_report_date,
                    p.link_report_en, p.link_report_id, COALESCE(p.initial_report_status, 'pending'), COALESCE(p.final_report_status, 'pending'),
                    p.initial_completed_by, p.final_completed_by, p.initial_completed_at, p.final_completed_at,
                    p.project_links, COALESCE(p.mandays_kickoff, 1), COALESCE(p.mandays_infogath, 5), COALESCE(p.retest_status, 'none'),
                    p.retest_start_date, p.retest_end_date, p.retest_pic_id, p.retest_assist_id,
                    COALESCE(p.project_method, 'blackbox'), COALESCE(p.mandays_assessment, 0), p.highlight_notes, p.highlight_text,
                    p.board_status_id, COALESCE(p.team, 'offensive'), p.service, p.engineer_3_id, p.engineer_4_id, p.engineer_5_id,
                    p.engineer_6_id, p.engineer_7_id, p.engineer_8_id, p.engineer_9_id, p.engineer_10_id,
                    p.start_date, COALESCE(p.mandays_initial_report, 1), COALESCE(p.is_archived, 0), p.archived_at, p.schedule_policy_version
                  FROM projects p
                  JOIN clients c ON c.id = p.client_id`,
                  (insertErr) => {
                    if (insertErr) return rollback(insertErr);

                    db.run('DROP TABLE projects', (dropErr) => {
                      if (dropErr) return rollback(dropErr);

                      db.run('ALTER TABLE projects_new RENAME TO projects', (renameErr) => {
                        if (renameErr) return rollback(renameErr);

                        db.run('COMMIT', (commitErr) => {
                          db.run('PRAGMA foreign_keys = ON');
                          if (commitErr) {
                            console.error('[Migration] Failed to commit projects rebuild:', commitErr.message);
                            return;
                          }
                          console.log('[Migration] projects client foreign key enabled.');
                        });
                      });
                    });
                  }
                );
              }
            );
          });
        });
      });
    }
  );
}

function migrateNotificationsConstraints() {
  db.get(
    `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'notifications'`,
    (err, row) => {
      if (err) {
        console.error('[Migration] Failed to inspect notifications:', err.message);
        return;
      }
      if (!row?.sql || row.sql.includes('FOREIGN KEY (user_id)')) return;

      console.log('[Migration] Rebuilding notifications with user foreign key...');

      const rollback = (migrationErr) => {
        db.run('ROLLBACK', () => {
          db.run('PRAGMA foreign_keys = ON');
          console.error('[Migration] Failed to rebuild notifications:', migrationErr.message);
        });
      };

      db.run('PRAGMA foreign_keys = OFF', (pragmaErr) => {
        if (pragmaErr) {
          console.error('[Migration] Failed to disable foreign keys:', pragmaErr.message);
          return;
        }

        db.run('BEGIN IMMEDIATE TRANSACTION', (beginErr) => {
          if (beginErr) return rollback(beginErr);

          db.run('DROP TABLE IF EXISTS notifications_new', (cleanupErr) => {
            if (cleanupErr) return rollback(cleanupErr);

            db.run(
              `CREATE TABLE notifications_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT,
                is_read INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
              )`,
              (createErr) => {
                if (createErr) return rollback(createErr);

                db.run(
                  `INSERT OR IGNORE INTO notifications_new (id, user_id, type, title, message, is_read, created_at)
                   SELECT n.id, n.user_id, n.type, n.title, n.message, COALESCE(n.is_read, 0), n.created_at
                   FROM notifications n
                   JOIN users u ON u.id = n.user_id`,
                  (insertErr) => {
                    if (insertErr) return rollback(insertErr);

                    db.run('DROP TABLE notifications', (dropErr) => {
                      if (dropErr) return rollback(dropErr);

                      db.run('ALTER TABLE notifications_new RENAME TO notifications', (renameErr) => {
                        if (renameErr) return rollback(renameErr);

                        db.run('COMMIT', (commitErr) => {
                          db.run('PRAGMA foreign_keys = ON');
                          if (commitErr) {
                            console.error('[Migration] Failed to commit notifications rebuild:', commitErr.message);
                            return;
                          }
                          console.log('[Migration] notifications user foreign key enabled.');
                        });
                      });
                    });
                  }
                );
              }
            );
          });
        });
      });
    }
  );
}

const PROJECT_ASSIGNMENT_SLOTS = [
  'assigned_engineer_id',
  'assist_engineer_id',
  'engineer_3_id',
  'engineer_4_id',
  'engineer_5_id',
  'engineer_6_id',
  'engineer_7_id',
  'engineer_8_id',
  'engineer_9_id',
  'engineer_10_id',
];

function normalizeNullableId(value) {
  if (value === null || value === undefined || value === '') return null;
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : NaN;
}

function validateDeliveryAssignments(team, assignments, callback) {
  const teamVal = team || 'offensive';
  const entries = Object.entries(assignments || {})
    .map(([slot, value]) => [slot, normalizeNullableId(value)])
    .filter(([, id]) => id !== null);

  const invalid = entries.find(([, id]) => Number.isNaN(id));
  if (invalid) return callback(new Error(`Invalid assignment user id for ${invalid[0]}`));

  const ids = entries.map(([, id]) => id);
  const duplicate = ids.find((id, idx) => ids.indexOf(id) !== idx);
  if (duplicate) return callback(new Error('Duplicate engineer assignment is not allowed'));
  if (!ids.length) return callback(null);

  const placeholders = ids.map(() => '?').join(',');
  db.all(
    `SELECT id, role, team, COALESCE(is_active, 1) AS is_active
     FROM users
     WHERE id IN (${placeholders})`,
    ids,
    (err, rows) => {
      if (err) return callback(err);
      const byId = new Map((rows || []).map(row => [Number(row.id), row]));
      for (const [slot, id] of entries) {
        const user = byId.get(Number(id));
        if (!user || Number(user.is_active) !== 1) {
          return callback(new Error(`Assigned user for ${slot} does not exist or is inactive`));
        }
        if (!['engineer', 'consultant'].includes(user.role)) {
          return callback(new Error(`Assigned user for ${slot} must be an engineer or consultant`));
        }
        if ((user.team || 'offensive') !== teamVal) {
          return callback(new Error(`Assigned user for ${slot} does not match project team`));
        }
      }
      callback(null);
    }
  );
}

function runProjectDataMigrations() {
  db.serialize(() => {
    db.run(
      `UPDATE projects
       SET final_report_status = 'completed',
           initial_report_status = 'completed',
           final_completed_at = COALESCE(archived_at, datetime('now')),
           initial_completed_at = COALESCE(archived_at, datetime('now')),
           final_completed_by = 'System Migration',
           initial_completed_by = 'System Migration'
       WHERE is_archived = 1 AND final_report_status = 'pending'`,
      function(err) {
        if (err) {
          console.error('[Migration] Failed to migrate archived projects:', err.message);
        } else if (this.changes > 0) {
          console.log(`[Migration] Successfully migrated ${this.changes} archived projects to completed.`);
        }
      }
    );

    db.run(
      `UPDATE projects
       SET initial_report_status = 'completed',
           initial_completed_at = COALESCE(initial_completed_at, final_completed_at, archived_at, datetime('now')),
           initial_completed_by = COALESCE(initial_completed_by, final_completed_by, 'System Migration')
       WHERE is_archived = 1
         AND final_report_status = 'completed'
         AND initial_report_status != 'completed'`,
      function(err) {
        if (err) {
          console.error('[Migration] Failed to migrate archived initial statuses:', err.message);
        } else if (this.changes > 0) {
          console.log(`[Migration] Successfully migrated ${this.changes} archived projects to initial completed.`);
        }
      }
    );

    db.run(
      `UPDATE projects
       SET board_status_id = (
         SELECT bs.id
         FROM board_statuses bs
         WHERE bs.team = COALESCE(projects.team, 'offensive')
         ORDER BY bs.sort_order ASC, bs.id ASC
         LIMIT 1
       )
       WHERE is_archived = 0
         AND board_status_id IS NULL
         AND EXISTS (
           SELECT 1
           FROM board_statuses bs
           WHERE bs.team = COALESCE(projects.team, 'offensive')
         )`,
      function(err) {
        if (err) {
          console.error('[Migration] Failed to assign default board status:', err.message);
        } else if (this.changes > 0) {
          console.log(`[Migration] Assigned default board status to ${this.changes} active projects.`);
        }
      }
    );
  });
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
      db.run(`ALTER TABLE vulnerabilities ADD COLUMN cvss_score TEXT`, () => {});
      db.run(`ALTER TABLE vulnerabilities ADD COLUMN cvss_vector TEXT`, () => {});
    }
  });

  db.run(`
    CREATE TABLE IF NOT EXISTS clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, () => {
    db.run(`ALTER TABLE clients ADD COLUMN engagement_reference TEXT`, () => {});
    db.run(`ALTER TABLE clients ADD COLUMN engagement_info TEXT`, () => {});
  });

  db.run(`
    CREATE TABLE IF NOT EXISTS projects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      project_type TEXT DEFAULT 'web',
      scope_target TEXT,
      assigned_engineer_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(client_id, name),
      FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
    )
  `, () => {
    db.serialize(() => {
      db.run(`ALTER TABLE projects ADD COLUMN project_type TEXT DEFAULT 'web'`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN scope_target TEXT`, () => {});
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
      db.run(`ALTER TABLE projects ADD COLUMN highlight_notes TEXT`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN highlight_text TEXT`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN board_status_id INTEGER`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN team TEXT DEFAULT 'offensive'`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN service TEXT`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN engineer_3_id INTEGER`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN engineer_4_id INTEGER`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN engineer_5_id INTEGER`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN engineer_6_id INTEGER`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN engineer_7_id INTEGER`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN engineer_8_id INTEGER`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN engineer_9_id INTEGER`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN engineer_10_id INTEGER`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN start_date TEXT`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN mandays_initial_report INTEGER DEFAULT 1`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN is_archived INTEGER DEFAULT 0`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN archived_at TEXT`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN schedule_policy_version TEXT`, () => {});
      db.run(`ALTER TABLE projects ADD COLUMN audit_metadata TEXT`, () => {});
      db.run(`ALTER TABLE clients ADD COLUMN team TEXT DEFAULT 'offensive'`, () => {});
      db.run(`ALTER TABLE board_statuses ADD COLUMN team TEXT DEFAULT 'offensive'`, () => {});
      migrateProjectsConstraints();
      runProjectDataMigrations();
    });
  });

  db.run(`
    CREATE TABLE IF NOT EXISTS engagements (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id INTEGER NOT NULL,
      engagement_reference TEXT,
      engagement_info TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS board_statuses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      color TEXT DEFAULT '#6366f1',
      sort_order INTEGER NOT NULL DEFAULT 0,
      team TEXT DEFAULT 'offensive',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, () => {
    db.run(`ALTER TABLE board_statuses ADD COLUMN team TEXT DEFAULT 'offensive'`, () => {});
  });

  db.run(`
    CREATE TABLE IF NOT EXISTS project_vulnerabilities (
      project_id INTEGER NOT NULL,
      vulnerability_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY(project_id, vulnerability_id),
      FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
      FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
    )
  `, (err) => {
    if (err) {
      console.error('Error creating project_vulnerabilities table:', err.message);
      return;
    }
    migrateProjectVulnerabilitiesConstraints();
  });

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
      role TEXT NOT NULL CHECK(role IN ('admin','manager','pm','engineer','consultant')),
      password_hash TEXT NOT NULL,
      team TEXT DEFAULT 'offensive',
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (!err) seedDefaultUsers();
    db.run(`ALTER TABLE users ADD COLUMN team TEXT DEFAULT 'offensive'`, () => {});
    db.run(`ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1`, () => {});
    db.run(`UPDATE users SET is_active = 1 WHERE is_active IS NULL`, () => {});
    // Migration: recreate users table to update CHECK constraint for 'consultant' role
    db.get("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'", (err, row) => {
      if (err || !row) return;
      if (row.sql && !row.sql.includes('consultant')) {
        console.log('[DB] Migrating users table to support consultant role...');
        db.serialize(() => {
          db.run(`CREATE TABLE users_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','manager','pm','engineer','consultant')),
            password_hash TEXT NOT NULL,
            team TEXT DEFAULT 'offensive',
            is_active INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
          )`);
          db.run(`INSERT INTO users_new SELECT id, username, display_name, role, password_hash, COALESCE(team,'offensive'), COALESCE(is_active,1), created_at FROM users`);
          db.run(`DROP TABLE users`);
          db.run(`ALTER TABLE users_new RENAME TO users`, () => {
            console.log('[DB] Users table migration complete.');
          });
        });
      }
    });
    db.serialize(() => {
      [...PROJECT_ASSIGNMENT_SLOTS, 'retest_pic_id', 'retest_assist_id'].forEach(slot => {
        db.run(
          `UPDATE projects
           SET ${slot} = NULL
           WHERE ${slot} IS NOT NULL
             AND NOT EXISTS (
               SELECT 1 FROM users u
               WHERE u.id = projects.${slot}
                 AND COALESCE(u.is_active, 1) = 1
             )`,
          () => {}
        );
      });
    });
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
    { username: 'admin',   display_name: 'Admin',   role: 'admin',   team: 'offensive' },
    { username: 'manager', display_name: 'Manager', role: 'manager', team: 'offensive' },
    { username: 'pm',      display_name: 'PM',      role: 'pm',      team: 'offensive' },
  ];

  for (const u of defaults) {
    db.get('SELECT id FROM users WHERE username = ?', [u.username], async (err, row) => {
      if (!row) {
        const hash = await bcrypt.hash(DEFAULT_PASSWORD, SALT_ROUNDS);
        db.run(
          'INSERT INTO users (username, display_name, role, password_hash, team) VALUES (?,?,?,?,?)',
          [u.username, u.display_name, u.role, hash, u.team],
          (e) => { if (!e) console.log(`[auth] Seeded user: ${u.username}`); }
        );
      }
    });
  }
}


// ─── User management ──────────────────────────────────────────────────────────
function getUserByUsername(username, callback) {
  getDb().get('SELECT * FROM users WHERE username = ? AND COALESCE(is_active, 1) = 1', [username], callback);
}

function getAllUsers(callback) {
  getDb().all(
    'SELECT id, username, display_name, role, team, is_active, created_at FROM users WHERE COALESCE(is_active, 1) = 1 ORDER BY role, username',
    callback
  );
}

function createUser({ username, display_name, role, password, team }, callback) {
  bcrypt.hash(password, SALT_ROUNDS, (err, hash) => {
    if (err) return callback(err);
    getDb().run(
      'INSERT INTO users (username, display_name, role, password_hash, team, is_active) VALUES (?,?,?,?,?,1)',
      [username, display_name, role, hash, team || 'offensive'],
      function(e) { callback(e, this?.lastID); }
    );
  });
}

function deleteUser(id, callback) {
  const db = getDb();
  db.serialize(() => {
    // Unassign from every delivery/retest slot before deleting the user.
    const assignmentSlots = [
      'assigned_engineer_id',
      'assist_engineer_id',
      'engineer_3_id',
      'engineer_4_id',
      'engineer_5_id',
      'engineer_6_id',
      'engineer_7_id',
      'engineer_8_id',
      'engineer_9_id',
      'engineer_10_id',
      'retest_pic_id',
      'retest_assist_id',
    ];
    assignmentSlots.forEach(slot => {
      db.run(`UPDATE projects SET ${slot} = NULL WHERE ${slot} = ?`, [id]);
    });
    // Clean up access requests
    db.run('DELETE FROM access_requests WHERE requester_id = ? OR target_engineer_id = ?', [id, id]);
    db.run('DELETE FROM project_access_requests WHERE engineer_id = ?', [id]);
    db.run('DELETE FROM notifications WHERE user_id = ?', [id]);
    // Preserve the user row for audit-log joins; only deactivate the account.
    db.run('UPDATE users SET is_active = 0 WHERE id = ?', [id], callback);
  });
}

function getUserById(id, callback) {
  getDb().get('SELECT id, username, display_name, role, team, password_hash, COALESCE(is_active, 1) AS is_active FROM users WHERE id = ?', [id], callback);
}

function changePassword(id, newPasswordHash, callback) {
  getDb().run('UPDATE users SET password_hash = ? WHERE id = ?', [newPasswordHash, id], function(err) {
    callback(err, { changes: this?.changes });
  });
}

function getAllEngineers(opts, callback) {
  if (typeof opts === 'function') { callback = opts; opts = {}; }
  let sql = 'SELECT id, username, display_name, team, role FROM users WHERE role IN ("engineer","consultant") AND COALESCE(is_active, 1) = 1';
  const params = [];
  if (opts.team) {
    sql += ' AND team = ?';
    params.push(opts.team);
  }
  sql += ' ORDER BY display_name';
  getDb().all(sql, params, callback);
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
function getDashboardSummary(opts, callback) {
  if (typeof opts === 'function') { callback = opts; opts = {}; }
  let sql = `
    SELECT c.id AS client_id, c.name AS client_name,
           p.id AS project_id, p.name AS project_name, p.scope_target, p.board_status_id,
           p.project_type, p.assigned_engineer_id, p.assist_engineer_id,
           p.engineer_3_id, p.engineer_4_id, p.engineer_5_id, p.engineer_6_id, p.engineer_7_id, p.engineer_8_id, p.engineer_9_id, p.engineer_10_id,
           p.kickoff_date, p.initial_report_date, p.final_report_date,
           p.initial_report_status, p.final_report_status,
           p.initial_completed_by, p.final_completed_by,
           p.initial_completed_at, p.final_completed_at,
           p.is_archived, p.archived_at,
           p.start_date, p.mandays_assessment, p.mandays_initial_report,
           p.team, p.service, p.audit_metadata,
           p.retest_status, p.retest_start_date, p.retest_end_date,
           p.retest_pic_id, p.retest_assist_id,
           u.display_name AS engineer_name,
           u2.display_name AS assist_engineer_name,
           u5.display_name AS engineer_3_name,
           u6.display_name AS engineer_4_name,
           u7.display_name AS engineer_5_name,
           u8.display_name AS engineer_6_name,
           u9.display_name AS engineer_7_name,
           u10.display_name AS engineer_8_name,
           u11.display_name AS engineer_9_name,
           u12.display_name AS engineer_10_name,
           u3.display_name AS retest_pic_name,
           u4.display_name AS retest_assist_name,
           (SELECT COUNT(*) FROM project_vulnerabilities pv WHERE pv.project_id = p.id) AS finding_count
    FROM clients c
    JOIN projects p ON p.client_id = c.id
    LEFT JOIN users u  ON u.id  = p.assigned_engineer_id
    LEFT JOIN users u2 ON u2.id = p.assist_engineer_id
    LEFT JOIN users u3 ON u3.id = p.retest_pic_id
    LEFT JOIN users u4 ON u4.id = p.retest_assist_id
    LEFT JOIN users u5 ON u5.id = p.engineer_3_id
    LEFT JOIN users u6 ON u6.id = p.engineer_4_id
    LEFT JOIN users u7 ON u7.id = p.engineer_5_id
    LEFT JOIN users u8 ON u8.id = p.engineer_6_id
    LEFT JOIN users u9 ON u9.id = p.engineer_7_id
    LEFT JOIN users u10 ON u10.id = p.engineer_8_id
    LEFT JOIN users u11 ON u11.id = p.engineer_9_id
    LEFT JOIN users u12 ON u12.id = p.engineer_10_id`;
  const params = [];
  if (opts.team) {
    sql += `\n    WHERE p.team = ?`;
    params.push(opts.team);
  }
  sql += `\n    ORDER BY c.name, p.name`;
  getDb().all(sql, params, callback);
}

// Engineers only see clients where they have an assigned project
function getClientsByEngineer(engineerId, callback) {
  getDb().all(`
    SELECT DISTINCT c.id, c.name, c.engagement_reference, c.engagement_info, c.created_at
    FROM clients c
    JOIN projects p ON p.client_id = c.id
    WHERE p.assigned_engineer_id = ?
       OR p.assist_engineer_id = ?
       OR p.engineer_3_id = ?
       OR p.engineer_4_id = ?
       OR p.engineer_5_id = ?
       OR p.engineer_6_id = ?
       OR p.engineer_7_id = ?
       OR p.engineer_8_id = ?
       OR p.engineer_9_id = ?
       OR p.engineer_10_id = ?
       OR p.retest_pic_id = ?
       OR p.retest_assist_id = ?
    ORDER BY c.name
  `, [engineerId, engineerId, engineerId, engineerId, engineerId, engineerId, engineerId, engineerId, engineerId, engineerId, engineerId, engineerId], callback);
}

// Consultants see clients that belong to the 'itaudit' team OR where they have an assigned project
function getClientsByConsultant(consultantId, callback) {
  getDb().all(`
    SELECT DISTINCT c.id, c.name, c.engagement_reference, c.engagement_info, c.team, c.created_at
    FROM clients c
    LEFT JOIN projects p ON p.client_id = c.id
    WHERE c.team = 'itaudit'
       OR p.assigned_engineer_id = ?
       OR p.assist_engineer_id = ?
       OR p.engineer_3_id = ?
       OR p.engineer_4_id = ?
       OR p.engineer_5_id = ?
       OR p.engineer_6_id = ?
       OR p.engineer_7_id = ?
       OR p.engineer_8_id = ?
       OR p.engineer_9_id = ?
       OR p.engineer_10_id = ?
       OR p.retest_pic_id = ?
       OR p.retest_assist_id = ?
    ORDER BY c.name
  `, [consultantId, consultantId, consultantId, consultantId, consultantId, consultantId, consultantId, consultantId, consultantId, consultantId, consultantId, consultantId], callback);
}

// All clients with their projects (LEFT JOIN so empty clients appear too)
function getClientsWithProjects(opts, callback) {
  if (typeof opts === 'function') { callback = opts; opts = {}; }
  let sql = `
    SELECT c.id AS client_id, c.name AS client_name, c.team AS client_team,
           c.engagement_reference, c.engagement_info,
           p.id AS project_id, p.name AS project_name, p.scope_target, p.project_type,
           p.kickoff_date, p.initial_report_date, p.final_report_date,
           p.initial_report_status, p.final_report_status,
           p.is_archived, p.archived_at,
           p.assigned_engineer_id,
           p.assist_engineer_id,
           p.engineer_3_id, p.engineer_4_id, p.engineer_5_id, p.engineer_6_id, p.engineer_7_id, p.engineer_8_id, p.engineer_9_id, p.engineer_10_id,
           p.link_report_en, p.link_report_id, p.project_links,
           p.project_method, p.start_date, p.mandays_assessment, p.mandays_initial_report,
           p.team, p.service, p.audit_metadata,
           p.retest_status, p.retest_start_date, p.retest_end_date,
           p.retest_pic_id, p.retest_assist_id,
           u.display_name AS engineer_name,
           u2.display_name AS assist_engineer_name,
           u5.display_name AS engineer_3_name,
           u6.display_name AS engineer_4_name,
           u7.display_name AS engineer_5_name,
           u8.display_name AS engineer_6_name,
           u9.display_name AS engineer_7_name,
           u10.display_name AS engineer_8_name,
           u11.display_name AS engineer_9_name,
           u12.display_name AS engineer_10_name,
           u3.display_name AS retest_pic_name,
           u4.display_name AS retest_assist_name,
           (SELECT COUNT(*) FROM project_vulnerabilities pv WHERE pv.project_id = p.id) AS finding_count
    FROM clients c`;

  const params = [];
  if (opts.team === 'itaudit') {
    sql += `\n    LEFT JOIN projects p ON p.client_id = c.id AND p.team = ?`;
    params.push('itaudit');
  } else if (opts.team === 'offensive') {
    sql += `\n    LEFT JOIN projects p ON p.client_id = c.id AND (p.team = 'offensive' OR p.team IS NULL)`;
  } else {
    sql += `\n    LEFT JOIN projects p ON p.client_id = c.id`;
  }

  sql += `
    LEFT JOIN users u ON u.id = p.assigned_engineer_id
    LEFT JOIN users u2 ON u2.id = p.assist_engineer_id
    LEFT JOIN users u3 ON u3.id = p.retest_pic_id
    LEFT JOIN users u4 ON u4.id = p.retest_assist_id
    LEFT JOIN users u5 ON u5.id = p.engineer_3_id
    LEFT JOIN users u6 ON u6.id = p.engineer_4_id
    LEFT JOIN users u7 ON u7.id = p.engineer_5_id
    LEFT JOIN users u8 ON u8.id = p.engineer_6_id
    LEFT JOIN users u9 ON u9.id = p.engineer_7_id
    LEFT JOIN users u10 ON u10.id = p.engineer_8_id
    LEFT JOIN users u11 ON u11.id = p.engineer_9_id
    LEFT JOIN users u12 ON u12.id = p.engineer_10_id`;

  if (opts.team === 'itaudit') {
    sql += `\n    WHERE c.team = ?`;
    params.push('itaudit');
  } else if (opts.team === 'offensive') {
    sql += `\n    WHERE (c.team = 'offensive' OR c.team IS NULL)`;
  }

  sql += `\n    ORDER BY c.name, p.name`;
  getDb().all(sql, params, callback);
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
    SELECT p.id, p.name, p.scope_target, p.project_type, p.client_id, p.assigned_engineer_id, p.assist_engineer_id,
           p.engineer_3_id, p.engineer_4_id, p.engineer_5_id, p.engineer_6_id, p.engineer_7_id,
           p.engineer_8_id, p.engineer_9_id, p.engineer_10_id, p.team,
           p.kickoff_date, p.initial_report_date, p.final_report_date,
           p.link_report_en, p.link_report_id,
           c.name AS client_name
    FROM projects p JOIN clients c ON c.id = p.client_id
    WHERE p.is_archived = 0
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
    let sql = `
      SELECT par.*, p.name AS project_name, c.name AS client_name,
             u.display_name AS engineer_name
      FROM project_access_requests par
      JOIN projects p ON p.id = par.project_id
      JOIN clients c ON c.id = p.client_id
      JOIN users u ON u.id = par.engineer_id
      WHERE par.status = 'pending'`;
    const params = [];
    if (filter.team) {
      sql += ' AND p.team = ?';
      params.push(filter.team);
    }
    sql += `\n      ORDER BY par.created_at DESC`;
    db.all(sql, params, callback);
  }
}

function createProjectAccessRequest({ engineerId, projectId, message }, callback) {
  const db = getDb();
  db.get(
    `SELECT p.*, u.team AS engineer_team, u.role AS engineer_role, COALESCE(u.is_active, 1) AS engineer_is_active
     FROM projects p
     JOIN users u ON u.id = ?
     WHERE p.id = ?`,
    [engineerId, projectId],
    (lookupErr, row) => {
      if (lookupErr) return callback(lookupErr);
      if (!row) return callback(new Error('Project or engineer not found'));
      if (row.is_archived === 1) return callback(new Error('Cannot request access to an archived project'));
      if (Number(row.engineer_is_active) !== 1) return callback(new Error('Engineer is inactive'));
      if (!['engineer', 'consultant'].includes(row.engineer_role)) return callback(new Error('Only delivery users can request project access'));
      if ((row.engineer_team || 'offensive') !== (row.team || 'offensive')) {
        return callback(new Error('Team mismatch: engineer and project teams do not match'));
      }

      const alreadyAssigned = PROJECT_ASSIGNMENT_SLOTS.some(slot => Number(row[slot]) === Number(engineerId));
      if (alreadyAssigned) return callback(new Error('Engineer is already assigned to this project'));

      const hasOpenSlot = PROJECT_ASSIGNMENT_SLOTS.some(slot => row[slot] === null || row[slot] === undefined || row[slot] === '');
      if (!hasOpenSlot) return callback(new Error('Project resource slots are full'));

      // Upsert: if request already exists and was rejected/approved, reset to pending.
      db.run(
        `INSERT INTO project_access_requests (engineer_id, project_id, message, status)
         VALUES (?,?,?,'pending')
         ON CONFLICT(engineer_id, project_id) DO UPDATE SET
           status='pending', message=excluded.message, created_at=CURRENT_TIMESTAMP, reviewed_at=NULL, reviewed_by=NULL
         WHERE status != 'pending'`,
        [engineerId, projectId, message || null],
        function(e) {
          if (e) return callback(e);
          db.get('SELECT id FROM project_access_requests WHERE engineer_id=? AND project_id=?', [engineerId, projectId], (errQuery, requestRow) => {
            if (errQuery) return callback(errQuery);
            callback(null, requestRow ? requestRow.id : this.lastID);
          });
        }
      );
    }
  );
}

function updateProjectAccessRequest({ id, status, reviewedBy }, callback) {
  const db = getDb();

  if (status !== 'approved') {
    db.run(
      `UPDATE project_access_requests
       SET status=?, reviewed_by=?, reviewed_at=CURRENT_TIMESTAMP
       WHERE id=? AND status='pending'`,
      [status, reviewedBy, id],
      function(err) {
        if (err) return callback(err);
        if (!this.changes) return callback(new Error('Access request is not pending'));
        callback(null);
      }
    );
    return;
  }

  const SLOTS = [
    'assigned_engineer_id',
    'assist_engineer_id',
    'engineer_3_id',
    'engineer_4_id',
    'engineer_5_id',
    'engineer_6_id',
    'engineer_7_id',
    'engineer_8_id',
    'engineer_9_id',
    'engineer_10_id'
  ];

  const rollback = (err) => {
    db.run('ROLLBACK', () => callback(err));
  };

  db.serialize(() => {
    db.run('BEGIN IMMEDIATE TRANSACTION', (beginErr) => {
      if (beginErr) return callback(beginErr);

      db.get(
        `SELECT par.project_id, par.engineer_id, par.status AS request_status,
                p.*, u.team AS engineer_team, COALESCE(u.is_active, 1) AS engineer_is_active
         FROM project_access_requests par
         JOIN projects p ON p.id = par.project_id
         JOIN users u ON u.id = par.engineer_id
         WHERE par.id = ?`,
        [id],
        (err, row) => {
          if (err) return rollback(err);
          if (!row) return rollback(new Error('Access request not found'));
          if (row.request_status !== 'pending') return rollback(new Error('Access request is not pending'));
          if (row.is_archived === 1) return rollback(new Error('Cannot approve access request for an archived project'));
          if (Number(row.engineer_is_active) !== 1) return rollback(new Error('Engineer is inactive'));
          if ((row.engineer_team || 'offensive') !== (row.team || 'offensive')) {
            return rollback(new Error('Team mismatch: engineer and project teams do not match'));
          }

          const engineerId = row.engineer_id;
          const alreadyAssigned = SLOTS.some(slot => Number(row[slot]) === Number(engineerId));
          if (alreadyAssigned) return rollback(new Error('Engineer is already assigned to this project'));

          const emptySlot = SLOTS.find(slot => row[slot] === null || row[slot] === undefined || row[slot] === '');
          if (!emptySlot) return rollback(new Error('Project resource slots are full'));

          db.run(
            `UPDATE projects SET ${emptySlot} = ? WHERE id = ?`,
            [engineerId, row.project_id],
            (projectErr) => {
              if (projectErr) return rollback(projectErr);

              db.run(
                `UPDATE project_access_requests
                 SET status = 'approved', reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP
                 WHERE id = ? AND status = 'pending'`,
                [reviewedBy, id],
                function(requestErr) {
                  if (requestErr) return rollback(requestErr);
                  if (!this.changes) return rollback(new Error('Access request is not pending'));

                  db.run('COMMIT', (commitErr) => {
                    if (commitErr) return rollback(commitErr);
                    callback(null);
                  });
                }
              );
            }
          );
        }
      );
    });
  });
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
            v.vuln_references as "references", v.screenshot_path, v.severity, v.cvss_score, v.cvss_vector, v.bilingual_payload, v.created_at, v.updated_at
     ${fromClause}
     ${whereClause}
     ORDER BY ${orderBy}`,
    params,
    callback
  );
}

// Engineers/users can retrieve all findings
function getAllVulnerabilities(callback) {
  listVulnerabilities({}, callback);
}

function getVulnerabilityById(id, callback) {
  const db = getDb();
  db.get(
    `SELECT id, name, description, affected_items, impact, recommendation, poc,
            vuln_references as "references", screenshot_path, severity, cvss_score, cvss_vector, bilingual_payload, created_at, updated_at
     FROM vulnerabilities WHERE id = ?`,
    [id], callback
  );
}

function saveVulnerability(data, callback) {
  const db = getDb();
  const {
    name, description, affected_items, impact,
    recommendation, poc, screenshot_path, severity,
    bilingual_payload, owner_engineer_id, cvss_score, cvss_vector
  } = data;
  const references = data.references || data.vuln_references || '';
  db.run(
    `INSERT INTO vulnerabilities 
      (name, description, affected_items, impact, recommendation, poc, vuln_references, screenshot_path, severity, bilingual_payload, owner_engineer_id, cvss_score, cvss_vector)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [name, description, affected_items, impact, recommendation, poc, references, screenshot_path || null, severity || 'Medium', bilingual_payload || null, owner_engineer_id || null, cvss_score || null, cvss_vector || null],
    function (err) {
      if (err) return callback(err);
      callback(null, { id: this.lastID });
    }
  );
}

function updateVulnerability(id, data, callback) {
  const db = getDb();
  const { name, description, affected_items, impact, recommendation, poc, screenshot_path, severity, bilingual_payload, cvss_score, cvss_vector } = data;
  const updates = [
    'name=?',
    'description=?',
    'affected_items=?',
    'impact=?',
    'recommendation=?',
    'poc=?',
    'screenshot_path=?',
    'severity=?',
    'cvss_score=?',
    'cvss_vector=?',
  ];
  const params = [
    name,
    description || null,
    affected_items || null,
    impact || null,
    recommendation || null,
    poc || null,
    screenshot_path || null,
    severity || 'Medium',
    cvss_score || null,
    cvss_vector || null,
  ];

  // Undefined means "preserve existing"; null/empty string means "clear".
  if (bilingual_payload !== undefined) {
    updates.push('bilingual_payload=?');
    params.push(bilingual_payload || null);
  }
  params.push(id);

  db.run(
    `UPDATE vulnerabilities SET ${updates.join(', ')} WHERE id=?`,
    params,
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

function getClients(opts, callback) {
  if (typeof opts === 'function') { callback = opts; opts = {}; }
  const db = getDb();
  let sql = 'SELECT id, name, engagement_reference, engagement_info, team, created_at FROM clients';
  const params = [];
  if (opts.team) {
    if (opts.team === 'offensive') {
      sql += ' WHERE (team = ? OR team IS NULL)';
    } else {
      sql += ' WHERE team = ?';
    }
    params.push(opts.team);
  }
  sql += ' ORDER BY name COLLATE NOCASE ASC';
  db.all(sql, params, callback);
}

function createClient(name, opts, callback) {
  // Handle legacy 2-arg call: createClient(name, callback)
  if (typeof opts === 'function') { callback = opts; opts = {}; }
  const { engagement_reference, engagement_info, team } = opts || {};
  const db = getDb();
  db.run('INSERT INTO clients (name, engagement_reference, engagement_info, team) VALUES (?, ?, ?, ?)', [name, engagement_reference || null, engagement_info || null, team || 'offensive'], function (err) {
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
    `SELECT p.id, p.client_id, p.name, p.project_type, p.project_method,
            p.assigned_engineer_id, p.assist_engineer_id,
            p.engineer_3_id, p.engineer_4_id, p.engineer_5_id, p.engineer_6_id, p.engineer_7_id, p.engineer_8_id, p.engineer_9_id, p.engineer_10_id,
            p.kickoff_date,
            p.initial_report_date, p.final_report_date,
            p.initial_report_status, p.final_report_status,
            p.is_archived, p.archived_at,
            p.link_report_en, p.link_report_id, p.project_links,
            p.start_date, p.mandays_assessment, p.mandays_initial_report,
            p.team, p.service,
            p.created_at,
            p.retest_status, p.retest_start_date, p.retest_end_date,
            p.retest_pic_id, p.retest_assist_id,
            u.display_name AS engineer_name,
            u2.display_name AS assist_engineer_name,
            u5.display_name AS engineer_3_name,
            u6.display_name AS engineer_4_name,
            u7.display_name AS engineer_5_name,
            u8.display_name AS engineer_6_name,
            u9.display_name AS engineer_7_name,
            u10.display_name AS engineer_8_name,
            u11.display_name AS engineer_9_name,
            u12.display_name AS engineer_10_name
     FROM projects p
     LEFT JOIN users u ON u.id = p.assigned_engineer_id
     LEFT JOIN users u2 ON u2.id = p.assist_engineer_id
     LEFT JOIN users u5 ON u5.id = p.engineer_3_id
     LEFT JOIN users u6 ON u6.id = p.engineer_4_id
     LEFT JOIN users u7 ON u7.id = p.engineer_5_id
     LEFT JOIN users u8 ON u8.id = p.engineer_6_id
     LEFT JOIN users u9 ON u9.id = p.engineer_7_id
     LEFT JOIN users u10 ON u10.id = p.engineer_8_id
     LEFT JOIN users u11 ON u11.id = p.engineer_9_id
     LEFT JOIN users u12 ON u12.id = p.engineer_10_id
     WHERE p.client_id = ?
     ORDER BY p.name COLLATE NOCASE ASC`,
    [clientId],
    callback
  );
}

// Returns the first board status ID for a given team, or null if none exist
function getDefaultBoardStatus(team, callback) {
  getDb().get(
    'SELECT id FROM board_statuses WHERE team = ? ORDER BY sort_order ASC LIMIT 1',
    [team || 'offensive'],
    (err, row) => callback(err, row ? row.id : null)
  );
}

function createProject(clientId, name, opts, callback) {
  // Handle legacy 2-arg call: createProject(clientId, name, callback)
  if (typeof opts === 'function') { callback = opts; opts = {}; }
  const db = getDb();
  const {
    project_type, scope_target, project_method, assigned_engineer_id, assist_engineer_id,
    engineer_3_id, engineer_4_id, engineer_5_id, engineer_6_id, engineer_7_id, engineer_8_id, engineer_9_id, engineer_10_id,
    kickoff_date, initial_report_date, final_report_date, project_links, start_date,
    mandays_initial_report, mandays_assessment, team, service, is_archived, archived_at,
    initial_report_status, final_report_status, initial_completed_at, final_completed_at,
    initial_completed_by, final_completed_by, board_status_id, schedule_policy_version,
    audit_metadata
  } = opts || {};

  const teamVal = team || 'offensive';
  const isArchivedVal = is_archived || 0;

  const runInsert = (statusId) => {
    db.run(
      `INSERT INTO projects (
        client_id, name, scope_target, project_type, project_method, assigned_engineer_id, assist_engineer_id,
        engineer_3_id, engineer_4_id, engineer_5_id, engineer_6_id, engineer_7_id, engineer_8_id, engineer_9_id, engineer_10_id,
        kickoff_date, initial_report_date, final_report_date, project_links, start_date,
        mandays_initial_report, mandays_assessment, team, service, is_archived, archived_at,
        initial_report_status, final_report_status, initial_completed_at, final_completed_at,
        initial_completed_by, final_completed_by, board_status_id, schedule_policy_version,
        audit_metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        clientId, name, scope_target || null, project_type || 'web', project_method || 'blackbox', assigned_engineer_id || null, assist_engineer_id || null,
        engineer_3_id || null, engineer_4_id || null, engineer_5_id || null, engineer_6_id || null, engineer_7_id || null, engineer_8_id || null, engineer_9_id || null, engineer_10_id || null,
        kickoff_date || null, initial_report_date || null, final_report_date || null, project_links || null, start_date || null,
        mandays_initial_report ?? 1, mandays_assessment ?? 0, teamVal, service || null, isArchivedVal, archived_at || null,
        initial_report_status || 'pending', final_report_status || 'pending',
        initial_completed_at || null, final_completed_at || null,
        initial_completed_by || null, final_completed_by || null,
        statusId, schedule_policy_version || null,
        audit_metadata || null
      ],
      function (err) {
        if (err) return callback(err);
        callback(null, { id: this.lastID });
      }
    );
  };

  validateDeliveryAssignments(teamVal, {
    assigned_engineer_id, assist_engineer_id, engineer_3_id, engineer_4_id, engineer_5_id,
    engineer_6_id, engineer_7_id, engineer_8_id, engineer_9_id, engineer_10_id,
  }, (validationErr) => {
    if (validationErr) return callback(validationErr);

    if (board_status_id !== undefined) {
      runInsert(board_status_id);
    } else if (isArchivedVal === 1) {
      runInsert(null);
    } else {
      getDefaultBoardStatus(teamVal, (err, statusId) => {
        if (err) return callback(err);
        runInsert(statusId);
      });
    }
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
      p.scope_target,
      p.project_type,
      p.project_method,
      p.kickoff_date,
      p.start_date,
      p.initial_report_date,
      p.final_report_date,
      p.service,
      p.team,
      v.id, v.name, v.description, v.affected_items, v.impact, v.recommendation, v.poc,
      v.vuln_references as "references", v.screenshot_path, v.severity, v.cvss_score, v.cvss_vector, v.bilingual_payload, v.created_at, v.updated_at
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

function getClientById(id, callback) {
  getDb().get('SELECT * FROM clients WHERE id = ?', [id], callback);
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

function updateProject(id, { name, scope_target, project_type, project_method, assigned_engineer_id, assist_engineer_id, engineer_3_id, engineer_4_id, engineer_5_id, engineer_6_id, engineer_7_id, engineer_8_id, engineer_9_id, engineer_10_id, kickoff_date, initial_report_date, final_report_date, project_links, start_date, mandays_initial_report, mandays_assessment, team, service, schedule_policy_version, audit_metadata }, callback) {
  const db = getDb();
  const teamVal = team || 'offensive';
  validateDeliveryAssignments(teamVal, {
    assigned_engineer_id, assist_engineer_id, engineer_3_id, engineer_4_id, engineer_5_id,
    engineer_6_id, engineer_7_id, engineer_8_id, engineer_9_id, engineer_10_id,
  }, (validationErr) => {
    if (validationErr) return callback(validationErr);

    db.run(
      `UPDATE projects SET
         name = ?,
         scope_target = ?,
         project_type = ?,
         project_method = ?,
         assigned_engineer_id = ?,
         assist_engineer_id = ?,
         engineer_3_id = ?,
         engineer_4_id = ?,
         engineer_5_id = ?,
         engineer_6_id = ?,
         engineer_7_id = ?,
         engineer_8_id = ?,
         engineer_9_id = ?,
         engineer_10_id = ?,
         kickoff_date = ?,
         initial_report_date = ?,
         final_report_date = ?,
         project_links = ?,
         start_date = ?,
         mandays_initial_report = ?,
         mandays_assessment = ?,
         team = ?,
         service = ?,
         schedule_policy_version = ?,
         audit_metadata = ?
       WHERE id = ?`,
      [name, scope_target || null, project_type || 'web', project_method || 'blackbox', assigned_engineer_id || null, assist_engineer_id || null, engineer_3_id || null, engineer_4_id || null, engineer_5_id || null, engineer_6_id || null, engineer_7_id || null, engineer_8_id || null, engineer_9_id || null, engineer_10_id || null, kickoff_date || null, initial_report_date || null, final_report_date || null, project_links || null, start_date || null, mandays_initial_report ?? 1, mandays_assessment ?? 0, teamVal, service || null, schedule_policy_version || null, audit_metadata || null, id],
      function(err) {
        if (err) return callback(err);
        callback(null, { changes: this.changes });
      }
    );
  });
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

// ─── Project Highlights ────────────────────────────────────────────────────────
function getProjectHighlight(projectId, callback) {
  getDb().get(
    'SELECT id, name, highlight_notes, highlight_text FROM projects WHERE id = ?',
    [projectId], callback
  );
}

function updateProjectHighlight(projectId, { highlight_notes, highlight_text }, callback) {
  getDb().run(
    'UPDATE projects SET highlight_notes = ?, highlight_text = ? WHERE id = ?',
    [highlight_notes || null, highlight_text || null, projectId],
    function(err) { callback(err, { changes: this?.changes }); }
  );
}

function startRetest(id, { retest_pic_id, retest_assist_id, retest_start_date, retest_end_date }, callback) {
  const db = getDb();
  db.get('SELECT team FROM projects WHERE id = ?', [id], (err, project) => {
    if (err) return callback(err);
    if (!project) return callback(null, { changes: 0 });

    validateDeliveryAssignments(project.team || 'offensive', { retest_pic_id, retest_assist_id }, (validationErr) => {
      if (validationErr) return callback(validationErr);

      db.run(
        `UPDATE projects SET
           retest_status = 'started',
           retest_pic_id = ?,
           retest_assist_id = ?,
           retest_start_date = ?,
           retest_end_date = ?,
           final_report_date = ?
         WHERE id = ?`,
        [retest_pic_id || null, retest_assist_id || null, retest_start_date || null, retest_end_date || null, retest_end_date || null, id],
        function (updateErr) { callback(updateErr, { changes: this?.changes }); }
      );
    });
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
            v.vuln_references as "references", v.screenshot_path, v.severity, v.bilingual_payload, v.created_at, v.updated_at
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
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `, (err) => {
    if (err) {
      console.error('Error creating notifications table:', err.message);
      return;
    }
    migrateNotificationsConstraints();
  });
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
  db.all("SELECT id FROM users WHERE role IN ('admin','manager','pm') AND COALESCE(is_active, 1) = 1", [], (err, rows) => {
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

// ─── Board Statuses (Kanban) ──────────────────────────────────────────────────
function getBoardStatuses(team, callback) {
  if (typeof team === 'function') { callback = team; team = null; }
  const sql = team 
    ? 'SELECT * FROM board_statuses WHERE team = ? ORDER BY sort_order ASC'
    : 'SELECT * FROM board_statuses ORDER BY sort_order ASC';
  const params = team ? [team] : [];
  getDb().all(sql, params, callback);
}

function getBoardStatusById(id, callback) {
  getDb().get('SELECT * FROM board_statuses WHERE id = ?', [id], callback);
}

function createBoardStatus({ name, color, sort_order, team }, callback) {
  getDb().run(
    'INSERT INTO board_statuses (name, color, sort_order, team) VALUES (?, ?, ?, ?)',
    [name, color || '#6366f1', sort_order ?? 0, team || 'offensive'],
    function(err) { callback(err, err ? null : { id: this.lastID }); }
  );
}

function updateBoardStatus(id, { name, color, sort_order }, callback) {
  const updates = [], params = [];
  if (name !== undefined) { updates.push('name = ?'); params.push(name); }
  if (color !== undefined) { updates.push('color = ?'); params.push(color); }
  if (sort_order !== undefined) { updates.push('sort_order = ?'); params.push(sort_order); }
  if (!updates.length) return callback(null, { changes: 0 });
  params.push(id);
  getDb().run(`UPDATE board_statuses SET ${updates.join(', ')} WHERE id = ?`, params,
    function(err) { callback(err, { changes: this?.changes }); }
  );
}

function deleteBoardStatus(id, callback) {
  const db = getDb();
  db.serialize(() => {
    db.run('UPDATE projects SET board_status_id = NULL WHERE board_status_id = ?', [id]);
    db.run('DELETE FROM board_statuses WHERE id = ?', [id], function(err) {
      callback(err, { changes: this?.changes });
    });
  });
}

function reorderBoardStatuses(orderedIds, team, callback) {
  if (typeof team === 'function') { callback = team; team = null; }
  const db = getDb();
  db.serialize(() => {
    const stmt = db.prepare('UPDATE board_statuses SET sort_order = ? WHERE id = ?');
    orderedIds.forEach((id, idx) => stmt.run([idx, id]));
    stmt.finalize(callback);
  });
}

function restoreProject(id, callback) {
  const db = getDb();
  db.get('SELECT team FROM projects WHERE id = ?', [id], (err, proj) => {
    if (err) return callback(err);
    if (!proj) return callback(new Error('Project not found'));
    getDefaultBoardStatus(proj.team, (err2, statusId) => {
      if (err2) return callback(err2);
      db.run(
        'UPDATE projects SET is_archived = 0, archived_at = NULL, board_status_id = ? WHERE id = ?',
        [statusId, id],
        function(err3) {
          if (err3) return callback(err3);
          callback(null, { changes: this.changes });
        }
      );
    });
  });
}

function updateProjectBoardStatus(projectId, statusId, callback) {
  getDb().run(
    'UPDATE projects SET board_status_id = ? WHERE id = ?',
    [statusId, projectId],
    function(err) { callback(err, { changes: this?.changes }); }
  );
}

function updateProjectBoardStatusAndCompletion(projectId, statusId, finalReportStatus, finalCompletedAt, callback) {
  getDb().run(
    'UPDATE projects SET board_status_id = ?, final_report_status = ?, final_completed_at = ? WHERE id = ?',
    [statusId, finalReportStatus, finalCompletedAt, projectId],
    function(err) { callback(err, { changes: this?.changes }); }
  );
}

function getArchivedProjects(opts, callback) {
  if (typeof opts === 'function') { callback = opts; opts = {}; }
  let sql = `
    SELECT p.*, c.name AS client_name, u.display_name AS engineer_name
    FROM projects p
    JOIN clients c ON c.id = p.client_id
    LEFT JOIN users u ON u.id = p.assigned_engineer_id
    WHERE p.is_archived = 1`;
  const params = [];
  if (opts.team) {
    sql += ' AND p.team = ?';
    params.push(opts.team);
  }
  sql += `\n    ORDER BY p.archived_at DESC`;
  getDb().all(sql, params, callback);
}

function archiveProject(id, callback) {
  getDb().run(
    'UPDATE projects SET is_archived = 1, archived_at = CURRENT_TIMESTAMP, board_status_id = NULL WHERE id = ?',
    [id],
    function(err) { callback(err, { changes: this?.changes }); }
  );
}

function getProjectsForBoard(opts, callback) {
  if (typeof opts === 'function') { callback = opts; opts = {}; }
  let sql = `
    SELECT p.id, p.name, p.project_type, p.project_method, p.board_status_id,
           p.kickoff_date, p.initial_report_date, p.final_report_date,
           p.initial_report_status, p.final_report_status,
           p.is_archived, p.archived_at,
           p.retest_status, p.retest_start_date, p.retest_end_date,
           p.assigned_engineer_id, p.assist_engineer_id,
           p.engineer_3_id, p.engineer_4_id, p.engineer_5_id, p.engineer_6_id, p.engineer_7_id, p.engineer_8_id, p.engineer_9_id, p.engineer_10_id,
           p.start_date, p.mandays_assessment, p.mandays_initial_report,
           p.link_report_en, p.link_report_id, p.project_links,
           p.retest_pic_id, p.retest_assist_id,
           p.team, p.service, p.audit_metadata,
           c.id AS client_id, c.name AS client_name,
           u.display_name AS engineer_name,
           u2.display_name AS assist_engineer_name,
           u5.display_name AS engineer_3_name,
           u6.display_name AS engineer_4_name,
           u7.display_name AS engineer_5_name,
           u8.display_name AS engineer_6_name,
           u9.display_name AS engineer_7_name,
           u10.display_name AS engineer_8_name,
           u11.display_name AS engineer_9_name,
           u12.display_name AS engineer_10_name,
           u3.display_name AS retest_pic_name,
           u4.display_name AS retest_assist_name,
           (SELECT COUNT(*) FROM project_vulnerabilities pv WHERE pv.project_id = p.id) AS finding_count
    FROM projects p
    JOIN clients c ON c.id = p.client_id
    LEFT JOIN users u  ON u.id  = p.assigned_engineer_id
    LEFT JOIN users u2 ON u2.id = p.assist_engineer_id
    LEFT JOIN users u3 ON u3.id = p.retest_pic_id
    LEFT JOIN users u4 ON u4.id = p.retest_assist_id
    LEFT JOIN users u5 ON u5.id = p.engineer_3_id
    LEFT JOIN users u6 ON u6.id = p.engineer_4_id
    LEFT JOIN users u7 ON u7.id = p.engineer_5_id
    LEFT JOIN users u8 ON u8.id = p.engineer_6_id
    LEFT JOIN users u9 ON u9.id = p.engineer_7_id
    LEFT JOIN users u10 ON u10.id = p.engineer_8_id
    LEFT JOIN users u11 ON u11.id = p.engineer_9_id
    LEFT JOIN users u12 ON u12.id = p.engineer_10_id
    WHERE p.is_archived = 0`;
  const params = [];
  if (opts.team) {
    sql += ' AND p.team = ?';
    params.push(opts.team);
  }
  sql += `\n    ORDER BY c.name, p.name`;
  getDb().all(sql, params, callback);
}

// ─── Engagements ──────────────────────────────────────────────────────────────
function getEngagementsByClient(clientId, callback) {
  getDb().all(
    'SELECT * FROM engagements WHERE client_id = ? ORDER BY created_at DESC',
    [clientId], callback
  );
}

function getAllEngagements(callback) {
  getDb().all(
    'SELECT e.*, c.name AS client_name FROM engagements e JOIN clients c ON c.id = e.client_id ORDER BY c.name, e.created_at DESC',
    callback
  );
}

function createEngagement(clientId, { engagement_reference, engagement_info }, callback) {
  getDb().run(
    'INSERT INTO engagements (client_id, engagement_reference, engagement_info) VALUES (?, ?, ?)',
    [clientId, engagement_reference || null, engagement_info || null],
    function(err) { callback(err, err ? null : { id: this.lastID }); }
  );
}

// Checks if a user is explicitly assigned to a project in any of the engineer/retest roles
function isUserAssignedToProject(userId, projectId, callback) {
  getDb().get(
    `SELECT 1 FROM projects
     WHERE id = ? AND (
       assigned_engineer_id = ? OR
       assist_engineer_id = ? OR
       engineer_3_id = ? OR
       engineer_4_id = ? OR
       engineer_5_id = ? OR
       engineer_6_id = ? OR
       engineer_7_id = ? OR
       engineer_8_id = ? OR
       engineer_9_id = ? OR
       engineer_10_id = ? OR
       retest_pic_id = ? OR
       retest_assist_id = ?
     )`,
    [projectId, userId, userId, userId, userId, userId, userId, userId, userId, userId, userId, userId, userId],
    (err, row) => {
      if (err) return callback(err);
      callback(null, !!row);
    }
  );
}

// Delivery users can access a project only when explicitly assigned to it.
function checkProjectAccess(userId, role, projectId, callback) {
  isUserAssignedToProject(userId, projectId, callback);
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
  getClientById,
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
  getProjectHighlight,
  updateProjectHighlight,
  getArchivedProjects,
  archiveProject,
  restoreProject,
  getDefaultBoardStatus,
  isUserAssignedToProject,
  checkProjectAccess,
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
  getClientsByConsultant,
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
  // Board statuses (Kanban)
  getBoardStatuses,
  getBoardStatusById,
  createBoardStatus,
  updateBoardStatus,
  deleteBoardStatus,
  reorderBoardStatuses,
  updateProjectBoardStatus,
  updateProjectBoardStatusAndCompletion,
  getProjectsForBoard,
  // Engagements
  getEngagementsByClient,
  getAllEngagements,
  createEngagement,
};
