const cp = require('child_process');

const files = [
  'server.js',
  'database.js',
  'auth.js',
  'public/js/app.js',
  'public/js/portal/shared.js',
  'public/js/portal/projectFormShared.js',
  'public/js/portal/boardShared.js',
  'public/js/portal/allocationShared.js',
  'public/js/portal/offensive.js',
  'public/js/portal/itaudit.js',
  'public/js/portal/admin.js',
  'services/teamPolicy.js',
  'services/projectService.js',
  'services/boardService.js',
  'services/clientService.js',
  'services/diagnosticsService.js'
];

for (const file of files) {
  try {
    cp.execFileSync(process.execPath, ['--check', file], { stdio: 'inherit' });
  } catch (err) {
    console.error(`Syntax check failed for: ${file}`);
    process.exit(1);
  }
}

console.log('All files syntax check passed successfully.');
