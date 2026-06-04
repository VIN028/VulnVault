const teamPolicy = require('./teamPolicy');

function validateClientProjectTeam(clientTeam, projectTeam) {
  const cTeam = teamPolicy.normalizeStoredTeam(clientTeam);
  const pTeam = teamPolicy.normalizeStoredTeam(projectTeam);
  if (cTeam !== pTeam) {
    const err = new Error(`Client belongs to ${cTeam}; cannot save project with team ${pTeam}`);
    err.status = 400;
    throw err;
  }
}

function validateProjectTeamImmutability(existingTeam, targetTeam) {
  const eTeam = teamPolicy.normalizeStoredTeam(existingTeam);
  const tTeam = teamPolicy.normalizeStoredTeam(targetTeam);
  if (eTeam !== tTeam) {
    const err = new Error('Project team cannot be changed from the edit endpoint.');
    err.status = 400;
    throw err;
  }
}

module.exports = {
  validateClientProjectTeam,
  validateProjectTeamImmutability
};
