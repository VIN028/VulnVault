const teamPolicy = require('./teamPolicy');

function validateClientTeam(team, { required = false } = {}) {
  const result = teamPolicy.parseTeam(team, { required });
  if (result && result.error) {
    const err = new Error(result.error);
    err.status = 400;
    throw err;
  }
  return result;
}

module.exports = {
  validateClientTeam
};
