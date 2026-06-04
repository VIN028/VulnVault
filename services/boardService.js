const teamPolicy = require('./teamPolicy');

function validateBoardStatusTeam(statusTeam, targetTeam, message = 'Board status team mismatch') {
  teamPolicy.assertSameTeam(statusTeam, targetTeam, message);
}

module.exports = {
  validateBoardStatusTeam
};
