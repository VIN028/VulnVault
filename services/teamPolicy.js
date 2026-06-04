const VALID_TEAMS = new Set(['offensive', 'itaudit']);

function parseTeam(value, { required = false } = {}) {
  if (!value) {
    if (required) return { error: 'Team is required. Must be offensive or itaudit.' };
    return null;
  }

  if (!VALID_TEAMS.has(value)) {
    return { error: 'Invalid team. Must be offensive or itaudit.' };
  }

  return value;
}

function normalizeStoredTeam(value) {
  return value || 'offensive';
}

function assertSameTeam(left, right, message = 'Team mismatch') {
  if (normalizeStoredTeam(left) !== normalizeStoredTeam(right)) {
    const err = new Error(message);
    err.status = 400;
    throw err;
  }
}

module.exports = {
  VALID_TEAMS,
  parseTeam,
  normalizeStoredTeam,
  assertSameTeam
};
