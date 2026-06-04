function summarizeDiagnostics(mismatches) {
  const clientCount = mismatches.clientMismatches?.length || 0;
  const boardCount = mismatches.boardMismatches?.length || 0;
  const userCount = mismatches.userMismatches?.length || 0;
  const total = clientCount + boardCount + userCount;

  return {
    clientCount,
    boardCount,
    userCount,
    total,
    isHealthy: total === 0
  };
}

module.exports = {
  summarizeDiagnostics
};
