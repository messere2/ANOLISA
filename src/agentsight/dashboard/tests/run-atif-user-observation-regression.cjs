// Behavioral regression runner for the ATIF viewer user-step observation
// fix (#6593): the companion test transpiles the production
// AtifViewerPage with the dashboard's babel toolchain (same driver as the
// round-model and atif-import-deferred suites) and drives the real page
// through a loaded document whose user step carries a stored observation.
const { execFileSync } = require('node:child_process');

execFileSync('node', [
  '--test',
  'tests/atif-user-observation-regression.test.cjs',
], {
  stdio: 'inherit',
});
