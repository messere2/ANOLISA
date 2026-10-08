// Behavioral regression runner for the dashboard's code-point-safe text
// truncation (#6738): direct fixtures against the shared truncateText
// utility plus the transpiled production viewer rendering a message whose
// clip boundary lands inside a surrogate pair.
const { execFileSync } = require('node:child_process');

execFileSync('node', [
  '--test',
  'tests/dashboard-truncate-regression.test.cjs',
], {
  stdio: 'inherit',
});
