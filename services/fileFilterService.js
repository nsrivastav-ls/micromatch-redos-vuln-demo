/**
 * fileFilterService.js
 *
 * Simulates a "search files by glob pattern" feature — a realistic reason
 * an app would pass user-controlled input into micromatch.
 *
 * This module is intentionally one call-hop away from the HTTP route handler
 * so that reachability/call-graph tools (e.g. CodeQL, Semgrep reachability,
 * Snyk/GitHub "vulnerable call path") have a non-trivial path to trace:
 *
 *   routes/files.js (HTTP layer)
 *     -> services/fileFilterService.js: filterFilesByPattern()  <-- this file
 *       -> node_modules/micromatch/index.js: braces()           <-- CVE-2024-4067 sink
 */

const micromatch = require('micromatch');

const SAMPLE_FILES = [
  'src/index.js',
  'src/utils/helpers.js',
  'src/components/Button.jsx',
  'docs/README.md',
  'test/unit/app.test.js',
  'config/webpack.config.js',
];

/**
 * Filters the file list using a user-supplied glob/brace pattern.
 *
 * VULNERABLE SINK: micromatch.braces() (via micromatch()) uses a greedy
 * `.*` regex internally (micromatch <4.0.8, index.js ~line 448) that causes
 * catastrophic backtracking on malformed/nested brace input such as:
 *   "{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{A"
 *
 * @param {string} pattern - untrusted, user-controlled glob pattern
 * @returns {string[]} matching file paths
 */
function filterFilesByPattern(pattern) {
  // First, brace-expansion is run directly (this is the documented sink
  // for CVE-2024-4067: micromatch.braces()).
  const expanded = micromatch.braces(pattern, { expand: true });

  // Then used for actual matching, a realistic downstream use.
  return micromatch(SAMPLE_FILES, expanded);
}

module.exports = { filterFilesByPattern, SAMPLE_FILES };
