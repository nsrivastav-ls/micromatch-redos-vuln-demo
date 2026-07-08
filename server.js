/**
 * server.js
 *
 * Intentionally vulnerable demo app for CVE-2024-4067
 * (ReDoS in micromatch < 4.0.8, sink: micromatch.braces()).
 *
 * Built for:
 *  - Dependabot / GitHub Advisory alert validation
 *  - SCA reachability analysis tooling (does the tool correctly trace
 *    HTTP route -> service -> vulnerable library function?)
 *
 * DO NOT deploy this app anywhere reachable from the internet or
 * an untrusted network. It has no auth, no rate limiting, and its
 * entire purpose is to expose a DoS-able code path.
 */

const express = require('express');
const filesRouter = require('./routes/files');

const app = express();
const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.json({
    name: 'micromatch-redos-demo',
    cve: 'CVE-2024-4067',
    vulnerable_package: 'micromatch',
    vulnerable_version_installed: require('micromatch/package.json').version,
    patched_version: '4.0.8',
    try_me: '/api/files/search?pattern=src/**/*.js',
  });
});

app.use('/api/files', filesRouter);

app.listen(PORT, () => {
  console.log(`micromatch-redos-demo listening on http://localhost:${PORT}`);
  console.log(`Installed micromatch version: ${require('micromatch/package.json').version}`);
});
