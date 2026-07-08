const express = require('express');
const router = express.Router();
const { filterFilesByPattern } = require('../services/fileFilterService');

/**
 * GET /api/files/search?pattern=<glob>
 *
 * Public, unauthenticated entrypoint that takes a fully user-controlled
 * query parameter and forwards it, unvalidated, into filterFilesByPattern()
 * -> micromatch.braces(). This is the "source" in source-to-sink terms.
 *
 * Example benign request:
 *   GET /api/files/search?pattern=src/**\/*.js
 *
 * Example PoC (do not run against a real server without isolation —
 * this will hang the Node.js event loop):
 *   GET /api/files/search?pattern=%7B%7B%7B%7B...A   (many "{" then "A")
 */
router.get('/search', (req, res) => {
  const pattern = req.query.pattern;

  if (typeof pattern !== 'string') {
    return res.status(400).json({ error: 'Query param "pattern" (string) is required' });
  }

  const start = Date.now();
  const matches = filterFilesByPattern(pattern); // <-- reachable sink call
  const elapsedMs = Date.now() - start;

  res.json({ pattern, matches, elapsedMs });
});

module.exports = router;
