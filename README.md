# micromatch-redos-demo

Intentionally vulnerable Node/Express app built to validate **Dependabot alerts**
and **SCA reachability analysis** tooling against a real, disclosed CVE.

**⚠️ Do not deploy this. Run it locally / in an isolated container only.**

## The vulnerability

| Field | Value |
|---|---|
| CVE | [CVE-2024-4067](https://nvd.nist.gov/vuln/detail/CVE-2024-4067) |
| GHSA | [GHSA-952p-6rrq-rcjv](https://github.com/advisories/GHSA-952p-6rrq-rcjv) |
| Package | `micromatch` (npm) |
| Affected | `< 4.0.8` |
| Patched | `4.0.8` |
| Type | CWE-1333, Regular Expression Denial of Service (ReDoS) |
| CVSS 3.1 | 5.3 (Medium) — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` |
| Sink function | `micromatch.braces()` in `index.js` (~line 448) |

The vulnerable check — `/\{.*\}/.test(pattern)` inside `micromatch.braces()` —
uses a greedy `.*` to look for a closing `}`. An input with many unmatched
`{` characters forces backtracking that's **quadratic (~O(n²))** in the
input length, measured directly against the pinned `4.0.7` in this repo:

| Pattern length | Time |
|---|---|
| 5,000 chars | ~20 ms |
| 10,000 chars | ~80 ms |
| 20,000 chars | ~315 ms |
| 40,000 chars | ~1,240 ms |

That's enough to noticeably block the single-threaded Node.js event loop
from one ~40KB HTTP request body/query string, and it keeps climbing —
this is a real (if "moderate," per the CVSS score) DoS vector, just not
the textbook *exponential* blowup you'd get from a nested-quantifier
pattern like `(a+)+`.

This demo pins `micromatch` to `4.0.7` in `package.json` (last vulnerable
release before the real fix landed in 4.0.8).

## Reachable call path (for reachability analysis)

```
routes/files.js            GET /api/files/search?pattern=<user input>   [SOURCE]
  └─ services/fileFilterService.js
       └─ filterFilesByPattern(pattern)
            └─ micromatch.braces(pattern, { expand: true })             [SINK — CVE-2024-4067]
```

The route handler is deliberately kept thin and the vulnerable call is
pushed one hop into a service module, so that a call-graph/reachability
tool has to actually resolve `filterFilesByPattern` -> `micromatch.braces`
rather than matching the sink directly against a route file. This mirrors
how the vulnerable call is usually buried in real codebases.

An unreachable copy of the vulnerable dependency (i.e. present in
`package.json` but never called) is a good negative-control addition if
you want to test whether your reachability tool correctly *down-ranks*
unreachable CVEs — see "Optional: add a negative control" below.

## Setup

```bash
npm install
npm start
# -> micromatch-redos-demo listening on http://localhost:3000
```

Confirm the vulnerable version actually got installed:

```bash
npm ls micromatch
# should show micromatch@4.0.7
```

## Triggering it

**Option A — in-process PoC (recommended, no server needed):**

```bash
# growth is quadratic, not exponential — needs thousands of chars to show up
timeout 10 node exploit/trigger_redos.js 20000
timeout 10 node exploit/trigger_redos.js 40000
```

**Option B — via the HTTP endpoint** (run in an isolated environment; this
will block that Node process's event loop for the duration of the call):

```bash
python3 -c "print('{' * 40000 + 'A')" > /tmp/payload.txt
curl -G 'http://localhost:3000/api/files/search' \
  --data-urlencode "pattern=$(cat /tmp/payload.txt)"
```

Benign request for comparison:

```bash
curl -G 'http://localhost:3000/api/files/search' \
  --data-urlencode 'pattern=src/**/*.js'
```

## Validating with Dependabot

1. Push this repo to GitHub with `package-lock.json` committed
   (run `npm install` once to generate it).
2. Enable **Settings → Code security and analysis → Dependabot alerts**
   (and optionally "Dependabot security updates").
3. GitHub should surface a Dependabot alert for `micromatch` referencing
   GHSA-952p-6rrq-rcjv / CVE-2024-4067, recommending an upgrade to `4.0.8+`.
4. The `.github/dependabot.yml` in this repo also enables daily
   version-update PRs for the `npm` ecosystem, so Dependabot should open
   a PR bumping `micromatch` to `^4.0.8`.

To confirm the fix actually closes the vulnerable path:

```bash
npm install micromatch@4.0.8
timeout 10 node exploit/trigger_redos.js 40000
# ~560ms on 4.0.8 vs. ~1,800ms on 4.0.7 for the same 40,000-char payload —
# the patch replaces the greedy check with a stricter hasBraces() function,
# meaningfully reducing (not fully eliminating) worst-case cost.
# Remember to `git checkout package.json && npm install` afterward to
# restore the vulnerable pin for further testing.
```

## Optional: add a negative control

To test whether a reachability tool distinguishes *reachable* vs
*unreachable* vulnerable code, add a second dependency that's never
imported anywhere (e.g. an old `braces` version used only in a devDependency
that's never required), and confirm the tool ranks it lower/differently
than the actively-called `micromatch` path above.

## Files

```
.
├── package.json                    # pins micromatch@4.0.7 (vulnerable)
├── server.js                       # Express app entrypoint
├── routes/files.js                 # SOURCE: HTTP route with user input
├── services/fileFilterService.js   # SINK: calls micromatch.braces()
├── exploit/trigger_redos.js        # standalone PoC / timing harness
└── .github/dependabot.yml          # Dependabot config
```
