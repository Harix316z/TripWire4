# Recon Console

Four self-contained security utilities in one Next.js app:

1. **Hash Identifier** — fingerprints hashes/tokens by length, charset, and structural prefix (MD5, SHA-1/2, bcrypt, Argon2, scrypt, Unix crypt variants, JWTs, etc). Runs entirely client-side.
2. **HTTP Header Auditor** — fetches a URL server-side (via a Next.js API route, so no CORS issues) and scores it against 8 security headers (CSP, HSTS, X-Frame-Options, etc).
3. **Secrets Scanner** — paste code/config, get flagged AWS/GitHub/Stripe/Slack keys, private key blocks, connection strings, and high-entropy generic secrets. Runs entirely client-side — nothing is sent over the network.
4. **Dependency Vulnerability Lookup** — queries [OSV.dev](https://osv.dev) (free, no API key required) for known advisories against a package name + ecosystem + optional version.

## Run locally

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

## Deploy to Vercel

**Option A — CLI**
```bash
npm i -g vercel
vercel
```
Follow the prompts. No environment variables are required — both API routes call public, keyless APIs (your own server's fetch, and OSV.dev).

**Option B — GitHub**
1. Push this folder to a new GitHub repo.
2. Go to [vercel.com/new](https://vercel.com/new), import the repo.
3. Framework preset should auto-detect as **Next.js** — leave build settings default.
4. Deploy.

## Notes on the two live tools

- **Header Auditor**: the fetch happens in `app/api/headers/route.js`, which runs as a Vercel serverless function. It has an 8-second timeout and follows redirects. It reports header *presence*, not a full config audit (e.g. it doesn't parse CSP directive quality) — treat the score as a fast triage signal, not a substitute for a real scanner.
- **Vulnerability Lookup**: hits `POST https://api.osv.dev/v1/query` from `app/api/vuln/route.js`. OSV aggregates GitHub Security Advisories, PyPA, RustSec, Go vuln DB, npm advisories, and more — coverage varies by ecosystem.

## Project structure

```
app/
  api/headers/route.js   → server-side header fetch + scoring
  api/vuln/route.js      → OSV.dev proxy
  page.js                → main UI, tab state, session log
  layout.js, globals.css → shell + design tokens
components/
  HashTool.js, HeadersTool.js, SecretsTool.js, VulnTool.js
  SessionLog.js, ui.js   → shared primitives (Button, Badge, Panel, etc)
lib/
  hashIdentifier.js      → hash fingerprint logic
  secretsPatterns.js     → secret-detection regex signatures
```

No database, no auth, no tracking. Everything except the two API calls above stays in the browser tab.
