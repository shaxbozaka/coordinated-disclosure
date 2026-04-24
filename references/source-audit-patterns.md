# Source-Code Audit Patterns

Expanded grep and ripgrep patterns for the INSIDE-mode checklist in SKILL.md. Each pattern comes with **what it finds**, **why it's suspect**, and **how to confirm it's actually a bug** (the grep pattern fires on many false positives — confirmation is the real audit).

Run from the repo root. Uses ripgrep (`rg`) where available; `grep -rIn` works too.

---

## 1. The fastest first pass

Before any target-specific hunting, run these three queries on any unfamiliar codebase. They almost always surface something within 60 seconds:

```bash
# (a) Every endpoint handler — map the attack surface
rg -n 'app\.(get|post|put|delete|patch)\(|router\.(get|post|put|delete|patch)\(|@(Get|Post|Put|Delete|Patch)\(|@app\.route\(|def (get|post|put|delete|patch)_' src/ | head -80

# (b) Every auth check call site — find where it's NOT called
rg -n 'requireAuth|isAuthenticated|@login_required|authGuard|protectedProcedure|getServerSession\(' src/ | head -40

# (c) Every "dangerous sink" in one sweep
rg -n 'dangerouslySetInnerHTML|eval\(|new Function\(|child_process\.exec|subprocess\.Popen.*shell=True|prisma\.\$queryRaw|db\.raw\(|fetch\(.*req\.' src/ | head -80
```

The third one hits ~all the major sinks in one pass. For each hit: read the surrounding 20 lines.

---

## 2. Authorization / IDOR — the most common class of real bug

The theory: every data-access query must either be scoped to the current user, or explicitly called on a public resource. If the server trusts a client-supplied `id`, you have an IDOR.

### 2a. Find every id-based lookup

```bash
# Prisma
rg -n 'findUnique\(\{|findFirst\(\{|findMany\(\{|update\(\{|delete\(\{' src/
# Drizzle
rg -n '\.where\(eq\(.+\.id,|\.where\(and\(' src/
# TypeORM / Sequelize
rg -n 'findOne\(\{|findByPk\(|findById\(|update\(' src/
# Raw SQL
rg -n 'SELECT.+WHERE.+id\s*=|UPDATE.+WHERE.+id\s*=|DELETE FROM.+WHERE.+id\s*=' src/
# MongoDB
rg -n '_id:\s*(req\.|input\.|params\.|body\.)|ObjectId\((req|input)' src/
```

### 2b. For each hit, check: does the query ALSO filter by the authenticated user?

A Prisma query that reads an object by ID should usually look like:

```ts
// GOOD
await prisma.resource.findFirst({
  where: { id: input.id, ownerId: context.user.id }
});

// BAD — IDOR
await prisma.resource.findUnique({
  where: { id: input.id }
});

// BAD — ownership check added AFTER, by string compare (race)
const r = await prisma.resource.findUnique({ where: { id: input.id } });
if (r.ownerId !== context.user.id) throw new Error();   // still loaded+returned
```

Drizzle equivalent:

```ts
// GOOD
await db.select().from(resource)
  .where(and(eq(resource.id, input.id), eq(resource.ownerId, ctx.user.id)));

// BAD
await db.select().from(resource).where(eq(resource.id, input.id));
```

### 2c. Forgeable "internal" or "admin" checks

```bash
# Headers-based "server-only" pattern — always broken when exposed over HTTP
rg -n 'x-server-side|x-internal|x-admin|x-forwarded-for\s*===|headers\[.(x-|X-)' src/
# Env-based bypasses that accidentally ship to prod
rg -n 'NODE_ENV\s*===.*(development|test)|DEBUG_|FLAG_DEBUG' src/
```

Any "is this a trusted caller?" check based on a request header is forgeable. The only reliable server-only primitive in an HTTP app is an in-process call (never goes through the HTTP handler at all).

### 2d. Middleware that only SOMETIMES fires

```bash
# Order matters — middleware declared after the route is never applied to it
rg -n 'app\.use\(|router\.use\(' src/
```

Compare the order of `app.use(authMiddleware)` vs `app.use('/api/auth', authRoutes)`. If `authRoutes` is registered BEFORE `authMiddleware`, the auth routes skip the auth middleware (usually intentional). If a route is registered inside a sub-router that doesn't inherit the middleware, same result.

---

## 3. SSRF — the second most common

### 3a. Find every outbound HTTP request where the URL is user-influenced

```bash
# Node
rg -n 'fetch\([^)]*(req\.|input\.|body\.|params\.|query\.)' src/
rg -n 'axios\.(get|post|put|delete)\([^)]*(req\.|input\.)' src/
rg -n 'got\([^)]*(req\.|input\.)' src/
rg -n 'http\.(get|request)\([^)]*(req\.|input\.)' src/

# Python
rg -n 'requests\.(get|post|put|delete)\([^)]*(request\.|data\[)' src/
rg -n 'urllib\.(request\.urlopen|urlopen)\(' src/
rg -n 'httpx\.(get|post)\(' src/

# Go
rg -n 'http\.(Get|Post|NewRequest)\(' --glob='*.go' src/
```

### 3b. Specific patterns that almost always leak

Server accepts a URL and echoes some part of the response back to the caller:

```bash
# Image URL → base64 data URL
rg -n 'toString\([^)]*base64|Buffer\.from\(.+\)\.toString\(.base64.\)' src/
# URL preview / unfurl
rg -n '(preview|unfurl|oembed|metadata|opengraph)' src/ | grep -i fetch
# Webhook test / "test connection" endpoints
rg -n 'testConnection|test_webhook|ping_url' src/
# AI provider baseURL — pure SSRF primitive when not validated
rg -n 'baseURL|api_base|endpoint_url' src/ | grep -iE 'openai|anthropic|provider|llm|ai'
```

### 3c. Confirmation checklist for each SSRF candidate

1. Is the URL validated against an **allowlist** of hosts? (blocklists are bypassable — always)
2. Is redirect-following disabled (`maxRedirects: 0`, `allow_redirects=False`, `RedirectPolicy = Never`)?
3. Is the DNS resolution pinned to non-private ranges? (pre-connect hook that rejects 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, ::1/128, fc00::/7, fe80::/10)
4. Is the response size capped? (A 10GB response to `/metrics` is a DoS primitive.)
5. Is the response body returned to the caller or silently consumed? (former is worse.)

Missing any of 1–4 = SSRF. Present 1–4 but returning body = content-exfiltration SSRF (higher severity).

---

## 4. Injection family — the third most common

### 4a. SQL injection

```bash
# Raw query with string concatenation / template literal
rg -n 'db\.(raw|execute|query)\([^)]*(\$\{|\+ )' src/
rg -n 'prisma\.\$queryRaw[^`]*\$\{' src/                     # template interp = injection
rg -n 'sequelize\.query\([^)]*\$' src/
rg -n 'knex\.raw\([^)]*\$' src/

# ORMs: look for where-clause string construction
rg -n '\.where\(["'\''][^"'\'']+\$\{' src/
```

Tagged templates are safe (`prisma.$queryRaw\`SELECT ... WHERE id = ${id}\`` — backticks with Prisma = parameterized). String-concat into the same function is not.

### 4b. NoSQL injection

```bash
# MongoDB $where, $function, $accumulator — eval-like behaviour
rg -n '\$where|\$function|\$accumulator' src/
# Object-based injection: { username: req.body.user } where user = { $ne: null }
rg -n 'findOne\(\{.*req\.|findOne\(\{.*body\.' src/
```

MongoDB with a pre-Express-v5 body parser accepts `{"username":{"$ne":null},"password":{"$ne":null}}` and returns the first user. Always strip `$`-prefixed keys from user input unless you're explicitly querying.

### 4c. Command injection

```bash
# Node
rg -n 'child_process\.(exec|execSync)\(' src/              # exec = shell: true
rg -n 'spawn\([^)]*,\s*\{\s*shell\s*:\s*true' src/
rg -n 'execFile\(' src/                                     # safer but not if args include user input
# Python
rg -n 'os\.system\(|os\.popen\(' src/
rg -n 'subprocess\.(call|run|Popen|check_output)\([^)]*shell\s*=\s*True' src/
# Shell construction
rg -n '`.+\$\{.+\}.+`' src/ | grep -iE 'exec|spawn|system|run'
```

### 4d. Path traversal

```bash
rg -n 'path\.join\([^)]*(req\.|input\.|params\.|body\.)' src/
rg -n 'fs\.(readFile|createReadStream|writeFile)\([^)]*(req\.|input\.)' src/
rg -n 'send(File|Download)\([^)]*(req\.|input\.)' src/
```

`path.join('/safe/dir', userInput)` does NOT prevent traversal if `userInput = "../../../etc/passwd"`. The fix is `path.resolve` plus a `startsWith` check, or a path map.

### 4e. Template injection (SSTI)

```bash
# Node
rg -n 'res\.render\([^)]*,\s*(req\.|input\.)' src/
rg -n 'handlebars\.compile\(.+(req|input)\.' src/
rg -n 'mustache\.render\([^)]*(req|input)' src/
# Python
rg -n 'Template\([^)]*request\.' src/
rg -n 'jinja2\.Template\(' src/ | grep -i render
# Eval-class
rg -n 'eval\(|new Function\(' src/
```

### 4f. XSS sinks

```bash
rg -n 'dangerouslySetInnerHTML' src/
rg -n 'v-html' src/
rg -n 'innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML\(' src/
rg -n 'document\.write\(|document\.writeln\(' src/
```

For each hit, ask: what feeds this? If it's derived from user-controlled data AND not through a configured sanitiser, that's XSS. If it's through a sanitiser, read the sanitiser config:

```bash
rg -n 'DOMPurify\.sanitize\(' src/
rg -n 'ALLOWED_TAGS|ALLOWED_ATTR|FORBID_' src/
rg -n 'sanitize-html|xss\s*=|bleach\.clean\(' src/
```

Wide `ALLOWED_ATTR` (`style`, `href`, `srcset`, `on*`) = probable bypass. `style` attribute alone = CSS-SSRF via `background:url(http://attacker/)`.

---

## 5. Authentication logic

### 5a. Password storage

```bash
# Raw md5 / sha1 on anything — tells you password storage or token generation is weak
rg -n 'createHash\([^)]*(md5|sha1)\)|hashlib\.(md5|sha1)\(' src/
# bcrypt used synchronously (blocks event loop) or with low cost factor
rg -n 'bcrypt\.hashSync|bcrypt\.hash\(.+,\s*[1-9](?!\d)\b' src/    # cost < 10
# Plaintext comparison
rg -n '\.password\s*===\s*(req\.|input\.)' src/
rg -n 'user\.password\s*==\s*' src/
```

### 5b. JWT configuration

```bash
rg -n 'algorithms:\s*\[.+none|algorithm:\s*.none.' src/   # none-alg accepted = trivially forgeable
rg -n 'verify\([^)]*,\s*undefined' src/                     # skipping the secret
rg -n 'jwt\.sign\([^)]*process\.env\.[A-Z_]*SECRET' src/   # secret = env var (ok if actually secret)
rg -n 'jwt\.sign\([^)]*["'\''](\w+)["'\'']' src/            # hardcoded secret — game over
```

### 5c. Session and cookie flags

```bash
rg -n 'cookie\(.*\{[^}]*(httpOnly|secure|sameSite)' src/
rg -n 'session\(\{|cookie\s*:\s*\{' src/
```

Missing `httpOnly` = XSS can steal the session. Missing `secure` = MITM on first HTTP request steals it. `sameSite: "none"` without `secure: true` = CSRF target.

### 5d. Password reset and OTP

```bash
rg -n 'Math\.random\(\)' src/ | grep -iE 'token|code|reset|otp'
rg -n 'randomBytes\([^)]*\d' src/ | grep -iE 'token|code|reset'    # confirm byte length ≥ 16
rg -n '(verify|compare|reset).+==' src/ | head                      # should be timingSafeEqual
```

OTP endpoints: check for rate limiting. A 6-digit OTP with 10 attempts/second and no limit is brute-forceable in ~2h.

---

## 6. File handling

### 6a. Upload

```bash
rg -n 'multer|formidable|busboy|express-fileupload' src/
# Filename persistence
rg -n 'originalname|\.file\.name' src/ | head
# MIME trust (client-set)
rg -n '\.mimetype\s*===' src/
# Size cap
rg -n 'limits\s*:\s*\{\s*fileSize' src/      # presence-check; absence = DoS
```

Risks:
- Persisting `originalname` as-is enables path traversal (`../../../etc/nginx/nginx.conf`)
- Trusting `req.file.mimetype` enables XSS via `image/svg+xml` containing `<script>`
- Unbounded upload size enables storage DoS

### 6b. Archive extraction (ZIP slip)

```bash
rg -n 'unzipper|yauzl|adm-zip|tar\.x\(|tarfile\.open|zipfile\.ZipFile' src/
```

For each hit, check: is each entry's target path validated to stay inside the extraction root? Absent = ZIP slip.

### 6c. Serving uploaded content

```bash
rg -n 'sendFile\(|send_file\(' src/
rg -n 'express\.static\(' src/
```

For each hit: does it set `Content-Type` based on extension (sniffable) or based on the file's actual MIME? Does it set `X-Content-Type-Options: nosniff`? Does it set `Content-Disposition: attachment` for non-image uploads?

---

## 7. Cryptography misuse

```bash
# Weak RNG for security-sensitive values
rg -n 'Math\.random\(\)' src/ | grep -iE 'token|code|id|secret|session|nonce|salt|iv'
# ECB mode, DES, RC4, MD5 — all broken
rg -n 'createCipheriv\([^)]*["'\''](aes-\w+-ecb|des|rc4|des-ede)' src/
rg -n 'EVP_\w+_ecb\(|"AES/ECB' src/
# Constant-time compare missing
rg -n 'timingSafeEqual|constant_time_compare|hmac\.compare_digest' src/   # presence check
rg -n 'token\s*===?\s*(stored|expected)' src/                              # non-constant-time
# Hardcoded keys / IVs
rg -nE 'key\s*=\s*Buffer\.from\(["'\''][0-9a-f]{32,}' src/
rg -nE 'iv\s*=\s*Buffer\.from\(["'\''][0-9a-f]{16,32}' src/
```

---

## 8. Race conditions and TOCTOU

```bash
# Check-then-act without transaction
rg -n '(findOne|findFirst|findUnique)\([^)]*\)[^;]*(create|update|insert)\(' src/ | head -30
# Money / balance ops
rg -nE 'balance|credits|points|quota|stock' src/ | grep -iE 'update|decrement|-=' | head
# Uniqueness enforced in app code rather than DB
rg -n '\.findFirst\([^)]*(username|email|slug)' src/
```

Patterns to read carefully:
- Signup: `findFirst({ where: { username } })` then `create({ username })` — race window lets two users claim the same name
- Payment: `if (user.balance >= amount)` then `update({ balance: { decrement: amount } })` — concurrent requests can double-spend
- "Claim once" invites: `if (invite.used === false)` then mark used — race lets two users claim

Fix is always: database constraint (UNIQUE) or transactional update with WHERE condition in a single round-trip.

---

## 9. Rate limiting

```bash
# Presence of a limiter
rg -n 'rateLimit|rate_limit|ratelimit|slowDown|express-rate-limit|@upstash/ratelimit|limiter\.check' src/
# Auth endpoints that typically need rate limits
rg -n '(sign-in|signin|login|register|sign-up|signup|forgot|reset.password|2fa|verify-otp|resend.verification|is-username-available)' src/ | head -40
```

For each auth endpoint, check: does a limiter wrap it? What's the budget? A budget of `max: 100 per minute` on sign-in is not useful. Tight budgets look like:

- `/sign-in/email` — 5 per minute per IP
- `/sign-up/email` — 3 per minute per IP
- `/request-password-reset` — 3 per 10 minutes per email
- `/two-factor/verify-otp` — 5 per 10 minutes per session
- `/send-verification-email` — 3 per 10 minutes per email
- `/is-username-available` — 20 per minute per IP (even without a secret, still an enumeration oracle)

---

## 10. CORS and CSRF

```bash
# Overly permissive CORS
rg -nE 'cors\([^)]*origin\s*:\s*(true|\*)' src/
rg -n 'credentials\s*:\s*true' src/
# Origin trust
rg -n 'req\.headers\.origin' src/
# CSRF middleware
rg -n 'csrf\(|csurf|@nestjs/csrf|django\.middleware\.csrf' src/
# Cookie SameSite
rg -n 'sameSite' src/ | grep -viE 'strict|lax'     # 'none' or missing
```

- `origin: true` with `credentials: true` = attackers can issue authenticated cross-origin requests
- `Origin` header used for auth decisions = forgeable from any non-browser client
- No CSRF protection on state-changing endpoints + no `SameSite: strict/lax` = CSRF

---

## 11. Docker / container / CI

```bash
# Dockerfile red flags
rg -nE '^FROM\s+\S+:latest' Dockerfile*
rg -nE '^USER\s+' Dockerfile*                      # absence = runs as root
rg -n 'ADD https?://' Dockerfile*                  # use COPY, ADD fetches network content
rg -nE 'ENV\s+\w*(SECRET|TOKEN|KEY|PASSWORD)' Dockerfile*

# docker-compose
rg -n 'privileged\s*:\s*true|network_mode\s*:\s*host|pid\s*:\s*host' docker-compose*.yml
rg -n 'ports:' docker-compose*.yml                 # check bindings — 0.0.0.0 vs 127.0.0.1

# GitHub Actions
rg -n 'pull_request_target' .github/workflows/
rg -nE 'uses:\s+[^@]+@(main|master|v\d+)\s*$' .github/workflows/    # unpinned actions
rg -n 'secrets\.' .github/workflows/              # secret usage in fork-triggered workflows is game over
rg -n 'runs-on:\s*self-hosted' .github/workflows/ # self-hosted runners + public PRs = host compromise
```

- `FROM X:latest` — anyone with push access to that upstream can silently pwn you
- No `USER` — container runs as root; any RCE = host root
- `privileged: true`, `network_mode: host`, `pid: host` — container escape is trivial
- Ports bound to `0.0.0.0` that should be internal — exposed to the public internet
- Unpinned GitHub Actions at `main` — upstream compromise is your compromise
- `pull_request_target` with `secrets.*` — any forked PR can exfiltrate secrets
- Self-hosted runner + public PRs allowed — arbitrary code execution on your infra

---

## 12. Secret scanning beyond just `grep`

```bash
# Presence of a .env* checked in at ANY point in git history
git log --all --full-history -- '**/.env*' '**/secrets*' '**/*.pem' '**/*.key'
# Strings in committed files
git grep -nE 'BEGIN RSA PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY|AKIA[0-9A-Z]{16}|xox[bap]-|sk-[A-Za-z0-9]{32,}|ghp_[A-Za-z0-9]{36}|gho_|ghu_|ghs_|ghr_'
# Client-shipped secrets in Next.js / Vite bundles
rg -n 'NEXT_PUBLIC_\|VITE_\|REACT_APP_' src/ app/ 2>/dev/null | grep -iE 'secret|private|key|token'
```

Once you find a leaked secret, check:
1. Is it still valid? (Rotate regardless.)
2. Was it in git history? (Rewrite history isn't enough — assume compromised.)
3. Did CI ever print it? (GitHub Actions logs persist; public repo = public secret.)

---

## 13. Logic bugs that grep can't find

These require reading the code. Budget 30–60 minutes per flow on a codebase you haven't seen before.

**Auth flow.** Read start to finish. Ask at each step:
- How is the user identified?
- Can that identifier be forged or guessed?
- What happens if the attacker controls each input?
- Are there side-effects (email sent, counter incremented, session created) that change state before the final auth check?

**Payment flow.** Same, with extra attention to:
- Idempotency keys — present? validated server-side?
- Webhook verification — signature checked before trusting the payload?
- Amount / currency parsing — `Number(req.body.amount)` allows negative, NaN, scientific notation; `parseFloat("100; DROP TABLE")` returns `100`

**Multi-tenant isolation.** Every table with a tenant_id / workspace_id / org_id column is a potential cross-tenant leak:
```bash
rg -n '(tenant_id|workspace_id|org_id|organization_id)' src/ | head -80
```
For every query touching those columns, confirm the tenant check is applied. One missing `WHERE tenant_id = ?` = cross-tenant data leak.

**Password reset flow.** Read the full happy path then the error paths:
- Is the reset token randomly generated? (`Math.random()` = no)
- Is it single-use? (Does the endpoint revoke it?)
- Is it time-limited? (TTL < 1 hour ideal)
- Is the email address verified before the reset is sent? (If not — stuff reset emails at any email)
- Can the reset token be guessed? (Short codes + no rate limit = guessable)

**Invitation flow.** Who can invite? Who can accept? Does accepting an invitation grant only the intended permissions, or does it cross workspaces?

**Webhook / callback flow.** Is the source authenticated? (Shared secret, HMAC, OAuth token?) Is the payload signature verified BEFORE trusting any part of it (including for "am I busy" / idempotency checks)?

---

## 14. When you think you've found it

Before writing up a source-code finding:

1. **Reproduce the attack path end-to-end**, at least in your head. Write out the attacker's exact HTTP request, the server's exact response, and what the attacker gains.
2. **Find the unit test that should have caught this.** It's usually missing, or tests the happy path only. The missing test is evidence.
3. **Find the commit that introduced it.** `git log -L :functionName:path/to/file.ts` or `git blame`. Knowing "this was added in PR #1234 for feature X" helps you understand *why* the bug exists and whether the fix might affect feature X.
4. **Confirm it reproduces at the HTTP layer** (if you have a running deployment). A code path that looks exploitable but is unreachable from HTTP is code-inspected-only, not verified.

Then write it up. See SKILL.md → Disclosure section for the advisory format.
