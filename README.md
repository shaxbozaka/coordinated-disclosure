# security-audit

A Claude Code skill + plugin marketplace for auditing web apps for security vulnerabilities — whether on your own codebase (defensive audit before you ship) or on a project you have written authorization to audit (GHSA collaborator, bug-bounty scope, CTF engagement).

**What Claude does with it:**

1. **Detects the mode** — is this a codebase it can read directly (source-code audit), a URL it can only reach over HTTP (black-box probing), or both?
2. **Runs the right checklist** — grep-based source-code audit with ripgrep patterns for every major class (auth bugs, IDOR, SSRF, injection, crypto misuse, file handling, race conditions, rate limits, CORS/CSRF, Docker/CI), OR black-box probing (subdomain enum, port scan, TLS/DNS, exposed admin surfaces, error-shape oracle for internal topology, version fingerprint via `/health`).
3. **Server/infrastructure sweep** — management ports, cloud metadata endpoints, CDN bypass to origin IP, container image version vs upstream stable, backup/debug file exposure.
4. **Rate-limit deep-dive** — the four questions (is there a limit at all / is the counter distributed across replicas / what key is it bucketing on / what is it actually protecting), plus framework-specific defaults that bite (`express-rate-limit`'s in-memory default, Better-Auth's "memory" storage default, Django's LocMemCache, XFF trust).
5. **After findings exist** — verification discipline, `gh api` advisory workflow, patch delivery when the GHSA temporary private fork is gated to the maintainer.

## Install

### As a Claude Code plugin (recommended)

```
/plugin marketplace add shaxbozaka/security-audit
/plugin install security-audit@security-audit
```

After install the skill appears in the registry and activates automatically when a prompt matches the trigger description.

### Manually (no Claude Code plugin system)

```bash
mkdir -p ~/.claude/skills
git clone https://github.com/shaxbozaka/security-audit ~/.claude/skills/security-audit
```

Restart Claude Code. The skill now lives at `~/.claude/skills/security-audit/SKILL.md` and Claude picks it up at session start.

## When the skill activates

The `description` frontmatter triggers on any of:

- "audit my project" / "audit this codebase" / "security review"
- "how could this get hacked" / "find bugs in this" / "how is this hackable"
- "I have authorization to audit {X}"
- "I'm listed as a collaborator on GHSA-…"
- "bug bounty scope for {program}"
- "CTF engagement on {host}"
- Stack keywords (Node, TypeScript, Next.js, Better-Auth, Drizzle, ORPC, tRPC, Django, Rails, Go) combined with a security-audit context

It's also invokable by name — just ask Claude to "use the security-audit skill."

## What's inside

```
.claude-plugin/marketplace.json   # plugin metadata
SKILL.md                          # core runbook
references/
  poc-templates.md                # 14 reusable probe snippets:
                                  #   1  auth bootstrap
                                  #   2  snapshot probe (living-target)
                                  #   3  rate-limit posture measurement
                                  #   3b distributed-counter smoke test
                                  #   3c X-Forwarded-For bypass test
                                  #   3d cost-inflation probe
                                  #   4  SSRF error-shape oracle +
                                  #      version fingerprint via SSRF
                                  #   5  sanitiser-bypass harness (JSDOM strict)
                                  #   6  security-headers audit
                                  #   7  advisory edit loop (gh api)
                                  #   8  patch-set export for advisory inlining
                                  #   9  cleanup rituals
                                  #   10 server port sweep
                                  #   11 TLS configuration audit
                                  #   12 DNS / subdomain takeover
                                  #   13 origin IP discovery (CDN bypass)
                                  #   14 cloud metadata via SSRF
  source-audit-patterns.md        # deep ripgrep recipes for INSIDE mode:
                                  #   auth, IDOR, SSRF, injection, XSS,
                                  #   file handling, crypto, races,
                                  #   rate-limit framework specifics,
                                  #   CORS/CSRF, Docker/CI, secrets,
                                  #   logic bugs grep can't find
README.md
LICENSE                           # MIT
```

## Non-goals

- **Not a hacking guide.** Every pattern assumes explicit written scope when probing from outside. No evasion techniques, no unauthorized targeting, no zero-day weaponisation.
- **Not a CVE knowledge base.** The skill doesn't enumerate specific vulns. It describes how to find and report them.
- **Not a replacement for funded engagements.** A good runbook beats shrugging improv; it doesn't beat a pentest firm with tooling + threat intel.

## Why this exists

Most security content online is either "101-level OWASP lists" or "obfuscated offensive tooling marketed as red-team." The gap in the middle — actually running an audit on a real codebase: where to grep, which sinks matter, how to confirm a hit, how to measure rate-limit posture without DoS'ing yourself, how to read error strings as a blind port scan, how to fingerprint a container's version from `/health` — is folklore you learn by doing. This skill is that folklore, written down.

## Contributing

PRs welcome, especially:

- Audit patterns for stacks not yet covered (Django, Rails, Go, Elixir, PHP, Java Spring)
- Additional payload libraries for sanitiser harnesses
- Platform-specific disclosure workflows (HackerOne, Bugcrowd, huntr)
- Better patterns for maintainer-communication timing

Please keep contributions **generic** — no references to specific products, engagements, or unpublished vulnerabilities.

## License

MIT. Use it, fork it, ship it.

## Acknowledgements

Distilled from real security audits where the wrong call cost time, trust, or both.
