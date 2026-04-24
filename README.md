# authorized-pentest

A Claude Code skill + plugin marketplace for running authorized security engagements on open-source web apps — from first probe through coordinated disclosure and patch delivery.

**What Claude can do with it:** probe non-destructively, verify every finding with discipline, write the GitHub Security Advisory via `gh api`, ship patches as `git format-patch` files when the advisory's temporary private fork is inaccessible, and do it all with typecheck + test gates before committing. Plus a pile of reusable techniques: SSRF error-shape oracle, rate-limit posture measurement, sanitiser-bypass harness with JSDOM strict check, version-fingerprint via content-echoing SSRF, living-target snapshot diffing.

## Install

### As a Claude Code plugin (recommended)

```
/plugin marketplace add shaxbozaka/authorized-pentest
/plugin install authorized-pentest@authorized-pentest
```

After install the skill appears in the registry and activates when a prompt matches the trigger description ("I have authorization to audit…", "GHSA collaborator", "bug-bounty scope", etc.).

### Manually

```bash
mkdir -p ~/.claude/skills
cd ~/.claude/skills
git clone https://github.com/shaxbozaka/authorized-pentest
```

Restart Claude Code. The skill now lives at `~/.claude/skills/authorized-pentest/` and Claude will pick it up.

## When the skill activates

The `description` frontmatter triggers on any of:

- "I have authorization to audit {X}"
- "I'm listed as a collaborator on GHSA-…"
- "bug bounty scope for {program}"
- "CTF engagement on {host}"
- Any prompt mentioning responsible-disclosure / coordinated-disclosure workflow
- Stack keywords (Node, TypeScript, Next.js, Better-Auth, Drizzle, ORPC, tRPC, etc.) combined with a security-audit context

It's also invokable by name — just ask Claude to "use the authorized-pentest skill."

## What's inside

```
.claude-plugin/marketplace.json      # plugin metadata
skills/authorized-pentest/
  SKILL.md                           # core runbook (≈225 lines, focused)
  references/poc-templates.md        # 9 reusable probe snippets:
                                     #   1 auth bootstrap
                                     #   2 snapshot probe (living-target)
                                     #   3 rate-limit posture measurement
                                     #   4 SSRF error-shape oracle
                                     #   5 sanitiser-bypass harness (JSDOM strict)
                                     #   6 security-headers audit
                                     #   7 advisory edit loop (gh api)
                                     #   8 patch-set export for advisory inlining
                                     #   9 cleanup rituals
README.md
LICENSE                              # MIT
```

## Non-goals

- **Not a hacking guide.** Every pattern assumes explicit, written scope from the maintainer. No evasion techniques, no unauthorized targeting, no zero-day weaponisation.
- **Not a CVE knowledge base.** It doesn't enumerate specific vulns. It describes how to find and report them with discipline.
- **Not a replacement for funded pentest engagements.** A good runbook beats a shrugging improv session; it doesn't beat professional firms with tooling + threat intel.

## Why this exists

Most pentest content online is either "101-level list of OWASP bugs" or "obfuscated offensive tooling marketed as red-team." The gap in the middle — actually running a coordinated-disclosure engagement: verifying claims, writing a clean advisory, shipping patches when you don't have push access to the temporary private fork — is folklore you only learn by screwing it up once. This skill is that folklore, written down, with the specific command-line recipes that save you two hours per engagement.

## Contributing

PRs welcome, especially:

- Techniques for stacks not yet covered (Python/Django, Ruby/Rails, Go, Elixir, PHP)
- Additional payload libraries for sanitiser harnesses
- Platform-specific disclosure workflows (HackerOne, Bugcrowd, huntr, etc.)
- Better patterns for maintainer-communication timing

Please keep contributions **generic** — no references to specific products, engagements, or unpublished vulnerabilities. The goal is reusable methodology.

## License

MIT. Use it, fork it, ship it.

## Acknowledgements

Distilled from real authorized security engagements where the wrong call cost time, trust, or both.
