# authorized-pentest

A runbook-style Claude Code skill for running authorized security engagements on open-source web apps — from first probe through coordinated disclosure and patch delivery.

## What this is

A Markdown skill in the Claude Code skills format. When installed at `~/.claude/skills/authorized-pentest/`, it becomes discoverable by Claude Code and activates when you describe an authorized audit (maintainer invite, GitHub Security Advisory collaborator, CTF scope, bug-bounty scope).

It's opinionated about:

- **Authorization hygiene** — pin the scope in writing, default to non-destructive, never evade rate limits.
- **Verification discipline** — every advisory sentence is a load-bearing claim; dump raw responses verbatim before calling anything "defended" or "missing."
- **`gh api` advisory workflow** — edit loops via JSON PATCH, CWE tagging, size budgets, recommended description structure.
- **Patch delivery when the temporary private fork is inaccessible** — inline patches in the advisory `<details>` blocks, not public forks or Gists.
- **Quality gates before commit** — typecheck + test suite + diff self-review, all green, before any commit goes in.
- **Techniques** — SSRF error-shape oracle, version-fingerprint via content-echoing SSRF, rate-limit posture measurement, sanitiser-bypass harness with strict JSDOM post-parse check, living-target snapshot diffing.

## Install

```bash
cd ~/.claude/skills
git clone https://github.com/YOUR_USERNAME/authorized-pentest
# or manually drop the contents into ~/.claude/skills/authorized-pentest/
```

After restarting Claude Code, the skill will appear in the skill registry. It triggers automatically when a prompt matches the `description` frontmatter, or can be invoked explicitly.

## Contents

- `SKILL.md` — the core runbook
- `references/poc-templates.md` — reusable Python + Node snippets for auth bootstrap, snapshot probing, rate-limit measurement, SSRF oracle, sanitiser harness, security-headers audit, advisory edit loop, patch-set export

## Non-goals

- **Not a hacking guide.** Every pattern assumes explicit, written scope from the maintainer. No evasion techniques, no exploitation of non-authorized targets, no zero-day weaponisation.
- **Not a CVE knowledge base.** It doesn't enumerate specific vulns. It describes how to find and report them with discipline.
- **Not a replacement for professional engagements.** A good runbook beats a shrugging improv session; it doesn't beat a funded pentest firm with access to additional tooling and threat intel.

## License

MIT. See `LICENSE`.

## Contributing

PRs welcome, especially:

- Techniques for stacks not covered (Python/Django, Ruby/Rails, Go, Elixir)
- Additional payload libraries for sanitiser harnesses
- Better patterns for maintainer-communication timing
- Platform-specific disclosure workflows (HackerOne, Bugcrowd, etc.)

Please keep contributions **generic** — no references to specific products, engagements, or unpublished vulnerabilities. The goal is reusable methodology.

## Acknowledgements

Distilled from authorized security engagements where the wrong call cost time, trust, or both.
