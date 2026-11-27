# Public-repo rule

Decision by the owner on 2026-11-27: **this repository will eventually be made public — no confidential information may leak into it, ever.**

Rules that follow from it:

- Real secrets live only in the uncommitted `.env` on the home server; `.env` is gitignored. `.env.example` carries placeholders only.
- Never commit tokens, keys, internal IPs, or credentials — including in commit messages, wiki pages, issues, or PRs.
- Before making the repo public (or before any risky change), run a history scan, e.g. `git log --all -p | grep -iE 'token|secret|password|PRIVATE KEY'` plus a dedicated scanner (gitleaks/trufflehog) in CI.

## Audit log

- 2026-11-27: scanned all tracked files + full history (`git log --all -p`) for token/secret/password/key patterns. Clean: only placeholder values (`your-gotify-app-token`, `gotify.example.com`) and doc mentions. `.env` never committed.

## Known soft spots to decide before going public

- RESOLVED 2026-11-27: all mentions of the internal hostname were scrubbed from tracked files and commit messages (package renamed to `server_monitor`, metric/Redis prefixes renamed); history rewritten and force-pushed.
- Add gitleaks (or equivalent) as a CI job so leaks are caught automatically — not yet added (CI is issue #8's scope, already merged; propose as follow-up).
