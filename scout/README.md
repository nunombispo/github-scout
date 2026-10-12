# History-aware secret scout

Minimal Python tool that clones GitHub repos you can access, walks **git history** (not just HEAD), matches a small set of commodity secret patterns, and prints **redacted** findings.

## Requirements

- Python 3.10+
- `git` on PATH
- `GITHUB_TOKEN` with read access to the repos you scan (needed for `--user` / `--org`; also helps with private clones)

No third-party packages.

## Usage

```bash
export GITHUB_TOKEN=ghp_…   # read-only is enough

# All repos you own
python scout.py --user YOUR_USER

# An org
python scout.py --org YOUR_ORG

# Explicit repos
python scout.py --repo owner/name --repo https://github.com/other/repo.git

# Local git checkout (no clone) — e.g. the bundled demo
python scout.py --path ../demo-leaky-history

# Machine-readable
python scout.py --user YOUR_USER --json
```

## Demo: secrets in history, not on `main`

`../demo-leaky-history` is a tiny git repo that committed a fake `.env`, then deleted it. The tip has no `.env`; `git show ec824970bd74:.env` still does. Fake values only (Amazon docs examples + invented hex).

Run from this directory (`scout/`), or:

```bash
python -m scout.scout --user YOUR_USER
```

from the repo root if you set `PYTHONPATH=.`.

## Output

Table columns: repo, commit, pattern, path, redacted value. Safe to paste into Slack or a ticket. **Rotate at the issuer** for every real hit — a clean `main` is not remediation.

## Extending

Add org-specific formats in `patterns.py`. Prefer GitHub secret scanning / gitleaks for commodity coverage; keep this scout thin.
