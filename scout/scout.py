#!/usr/bin/env python3
"""
Minimal history-aware secret scout for GitHub repos you can clone.

Requires: git, Python 3.10+, and GITHUB_TOKEN (repo read scope) for --user/--org.
Findings are printed redacted by default — safe to paste into Slack/tickets.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

try:
    from patterns import PATTERNS, redact
except ImportError:  # python -m scout.scout from repo root
    from scout.patterns import PATTERNS, redact


GITHUB_API = "https://api.github.com"


@dataclass
class Finding:
    repo: str
    commit: str
    path: str
    pattern: str
    redacted: str


def run(cmd: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(
        cmd,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def run_bytes(cmd: list[str], cwd: Path | None = None) -> bytes:
    result = subprocess.run(
        cmd,
        cwd=cwd,
        check=True,
        capture_output=True,
    )
    return result.stdout


def blob_as_text(raw: bytes) -> str | None:
    """Return decoded text, or None if the blob looks binary / non-text."""
    if not raw:
        return ""
    sample = raw[:8192]
    if b"\0" in sample:
        return None
    # UTF-16 BOM and other obvious non-UTF-8 binaries (e.g. images).
    if sample.startswith((b"\xff\xfe", b"\xfe\xff", b"\xff\xd8\xff", b"\x89PNG")):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("latin-1")
        except UnicodeDecodeError:
            return None


def gh_get(path: str, token: str) -> list | dict:
    req = urllib.request.Request(
        f"{GITHUB_API}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "history-secret-scout",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def list_repos(owner: str, kind: str, token: str) -> list[str]:
    """Return clone URLs for public+accessible repos owned by user or org."""
    urls: list[str] = []
    page = 1
    while True:
        if kind == "user":
            path = f"/users/{owner}/repos?type=owner&per_page=100&page={page}"
        else:
            path = f"/orgs/{owner}/repos?type=all&per_page=100&page={page}"
        batch = gh_get(path, token)
        if not isinstance(batch, list) or not batch:
            break
        for repo in batch:
            if repo.get("archived"):
                continue
            clone = repo.get("clone_url")
            if clone:
                urls.append(clone)
        if len(batch) < 100:
            break
        page += 1
    return urls


def clone_repo(url: str, dest: Path, token: str | None) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    # Prefer HTTPS with token when provided (private repos / higher rate limits).
    clone_url = url
    if token and url.startswith("https://github.com/"):
        clone_url = url.replace(
            "https://github.com/",
            f"https://x-access-token:{token}@github.com/",
            1,
        )
    subprocess.run(
        ["git", "clone", "--quiet", "--no-checkout", clone_url, str(dest)],
        check=True,
        env=env,
        capture_output=True,
        text=True,
    )
    # Materialize all objects without a working tree checkout.
    run(["git", "config", "core.bare", "false"], cwd=dest)
    return dest


def scan_history(repo_dir: Path, repo_label: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()

    # All commits reachable from any ref.
    commits = [
        c
        for c in run(["git", "rev-list", "--all"], cwd=repo_dir).splitlines()
        if c.strip()
    ]

    for commit in commits:
        # Paths introduced or present at this commit (name-only is enough).
        try:
            names = run(
                ["git", "ls-tree", "-r", "--name-only", commit],
                cwd=repo_dir,
            ).splitlines()
        except subprocess.CalledProcessError:
            continue

        for path in names:
            if not path or _skip_path(path):
                continue
            try:
                raw = run_bytes(["git", "show", f"{commit}:{path}"], cwd=repo_dir)
            except subprocess.CalledProcessError:
                continue
            if len(raw) > 1_000_000:
                raw = raw[:1_000_000]
            text = blob_as_text(raw)
            if text is None:
                continue

            for pattern in PATTERNS:
                for match in pattern.regex.finditer(text):
                    value = match.group(1) if match.lastindex else match.group(0)
                    key = (commit[:12], path, pattern.name, value)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        Finding(
                            repo=repo_label,
                            commit=commit[:12],
                            path=path,
                            pattern=pattern.name,
                            redacted=redact(value),
                        )
                    )
    return findings


def _skip_path(path: str) -> bool:
    lower = path.lower()
    skip_ext = (
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".bmp",
        ".tif",
        ".tiff",
        ".pdf",
        ".zip",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".jar",
        ".war",
        ".class",
        ".o",
        ".so",
        ".dylib",
        ".dll",
        ".exe",
        ".bin",
        ".pyc",
        ".pyo",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".ico",
        ".mp3",
        ".mp4",
        ".mov",
        ".avi",
        ".wasm",
        ".sqlite",
        ".db",
    )
    return lower.endswith(skip_ext) or path.startswith(".git/")


def repo_label_from_url(url: str) -> str:
    # https://github.com/owner/name.git -> owner/name
    cleaned = url.rstrip("/").removesuffix(".git")
    parts = cleaned.split("/")
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return cleaned


def print_table(findings: list[Finding]) -> None:
    if not findings:
        print("No matches for configured patterns.")
        return
    print(f"{'REPO':<28} {'COMMIT':<12} {'PATTERN':<22} {'PATH':<32} REDACTED")
    print("-" * 120)
    for f in findings:
        print(
            f"{f.repo[:27]:<28} {f.commit:<12} {f.pattern[:21]:<22} "
            f"{f.path[:31]:<32} {f.redacted}"
        )
    print(f"\n{len(findings)} finding(s). Values are redacted — rotate at the issuer.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan git history of GitHub repos for commodity secret patterns."
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--user", help="GitHub username whose owned repos to scan")
    src.add_argument("--org", help="GitHub org whose repos to scan")
    src.add_argument(
        "--repo",
        action="append",
        dest="repos",
        help="Clone URL or owner/name (repeatable)",
    )
    src.add_argument(
        "--path",
        action="append",
        dest="paths",
        type=Path,
        help="Local git repo directory to scan (repeatable; no clone)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON findings instead of a table",
    )
    parser.add_argument(
        "--keep",
        type=Path,
        help="Directory to keep clones in (default: temp, deleted after run)",
    )
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN", "").strip() or None

    if not shutil.which("git"):
        print("git is required on PATH", file=sys.stderr)
        return 1

    all_findings: list[Finding] = []

    # Local paths: scan in place (used by demo-leaky-history).
    if args.paths:
        for raw in args.paths:
            repo_dir = raw.expanduser().resolve()
            if not (repo_dir / ".git").exists() and not (repo_dir / "HEAD").exists():
                print(f"Not a git repo: {repo_dir}", file=sys.stderr)
                return 2
            label = repo_dir.name
            print(f"Scanning {label} ({repo_dir})…", file=sys.stderr)
            all_findings.extend(scan_history(repo_dir, label))
        if args.json:
            print(json.dumps([asdict(f) for f in all_findings], indent=2))
        else:
            print_table(all_findings)
        return 0

    clone_urls: list[str] = []
    if args.user or args.org:
        if not token:
            print("GITHUB_TOKEN is required for --user/--org", file=sys.stderr)
            return 2
        try:
            if args.user:
                clone_urls = list_repos(args.user, "user", token)
            else:
                clone_urls = list_repos(args.org, "org", token)
        except urllib.error.HTTPError as exc:
            print(f"GitHub API error: {exc.code} {exc.reason}", file=sys.stderr)
            return 1
    else:
        for item in args.repos or []:
            if item.startswith("http://") or item.startswith("https://") or item.endswith(".git"):
                clone_urls.append(item)
            elif "/" in item:
                clone_urls.append(f"https://github.com/{item}.git")
            else:
                print(f"Unrecognized --repo value: {item}", file=sys.stderr)
                return 2

    if not clone_urls:
        print("No repositories to scan.", file=sys.stderr)
        return 1

    work_root = args.keep
    cleanup = False
    if work_root is None:
        work_root = Path(tempfile.mkdtemp(prefix="secret-scout-"))
        cleanup = True
    else:
        work_root.mkdir(parents=True, exist_ok=True)

    try:
        for url in clone_urls:
            label = repo_label_from_url(url)
            dest = work_root / label.replace("/", "__")
            if dest.exists():
                shutil.rmtree(dest)
            print(f"Scanning {label}…", file=sys.stderr)
            try:
                clone_repo(url, dest, token)
                all_findings.extend(scan_history(dest, label))
            except subprocess.CalledProcessError as exc:
                err = (exc.stderr or exc.stdout or str(exc)).strip()
                print(f"  skip {label}: {err}", file=sys.stderr)
    finally:
        if cleanup:
            shutil.rmtree(work_root, ignore_errors=True)

    if args.json:
        print(json.dumps([asdict(f) for f in all_findings], indent=2))
    else:
        print_table(all_findings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
