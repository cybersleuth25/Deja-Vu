"""Post (or update) one DejaVu comment on a pull request whose changed files have incident history.

Standard library only, so the workflow needs no `pip install`.

    # in GitHub Actions (see .github/workflows/dejavu-pr.yml)
    python scripts/pr_comment.py --files-from changed.txt

    # locally, print the comment without calling GitHub
    python scripts/pr_comment.py --dry-run auth/session.py docs/readme.md

GitHub REST endpoints used (issue comments are how PR conversation comments are made):
  GET   /repos/{owner}/{repo}/issues/{number}/comments
  POST  /repos/{owner}/{repo}/issues/{number}/comments
  PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import prcheck  # noqa: E402
from store import load_seed  # noqa: E402

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")


def gh(method: str, url: str, token: str, body: dict | None = None):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "dejavu-pr-bot")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read() or b"null")


def find_existing(repo: str, number: int, token: str) -> dict | None:
    page = 1
    while True:
        rows = gh("GET", f"{API}/repos/{repo}/issues/{number}/comments?per_page=100&page={page}", token)
        for c in rows:
            if prcheck.MARKER in (c.get("body") or ""):
                return c
        if len(rows) < 100:
            return None
        page += 1


def pr_number() -> int | None:
    if os.environ.get("PR_NUMBER"):
        return int(os.environ["PR_NUMBER"])
    path = os.environ.get("GITHUB_EVENT_PATH")
    if path and Path(path).exists():
        event = json.loads(Path(path).read_text(encoding="utf-8"))
        return (event.get("pull_request") or {}).get("number")
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="*", help="changed file paths")
    ap.add_argument("--files-from", help="file with one changed path per line")
    ap.add_argument("--incidents", default=str(ROOT / "data" / "incidents.json"))
    ap.add_argument("--dry-run", action="store_true", help="print the comment, do not call GitHub")
    args = ap.parse_args(argv)

    files = list(args.files)
    if args.files_from:
        files += Path(args.files_from).read_text(encoding="utf-8").splitlines()
    result = prcheck.check(files, load_seed(Path(args.incidents)))
    body = prcheck.render_markdown(result)
    print(f"changed files: {len(result['changed_files'])}, with incident history: {len(result['findings'])}")

    if args.dry_run:
        sys.stdout.flush()
        sys.stdout.buffer.write(body.encode("utf-8"))
        return 0

    token, repo, number = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_REPOSITORY"), pr_number()
    if not (token and repo and number):
        print("GITHUB_TOKEN, GITHUB_REPOSITORY and a pull request number are required (or use --dry-run).")
        return 2

    existing = find_existing(repo, number, token)
    if existing:
        gh("PATCH", f"{API}/repos/{repo}/issues/comments/{existing['id']}", token, {"body": body})
        print(f"updated comment {existing['id']}")
    elif result["findings"]:
        c = gh("POST", f"{API}/repos/{repo}/issues/{number}/comments", token, {"body": body})
        print(f"created comment {c.get('id')}")
    else:
        print("no incident history and no previous comment: nothing to post")
    return 0


if __name__ == "__main__":
    sys.exit(main())
