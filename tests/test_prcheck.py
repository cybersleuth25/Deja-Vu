import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import prcheck
from scripts import pr_comment


def test_auth_session_has_findings(incidents):
    r = prcheck.check(["auth/session.py"], incidents)
    assert len(r["findings"]) == 1
    f = r["findings"][0]
    assert f["outages"] == 3 and f["security"] == 0
    assert [h["id"] for h in f["incidents"]] == ["INC-0007", "INC-0025", "INC-0029"]
    assert r["pattern"] and r["pattern"]["count"] == 4


def test_unrelated_file_has_none(incidents):
    r = prcheck.check(["docs/onboarding.md", "README.md"], incidents)
    assert r["findings"] == [] and r["pattern"] is None


def test_markdown_has_marker_and_ids(incidents):
    md = prcheck.render_markdown(prcheck.check(["./auth/session.py", "docs/x.md"], incidents))
    assert md.startswith(prcheck.MARKER)
    assert "`auth/session.py` was involved in 3 outages" in md
    assert "INC-0025" in md and "docs/x.md" not in md


# ---- pr_comment.py against a fake GitHub API ----
class FakeGitHub(BaseHTTPRequestHandler):
    comments: list = []
    calls: list = []

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.calls.append(("GET", self.path))
        self._send(200, self.comments)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.calls.append(("POST", self.path))
        c = {"id": 100 + len(self.comments), "body": body["body"], "user": {"login": "github-actions[bot]"}}
        self.comments.append(c)
        self._send(201, c)

    def do_PATCH(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.calls.append(("PATCH", self.path))
        cid = int(self.path.rsplit("/", 1)[1])
        for c in self.comments:
            if c["id"] == cid:
                c["body"] = body["body"]
        self._send(200, {"id": cid})

    def log_message(self, *a):
        pass


def test_pr_comment_creates_then_updates_one_comment(monkeypatch):
    FakeGitHub.comments, FakeGitHub.calls = [{"id": 1, "body": "unrelated human comment"}], []
    srv = HTTPServer(("127.0.0.1", 0), FakeGitHub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setattr(pr_comment, "API", f"http://127.0.0.1:{srv.server_port}")
        monkeypatch.setenv("GITHUB_TOKEN", "test-token")
        monkeypatch.setenv("GITHUB_REPOSITORY", "acme/shop")
        monkeypatch.setenv("PR_NUMBER", "7")
        assert pr_comment.main(["auth/session.py"]) == 0
        assert ("POST", "/repos/acme/shop/issues/7/comments") in FakeGitHub.calls
        assert pr_comment.main(["auth/session.py", "db/pool.py"]) == 0
        assert any(m == "PATCH" and p == "/repos/acme/shop/issues/comments/101" for m, p in FakeGitHub.calls)
        bot = [c for c in FakeGitHub.comments if prcheck.MARKER in c["body"]]
        assert len(bot) == 1 and "db/pool.py" in bot[0]["body"]
    finally:
        srv.shutdown()


def test_pr_comment_skips_when_nothing_to_say(monkeypatch):
    FakeGitHub.comments, FakeGitHub.calls = [], []
    srv = HTTPServer(("127.0.0.1", 0), FakeGitHub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setattr(pr_comment, "API", f"http://127.0.0.1:{srv.server_port}")
        monkeypatch.setenv("GITHUB_TOKEN", "t"); monkeypatch.setenv("GITHUB_REPOSITORY", "a/b"); monkeypatch.setenv("PR_NUMBER", "1")
        assert pr_comment.main(["docs/x.md"]) == 0
        assert [m for m, _ in FakeGitHub.calls] == ["GET"]
    finally:
        srv.shutdown()


def test_marker_pasted_by_a_human_is_not_treated_as_the_bot_comment(monkeypatch):
    spoof = {"id": 1, "body": prcheck.MARKER + " nothing to see here", "user": {"login": "someone"}}
    FakeGitHub.comments, FakeGitHub.calls = [spoof], []
    srv = HTTPServer(("127.0.0.1", 0), FakeGitHub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setattr(pr_comment, "API", f"http://127.0.0.1:{srv.server_port}")
        monkeypatch.setenv("GITHUB_TOKEN", "t"); monkeypatch.setenv("GITHUB_REPOSITORY", "a/b"); monkeypatch.setenv("PR_NUMBER", "3")
        assert pr_comment.main(["auth/session.py"]) == 0
        assert not any(m == "PATCH" for m, _ in FakeGitHub.calls)  # the human's comment is untouched
        assert ("POST", "/repos/a/b/issues/3/comments") in FakeGitHub.calls  # the real warning is posted
        assert FakeGitHub.comments[0] == spoof
    finally:
        srv.shutdown()


def test_is_ours_needs_bot_author_and_leading_marker():
    bot = {"login": "github-actions[bot]"}
    assert pr_comment.is_ours({"user": bot, "body": prcheck.MARKER + "x"})
    assert not pr_comment.is_ours({"user": {"login": "mallory"}, "body": prcheck.MARKER + "x"})
    assert not pr_comment.is_ours({"user": bot, "body": "quoted: " + prcheck.MARKER})
    assert not pr_comment.is_ours({"body": prcheck.MARKER})
