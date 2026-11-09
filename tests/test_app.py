import json

from app import create_app
from memory_backend import INC_RE, MemoryUnavailable, MockMemory


class FailingMemory(MockMemory):
    name = "failing"

    def retain_verdict(self, *a, **k):
        raise MemoryUnavailable("Hindsight retain failed: 503 Service Unavailable")

    def retain_incident(self, *a, **k):
        raise MemoryUnavailable("Hindsight retain failed: 503 Service Unavailable")

    def recall(self, *a, **k):
        raise MemoryUnavailable("Hindsight recall failed: timeout")

    def reflect(self, *a, **k):
        raise MemoryUnavailable("Hindsight reflect failed: timeout")


def test_index_and_state(client):
    assert client.get("/").status_code == 200
    s = client.get("/api/state").get_json()
    assert len(s["incidents"]) == 32 and s["memory_backend"] == "mock"
    assert s["insights"]["tuesday_evening"]["count"] == 8


def test_trigger_with_memory(client):
    r = client.post("/api/trigger", json={"scenario": "checkout_500s", "use_memory": True}).get_json()
    assert r["detected"] and r["incident"]["id"] == "INC-0033"
    assert r["analysis"]["deja_vu"]
    assert r["analysis"]["do_first"][0]["action"] == "Roll back pool config"


def test_memory_off_response_has_no_past_incident_ids(client):
    r = client.post("/api/trigger", json={"scenario": "checkout_500s", "use_memory": False}).get_json()
    own = r["incident"]["id"]
    blob = json.dumps(r["analysis"]) + json.dumps(r["alert"])
    assert not INC_RE.search(blob)
    assert set(INC_RE.findall(json.dumps(r))) == {own}


def test_normal_traffic_opens_nothing(client):
    r = client.post("/api/trigger", json={"scenario": "normal"}).get_json()
    assert r["detected"] is False
    assert len(client.get("/api/state").get_json()["incidents"]) == 32


def test_failing_retain_does_not_break_outcome(store):
    c = create_app(store=store, memory=FailingMemory(), llm=None).test_client()
    trig = c.post("/api/trigger", json={"scenario": "checkout_500s", "use_memory": True})
    assert trig.status_code == 200
    iid = trig.get_json()["incident"]["id"]
    assert trig.get_json()["warnings"]  # recall failure surfaced, not raised
    r = c.post(f"/api/incidents/{iid}/outcome", json={"action": "Roll back pool config", "worked": True})
    assert r.status_code == 200
    body = r.get_json()
    assert body["retained"] is False and "not retained" in body["warnings"][0]
    assert body["incident"]["actions"] == [{"action": "Roll back pool config", "worked": True, "note": ""}]
    res = c.post(f"/api/incidents/{iid}/resolve", json={"root_cause": "pool_size reverted"})
    assert res.status_code == 200 and res.get_json()["incident"]["status"] == "resolved"
    ins = c.get("/api/insights")
    assert ins.status_code == 200 and ins.get_json()["warnings"]


def test_outcome_validation(client):
    assert client.post("/api/incidents/INC-0001/outcome", json={"worked": True}).status_code == 400
    assert client.post("/api/incidents/INC-9999/outcome", json={"action": "x", "worked": True}).status_code == 404


def test_feedback_loop_improves_next_answer(client):
    iid = client.post("/api/trigger", json={"scenario": "checkout_500s"}).get_json()["incident"]["id"]
    client.post(f"/api/incidents/{iid}/outcome", json={"action": "Restart connection pool", "worked": False})
    client.post(f"/api/incidents/{iid}/outcome", json={"action": "Roll back pool config", "worked": True})
    client.post(f"/api/incidents/{iid}/resolve", json={"root_cause": "pool_size reverted again"})
    nxt = client.post("/api/trigger", json={"scenario": "checkout_500s"}).get_json()["analysis"]
    assert iid in {m["id"] for m in nxt["matches"]}
    restart = next(a for a in nxt["avoid"] if a["action"] == "Restart connection pool")
    assert restart["tried"] == 5


def test_pr_check_endpoint(client):
    r = client.post("/api/pr-check", json={"files": ["auth/session.py", "docs/a.md"]}).get_json()
    assert [f["file"] for f in r["findings"]] == ["auth/session.py"]
    assert r["markdown"].startswith("<!-- dejavu-pr-warning -->")


def test_reset_restores_seed(client):
    client.post("/api/trigger", json={"scenario": "port_scan"})
    assert client.post("/api/reset").get_json()["ok"]
    assert len(client.get("/api/state").get_json()["incidents"]) == 32
