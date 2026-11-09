import json

import analyzer
import detector
import sim_events
from memory_backend import INC_RE, MemoryUnavailable


def alert(scenario):
    return detector.primary_alert(sim_events.generate(scenario))


def actions(rows):
    return [a["action"] for a in rows]


def test_db_pool_restart_is_avoid_and_rollback_is_do_first(incidents, memory):
    r = analyzer.investigate(alert("checkout_500s"), incidents, memory, use_memory=True)
    assert r["deja_vu"]
    assert {"INC-0004", "INC-0009", "INC-0014", "INC-0020"} <= {m["id"] for m in r["matches"]}
    assert r["do_first"][0]["action"] == "Roll back pool config"
    assert (r["do_first"][0]["worked"], r["do_first"][0]["tried"]) == (3, 4)
    restart = next(a for a in r["avoid"] if a["action"] == "Restart connection pool")
    assert (restart["worked"], restart["tried"]) == (0, 4)
    assert "Restart connection pool" not in actions(r["do_first"])
    assert "INC-0004" in r["narrative"] and "failed" in r["narrative"]


def test_credential_stuffing_rate_limit_avoid_block_asn_do_first(incidents, memory):
    r = analyzer.investigate(alert("credential_stuffing"), incidents, memory, use_memory=True)
    assert r["do_first"][0]["action"] == "Block ASN at WAF"
    assert "Per-IP rate limit" in actions(r["avoid"])
    assert {m["id"] for m in r["matches"]} == {"INC-0002", "INC-0008", "INC-0012", "INC-0019"}


def test_memory_off_returns_generic_advice_and_no_incident_ids(incidents, memory):
    r = analyzer.investigate(alert("checkout_500s"), incidents, memory, use_memory=False)
    assert r["matches"] == [] and r["avoid"] == [] and not r["deja_vu"]
    assert "Restart service" in actions(r["do_first"])
    assert not INC_RE.search(json.dumps(r))


def test_recall_failure_degrades_to_store(incidents):
    class Broken:
        name = "broken"
        def recall(self, q, max_tokens=3000):
            raise MemoryUnavailable("connection refused")
    r = analyzer.investigate(alert("checkout_500s"), incidents, Broken(), use_memory=True)
    assert r["warnings"] and "recall failed" in r["warnings"][0]
    assert r["do_first"][0]["action"] == "Roll back pool config"


def test_scoring_follows_spec(incidents):
    a = alert("checkout_500s")
    inc = next(i for i in incidents if i["id"] == "INC-0020")
    s_without, _ = analyzer.score_incident(a, inc, set())
    s_with, why = analyzer.score_incident(a, inc, {"INC-0020"})
    assert s_with - s_without == 4 and "recalled by Hindsight" in why
    # type 2 + service 2 + two shared files 6 = 10 before keywords
    assert s_without >= 10


def test_rank_actions_rules():
    def m(iid, acts, score=10):
        return {"id": iid, "score": score, "incident": {"actions": [{"action": a, "worked": w} for a, w in acts]}}
    ranked = analyzer.rank_actions([
        m("A", [("x", True), ("y", False), ("z", True)]),
        m("B", [("x", True), ("y", False)]),
        m("C", [("x", False), ("w", False)]),
        m("D", [("x", True), ("q", False), ("q2", True)]),
    ])
    # x worked 3/4 and z worked 1/1 have the same smoothed rate (4/6 vs 2/3); more successes wins.
    assert actions(ranked["do_first"])[0] == "x"
    assert set(actions(ranked["avoid"])) == {"y", "w", "q"}
    assert all(a["rate"] >= 0.5 for a in ranked["do_first"]) and len(ranked["do_first"]) <= 3


def test_llm_narrative_with_unknown_id_falls_back_to_template(incidents, memory):
    class Liar:
        def complete(self, system, user, max_tokens=700):
            return "This is just like INC-9999. Restart everything."
    r = analyzer.investigate(alert("checkout_500s"), incidents, memory, use_memory=True, llm=Liar())
    assert r["narrative_source"] == "template" and "INC-9999" not in r["narrative"]


def test_llm_narrative_used_when_it_cites_matches(incidents, memory):
    class Good:
        def complete(self, system, user, max_tokens=700):
            return "Roll back the pool config (INC-0004, INC-0020); restarting the pool failed (INC-0009)."
    r = analyzer.investigate(alert("checkout_500s"), incidents, memory, use_memory=True, llm=Good())
    assert r["narrative_source"] == "llm"


def test_llm_error_falls_back(incidents, memory):
    class Down:
        def complete(self, *a, **k):
            raise RuntimeError("429 rate limited")
    r = analyzer.investigate(alert("checkout_500s"), incidents, memory, use_memory=True, llm=Down())
    assert r["narrative_source"] == "template" and any("LLM" in w for w in r["warnings"])
