import copy

import insights


def test_tuesday_evening_is_8_of_10(incidents):
    t = insights.compute(incidents)["tuesday_evening"]
    assert (t["count"], t["total"]) == (8, 10)
    assert len(t["ids"]) == 8


def test_auth_precursor_is_4_of_last_6(incidents):
    p = insights.compute(incidents)["auth_precursor"]
    assert (p["count"], p["total"]) == (4, 6)
    assert p["ids"] == ["INC-0025", "INC-0028", "INC-0029", "INC-0032"]


def test_insights_are_computed_not_hard_coded(incidents):
    data = copy.deepcopy(incidents)
    for i in data:
        if i["id"] == "INC-0032":
            i["prior_change"] = None
    assert insights.compute(data)["auth_precursor"]["count"] == 3


def test_open_incidents_are_excluded(incidents):
    data = copy.deepcopy(incidents) + [{"id": "INC-0099", "type": "outage", "status": "open",
                                         "opened_at": "2026-11-09T10:00", "actions": [], "files": []}]
    assert insights.compute(data)["auth_precursor"]["window_ids"][-1] == "INC-0032"


def test_always_fail_actions(incidents):
    names = {a["action"]: a for a in insights.compute(incidents)["always_fail"]}
    assert names["Restart connection pool"]["tried"] == 4
    assert names["Per-IP rate limit"]["tried"] == 3


def test_reflect_summary_never_raises():
    class Broken:
        name = "broken"
        def reflect(self, q):
            raise RuntimeError("timeout")
    out = insights.reflect_summary(Broken())
    assert out["text"] == "" and "timeout" in out["error"]
