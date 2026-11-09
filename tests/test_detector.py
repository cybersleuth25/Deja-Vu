import pytest

import detector
import sim_events

EXPECTED = {
    "checkout_500s": ("pool_saturation", "outage"),
    "credential_stuffing": ("failed_login_burst", "security"),
    "password_spray": ("password_spray", "security"),
    "port_scan": ("port_scan", "security"),
    "api_5xx_spike": ("error_spike", "outage"),
}


@pytest.mark.parametrize("scenario,expected", EXPECTED.items())
def test_rule_fires_for_scenario(scenario, expected):
    alert = detector.primary_alert(sim_events.generate(scenario))
    assert alert is not None
    assert (alert["rule"], alert["type"]) == expected


def test_normal_traffic_fires_nothing():
    for seed in range(5):
        assert detector.detect(sim_events.generate("normal", seed=seed)) == []


def test_credential_stuffing_is_not_also_a_spray():
    rules = [a["rule"] for a in detector.detect(sim_events.generate("credential_stuffing"))]
    assert rules == ["failed_login_burst"]


def test_alerts_carry_context_for_matching():
    pool = detector.primary_alert(sim_events.generate("checkout_500s"))
    assert pool["service"] == "payments-api" and "db/pool.py" in pool["files"]
    assert pool["prior_change"]["files"] == ["db/pool.py"]
    stuffing = detector.primary_alert(sim_events.generate("credential_stuffing"))
    assert stuffing["asn"] == "AS14061" and stuffing["files"] == ["auth/login.py"]


def test_thresholds_are_respected():
    # 199 failed logins is below the burst threshold.
    events = [{"kind": "login", "ok": False, "user": f"u{n}", "ip": f"1.2.3.{n % 50}", "asn": "AS1",
               "service": "auth-api", "path": "/api/v1/login"} for n in range(199)]
    assert detector.failed_login_burst(events) == []
    events.append(dict(events[0]))
    assert len(detector.failed_login_burst(events)) == 1
    # 94% pool usage does not fire; 95% does.
    assert detector.pool_saturation([{"kind": "db_pool", "service": "s", "in_use": 94, "max": 100, "error": ""}]) == []
    assert detector.pool_saturation([{"kind": "db_pool", "service": "s", "in_use": 95, "max": 100, "error": ""}])
