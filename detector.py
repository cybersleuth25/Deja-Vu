"""Rule-based detection (no ML). Thresholds come from the tech spec, section 8."""
from __future__ import annotations

from collections import Counter, defaultdict

# Handler files for login endpoints, so security alerts can be matched to code with history.
ROUTE_FILES = {"/api/v1/login": ["auth/login.py"], "/sso/login": ["auth/sso.py"]}
EDGE_FILES = ["infra/firewall/edge.tf"]

FAILED_LOGIN_MIN = 200
FAILED_LOGIN_MIN_IPS = 20
SPRAY_MIN_USERS = 30
SPRAY_MAX_TRIES = 4
SCAN_MIN_PORTS = 100
POOL_PCT = 0.95
ERROR_RATE = 0.05
ERROR_MIN_REQUESTS = 100


def _recent_change(events: list[dict], service: str) -> dict | None:
    deploys = [e for e in events if e["kind"] == "deploy" and e["service"] == service]
    if not deploys:
        return None
    d = min(deploys, key=lambda e: e["hours_ago"])
    return {"summary": d["summary"], "files": d["files"], "hours_before": d["hours_ago"]}


def failed_login_burst(events: list[dict]) -> list[dict]:
    by_asn: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e["kind"] == "login" and not e["ok"]:
            by_asn[e["asn"]].append(e)
    alerts = []
    for asn, evs in by_asn.items():
        ips = {e["ip"] for e in evs}
        if len(evs) >= FAILED_LOGIN_MIN and len(ips) >= FAILED_LOGIN_MIN_IPS:
            path = Counter(e["path"] for e in evs).most_common(1)[0][0]
            svc = evs[0]["service"]
            subnets = sorted({".".join(e["ip"].split(".")[:2]) + ".0.0/16" for e in evs})[:3]
            alerts.append({
                "rule": "failed_login_burst", "type": "security", "service": svc, "severity": "SEV2",
                "title": f"Credential stuffing against {path}",
                "signal": f"{len(evs)} failed logins from {len(ips)} IPs in {', '.join(subnets)} ({asn})",
                "files": ROUTE_FILES.get(path, []), "asn": asn,
                "evidence": {"failed_logins": len(evs), "distinct_ips": len(ips), "asn": asn},
            })
    return alerts


def password_spray(events: list[dict]) -> list[dict]:
    per_asn_user: dict[str, Counter] = defaultdict(Counter)
    svc_path: dict[str, tuple[str, str]] = {}
    for e in events:
        if e["kind"] == "login" and not e["ok"]:
            per_asn_user[e["asn"]][e["user"]] += 1
            svc_path[e["asn"]] = (e["service"], e["path"])
    # A high-volume burst is credential stuffing, not a low-and-slow spray; report it once.
    burst_asns = {a["asn"] for a in failed_login_burst(events)}
    alerts = []
    for asn, users in per_asn_user.items():
        if asn in burst_asns:
            continue
        if len(users) >= SPRAY_MIN_USERS and max(users.values()) <= SPRAY_MAX_TRIES:
            svc, path = svc_path[asn]
            alerts.append({
                "rule": "password_spray", "type": "security", "service": svc, "severity": "SEV2",
                "title": f"Password spray against {svc} accounts",
                "signal": f"{len(users)} accounts each hit with 1-{max(users.values())} attempts from {asn}",
                "files": ROUTE_FILES.get(path, []), "asn": asn,
                "evidence": {"distinct_users": len(users), "max_tries_per_user": max(users.values()), "asn": asn},
            })
    return alerts


def port_scan(events: list[dict]) -> list[dict]:
    ports: dict[str, set] = defaultdict(set)
    meta: dict[str, dict] = {}
    for e in events:
        if e["kind"] == "conn":
            ports[e["src_ip"]].add(e["dst_port"])
            meta[e["src_ip"]] = e
    alerts = []
    for ip, ps in ports.items():
        if len(ps) >= SCAN_MIN_PORTS:
            m = meta[ip]
            alerts.append({
                "rule": "port_scan", "type": "security", "service": m["service"], "severity": "SEV3",
                "title": f"Port scan against {m['service']}",
                "signal": f"SYN to {len(ps)} distinct ports from {ip} ({m['asn']})",
                "files": EDGE_FILES, "asn": m["asn"],
                "evidence": {"src_ip": ip, "distinct_ports": len(ps)},
            })
    return alerts


def pool_saturation(events: list[dict]) -> list[dict]:
    alerts = []
    for e in events:
        if e["kind"] == "db_pool" and e["max"] and e["in_use"] / e["max"] >= POOL_PCT:
            svc = e["service"]
            stack = Counter(f for x in events if x["kind"] == "http" and x["service"] == svc for f in x["stack"])
            alerts.append({
                "rule": "pool_saturation", "type": "outage", "service": svc, "severity": "SEV1",
                "title": "Checkout 500s: DB connection pool exhausted" if svc == "payments-api"
                         else f"{svc}: DB connection pool exhausted",
                "signal": e["error"] or f"pool in use {e['in_use']}/{e['max']}",
                "files": [f for f, _ in stack.most_common(4)],
                "prior_change": _recent_change(events, svc), "asn": None,
                "evidence": {"in_use": e["in_use"], "max": e["max"]},
            })
    return alerts


def error_spike(events: list[dict]) -> list[dict]:
    by_svc: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e["kind"] == "http":
            by_svc[e["service"]].append(e)
    alerts = []
    for svc, evs in by_svc.items():
        bad = [e for e in evs if e["status"] >= 500]
        if len(evs) >= ERROR_MIN_REQUESTS and len(bad) / len(evs) > ERROR_RATE:
            err = Counter(e["error"] for e in bad if e["error"]).most_common(1)
            stack = Counter(f for e in bad for f in e["stack"])
            rate = 100 * len(bad) / len(evs)
            alerts.append({
                "rule": "error_spike", "type": "outage", "service": svc, "severity": "SEV1",
                "title": f"{svc}: HTTP 5xx spike",
                "signal": f"HTTP 5xx rate {rate:.1f}% over {len(evs)} requests; {err[0][0] if err else 'no error text'}",
                "files": [f for f, _ in stack.most_common(4)],
                "prior_change": _recent_change(events, svc), "asn": None,
                "evidence": {"requests": len(evs), "errors": len(bad), "rate_pct": round(rate, 1)},
            })
    return alerts


# Order matters: a pool saturation also produces 5xx, and the more specific rule should win.
RULES = [pool_saturation, failed_login_burst, password_spray, port_scan, error_spike]


def detect(events: list[dict]) -> list[dict]:
    alerts: list[dict] = []
    for rule in RULES:
        alerts.extend(rule(events))
    return alerts


def primary_alert(events: list[dict]) -> dict | None:
    """The single alert an incident is opened for (most specific rule first)."""
    alerts = detect(events)
    if not alerts:
        return None
    first = alerts[0]
    # A pool saturation and the 5xx spike it causes on the same service are one incident.
    first["related_rules"] = sorted({a["rule"] for a in alerts if a["service"] == first["service"]} - {first["rule"]})
    return first
