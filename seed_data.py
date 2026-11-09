"""Generate data/incidents.json: 32 resolved incidents (22 outages, 10 security), Aug-Nov 2026.

The file is the system of record that analyzer, insights and the PR bot read. Patterns are
planted on purpose and verified at the bottom of this script (and again in tests/), so every
claim the UI makes can be traced back to incident ids.

    python seed_data.py          # writes data/incidents.json and prints the pattern check
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

DATA_PATH = Path(__file__).parent / "data" / "incidents.json"

# Canonical action strings. Always reuse these exact strings so success rates aggregate.
RESTART_POOL = "Restart connection pool"
ROLLBACK_POOL = "Roll back pool config"
PATCH_LEAK = "Patch connection leak"
RESTART_SERVICE = "Restart service"
ROLLBACK_DEPLOY = "Roll back last deploy"
SCALE_REPLICAS = "Scale up replicas"
PER_IP_RATE_LIMIT = "Per-IP rate limit"
BLOCK_ASN = "Block ASN at WAF"
LOGIN_CAPTCHA = "Enable CAPTCHA on login"
ENFORCE_MFA = "Enforce MFA for targeted users"
LOCK_ACCOUNTS = "Lock targeted accounts"
BLOCK_IP = "Block source IP at firewall"


def act(action: str, worked: bool, note: str = "") -> dict:
    return {"action": action, "worked": worked, "note": note}


def change(summary: str, files: list[str], hours_before: int) -> dict:
    return {"summary": summary, "files": files, "hours_before": hours_before}


# Chronological list. ids are assigned in this order (INC-0001 ... INC-0032).
RAW: list[dict] = [
    # ---- August ----
    dict(type="outage", opened_at="2026-08-03T09:14", service="search-svc", severity="SEV2",
         title="Search 503s: Elasticsearch circuit breaker tripped",
         signal="circuit_breaking_exception: [parent] Data too large, data for [<http_request>] would be [4089446912/3.8gb], which is larger than the limit of [4080218931/3.7gb]",
         files=["search/indexer.py", "search/query_builder.py"],
         root_cause="Nightly reindex ran during peak traffic and doubled heap pressure on the 3-node cluster.",
         actions=[act(RESTART_SERVICE, False, "Breaker tripped again within 4 minutes."),
                  act("Scale out search nodes", True, "Added 2 data nodes; heap settled at 61%.")],
         prior_change=None, asn=None),
    dict(type="security", opened_at="2026-08-04T19:42", service="auth-api", severity="SEV2",
         title="Credential stuffing against /api/v1/login",
         signal="2,914 failed logins in 11 min from 63 IPs in 104.248.0.0/16 and 159.65.0.0/16 (AS14061 DigitalOcean)",
         files=["auth/login.py"],
         root_cause="Combo-list replay from rented VPS hosts; each IP stayed under the per-IP threshold.",
         actions=[act(PER_IP_RATE_LIMIT, False, "Attacker spread load across 63 IPs at ~4 req/min each."),
                  act(BLOCK_ASN, True, "Failed logins dropped to baseline within 2 minutes.")],
         prior_change=None, asn="AS14061"),
    dict(type="outage", opened_at="2026-08-07T15:32", service="notifications-worker", severity="SEV3",
         title="Notification backlog: SQS queue age above 40 minutes",
         signal="ApproximateAgeOfOldestMessage=2417s on queue notify-prod; worker crash loop: KeyError: 'template_id'",
         files=["workers/notify.py"],
         root_cause="A malformed message without template_id crashed every worker that picked it up.",
         actions=[act(RESTART_SERVICE, False, "Workers crashed again on the same message."),
                  act("Move poison message to DLQ", True, "Queue drained in 9 minutes.")],
         prior_change=change("Add marketing template fields", ["workers/notify.py"], 26), asn=None),
    dict(type="outage", opened_at="2026-08-12T11:05", service="payments-api", severity="SEV1",
         title="Checkout 500s: DB connection pool exhausted",
         signal="sqlalchemy.exc.TimeoutError: QueuePool limit of size 20 overflow 10 reached, connection timed out, timeout 30.00",
         files=["db/pool.py", "payments/checkout.py"],
         root_cause="Config cleanup lowered pool_size from 50 to 20 while checkout traffic was at weekday peak.",
         actions=[act(RESTART_POOL, False, "Pool refilled and saturated again in under a minute."),
                  act(ROLLBACK_POOL, True, "Restored pool_size=50; 500s stopped.")],
         prior_change=change("Tidy db config", ["db/pool.py"], 4), asn=None),
    dict(type="security", opened_at="2026-08-18T20:15", service="sso-gateway", severity="SEV2",
         title="Password spray against SSO accounts",
         signal="412 accounts each hit with 2-3 attempts of 'Summer2026!' from 89.46.0.0/16 (AS9009 M247)",
         files=["auth/sso.py"],
         root_cause="Low-and-slow spray of seasonal passwords across the employee directory.",
         actions=[act(LOCK_ACCOUNTS, True, "Temporarily locked 412 targeted accounts."),
                  act(ENFORCE_MFA, True, "Forced MFA enrolment for 37 accounts without it.")],
         prior_change=None, asn="AS9009"),
    dict(type="outage", opened_at="2026-08-20T13:40", service="api-gateway", severity="SEV1",
         title="All API traffic failing: TLS certificate expired",
         signal="x509: certificate has expired or is not yet valid: current time 2026-08-20T13:38:02Z is after 2026-08-20T12:00:00Z",
         files=["infra/certs/gateway.yaml"],
         root_cause="cert-manager renewal failed silently after the ACME account key was rotated.",
         actions=[act("Renew TLS certificate", True, "Manually issued and rolled the cert.")],
         prior_change=None, asn=None),
    dict(type="outage", opened_at="2026-08-27T16:10", service="auth-api", severity="SEV2",
         title="Users logged out at random: session store evictions",
         signal="redis: evicted_keys=184233 in 5m; auth.session: SessionNotFound for valid cookies (rate 31%)",
         files=["auth/session.py"],
         root_cause="Session TTL change wrote keys without expiry to a maxmemory-policy=allkeys-lru cache.",
         actions=[act(RESTART_SERVICE, False, "No effect; sessions still evicted."),
                  act(ROLLBACK_DEPLOY, True, "Restored previous session writer.")],
         prior_change=change("Shorten session TTL", ["auth/session.py"], 20), asn=None),
    # ---- September ----
    dict(type="security", opened_at="2026-09-01T18:30", service="auth-api", severity="SEV2",
         title="Credential stuffing against /api/v1/login",
         signal="5,120 failed logins in 18 min from 88 IPs in 167.99.0.0/16 and 104.248.0.0/16 (AS14061 DigitalOcean)",
         files=["auth/login.py"],
         root_cause="Same combo-list campaign as INC-0002, new VPS range in the same ASN.",
         actions=[act(PER_IP_RATE_LIMIT, False, "Lowered per-IP limit to 10/min; attacker added more IPs."),
                  act(BLOCK_ASN, True, "Blocked AS14061 on /login; attack stopped.")],
         prior_change=None, asn="AS14061"),
    dict(type="outage", opened_at="2026-09-03T14:20", service="payments-api", severity="SEV1",
         title="Checkout 500s: DB connection pool exhausted",
         signal="sqlalchemy.exc.TimeoutError: QueuePool limit of size 20 overflow 5 reached, connection timed out, timeout 30.00",
         files=["db/pool.py", "payments/checkout.py"],
         root_cause="max_overflow lowered from 20 to 5 while a marketing email drove a traffic burst.",
         actions=[act(RESTART_POOL, False, "Saturated again after 40 seconds."),
                  act(ROLLBACK_POOL, True, "Restored max_overflow=20.")],
         prior_change=change("Lower pool max_overflow", ["db/pool.py"], 6), asn=None),
    dict(type="outage", opened_at="2026-09-09T10:05", service="checkout-web", severity="SEV2",
         title="Checkout page blank: CDN serving stale JS bundle",
         signal="ChunkLoadError: Loading chunk 812 failed. (missing: https://cdn.shop.example/_next/static/chunks/812.4f1c.js)",
         files=["web/next.config.js"],
         root_cause="CDN cache rule kept HTML for 1h but asset filenames changed on deploy.",
         actions=[act("Purge CDN cache", True, "Full purge; page loaded again.")],
         prior_change=change("Change CDN cache headers", ["web/next.config.js"], 14), asn=None),
    dict(type="security", opened_at="2026-09-10T03:12", service="edge-lb", severity="SEV3",
         title="Port scan against edge load balancer",
         signal="SYN to 1,846 distinct ports from 218.92.0.112 (AS4134 Chinanet) in 90 seconds",
         files=["infra/firewall/edge.tf"],
         root_cause="Internet-wide scanner; no service exposed beyond 80/443.",
         actions=[act(BLOCK_IP, True, "Dropped 218.92.0.112 at the edge firewall.")],
         prior_change=None, asn="AS4134"),
    dict(type="security", opened_at="2026-09-15T21:05", service="auth-api", severity="SEV1",
         title="Credential stuffing against /api/v1/login",
         signal="7,882 failed logins in 25 min from 140 IPs in 138.68.0.0/16 (AS14061 DigitalOcean), later residential IPs",
         files=["auth/login.py"],
         root_cause="Campaign switched to residential proxies minutes after the ASN block.",
         actions=[act(PER_IP_RATE_LIMIT, False, "No effect at 140 source IPs."),
                  act(BLOCK_ASN, False, "Attacker moved to residential proxies (AS7922, AS701)."),
                  act(LOGIN_CAPTCHA, True, "CAPTCHA after 1 failed login stopped the replay.")],
         prior_change=None, asn="AS14061"),
    dict(type="outage", opened_at="2026-09-17T08:55", service="orders-api", severity="SEV2",
         title="Orders API 500s: log volume full",
         signal="OSError: [Errno 28] No space left on device: '/var/log/orders/app.log'",
         files=["orders/logging.yaml"],
         root_cause="Debug logging left on after an investigation; logrotate not configured for the new path.",
         actions=[act(RESTART_SERVICE, False, "Disk still full; failed again on first write."),
                  act("Rotate and compress logs", True, "Freed 61 GB.")],
         prior_change=change("Enable debug logging", ["orders/logging.yaml"], 41), asn=None),
    dict(type="outage", opened_at="2026-09-24T09:47", service="payments-api", severity="SEV1",
         title="Checkout 500s: DB connection pool exhausted",
         signal="sqlalchemy.exc.TimeoutError: QueuePool limit of size 50 overflow 20 reached, connection timed out, timeout 30.00",
         files=["db/pool.py", "payments/checkout.py"],
         root_cause="Connection leak: new retry wrapper in checkout did not return connections on exception.",
         actions=[act(RESTART_POOL, False, "Leak refilled the pool within 3 minutes."),
                  act(ROLLBACK_POOL, False, "Pool config was unchanged; nothing to roll back."),
                  act(PATCH_LEAK, True, "Wrapped session in context manager; hotfix deployed.")],
         prior_change=change("Add retry wrapper to checkout", ["payments/checkout.py"], 30), asn=None),
    dict(type="security", opened_at="2026-09-29T17:48", service="public-api", severity="SEV2",
         title="API token enumeration on /v2/orders",
         signal="1.2M requests with 38,000 distinct bearer tokens from 51.68.0.0/16 (AS16276 OVH); 214 valid hits",
         files=["api/auth_tokens.py"],
         root_cause="Short legacy API tokens were brute-forceable; tokens leaked in an old partner script.",
         actions=[act("Revoke leaked API tokens", True, "Revoked 214 tokens and notified partners.")],
         prior_change=None, asn="AS16276"),
    # ---- October ----
    dict(type="outage", opened_at="2026-10-01T12:30", service="inventory-svc", severity="SEV2",
         title="Stock reservations timing out: row lock contention",
         signal="psycopg2.errors.LockNotAvailable: canceling statement due to lock timeout (reservations, sku=...)",
         files=["inventory/reserve.py"],
         root_cause="New bulk reservation path locked rows in a different order than single reservations.",
         actions=[act("Kill blocking DB sessions", True, "Cleared 14 blocked sessions."),
                  act(ROLLBACK_DEPLOY, True, "Removed bulk reservation path.")],
         prior_change=change("Bulk reservation endpoint", ["inventory/reserve.py"], 8), asn=None),
    dict(type="outage", opened_at="2026-10-06T22:10", service="search-svc", severity="SEV3",
         title="Search latency p99 above 6s after mapping change",
         signal="slowlog: took[6.4s] query: wildcard on keyword field 'title.raw'",
         files=["search/query_builder.py"],
         root_cause="Query builder started using leading wildcards on an unanalyzed field.",
         actions=[act(RESTART_SERVICE, False, "No change in latency."),
                  act(ROLLBACK_DEPLOY, True, "Latency back to 180ms.")],
         prior_change=change("Fuzzy title search", ["search/query_builder.py"], 3), asn=None),
    dict(type="outage", opened_at="2026-10-09T14:45", service="notifications-worker", severity="SEV3",
         title="Email delivery failing: provider rate limit",
         signal="smtplib.SMTPDataError: (421, b'4.7.0 Rate limit exceeded for account 88213')",
         files=["workers/email.py"],
         root_cause="Weekly digest sent 1.4M emails in one burst against a 50k/min account limit.",
         actions=[act("Fail over to secondary email provider", True, "Digest completed on secondary.")],
         prior_change=None, asn=None),
    dict(type="security", opened_at="2026-10-13T19:20", service="auth-api", severity="SEV2",
         title="Credential stuffing against /api/v1/login",
         signal="3,406 failed logins in 9 min from 57 IPs in 164.90.0.0/16 (AS14061 DigitalOcean)",
         files=["auth/login.py"],
         root_cause="Same campaign, new DigitalOcean range; CAPTCHA had been relaxed for mobile clients.",
         actions=[act(BLOCK_ASN, True, "Blocked AS14061 on /login and /token immediately.")],
         prior_change=None, asn="AS14061"),
    dict(type="outage", opened_at="2026-10-15T11:05", service="payments-api", severity="SEV1",
         title="Checkout 500s: DB connection pool exhausted",
         signal="sqlalchemy.exc.TimeoutError: QueuePool limit of size 20 overflow 10 reached, connection timed out, timeout 30.00",
         files=["db/pool.py", "payments/checkout.py"],
         root_cause="'Tidy db config' reverted pool_size to the library default of 20.",
         actions=[act(RESTART_POOL, False, "Saturated again in 50 seconds."),
                  act(ROLLBACK_POOL, True, "Restored pool_size=50 and max_overflow=20.")],
         prior_change=change("Tidy db config", ["db/pool.py"], 4), asn=None),
    dict(type="outage", opened_at="2026-10-19T17:20", service="api-gateway", severity="SEV2",
         title="Gateway 502s after autoscaler scale-down",
         signal="upstream connect error or disconnect/reset before headers. reset reason: connection termination (502 rate 9.1%)",
         files=["infra/k8s/gateway-hpa.yaml"],
         root_cause="HPA minReplicas lowered to 2; pods terminated without draining connections.",
         actions=[act(SCALE_REPLICAS, True, "Scaled to 6 replicas; 502s stopped.")],
         prior_change=change("Lower gateway minReplicas", ["infra/k8s/gateway-hpa.yaml"], 12), asn=None),
    dict(type="security", opened_at="2026-10-20T18:05", service="sso-gateway", severity="SEV2",
         title="Password spray against SSO accounts",
         signal="296 accounts each hit with 1-3 attempts of 'Autumn2026!' from 185.156.0.0/16 (AS9009 M247)",
         files=["auth/sso.py"],
         root_cause="Seasonal spray from the same hosting provider as INC-0005.",
         actions=[act(LOCK_ACCOUNTS, True, "Locked targeted accounts for 30 minutes."),
                  act(ENFORCE_MFA, True, "MFA now mandatory for all SSO users.")],
         prior_change=None, asn="AS9009"),
    dict(type="outage", opened_at="2026-10-22T09:30", service="orders-api", severity="SEV3",
         title="Order confirmations delayed: Kafka consumer lag",
         signal="consumer group orders-confirm lag=412,907 on topic orders.created (partitions 0-11)",
         files=["orders/consumer.py"],
         root_cause="Consumer count stayed at 3 while topic was repartitioned to 12.",
         actions=[act("Scale out consumers", True, "Scaled consumers to 12; lag cleared in 20 min.")],
         prior_change=None, asn=None),
    dict(type="outage", opened_at="2026-10-23T15:50", service="checkout-web", severity="SEV2",
         title="Checkout button broken: JS TypeError",
         signal="TypeError: Cannot read properties of undefined (reading 'currency') at CartSummary.tsx:88",
         files=["web/components/CartSummary.tsx"],
         root_cause="Cart API returned a null price for gift cards; the component assumed it was always set.",
         actions=[act(ROLLBACK_DEPLOY, True, "Rolled back web release 2026.10.23-2.")],
         prior_change=change("Gift card checkout", ["web/components/CartSummary.tsx"], 5), asn=None),
    dict(type="outage", opened_at="2026-10-27T10:12", service="auth-api", severity="SEV1",
         title="Login 500s: JWT verification failing after key rotation",
         signal="jwt.exceptions.InvalidSignatureError: Signature verification failed (kid=2026-10-27a not in JWKS cache)",
         files=["middleware/jwt_verify.py", "auth/session.py"],
         root_cause="New signing key published before verifiers refreshed their JWKS cache.",
         actions=[act(RESTART_SERVICE, False, "Pods came back with the same stale JWKS."),
                  act(ROLLBACK_DEPLOY, True, "Rolled back key rotation; re-ran with overlap window.")],
         prior_change=change("Rotate JWT signing keys", ["middleware/jwt_keys.py"], 6), asn=None),
    dict(type="security", opened_at="2026-10-27T20:40", service="api-gateway", severity="SEV1",
         title="Forged JWTs with alg=none accepted on internal route",
         signal="1,940 requests with header {\"alg\":\"none\"} to /internal/admin/users from 45.155.205.0/24 (AS206728)",
         files=["middleware/jwt_verify.py"],
         root_cause="Fallback verifier on an internal route did not pin the allowed algorithms.",
         actions=[act("Reject alg=none tokens", True, "Pinned algorithms to RS256."),
                  act("Rotate JWT signing key", True, "Rotated as a precaution.")],
         prior_change=None, asn="AS206728"),
    dict(type="outage", opened_at="2026-10-29T13:25", service="orders-api", severity="SEV2",
         title="Orders API 500s after feature flag rollout",
         signal="AttributeError: 'NoneType' object has no attribute 'tax_region' (flag: split_shipping=100%)",
         files=["orders/shipping.py"],
         root_cause="split_shipping flag enabled for all users before tax region backfill finished.",
         actions=[act("Disable feature flag", True, "Flag back to 0%; errors stopped.")],
         prior_change=None, asn=None),
    # ---- November ----
    dict(type="outage", opened_at="2026-11-02T09:40", service="api-gateway", severity="SEV1",
         title="API 5xx spike: auth middleware rejecting valid tokens",
         signal="HTTP 5xx rate 14.2% over 12,880 requests; auth.middleware: TokenParseError: unexpected claim 'scp'",
         files=["auth/middleware.py", "middleware/jwt_verify.py"],
         root_cause="Middleware refactor made the scope claim parser strict; IdP sends 'scp' as a string.",
         actions=[act(RESTART_SERVICE, False, "Same errors after restart."),
                  act(ROLLBACK_DEPLOY, True, "Rolled back middleware refactor.")],
         prior_change=change("Refactor auth middleware", ["auth/middleware.py"], 18), asn=None),
    dict(type="outage", opened_at="2026-11-03T16:05", service="payments-api", severity="SEV2",
         title="Checkout 5xx: session lookup timeouts",
         signal="redis.exceptions.TimeoutError: Timeout reading from sessions-v2.cache:6379 (p99 2.8s)",
         files=["payments/checkout.py", "auth/session.py"],
         root_cause="New Redis cluster for sessions had TLS enabled but clients used a 200ms timeout.",
         actions=[act(SCALE_REPLICAS, False, "More replicas made the Redis connection storm worse."),
                  act(ROLLBACK_DEPLOY, True, "Pointed sessions back at the old cluster.")],
         prior_change=change("Move session cache to new Redis cluster", ["auth/session.py"], 30), asn=None),
    dict(type="security", opened_at="2026-11-05T10:22", service="edge-lb", severity="SEV3",
         title="Port scan against edge load balancer",
         signal="SYN to 2,310 distinct ports from 218.92.0.205 (AS4134 Chinanet) in 2 minutes",
         files=["infra/firewall/edge.tf"],
         root_cause="Internet-wide scanner from the same range as INC-0011.",
         actions=[act(BLOCK_IP, True, "Dropped 218.92.0.205 at the edge firewall.")],
         prior_change=None, asn="AS4134"),
    dict(type="outage", opened_at="2026-11-05T11:30", service="search-svc", severity="SEV2",
         title="Search pods OOMKilled after reindex",
         signal="OOMKilled: container search-api exceeded memory limit 2Gi (restarts: 7)",
         files=["search/indexer.py"],
         root_cause="Reindex job and query pods shared a node pool during peak.",
         actions=[act("Scale out search nodes", True, "Moved reindex to a dedicated node pool.")],
         prior_change=None, asn=None),
    dict(type="outage", opened_at="2026-11-07T20:50", service="auth-api", severity="SEV2",
         title="Login with Google failing: OAuth callback 500s",
         signal="authlib.integrations.base_client.errors.MismatchingStateError: mismatching_state: CSRF Warning! State not equal in request and response.",
         files=["auth/oauth.py"],
         root_cause="OAuth library upgrade changed where state is stored; sticky sessions were off.",
         actions=[act(RESTART_SERVICE, False, "Errors continued."),
                  act(ROLLBACK_DEPLOY, True, "Pinned previous authlib version.")],
         prior_change=change("Upgrade OAuth library", ["auth/oauth.py"], 40), asn=None),
]


def build() -> list[dict]:
    rows = sorted(RAW, key=lambda r: r["opened_at"])
    incidents = []
    for i, r in enumerate(rows, start=1):
        inc = {"id": f"INC-{i:04d}", "status": "resolved"}
        inc.update(r)
        incidents.append(inc)
    return incidents


# ---- pattern verification (also used by tests) ----
def is_tuesday_evening(opened_at: str) -> bool:
    dt = datetime.fromisoformat(opened_at)
    return dt.weekday() == 1 and 17 <= dt.hour < 22


def is_auth_change(prior_change: dict | None) -> bool:
    if not prior_change or prior_change.get("hours_before", 999) > 48:
        return False
    return any(f.startswith("auth/") or f.startswith("middleware/jwt") for f in prior_change["files"])


def verify(incidents: list[dict]) -> dict:
    sec = [i for i in incidents if i["type"] == "security"]
    out = sorted([i for i in incidents if i["type"] == "outage"], key=lambda i: i["opened_at"])
    tue = [i["id"] for i in sec if is_tuesday_evening(i["opened_at"])]
    last6 = out[-6:]
    auth = [i["id"] for i in last6 if is_auth_change(i.get("prior_change"))]

    def tally(action, pred):
        rows = [a for i in incidents if pred(i) for a in i["actions"] if a["action"] == action]
        return sum(a["worked"] for a in rows), len(rows)

    pool = lambda i: "db/pool.py" in i["files"]
    asn = lambda i: i.get("asn") == "AS14061"
    return {
        "counts": (len(incidents), len(out), len(sec)),
        "tuesday_evening": (len(tue), len(sec), tue),
        "auth_before_last6": (len(auth), len(last6), auth),
        "pool_incidents": [i["id"] for i in incidents if pool(i)],
        "restart_pool": tally(RESTART_POOL, pool),
        "rollback_pool": tally(ROLLBACK_POOL, pool),
        "asn_incidents": [i["id"] for i in incidents if asn(i)],
        "per_ip_rate_limit": tally(PER_IP_RATE_LIMIT, asn),
        "block_asn": tally(BLOCK_ASN, asn),
        "session_py": [i["id"] for i in incidents
                       if "auth/session.py" in i["files"] + ((i.get("prior_change") or {}).get("files") or [])],
    }


def main() -> None:
    incidents = build()
    v = verify(incidents)
    assert v["counts"] == (32, 22, 10), v["counts"]
    assert v["tuesday_evening"][:2] == (8, 10), v["tuesday_evening"]
    assert v["auth_before_last6"][:2] == (4, 6), v["auth_before_last6"]
    assert len(v["pool_incidents"]) == 4 and v["restart_pool"] == (0, 4) and v["rollback_pool"] == (3, 4), v
    assert len(v["asn_incidents"]) >= 3 and v["per_ip_rate_limit"][0] == 0 and v["block_asn"][0] > v["block_asn"][1] / 2, v
    DATA_PATH.parent.mkdir(exist_ok=True)
    DATA_PATH.write_text(json.dumps(incidents, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {DATA_PATH} ({len(incidents)} incidents)")
    for k, val in v.items():
        print(f"  {k}: {val}")


if __name__ == "__main__":
    main()
