"""Simulated telemetry for the trigger buttons. No real log ingestion.

Event shapes:
  {"kind": "login", "ok": bool, "user": str, "ip": str, "asn": str, "service": str, "path": str}
  {"kind": "conn", "src_ip": str, "asn": str, "dst_port": int, "service": str}
  {"kind": "http", "service": str, "status": int, "error": str | None, "stack": [file, ...]}
  {"kind": "db_pool", "service": str, "in_use": int, "max": int, "error": str}
  {"kind": "deploy", "service": str, "summary": str, "files": [...], "hours_ago": int}
"""
from __future__ import annotations

import random

SCENARIOS = {
    "checkout_500s": "Checkout 500s (DB pool)",
    "credential_stuffing": "Credential stuffing",
    "password_spray": "Password spray",
    "port_scan": "Port scan",
    "api_5xx_spike": "API 5xx spike",
    "normal": "Normal traffic",
}

POOL_ERR = ("sqlalchemy.exc.TimeoutError: QueuePool limit of size 20 overflow 10 reached, "
            "connection timed out, timeout 30.00")


def _normal_background(rng: random.Random) -> list[dict]:
    ev = []
    for _ in range(400):
        ev.append({"kind": "http", "service": rng.choice(["payments-api", "api-gateway", "orders-api"]),
                   "status": 500 if rng.random() < 0.005 else 200, "error": None, "stack": []})
    for _ in range(120):
        ip = f"10.20.{rng.randint(0, 9)}.{rng.randint(1, 250)}"
        ev.append({"kind": "login", "ok": rng.random() > 0.08, "user": f"user{rng.randint(1, 900)}",
                   "ip": ip, "asn": "AS7922", "service": "auth-api", "path": "/api/v1/login"})
    for port in (80, 443, 443, 8443):
        ev.append({"kind": "conn", "src_ip": "73.44.10.12", "asn": "AS7922", "dst_port": port,
                   "service": "edge-lb"})
    ev.append({"kind": "db_pool", "service": "payments-api", "in_use": 12, "max": 30, "error": ""})
    return ev


def generate(scenario: str, seed: int = 7) -> list[dict]:
    rng = random.Random(seed)
    ev = _normal_background(rng)
    if scenario == "normal":
        return ev
    if scenario == "checkout_500s":
        ev.append({"kind": "db_pool", "service": "payments-api", "in_use": 30, "max": 30, "error": POOL_ERR})
        for _ in range(180):
            ev.append({"kind": "http", "service": "payments-api", "status": 500, "error": POOL_ERR,
                       "stack": ["payments/checkout.py", "db/pool.py"]})
        ev.append({"kind": "deploy", "service": "payments-api", "summary": "Tidy db config",
                   "files": ["db/pool.py"], "hours_ago": 3})
    elif scenario == "credential_stuffing":
        subnets = ["104.248", "167.99", "164.90"]
        ips = [f"{subnets[n % 3]}.{rng.randint(1, 254)}.{rng.randint(1, 254)}" for n in range(90)]
        for _ in range(620):
            ip = rng.choice(ips)
            ev.append({"kind": "login", "ok": False, "user": f"victim{rng.randint(1, 5000)}@mail.example",
                       "ip": ip, "asn": "AS14061", "service": "auth-api", "path": "/api/v1/login"})
    elif scenario == "password_spray":
        for u in range(80):
            for _ in range(rng.randint(1, 3)):
                ev.append({"kind": "login", "ok": False, "user": f"emp{u:03d}@corp.example",
                           "ip": f"185.156.{rng.randint(1, 254)}.{rng.randint(1, 254)}", "asn": "AS9009",
                           "service": "sso-gateway", "path": "/sso/login"})
    elif scenario == "port_scan":
        for port in rng.sample(range(1, 65535), 1500):
            ev.append({"kind": "conn", "src_ip": "218.92.0.77", "asn": "AS4134", "dst_port": port,
                       "service": "edge-lb"})
    elif scenario == "api_5xx_spike":
        err = "auth.middleware: TokenParseError: unexpected claim 'scp'"
        for _ in range(140):
            ev.append({"kind": "http", "service": "api-gateway", "status": 503, "error": err,
                       "stack": ["auth/middleware.py", "middleware/jwt_verify.py"]})
        ev.append({"kind": "deploy", "service": "api-gateway", "summary": "Tighten JWT claim parsing",
                   "files": ["middleware/jwt_verify.py"], "hours_ago": 9})
    else:
        raise ValueError(f"unknown scenario {scenario!r}")
    rng.shuffle(ev)
    return ev
