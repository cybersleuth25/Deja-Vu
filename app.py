"""DejaVu web app: one incident view, one memory panel.

    python app.py            # http://127.0.0.1:5000

Memory or LLM failures never break a request: the response carries a `warnings` list instead.
"""
from __future__ import annotations

import os
import socket
import time
from datetime import datetime

from flask import Flask, jsonify, render_template, request

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # python-dotenv is optional
    pass

import analyzer
import detector
import insights
import prcheck
import sim_events
from llm import get_llm
from memory_backend import MockMemory, get_memory
from store import Store

REFLECT_TTL = 120  # seconds; reflect is an LLM call on the Hindsight side
MAX_BODY = 64 * 1024  # bytes; the largest real request is a pasted list of changed files


def port_is_free(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def pick_port(env: dict = os.environ) -> int:
    """An explicit PORT is used as given. Otherwise 5000, or the next free port up to 5010
    (5000 is often taken, for example by AirPlay Receiver on macOS)."""
    if env.get("PORT"):
        return int(env["PORT"])
    return next((p for p in range(5000, 5011) if port_is_free(p)), 5000)


def _summary(inc: dict) -> dict:
    return {k: inc.get(k) for k in ("id", "type", "status", "opened_at", "service", "title", "severity")}


def create_app(store: Store | None = None, memory=None, llm="auto") -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY  # larger request bodies get 413 before parsing
    store = store or Store()
    startup_warnings: list[str] = []
    if memory is None:
        try:
            memory = get_memory()
        except Exception as exc:
            startup_warnings.append(f"Hindsight unavailable, using offline mock memory: {exc}")
            memory = MockMemory()
    if isinstance(memory, MockMemory) and not memory.docs:
        try:
            memory.retain_many(store.resolved())  # the mock has no server: preload it like a seeded bank
        except Exception as exc:
            startup_warnings.append(f"Could not preload memory: {exc}")
    llm = get_llm() if llm == "auto" else llm
    reflect_cache: dict = {"key": None, "at": 0.0, "value": None}

    app.config.update(STORE=store, MEMORY=memory, LLM=llm)

    def meta() -> dict:
        return {"memory_backend": memory.name, "bank": getattr(memory, "bank_id", None),
                "llm": bool(llm), "startup_warnings": startup_warnings}

    @app.before_request
    def require_json_for_writes():
        # Browsers send text/plain and form posts cross-origin without a CORS preflight, so a page
        # on another site could otherwise call these endpoints. A JSON content type forces the
        # preflight, which this app never approves.
        if request.method == "POST" and not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 415

    def must_be_open(iid: str):
        inc = store.get(iid)
        if inc is None:
            return jsonify({"error": "not found"}), 404
        if inc.get("status") != "open":
            return jsonify({"error": f"{iid} is {inc.get('status')}; history of closed incidents is read-only"}), 409
        return None

    @app.get("/")
    def index():
        return render_template("index.html", scenarios=sim_events.SCENARIOS)

    @app.get("/api/state")
    def state():
        incs = store.all()
        return jsonify({"incidents": [_summary(i) for i in incs], "insights": insights.compute(incs), **meta()})

    @app.post("/api/trigger")
    def trigger():
        body = request.get_json(silent=True) or {}
        scenario = body.get("scenario", "checkout_500s")
        use_memory = bool(body.get("use_memory", True))
        if scenario not in sim_events.SCENARIOS:
            return jsonify({"error": f"unknown scenario {scenario}"}), 400
        alert = detector.primary_alert(sim_events.generate(scenario))
        if alert is None:
            return jsonify({"detected": False, "message": "No detection rule fired. Traffic looks normal.",
                            "warnings": []})
        inc = store.create(alert)
        result = analyzer.investigate(alert, store.all(), memory if use_memory else None,
                                      use_memory=use_memory, llm=llm, exclude=inc["id"])
        inc = store.update(inc["id"], analysis=result)
        return jsonify({"detected": True, "incident": inc, "alert": alert, "analysis": result,
                        "warnings": result["warnings"]})

    @app.get("/api/incidents/<iid>")
    def get_incident(iid):
        inc = store.get(iid)
        return (jsonify(inc), 200) if inc else (jsonify({"error": "not found"}), 404)

    @app.post("/api/incidents/<iid>/outcome")
    def outcome(iid):
        body = request.get_json(silent=True) or {}
        action = (body.get("action") or "").strip()
        if not action or "worked" not in body:
            return jsonify({"error": "action and worked are required"}), 400
        if (refused := must_be_open(iid)) is not None:
            return refused
        worked, note = bool(body["worked"]), (body.get("note") or "").strip()
        inc = store.record_action(iid, action, worked, note)
        warnings, retained = [], False
        try:
            memory.retain_verdict(inc, action, worked, note)
            retained = True
        except Exception as exc:
            warnings.append(f"Verdict saved locally but not retained in memory: {exc}")
        return jsonify({"incident": inc, "retained": retained, "warnings": warnings})

    @app.post("/api/incidents/<iid>/resolve")
    def resolve(iid):
        body = request.get_json(silent=True) or {}
        if (refused := must_be_open(iid)) is not None:
            return refused
        inc = store.update(iid, status="resolved", root_cause=(body.get("root_cause") or "").strip(),
                           resolved_at=datetime.now().strftime("%Y-%m-%dT%H:%M"))
        warnings, retained = [], False
        try:
            memory.retain_incident(inc)
            retained = True
        except Exception as exc:
            warnings.append(f"Resolved locally but postmortem not retained in memory: {exc}")
        return jsonify({"incident": inc, "retained": retained, "warnings": warnings})

    @app.get("/api/insights")
    def get_insights():
        incs = store.all()
        computed = insights.compute(incs)
        want_reflect = request.args.get("reflect", "1") != "0"
        reflect = None
        if want_reflect:
            key = (computed["resolved_count"], sum(len(i.get("actions", [])) for i in incs))
            if reflect_cache["key"] == key and time.time() - reflect_cache["at"] < REFLECT_TTL:
                reflect = reflect_cache["value"]
            else:
                reflect = insights.reflect_summary(memory)
                if not reflect.get("error"):
                    reflect_cache.update(key=key, at=time.time(), value=reflect)
        return jsonify({"computed": computed, "reflect": reflect,
                        "warnings": [reflect["error"]] if reflect and reflect.get("error") else []})

    @app.post("/api/pr-check")
    def pr_check():
        body = request.get_json(silent=True) or {}
        files = body.get("files") or []
        if isinstance(files, str):
            files = files.splitlines()
        result = prcheck.check(files, store.all())
        return jsonify({**result, "markdown": prcheck.render_markdown(result)})

    @app.post("/api/reset")
    def reset():
        store.reset()
        warnings = []
        if isinstance(memory, MockMemory):
            memory.reset()
            memory.retain_many(store.resolved())
        else:
            warnings.append("App state reset. The Hindsight bank is long-term memory and was not wiped; "
                            "verdicts retained earlier remain in it.")
        reflect_cache.update(key=None, value=None)
        return jsonify({"ok": True, "warnings": warnings})

    return app


if __name__ == "__main__":
    # Werkzeug exits on a busy port instead of raising, so the free port is chosen before run().
    port = pick_port()
    if port != 5000 and not os.environ.get("PORT"):
        print(f"Port 5000 is in use; serving on http://127.0.0.1:{port}")
    create_app().run(host="127.0.0.1", port=port, debug=False)
