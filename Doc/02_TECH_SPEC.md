# DejaVu: Technical Spec

## 1. Stack
Python 3.11, Flask, vanilla HTML/JS UI, Groq LLM (default model `openai/gpt-oss-120b`, fallback `qwen/qwen3-32b`), Hindsight (Cloud or Docker), GitHub Actions, Band (desktop app + `band-sdk`).

## 2. Architecture
```
Simulated telemetry -> detector.py (rules) -> alert
alert -> analyzer.investigate()
           |-- memory.recall(query)            [Hindsight recall]
           |-- structured store (JSON) match   [score by type, service, files, ASN, text overlap]
           |-- rank_actions()                  [success rate per action]
           |-- Groq narrative (falls back to a template that still cites incidents)
UI buttons -> /outcome -> memory.retain_verdict()   [Hindsight retain]
UI resolve -> /resolve -> memory.retain(full incident)
Insights   -> computed from data + memory.reflect()  [Hindsight reflect]
GitHub PR  -> scripts/pr_comment.py -> data/incidents.json -> PR comment
```
Two stores on purpose: **Hindsight** is long-term memory (semantic recall, consolidation, reflect). The **JSON store** is the system of record for status and structured outcomes, which makes success rates exact and the PR bot independent of the network.

## 3. Incident schema (`data/incidents.json`)
```json
{
  "id": "INC-0016",
  "type": "outage | security",
  "status": "open | resolved",
  "opened_at": "2026-10-15T11:05",
  "service": "payments-api",
  "title": "Checkout 500s: DB connection pool exhausted",
  "signal": "psycopg2.OperationalError: QueuePool limit of size 20 overflow 10 reached",
  "files": ["db/pool.py", "payments/checkout.py"],
  "root_cause": "text",
  "actions": [{"action": "Restart connection pool", "worked": false, "note": ""}],
  "severity": "SEV1",
  "prior_change": {"summary": "Tidy db config", "files": ["db/pool.py"], "hours_before": 4},
  "asn": "AS14061"
}
```
Use **exact, canonical action strings** (for example always "Restart connection pool") so success rates aggregate correctly.

## 4. Data requirements (32 incidents)
- 22 outages, 10 security incidents, Aug to Nov 2026.
- **Planted pattern A:** 8 of 10 security incidents on a Tuesday evening (17:00-22:00).
- **Planted pattern B:** 4 of the last 6 outages preceded by an auth-related change (`auth/*`, `middleware/jwt*`) within 48h.
- **Recurring DB-pool outage (4 times):** "Restart connection pool" failed every time; "Roll back pool config" worked 3 of 4; fourth was a connection leak fixed by a code patch.
- **Recurring credential stuffing from one ASN (3+ times):** "Per-IP rate limit" failed every time; "Block ASN at WAF" worked most times.
- Real-looking error strings, ASNs, subnets, service and file names.

## 5. Hindsight usage (verified against the Python client)
```python
from hindsight_client import Hindsight
client = Hindsight(base_url=HINDSIGHT_BASE_URL, api_key=HINDSIGHT_API_KEY, timeout=60.0)

client.create_bank(bank_id=bank, name="DejaVu incident memory", mission=MISSION,
                   disposition={"skepticism": 4, "literalism": 4, "empathy": 2})

client.retain(bank_id=bank, content=incident_text, timestamp=opened_at, context="incident postmortem",
              document_id="INC-0016", tags=["type:outage","svc:payments-api","file:db/pool.py"],
              metadata={"incident_id": "INC-0016"})

res = client.recall(bank_id=bank, query=query, max_tokens=3000, budget="mid", include_chunks=True)
for r in res.results: print(r.text)

answer = client.reflect(bank_id=bank, query="Which fixes keep failing?", budget="low")
print(answer.text)
```
- `HINDSIGHT_BASE_URL` for Cloud is the API URL shown in your Hindsight Cloud console (copy it exactly; not verified here).
- Put the incident id (for example `INC-0016`) inside the retained text so recalled facts and chunks map back to structured records.
- One bank per environment or customer (`dejavu-prod`). Use `tags` for per-service or per-file filtering.
- Use `recall` for evidence, `reflect` for synthesis. Hindsight consolidates observations in the background, so wait about a minute after bulk seeding before demoing `reflect`.

## 6. Similarity and ranking
Score each resolved incident: +2 same type, +2 same service, +3 per shared file, +3 same ASN, +0.5 per overlapping keyword (max 8), +4 if Hindsight recalled it. Keep incidents with score at least 5 (top 5). Aggregate actions across matches: `rate = worked / tried`. "Do first" = rate at least 0.5, top 3. "Avoid" = worked 0 and tried at least 1.

## 7. API
| Method | Path | Purpose |
|---|---|---|
| GET | `/` | UI |
| GET | `/api/state` | incidents + insights |
| POST | `/api/trigger` `{scenario, use_memory}` | detect, create incident, investigate |
| POST | `/api/incidents/<id>/outcome` `{action, worked, note}` | record verdict, retain |
| POST | `/api/incidents/<id>/resolve` `{root_cause}` | close, retain postmortem |
| GET | `/api/insights` | computed patterns + `reflect` text |
| POST | `/api/pr-check` `{files:[...]}` | PR warning |
| POST | `/api/reset` | reset demo data |

## 8. Detection rules
| Rule | Condition | Type |
|---|---|---|
| failed_login_burst | at least 200 failed logins from one ASN across at least 20 IPs | security |
| password_spray | at least 30 distinct users from one ASN, at most 4 tries each | security |
| port_scan | at least 100 distinct ports from one IP | security |
| pool_saturation | pool in use at least 95% of max | outage |
| error_spike | 5xx rate above 5% with at least 100 requests | outage |

## 9. PR bot
GitHub Action on `pull_request`: list changed files with `git diff --name-only`, run `scripts/pr_comment.py` against `data/incidents.json`, create or update one comment (marker `<!-- dejavu-pr-warning -->`). Needs `pull-requests: write`. Comments from forked PRs may be read-only; demo from a branch in the same repo. Add a repo secret only if you extend the bot to call Hindsight.

## 10. Band integration (stretch, partly unverified)
Band is a platform where agents and humans collaborate in shared rooms; the Python SDK (`band-sdk`, Python 3.11+) connects an agent with `Agent.create(adapter=..., agent_id=..., api_key=...)` then `await agent.run()`. Agents are created in the Band app, which gives each an id and API key; add them to a room and @mention them. Plan: **SecurityAgent** and **ReliabilityAgent**, both calling the same Hindsight bank. Confirm adapter options and tool names at docs.band.ai before coding. Minimum for compliance: download Band desktop, run the two agents in a room, show one handoff in the demo.

## 11. Repo layout
```
dejavu/
  app.py  analyzer.py  detector.py  insights.py  prcheck.py
  memory_backend.py  store.py  sim_events.py  seed_data.py
  seed_memory.py  demo_curve.py
  templates/index.html
  scripts/pr_comment.py
  .github/workflows/dejavu-pr.yml
  data/incidents.json
  tests/
  requirements.txt  .env.example  README.md
```
`.env.example`: `HINDSIGHT_BASE_URL`, `HINDSIGHT_API_KEY`, `DEJAVU_BANK=dejavu-prod`, `GROQ_API_KEY`, `GROQ_MODEL=openai/gpt-oss-120b`. Never commit `.env`.

## 12. Tests to write
1. Detector fires for each simulated scenario and not on normal traffic.
2. Ranking: restart ranks as "avoid", rollback as "do first" for the DB-pool alert.
3. Insights: Tuesday-evening count equals 8 of 10; auth-precursor equals 4 of last 6.
4. PR check: `auth/session.py` returns findings; an unrelated file returns none.
5. Memory off returns generic advice and no incident ids.
6. Memory failure (raise in `retain`) does not break `/outcome`.
