# DejaVu

**Never fight the same incident twice.**

DejaVu is an incident-response agent with long-term memory. It detects outages and security
attacks from telemetry. It investigates each one against your own incident history, and it
warns when a fix was tried before and failed: *"we tried this before and it failed"*. It also
comments on pull requests that touch code with a bad history.

It is built for small and mid-sized engineering teams (5-50 engineers) that have no dedicated
SOC or SRE rotation, where incident knowledge lives in people's heads and old postmortems.

DejaVu only recommends. It never blocks traffic or remediates anything automatically; an
engineer decides.

```
Without memory:  "Restart connection pool. Restart service. Increase pool size."
With memory:     "Déjà vu: matches INC-0004, INC-0009, INC-0014, INC-0020.
                  Do first: Roll back pool config, worked 3 of 4 times (INC-0004, INC-0009, INC-0020).
                  We tried this before and it failed: Restart connection pool, failed 4 of 4 times."
```

## Architecture

```
 Simulated telemetry ──► detector.py (5 rules) ──► alert
                                                     │
                                                     ▼
                                          analyzer.investigate()
              ┌──────────────────────────────────────┼─────────────────────────────────┐
              ▼                                      ▼                                 ▼
   Hindsight recall(query)            JSON store (data/state.json)          Groq narrative
   ids parsed from facts + chunks     score: type, service, files,          (template fallback,
   (+4 to recalled incidents)         ASN, keywords, recall bonus           must cite matched ids)
              └──────────────────────────────────────┬─────────────────────────────────┘
                                                     ▼
                              rank_actions(): "Do first" / "We tried this before and it failed"
                                                     │
 UI Worked / Failed ──► /outcome ──► store + Hindsight retain(verdict)
 UI Resolve         ──► /resolve ──► store + Hindsight retain(full postmortem)
 Insights           ──► computed from the store + Hindsight reflect(synthesis)
 Pull request       ──► GitHub Action ──► scripts/pr_comment.py ──► data/incidents.json ──► one PR comment
```

There are two stores, on purpose:

| Store | Role |
|---|---|
| **Hindsight** bank (`DEJAVU_BANK`) | Long-term memory: semantic recall across differently worded incidents, background consolidation, `reflect` synthesis. |
| **JSON** (`data/incidents.json` seed, `data/state.json` live) | System of record for status and structured outcomes, so success rates are exact and the PR bot works without network access. |

## How Hindsight memory is used

Memory is the core of the product. Without the history, DejaVu gives the same generic advice
as any chatbot ("restart the service"). With it, DejaVu can say *which* fix to try first and
*which* fix to skip, and it cites the incidents behind both. Turn the **Memory** toggle off in
the UI to see the difference on the same alert.

All calls go through [`memory_backend.py`](memory_backend.py) using `hindsight-client` 1.2.0.
Every parameter was checked against `inspect.signature` of the installed client.
[`tests/test_memory_backend.py`](tests/test_memory_backend.py) re-checks this on every run by
binding each call to the real method signatures.

| Operation | Where | What it does |
|---|---|---|
| `create_bank(bank_id, name, mission, disposition_skepticism=4, disposition_literalism=4, disposition_empathy=2)` | `seed_memory.py` | Creates (or updates) the bank with an incident-response mission. The client maps this to `create_or_update_bank`, so it is safe to re-run. |
| `retain_batch(items, retain_async=True)` | `seed_memory.py` | Bulk-loads the 32 historical postmortems. Each item has `timestamp=opened_at`, `document_id=INC-xxxx`, `tags` (`type:`, `svc:`, `file:`, `asn:`) and `metadata.incident_id`. |
| `retain(content, document_id, update_mode="replace", ...)` | `/resolve` | Stores the full postmortem when an engineer resolves an incident, so the next similar incident can find it. |
| `retain(content, context="remediation verdict", tags=[..., "action:<name>"])` | `/outcome` | Stores each Worked/Failed verdict as soon as it is clicked. |
| `recall(query, max_tokens=3000, budget="mid", include_chunks=True)` | `analyzer.investigate` | Evidence for a new alert. Incident ids are parsed from fact text, `document_id`, `metadata` and raw chunks, then mapped back to JSON records. A recalled incident gets +4 in similarity scoring. |
| `reflect(query, budget="low")` | `/api/insights` | Synthesis across the whole bank: which fixes keep failing, which work, recurring attackers and risky code. |

Every retained text repeats the incident id on every line (for example `INC-0020 root cause:
...`). Whatever fact or chunk Hindsight returns, it can be traced back to a structured record.
This is what lets the UI and PR comments cite ids for every claim.

**Failure handling:** a recall failure falls back to scoring against the JSON store only. A
retain failure keeps the verdict or postmortem in the JSON store. A reflect failure hides the
reflect text. In all three cases the UI shows a warning and the request still succeeds.
Without `HINDSIGHT_BASE_URL`, an in-process keyword `MockMemory` stands in, so tests and
offline runs work (the header chip shows `memory: mock`).

## Similarity and ranking

Each resolved incident gets a score against the alert:

| Signal | Points |
|---|---|
| Same type | +2 |
| Same service | +2 |
| Each shared file | +3 |
| Same ASN | +3 |
| Each overlapping keyword (up to 8 counted) | +0.5 |
| Recalled by Hindsight | +4 |

Incidents scoring at least 5 are kept (top 5). On top of that, matches scoring below half of
the best match are dropped, so a strong match is not diluted by incidents that only share a
type.

Actions are aggregated across matches, with `rate = worked / tried`:
- **Do first:** rate ≥ 0.5, top 3. Ordered by smoothed rate `(worked+1)/(tried+2)`, then by
  number of successes, so a 3-of-4 fix outranks a 1-of-1 fluke.
- **We tried this before and it failed:** worked 0 times, tried at least once.

The Groq narrative (`openai/gpt-oss-120b`, falling back to `qwen/qwen3-32b`) receives only
these computed facts. If it cites an incident id outside the matched set, or no id at all, it
is discarded and a template narrative is used instead.

## Setup

Requires Python 3.11+.

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows;  source .venv/bin/activate on macOS/Linux
pip install -r requirements.txt
cp .env.example .env            # then fill in HINDSIGHT_BASE_URL, HINDSIGHT_API_KEY, GROQ_API_KEY
```

```bash
python seed_data.py             # optional: regenerate data/incidents.json and verify planted patterns
python seed_memory.py           # create the bank and retain the 32 incidents (async)
python seed_memory.py --check   # after ~1 minute: recall should return INC ids
python app.py                   # http://127.0.0.1:5000
python demo_curve.py            # same outage with 0, 5 and 20 incidents of memory
pytest                          # 54 tests, no network needed
```

Without Hindsight or Groq credentials, everything still runs: memory uses the offline mock,
and narratives use the template.

## Walkthrough (about 3 minutes)

1. **Without memory.** Switch **Memory** OFF and click **Checkout 500s (DB pool)**. The
   advice is generic ("Restart connection pool; Restart service; Increase pool size") and the
   memory panel is empty.
2. **With memory.** Switch **Memory** ON and trigger the same alert. You get the **Déjà vu
   detected** badge, "Roll back pool config: worked 3/4", "Restart connection pool: failed
   4/4", and the memory panel listing INC-0004, INC-0009, INC-0014 and INC-0020 with the reason
   each one matched. Click **Worked** on the rollback; the verdict is retained.
3. **Security.** Click **Credential stuffing**. The same memory answers a different kind of
   incident: "Per-IP rate limit" failed 3/3, and "Block ASN at WAF" worked 3/4, against
   AS14061.
4. **PR warning.** In the PR check box, `auth/session.py` returns 3 outages (INC-0007,
   INC-0025, INC-0029) plus the pattern line "4 of the last 6 outages were preceded by an
   auth-related change". The GitHub Action posts the same text on real pull requests.
5. **Insights.** The panel shows "8 of 10 security incidents started on a Tuesday evening" and
   the fixes that always fail. **Ask Hindsight reflect** adds a synthesis from the bank.
6. **Learning curve.** Run `python demo_curve.py`. At 0 incidents you get generic advice; at 5
   incidents it cites one past incident; at 20 it has the full 3/4 and 4/4 track record.

Note: insights are computed from *resolved* incidents. If you resolve an incident during the
walkthrough, it joins the history and the numbers change honestly (for example, a resolved DB
pool outage moves "4 of the last 6" to "3 of the last 6"). **Reset** restores the seed data.

## PR bot

[`.github/workflows/dejavu-pr.yml`](.github/workflows/dejavu-pr.yml) runs on `pull_request`.
It lists changed files with `git diff --name-only origin/<base>...HEAD`, then runs
[`scripts/pr_comment.py`](scripts/pr_comment.py) against `data/incidents.json`. The script
creates one comment, or updates it, identified by the marker `<!-- dejavu-pr-warning -->`.

- The job needs only `pull-requests: write` and the built-in `GITHUB_TOKEN`. No repo secret
  is needed, because the bot does not call Hindsight.
- Comments from pull requests opened from forks may be read-only. Open the PR from a branch in
  the same repository.
- To preview locally: `python scripts/pr_comment.py --dry-run auth/session.py`

## Two agents in Band

[`band_agents.py`](band_agents.py) runs **SecurityAgent** and **ReliabilityAgent** in a
[Band](https://docs.band.ai) room. Both use the same detector, analyzer and **Hindsight
bank**, so a verdict retained through one agent (or the web UI) is recalled by the other.

- An agent is triggered only when it is @mentioned. Each answers alerts in its own domain.
- For an alert outside its domain, an agent hands off by adding the other agent's id to the
  `mentions` of `tools.send_message`.
- SecurityAgent also mentions ReliabilityAgent when the attacked code has outage history.
- An agent never hands a message from the other agent back, so the two cannot loop.

The agents use `band-sdk==8.1.0`: a `SimpleAdapter` subclass with `on_message`, plus
`Agent.from_config`. These match the docs at docs.band.ai and were checked against the
installed package.

```bash
pip install band-sdk==8.1.0
cp agent_config.example.yaml agent_config.yaml   # fill in the IDs and keys from Band
python band_agents.py security                   # terminal 1
python band_agents.py reliability                # terminal 2
```

Create both agents in Band under **Agents → Connect remote agent** and copy each ID and API key;
each key is shown only once. Add both agents to a room, then send for example:
`@ReliabilityAgent credential stuffing on /api/v1/login from AS14061`. ReliabilityAgent hands
off to SecurityAgent, which answers with the "Block ASN at WAF (3/4)" history.

## Data

[`seed_data.py`](seed_data.py) generates `data/incidents.json`: 32 resolved incidents (22
outages, 10 security incidents, Aug-Nov 2026) with realistic error strings, services, files,
subnets and ASNs. Action names are canonical strings, so success rates aggregate. These
patterns are planted on purpose; the script and the tests verify them from the data:

- 8 of 10 security incidents started on a Tuesday evening (17:00-22:00).
- 4 of the last 6 outages were preceded by an auth-related change (`auth/*`, `middleware/jwt*`)
  within 48h.
- A DB pool exhaustion on `payments-api` happened 4 times. "Restart connection pool" failed
  every time. "Roll back pool config" worked 3 of 4 times; the fourth (INC-0014) was a
  connection leak fixed by a code patch.
- Credential stuffing from AS14061 happened 4 times. "Per-IP rate limit" failed every time
  (3/3). "Block ASN at WAF" worked 3 of 4 times.

## Detection rules

| Rule | Condition | Type |
|---|---|---|
| `failed_login_burst` | ≥ 200 failed logins from one ASN across ≥ 20 IPs | security |
| `password_spray` | ≥ 30 distinct users from one ASN, ≤ 4 tries each (and not already a burst) | security |
| `port_scan` | ≥ 100 distinct ports from one IP | security |
| `pool_saturation` | DB pool in use ≥ 95% of max | outage |
| `error_spike` | 5xx rate > 5% with ≥ 100 requests | outage |

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | UI |
| GET | `/api/state` | incidents and computed insights |
| POST | `/api/trigger` `{scenario, use_memory}` | detect, open an incident, investigate |
| GET | `/api/incidents/<id>` | one incident with its analysis |
| POST | `/api/incidents/<id>/outcome` `{action, worked, note}` | record a verdict and retain it |
| POST | `/api/incidents/<id>/resolve` `{root_cause}` | close the incident and retain the postmortem |
| GET | `/api/insights` | computed patterns and `reflect` text |
| POST | `/api/pr-check` `{files:[...]}` | PR warning |
| POST | `/api/reset` | restore the seed incident data |

## Project layout

```
app.py              Flask app and API
analyzer.py         recall, similarity, action ranking, narrative
detector.py         rule-based detection
sim_events.py       simulated telemetry for the trigger buttons
memory_backend.py   Hindsight backend + offline mock
llm.py              Groq client with model fallback
store.py            JSON system of record
insights.py         patterns computed from data + reflect
prcheck.py          PR file-history check and comment rendering
seed_data.py        generates data/incidents.json and verifies the patterns
seed_memory.py      loads the history into Hindsight
band_agents.py      SecurityAgent + ReliabilityAgent for Band
demo_curve.py       0 / 5 / 20 incident learning curve
scripts/pr_comment.py, .github/workflows/dejavu-pr.yml
templates/index.html, tests/
```

## Limitations

- Telemetry is simulated. There is no real log ingestion, and the detection rules are fixed
  thresholds, not anomaly detection.
- The incident history is synthetic, with planted patterns. Real value depends on teams
  recording Worked/Failed verdicts consistently, using the same action names.
- The offline mock memory is keyword overlap, not semantic search. It exists so the app and
  tests work without a network; use Hindsight for real recall.
- Resetting the app restores the JSON store but does not wipe the Hindsight bank, which is
  long-term memory by design. Verdicts retained earlier stay in it.
- Similarity weights are hand-set (see the table above), not learned.
