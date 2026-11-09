# DejaVu: Product Requirements Document

**Tagline:** Never fight the same incident twice.
**One-liner:** An incident-response agent with long-term memory. It detects outages and security attacks, investigates them using your own incident history, warns "we tried this before and it failed", and comments on pull requests that touch code with a bad history.

## 1. Problem
When production breaks, engineers start from scratch even when the same incident happened before. Fixes that failed last time get tried again. Security attacks and outages are tracked in separate tools, so nobody connects "this attacker pattern" or "this risky code change" to what happened last month. Knowledge lives in people's heads and old postmortems.

## 2. Target user
Small-to-mid engineering teams (5-50 engineers) without a dedicated SOC or SRE rotation. Personas:
- **On-call engineer:** needs the fastest path to a fix that has worked before.
- **Security engineer:** needs to know if an attack pattern is recurring and what stopped it.
- **Developer opening a PR:** needs to know if the code they touch has caused incidents.

## 3. Goals and non-goals
**Goals**
1. Detect an incident from telemetry using simple rules.
2. Recall similar past incidents and rank fixes by track record.
3. Explicitly warn about fixes that failed before.
4. Learn: engineer marks each action Worked/Failed; next similar incident is better.
5. Warn on risky pull requests using incident history.
6. Show patterns across history (for example attacks cluster on Tuesday evenings).

**Non-goals (do not build)**
- Real log ingestion, ML anomaly detection, auto-remediation or auto-blocking. The agent recommends; a human confirms.
- A separate security dashboard. One incident view, one memory panel.

## 4. Core user stories
| # | As a... | I want... | So that... |
|---|---|---|---|
| 1 | on-call engineer | an alert to show similar past incidents and the fix that worked | I resolve it faster |
| 2 | on-call engineer | a warning when a suggested fix failed before | I do not waste time repeating it |
| 3 | engineer | to mark an action Worked or Failed | the agent learns from the outcome |
| 4 | security engineer | attack alerts matched to earlier attacks (same ASN, same pattern) | I know what blocked them last time |
| 5 | developer | a PR comment when my change touches files with incident history | I add tests or review before shipping |
| 6 | team lead | patterns across incidents | I can prevent repeats |

## 5. Features
**F1. Detection (rules only).** Failed-login burst (credential stuffing), password spray, port scan, DB pool saturation, HTTP error spike. Input is simulated events from a "trigger incident" button.
**F2. Investigation with memory.** For each alert: query memory, map recalled incidents to structured records, score similarity (type, service, files, ASN, text overlap), aggregate actions by success rate. Output: narrative, "Do first" list with success rates, "We tried this before and it failed" list, and the incidents that influenced the answer.
**F3. Memory on/off toggle.** Same alert with memory off gives generic advice; with memory on gives history-based advice. This is the before/after proof.
**F4. Outcome feedback loop.** Worked/Failed buttons retain a verdict. Resolving an incident retains the full postmortem.
**F5. Memory panel.** Always visible: which recalled incidents influenced the answer.
**F6. PR check.** GitHub Action reads changed files, finds incidents involving them, posts or updates one PR comment.
**F7. Insights.** Patterns computed from the data (Tuesday-evening share, auth-change-before-outage share, actions that always fail) plus a Hindsight `reflect` summary.
**F8. Two-agent mode via Band (stretch).** Security agent and Reliability agent in one Band room; they share one Hindsight bank and hand off with @mentions.

## 6. Why memory is the product
Without memory the agent gives generic advice ("restart the service"). With memory it says "restarting the pool failed in all 4 earlier pool incidents; rolling back config worked 3 of 4." The product is worthless without the history, so memory is central, not a feature.

## 7. Success criteria
- Same outage shown at 0, 5 and 20 incidents of memory gives visibly different, better answers.
- PR comment appears on a real demo pull request.
- Every claim shown in the UI can be traced to incident ids in the data.
- Full demo runs in under 3 minutes with no manual fixes.

## 8. Risks and mitigations
| Risk | Mitigation |
|---|---|
| Live demo breaks | Pre-seed memory, keep a mock backend fallback, record a backup video |
| Synthetic data looks fake | Realistic error strings, services, ASNs, timestamps; patterns planted and verified by code |
| Hindsight latency or credit limits | Seed once before the demo; use `retain_async` only for bulk seeding |
| Scope creep | Features F1-F7 are the product; F8 only if time remains |
| Claims that are not true | Insights are computed from data, never hard-coded |
