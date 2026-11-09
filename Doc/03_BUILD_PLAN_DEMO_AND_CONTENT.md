# DejaVu: Build Plan, Demo Script and Submission Checklist

Deadline: **Nov 9, 11:59 PM.** Aim to submit by 9 PM. Only ONE submission per team.

## 1. Build plan (team of 6)
| # | Owner | Job | Done when |
|---|---|---|---|
| 1 | Backend lead | Hindsight wrapper (`retain`, `recall`, `reflect`), seed script, outcome loop | seed script retains 32 incidents; recall returns INC ids |
| 2 | Analysis | detector, similarity and ranking, Groq narrative with template fallback | DB-pool alert recommends rollback and warns on restart |
| 3 | Frontend | UI: trigger buttons, memory toggle, memory panel, Worked/Failed, PR check | full flow works without page errors |
| 4 | Data and demo | incident data, planted patterns, 0/5/20 curve, demo rehearsal | insights show 8/10 and 4/6 |
| 5 | Repo and Band | README (How Hindsight is used), architecture diagram, GitHub Action, Band download and two agents | PR comment appears on a real PR |
| 6 | Video | script, screen recording (1080p), thumbnail, YouTube upload | public video, 2-5 min |

**Everyone:** fill the Profile Review Form, then write your own article and LinkedIn post (see section 4).

## 2. Timeline (today)
- 10:30-12:30 Hindsight running, seed script works, detector and UI skeleton.
- 12:30-14:30 ranking and narrative, Worked/Failed loop, memory toggle.
- 14:30-16:00 PR bot on a demo repo, 0/5/20 curve, insights.
- 16:00 **feature freeze.** Only bug fixes after this.
- 16:00-18:00 rehearse demo, record video, README, architecture diagram.
- 18:00-20:30 articles and posts, upload video, final checks.
- 21:00 submit the team form. Re-open the links in a private window to confirm they are public.

## 3. Demo script (about 3 minutes)
1. **Setup (20s):** "On-call at 2 AM. Production is down, and the same thing happened before."
2. **Without memory (30s):** memory toggle OFF, trigger *Checkout 500s*. Generic answer: "restart the service." Say: this is what any chatbot says.
3. **With memory (60s):** toggle ON, same alert. Show the Déjà vu badge, "restarting the pool failed 4/4 times", "rolling back config worked 3/4", and the memory panel listing INC ids. Click **Worked** on the rollback; point out it is retained.
4. **Security twist (30s):** trigger *Credential stuffing*. Memory says per-IP rate limits failed 3 times, blocking the ASN worked. Same memory, a different kind of incident.
5. **PR warning (30s):** show the GitHub PR comment: "`auth/session.py` was involved in 3 outages." Show the pattern line (4 of last 6 outages followed an auth change).
6. **Learning curve (20s):** run `python demo_curve.py`; show the answer at 0, 5, 20 incidents.
7. **Close (10s):** "It gets better with every incident because it remembers, not because we re-train."

Rehearse twice. Pre-seed memory and keep a recorded backup of step 3 in case the network fails.

## 4. Content deliverables (per the content guide)
**Per person:** 1 article (800-1,500 words, public on Medium / Dev.to / Hashnode / Substack / LinkedIn Article) + 1 LinkedIn post (under 800 characters).
**Per team:** 1 YouTube video (2-5 min, 1080p) with a thumbnail.

**Hard rules (disqualification):**
- Never name the event or competition anywhere in titles, bodies or hashtags. Avoid student-related tags too.
- Articles need links to: https://github.com/vectorize-io/hindsight, https://hindsight.vectorize.io/, https://vectorize.io/what-is-agent-memory
- Article needs at least: one real code snippet, one before/after example, one honest limitation, screenshots.
- LinkedIn post: bold hook (no hashtags or links in first 2 lines), 3-7 takeaways with one before/after, your project repo link in the post, hashtags on the last line only (#AIAgents #AgentMemory #Hindsight #LLM). First comment: article URL, then a comment linking the Hindsight repo.
- Tag Code.in on LinkedIn and in articles.
- Video goes on YouTube, not Google Drive. Articles go on a public site, not a Google Doc.

**Article angles (pick one each, same project):**
1. Why my agent warns "we tried this before and it failed" (memory of failures)
2. Recall vs reflect: what each is actually for in an incident agent
3. Linking attackers to our own code: one memory for security and engineering
4. Seeding realistic incident data and planting patterns you can verify
5. A PR bot that cites our own outages
6. The 0 / 5 / 20 incident learning curve

Write only what really works. If a feature is partial, say so under "limitations".

## 5. Judging checklist
| Criterion | Weight | What proves it |
|---|---|---|
| Innovation | 30% | code-to-incident link in PR comments; memory of failed fixes |
| Use of Hindsight | 25% | toggle ON/OFF, memory panel, 0/5/20 curve, `reflect` insights |
| Technical implementation | 20% | clean repo, README, tests, graceful failures |
| User experience | 15% | one-screen flow, 3-minute story |
| Real-world impact | 10% | clear "who pays": small teams without a SOC; honest limits |

## 6. Submission checklist
- [ ] Repo public, README explains **How Hindsight memory is used**
- [ ] No keys in git (check history); `.env.example` present
- [ ] Demo video on YouTube (public) with thumbnail
- [ ] Every member: article + LinkedIn post live
- [ ] Every member: Profile Review Form filled
- [ ] Band desktop downloaded and shown in the demo
- [ ] Live demo machine chosen; memory pre-seeded; backup recording saved
- [ ] One person submits the final form once, after all links are verified
