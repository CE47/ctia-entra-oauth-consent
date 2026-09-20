# Track B — Independent Investigation Worksheet

**Bloomline Technologies — M365 tenant, June–September 2026**

You are the on-shift analyst. Management only knows three things:

1. "We gave a third-party app access a few months ago."
2. "Our finance user can't find emails and some files are missing."
3. "The password reset over the summer didn't seem to fix anything."

Your objective: **investigate the three-source log package and produce a
thorough, evidence-cited incident report.** No hand-holding here — but the
templates below will keep your work structured and audit-proof. Use `grep`,
`cut`, `sort`, `uniq`, `awk` (or any tooling you know) on the `.log` files.

Estimated effort: 3–5 focused hours.

---

## 1. Define the problem space

Before any command, write your answers:

1. What are the three log sources and what does each one prove (identity, data
   plane, network)?
2. What time zone are all timestamps in, and what is the full date range?
3. What is "normal" in this tenant? (Users, apps, IPs, operation mix — actually
   measure it, don't guess.)

*Templates — paste your evidence below.*

```
Normal users (UPN) and login frequency:
Normal successful sign-in source IPs:
Normal applications in use:
Normal Graph operations:
```

---

## 2. Case questions

Use these to drive the hunt. Answer **all** of them, each with at least one
`record_id` citation and timestamp.

1. **How did the attacker get in?** Identify the exact consent event, the app
   involved, who approved it, which permissions were granted, and the original
   point of human contact (what the victim actually clicked).
2. **Who is the victim account?** Prove it from the logs.
3. **What credentials/artefacts does the attacker now hold** and why is that
   different from a stolen password?
4. **Where does the attacker operate from?** (IPs — and are they ever inside
   the corporate ranges?)
5. **What did they read?** Every mailbox/SharePoint/OneDrive object accessed,
   in chronological order.
6. **What did they change?** Every mailbox rule, deleted item, uploaded file,
   and modified file — including the odd `.txt` that appeared late.
7. **Why did the password reset not work?** Find the password-change event and
   then demonstrate the attacker's access continuing *after* it.
8. **How did they try to blend in / cover up?** Look for rule changes, deletions,
   and removal of the forwarding behaviour at the end.
9. **What was the endgame / business impact?** Be specific about which files,
   and what the `.txt` message claims.
10. **What is NOT the incident?** Document the red herrings you excluded and
    *why* (with evidence).

---

## 3. Investigation journal

Log every meaningful command + its result table here as you go. This is what
makes conclusions auditable.

| # | Question being answered | Command(s) run | Result (table / IDs) | Conclusion |
|---|---|---|---|---|
| 1 |  |  |  |  |
| 2 |  |  |  |  |
| 3 |  |  |  |  |
| 4 |  |  |  |  |
| 5 |  |  |  |  |
| 6 |  |  |  |  |
| 7 |  |  |  |  |
| 8 |  |  |  |  |
| 9 |  |  |  |  |
| 10 |  |  |  |  |

---

## 4. Indicators of Compromise (IoC) table

Complete with your findings. Type can be `IP`, `Domain`, `App client ID`,
`Email address`, `File name`, `Rule name`, `User agent`, `Device ID`.

| IoC value | Type | Where first seen (date) | Evidence record IDs |
|---|---|---|---|
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |

---

## 5. Timeline

Build a full chronological timeline from **all three** sources. Sort, then
transcribe the key rows.

| Timestamp (+08:00) | Source | Operation | Detail (from log) | Record ID |
|---|---|---|---|---|
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |

---

## 6. Phases of the attack

Group your timeline into phases and map each to MITRE ATT&CK:

| # | Phase (e.g. Initial Access, Collection, Persistence, Impact) | Key evidence | ATT&CK technique ID(s) |
|---|---|---|---|
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |

---

## 7. Confidence assessment

For each major claim, rate confidence and justify it:

| Claim | Confidence (H/M/L) | Justification (which sources agree, gaps) |
|---|---|---|
| Identity of the app |  |  |
| Attacker source IPs |  |  |
| Data accessed list |  |  |
| Persistence mechanism |  |  |
| Impact |  |  |

---

## 8. Recommended response

Write actionable guidance, tuned to *this* attack chain:

**Containment** — what do you break NOW to stop the bleeding (consider: the
consent grant itself, the app registration, refresh tokens, the forward
rule, network blocks)?

**Eradication** — what do you remove/remediate so it can't come back?

**Recovery** — how do you restore integrity (files, mailbox items) and prove
cleanliness?

**Detection** — which future log queries / alerts would have caught this at
Day 1? (Give concrete queries.)

---

## 9. Final deliverable

Write `incident_report.md` with: executive summary (non-technical language);
scope; narrative timeline; IoC table; ATT&CK mapping; confidence ratings;
containment/eradication/recovery/detection; and three lessons-learned bullets
aimed at the CSIO.

Citation is mandatory — **no citation, no finding**. 

---

*Rubric hint: answers are judged on (a) correct identification of the affected
account/app, (b) correctness + completeness of the timeline, (c) whether each
conclusion is backed by a real record ID, and (d) quality of the response plan.*