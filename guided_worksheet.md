# Track A — Guided Investigation Worksheet

**Bloomline Technologies — M365 tenant, June–September 2026**

You are a junior analyst on the SOC rotation. Your mentor has handed you a
three-source log package and a mission: **find out what the company just
breached — how it happened, what the actor touched, and how long they kept
secrets.** The mentor has also left you a breadcrumb: *"Start from who could
act as someone else, then follow the app."*

Work through the checkpoints below in order. Every checkpoint ends with a
**Verification** you must be able to explain out loud. Commands use GNU tools
(`grep`, `cut`, `sort`, `uniq`, `awk`) — run them from the folder with the
three `.log` files.

---

## Step 0 — Get oriented (never skip)

Look at each head-line and a sample row so your eyes learn the column order.

```bash
head -3 entra_id_signin_audit.log
head -3 graph_unified_audit.log
head -3 swg_dns.log
```

For each file, count **data** rows (the three files each have exactly one
header line, so subtract 1 from `wc -l`):

```bash
wc -l entra_id_signin_audit.log graph_unified_audit.log swg_dns.log
# e.g. entra_id_signin_audit.log has 1003 data rows + 1 header line
```

**Verification:** name the columns of all three files from memory. State the
time zone and the date range covered.

---

## Step 1 — Build the "normal" baseline

Before you can notice anything weird, know the numbers:

```bash
# Who signs in and how often
cut -d'|' -f6 entra_id_signin_audit.log | sort | uniq -c | sort -rn

# What are the outcomes of those events? (Success / Failure)
cut -d'|' -f4 entra_id_signin_audit.log | sort | uniq -c | sort -rn

# Which applications are users touching?
cut -d'|' -f7 entra_id_signin_audit.log | sort | uniq -c | sort -rn | head -20

# Where are successful logins coming from? (top source IPs)
grep '|UserLogin|Success|' entra_id_signin_audit.log | cut -d'|' -f11 | sort | uniq -c | sort -rn | head

# What operations is the data plane recording?
cut -d'|' -f3 graph_unified_audit.log | sort | uniq -c | sort -rn
```

**Verification:** you can now describe *typical* behaviour: the users, the
usual apps, the usual IP ranges (notice the internal `10.x` and office NAT
`192.0.2.x` ranges), and the operation mix.

---

## Step 2 — Filter out the noise you are told to ignore

Two categories exist in this dataset that are **unrelated to the case**. Find
them and confirm each one is a dead end:

```bash
# 1) Failed sign-ins: an external account/password spray
grep 'UserLogin|Failure' entra_id_signin_audit.log | cut -d'|' -f11 | sort | uniq -c | sort -rn

# 2) Blocked proxy signatures from unauthenticated sources
grep '|BLOCKED|' swg_dns.log | cut -d'|' -f3,6,8,9 | head -20
```

Loosely: an unauthenticated `198.18.1.x` block of a scanner-like `_layouts/15/Checkout.aspx`
request and `liveid/token` HTTP calls, plus failed password attempts from
`198.18.1.12/13`. These are **noise** (failure / blocked, no data accessed).

**Verification:** explain *why* each of these is a false start — what does a
"failed" sign-in actually let an attacker do, and what does a "blocked" flow
actually touch? (Answer: nothing.)

---

## Step 3 — Find the consent grants

The tenant had users approve external apps (OAuth). List every approval:

```bash
grep 'ConsentedToApplication' entra_id_signin_audit.log
```

Observe the shape of each row: **who** consented, **what app**, **which
permissions**, and `consent_type` (`delegated` = a user approved it;
`admin` = a tenant admin approved it on behalf of all).

You should see several *benign* entries (admin rollout apps, a transcription
tool, a signing service). **One** entry stands out: a meeting-support app whose
permission list is far too broad for what it claims to do.

Save that suspicious app's client ID (the `app_id`) and its display name:

```bash
grep 'ConsentedToApplication' entra_id_signin_audit.log | \
  cut -d'|' -f7,8 | sort -u
```

**Verification:** list every app consented between June and September, who
approved each, and the permission set each requested. Highlight the mismatch
(app purpose vs. permissions).

---

## Step 4 — Follow the app in the identity log

Take the suspicious `app_id` and search the **Entra** log for everything that
used it:

```bash
grep -n 'a2e8e3f2-6c4d-4d5a-b1c2-1f9a3b4c5d6e' entra_id_signin_audit.log
```

Study the rows. Now answer:

1. Who consents/uses the app? (user UPN)
2. What **IP addresses** does the app log in from?
3. What `device_id` / `mfa` / `auth_type` do those logins claim?
4. What is the sign-in *result* and the *correlation ID* pattern?

Then compare those IPs against Step 1's "normal" IP list.

```bash
# Source IPs of the suspicious app
grep 'a2e8e3f2-6c4d-4d5a-b1c2-1f9a3b4c5d6e' entra_id_signin_audit.log | cut -d'|' -f11 | sort | uniq -c
```

**Verification:** you now have a short list of IPs used by this app. Confirm
they are **not** in the office NAT range (`192.0.2.150-152`) nor the internal
`10.x` range, i.e. this app's activity originates *outside* Bloomline.

---

## Step 5 — Prove the user really clicked (the web-gateway view)

The victim's consent happened at a precise moment. Find the surrounding
**DNS** and **HTTP** rows in the SWG log for that user/device:

```bash
# The minute before the consent: what did the victim's device resolve?
awk -F'|' '$4 ~ /priya.raman/ && $1 ~ /2026-06-09T10:2/' swg_dns.log

# Look for the authorize URL against login.microsoftonline.com
grep 'login.microsoftonline.com/common/oauth2/v2.0/authorize' swg_dns.log
```

Read the `url` in the HTTP row carefully. You will see, for the victim's
device, a query string for `login.microsoftonline.com` that contains:

- `client_id=<the app you flagged>`
- `redirect_uri=...` → where approvals are sent back
- `scope=...` → the exact permissions being requested

**Verification:** explain the full chain *for the victim's session*: browser
resolves the app's own domain → returns an IP → browser calls the Entra
authorization endpoint asking that the flagged app be allowed the listed
scopes. This is the *initial entry point* — made possible because the attacker
tricked a human into approving.

---

## Step 6 — Chase tokens, not passwords (the same consent, minutes later)

The instant after consent, the app starts acting *as* the user. Look at the
sign-in rows **minutes after** the consent timestamp, still in the Entra log:

```bash
grep 'a2e8e3f2-6c4d-4d5a-b1c2-1f9a3b4c5d6e' entra_id_signin_audit.log | \
  awk -F'|' '$1 >= "2026-06-09T10:00:00" && $1 <= "2026-06-09T12:00:00"'
```

Notice the shape of these rows:

- `auth_type` and `mfa` say token/refresh-token, **not** a password.
- The `ip_address` is one of the *outside* IPs you found in Step 4.
- `device_id` is bogus/empty — no managed device was used.
- The sign-in is classified **Success**.

This is the heart of the whole event: the app keeps a long-lived **refresh
token**, and it replays that token on a machine the user never touched.

**Verification:** state, in your own words, how the account was compromised
with *no passwords stolen at all*.

---

## Step 7 — Cross into the data plane (Graph log)

Now use the same `app_id` in the **Graph** log:

```bash
grep 'a2e8e3f2-6c4d-4d5a-b1c2-1f9a3b4c5d6e' graph_unified_audit.log
```

Group by operation and by target:

```bash
grep 'a2e8e3f2-6c4d-4d5a-b1c2-1f9a3b4c5d6e' graph_unified_audit.log | cut -d'|' -f3 | sort | uniq -c | sort -rn
grep 'a2e8e3f2-6c4d-4d5a-b1c2-1f9a3b4c5d6e' graph_unified_audit.log | cut -d'|' -f10 | sort -u | head -30
```

**Verification:** summarise, in order, *everything* the app did to the
victim's mailbox (read mail, send mail, create/alter/delete a rule, hard-delete
items) and to SharePoint/OneDrive (downloads, uploads, modifications). Note
each file path and payload object.

---

## Step 8 — Do not trust the password reset (persistence check)

Find the human-driven account event in mid-August:

```bash
grep 'ChangePassword' entra_id_signin_audit.log
grep 'UpdateUser' entra_id_signin_audit.log
```

Then check: **does the suspicious app still sign in after that date?**

```bash
grep 'a2e8e3f2-6c4d-4d5a-b1c2-1f9a3b4c5d6e' entra_id_signin_audit.log | \
  awk -F'|' '$1 >= "2026-08-17T18:41:00"'
```

**Verification:** explain why changing the password did **not** end the access.
What credential lives on *the app's* side and was never revoked?

---

## Step 9 — Reconstruct the timeline end-to-end

Merge all three files onto one clock and sort:

```bash
cat entra_id_signin_audit.log graph_unified_audit.log swg_dns.log | \
  grep 'a2e8e3f2-6c4d-4d5a-b1c2-1f9a3b4c5d6e\|smartnotes-ai\|relay@mail.deliver.example' | \
  sort > attack_timeline.txt
head -60 attack_timeline.txt
```

Also capture the **mail-forward** behaviour the app installed (it is in the
Entra audit *and* visible in Graph):

```bash
grep -i 'inboxrule' entra_id_signin_audit.log
grep 'forward_to' entra_id_signin_audit.log
```

The rule name and its `forward_to` address are important: an attacker who
forwards mail after exfiltrating is often keeping a *second* copy going to
their own mailbox.

**Verification:** produce a chronological table of the incident with at least
these columns — timestamp | source file | operation | detail (from details
field) | record ID. It should tell the full story at a glance.

---

## Step 10 — Identify the endgame / impact

Look at early September for the destructive / financial-sounding operations:

```bash
grep -E 'HardDeleteMail|FileModified|FileUploaded' graph_unified_audit.log | \
  grep -v 'Teams' | tail -30
```

Note the odd filename that appears (`HowToRestoreFiles.txt`) and its parent
folder, plus message deletions in the victim's mailbox.

**Verification:** from *evidence* (not vibes), describe what the actor did at
the very end that would alarm a human or an EDR — even though they deleted
their tracks.

---

## Step 11 — Collect IoCs and rule out the red herrings

Create an indicator file and enrich it:

```bash
cat > iocs.txt <<'EOF'
a2e8e3f2-6c4d-4d5a-b1c2-1f9a3b4c5d6e
smartnotes-ai.example
203.0.113.41
203.0.113.47
203.0.113.50
203.0.113.52
relay@mail.deliver.example
EOF

# Any other source referencing these? Sweep all three logs
grep -F -f iocs.txt entra_id_signin_audit.log
grep -F -f iocs.txt graph_unified_audit.log
grep -F -f iocs.txt swg_dns.log | wc -l
```

(smartnotes-ai.example is fictional, but a real analyst would confirm via
Whois/PassiveDNS — you are told it is fictional here.)

Now **red herrings** — deliberately present in the package — to double-check:

1. The `Noteworthy Transcriptions` consent asks for `Calendars.Read` only.
   Is that alarming? What is the *worst* it could read? Verify the app's sign-in
   rows and its Graph operations. Conclusion: limited surface — a false lead.
2. The admin rollout consents (`PolicyNinja`, `HRMS-Bridge`, `OrgChartSync`)
   are `consent_type=admin` and were approved by the tenant admin on the
   company IP during office hours. Not the incident.
3. The failed `198.18.1.12/13` sign-ins and the blocked `198.18.1.11` scanner
   never succeed, so they never touch data. Not the incident.

**Verification:** write a one-line disposition for *each* of the three
red-herring categories, quoting the log rows that prove it.

---

## Step 12 — Map to the MITRE ATT&CK framework

For each phase below, you will later paste in AT&T&CK technique IDs. Identify
the phases from the evidence you already have:

| Phase (you decide the row) | What you found | ATT&CK technique ID (use docs) |
|---|---|---|
| Initial access (how the attacker first got in) |  |  |
| Credential/access (what the attacker now holds) |  |  |
| Defence evasions (deleting emails, removing rules) |  |  |
| Collection (mail read, files downloaded) |  |  |
| Persistence (mail forward rule) |  |  |
| Impact (end-of-chain damage) |  |  |

You do not need to be perfect — but each cell must be a **technique that
matches the cited evidence**, e.g. an *email collection* technique that
explains the forwarding rule, or an *account manipulation* technique that
explains the rule change itself.

**Verification:** justify two of your MITRE rows out loud with the exact
record IDs that support them.

---

## Step 13 — Produce the incident report

Write `incident_report.md` containing, **at minimum**:

1. Executive summary (2–3 sentences, non-technical audience).
2. Scope: which tenant(s), which user account(s), which workloads (mail, files,
   identity), which date range.
3. Narrative timeline (chronological, evidence-cited — pull from Step 9).
4. Indicators of Compromise (IoC) table: value | type (IP/domain/app-id/email) |
   evidence record IDs.
5. MITRE ATT&CK mapping table (from Step 12).
6. Confidence assessment per phase (High / Med / Low) with the reasoning —
   e.g., "High — 3 independent sources agree".
7. Recommended containment + eradication + recovery + detection steps for
   *this* attack chain.
8. Lessons-learned bullet list for the CSIO.

**Verification:** have a peer (or your instructor) try to *disprove* each
claim using only the logs. A claim that survives is a finding; one that
doesn't gets rewritten.

---

## When you're done

- Redo Step 9 with **no** `grep` filter for the app — find the chain by hand
  from a blank folder. If you can find it again from nothing but SQL-style
  counts of operations and IPs, you've internalised the methodology.