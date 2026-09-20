# Bloomline Technologies — Log Analysis Investigation

A 3-month, multi-source log dataset built for an **Introduction to Cyber Threat
Intelligence (CTIA)** capstone. You are a junior security analyst joining the
"Blue Team Fundamentals" rotation at Bloomline Technologies (a mid-size SaaS
vender in Singapore). Something happened in the Microsoft 365 tenant over the
months of **June – September 2026**, and the evidence is spread across three
different logging sources. Your job is to reconstruct what happened, prove it
with the raw evidence, and write an incident report.

All activity takes place inside a fictional world. Nothing in these logs
references a real company or a real user.

---

## Deliverables in this folder

| File | What it is |
|---|---|
| `entra_id_signin_audit.log` | Microsoft Entra ID sign-in + audit events (successes, failures, app consents, admin actions) |
| `graph_unified_audit.log` | Unified audit activity for Exchange, SharePoint, OneDrive and other Graph workloads |
| `swg_dns.log` | Secure web gateway flow + internal DNS resolution logs (web proxy egress + name resolution) |
| `guided_worksheet.md` | **Track A** — a step-by-step, command-driven walkthrough (for students who want maximum support) |
| `student_worksheet.md` | **Track B** — an open investigation with templates and prompts (for students who want to drive) |


---

## Time zone and date range

- Every timestamp is in **UTC+08:00** (Singapore Standard Time), formatted as
  `YYYY-MM-DDTHH:MM:SS+08:00`.
- The dataset covers **2026-06-01 through 2026-09-05** (~3 months).
- Record IDs (e.g. `E-0000096`, `G-0000568`, `S-0000215`) are a `Grep`-able
  convenience for citing evidence in your report.

---

## The three log sources (understand these first)

### 1. `entra_id_signin_audit.log`
**What it records:** identity events from the tenant — who signed in, with which
application, from where, with what result — plus tenant audit events such as
application consent grants, inbox-rule changes, and password resets.

`|`-separated, 16 columns:

```
timestamp|log_type|operation|result|error_code|user_upn|app_display|app_id|client_app|auth_type|ip_address|user_agent|device_id|mfa|details|record_id
```

- `log_type` = `SignInLogs` (an interactive/app sign-in) or `AuditLogs`
  (a tenant/admin/indexed action).
- `auth_type`: `Interactive`, `ManagedClient`, `TokenResurrect`-style flows; the
  **`mfa`** column states whether MFA was required and by which method.
- `details` often carries `permissions=...`, `consent_type=...`, `rule_name=...`,
  `forward_to=...` and `clientRequestId=C-...` correlation handles.

### 2. `graph_unified_audit.log`
**What it records:** data-plane activity on Microsoft workloads — mail actions
(send, delete, rule change), SharePoint/OneDrive file actions, Edge telemetry.

`|`-separated, 13 columns:

```
timestamp|log_type|operation|result|user_upn|app_display|app_id|client_app|ip_address|object_url|item|details|record_id
```

- `operation` values include `MailItemsAccessed`, `Send`, `NewInboxRule`,
  `UpdateInboxRule`, `RemoveInboxRule`, `HardDeleteMail`, `FileDownloaded`,
  `FileModified`, `FileUploaded`.
- `object_url` and `item` identify the mailbox/document; `details` carries
  message subjects, `forward_to`, and `clientRequestId`.

### 3. `swg_dns.log`
**What it records:** (a) DNS resolutions observed from internal clients by the
corporate resolver, and (b) HTTP(S) egress flows through the corporate secure
web gateway (including allowed and blocked categories).

`|`-separated, 16 columns:

```
timestamp|log_type|src_ip|user|hostname|dst|method|url|action|category|risk|bytes|qtype|answer|details|record_id
```

- `log_type` = `DNS` (name resolution, `qtype`/`answer` populated) or `HTTP`
  (web request, `url` populated).
- `action` = `PERMITTED` or `BLOCKED` (the gateway category policy verdict).
- `user` is `-` when the gateway could not attribute the flow to a user.

---

## Environment and tooling (recommended)

You need a Unix-like shell. Recommended options:

- **Kali Linux VM** (VirtualBox/VMware) — everything in the worksheets is
  standard GNU text tools.
- **Git Bash / WSL** on Windows — `grep`, `cut`, `sort`, `uniq`, `awk` all work.
- macOS Terminal works identically.

Core command set you will use (all plain GNU tools, no installs needed):

| Task | Command |
|---|---|
| Match lines | `grep -n -i "pattern" file.log` |
| Match from file of IDs/IPs | `grep -F -f iocs.txt file.log` |
| Split on the `|` separator | `cut -d'|' -f2 file.log` |
| Deduplicate + count | `sort \| uniq -c \| sort -rn` |
| Field arithmetic | `awk -F'|' '{print $1}' file.log` |

Copy the three `.log` files into a tidy workspace, e.g.:

```bash
mkdir -p ~/bloomline && cd ~/bloomline
cp /path/to/logs/*.log .
ls -la
```

**Pro tip for a messy-but-real hunt:** `details` fields sometimes contain the
same value twice or are truncated in a terminal — always push full rows to a
file and let `cut`/`awk` parse them rather than eyeballing.

---

## Working as an analyst

1. **Start broad, then narrow.** Count unique users, apps, IPs, and operations
   first. Abnormal actors become visible when you know what "normal" looks like.
2. **Correlate across sources.** The same app, IP, mailbox, or subject should
   appear in multiple logs. A finding that lives in only one log is a *hint*,
   not a *conclusion*.
3. **Separate signal from noise.** This dataset deliberately includes benign
   volume: routine M365 sign-ins, Teams/OneDrive sync traffic, admin app
   consents during an "enterprise app rollout", and **unrelated** failed
   authentication from an external scanner. Not every anomaly is the incident.
4. **Cite your evidence.** Every conclusion in your report must reference at
   least one record ID and timestamp.

## Ground rules

- You may use ANY tooling you like — the worksheets use plain
  `grep/cut/sort/uniq/awk` so nobody is blocked by builds or packages.
- The scenario is entirely synthetic; treat it as a training sandbox.

Good luck, and trust the data.

*— The Bloomline Security 101 team*