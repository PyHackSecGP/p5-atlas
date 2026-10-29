# ATLAS — Autonomous Team for LLM-Assisted Security

![tests](https://img.shields.io/badge/tests-194%20passing-brightgreen)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![llm](https://img.shields.io/badge/LLM-Claude%20Haiku%20%2B%20Sonnet-6b4bff)
![fallback](https://img.shields.io/badge/local-Ollama-black)
![status](https://img.shields.io/badge/status-active-success)

Security researchers test whether systems can be broken into — not to do harm, but to find weaknesses before attackers do. This is called **penetration testing**, and it's a critical part of how organisations stay secure.

ATLAS automates that process. Give it a target IP, and nine specialist AI agents collaborate to scan services, enumerate shares, test web apps, exploit known vulns, escalate privileges, parse loot, and write a professional MITRE ATT&CK-mapped report — all with human checkpoints at every risky step.

---

## 60-Second Overview

- **What it is:** autonomous HackTheBox pentest pipeline, driven by nine specialist agents.
- **What's novel:** stage order is *not* hardcoded — a Planner agent reads recon output and dynamically routes the pipeline (skip web if no HTTP, skip enum if no SMB, jump straight to report once both flags land).
- **How it stays safe:** every risky action pauses on a checkpoint; `--auto` only auto-approves up to a configurable risk ceiling; high/critical always ask.
- **How it stays cheap:** stage-aware LLM tiering (Haiku for routine scans, Sonnet for strategic reasoning), ephemeral prompt caching, optional local Ollama fallback.
- **How it proves itself:** every run appends to `~/.atlas/portfolio.json` — flag-capture rate, duration, MITRE technique histogram, agents involved. `python -m metrics` prints the leaderboard.
- **Tested:** 194 passing tests across models, routing, metrics, agents, LLM provider, MITRE mapper, checkpoint, state.

---

## See It In Action

**Scenario:** a security team drops a new HTB-style machine into their training lab. They need to document the attack path so defenders can build detections against it.

```bash
# 1. Connect HTB VPN, then launch ATLAS
python atlas.py 10.10.11.227 --auto
```

Over the next ~22 minutes:

**1. Recon →** nmap + WhatWeb find SSH:22 and a web app on :80 running Request Tracker 4.4.4. The Planner agent reads this and sets stage order: `web → exploit → privesc → report` (enumeration skipped — no SMB).

**2. Web + Exploit →** Request Tracker 4.4.4 ships with default `root:password`. Login succeeds. An SSH key is sitting in a user's profile notes field. ATLAS extracts it and connects.

```
[exploit] SSH access established as: lnorgaard
[exploit] User flag captured: HTB{5a4c2f3d...}
```

**3. PrivEsc →** a cron-driven backup script runs as root every 5 minutes and is world-writable. ATLAS appends a reverse-shell line, waits, catches root.

```
[privesc] Root shell obtained
[privesc] Root flag captured: HTB{9f1e7b2c...}
```

**4. Report →** the Reporter agent writes the walkthrough and maps each step to MITRE ATT&CK:

| Technique  | What ATLAS Did                                    | Tactic                 |
|------------|---------------------------------------------------|------------------------|
| T1078.001  | Default credentials on web app                    | Initial Access         |
| T1552.004  | SSH private key stored in app data                | Credential Access      |
| T1053.003  | Modified world-writable cron job to get root      | Privilege Escalation   |

The writeup is committed into a `ctf-lab` portfolio repo. The run is appended to `~/.atlas/portfolio.json`.

---

## For Interviewers

### Problem Statement

Solo HTB practice is slow — a single medium box is 4–8 hours of mostly repetitive scanning and lookup work interleaved with a few flashes of real reasoning. Scaling that for a security team means weeks of operator time per training cycle. ATLAS compresses the mechanical work to ~20–40 minutes and demonstrates **agentic LLM reasoning under real safety constraints** (destructive actions, legal scope, token budget, flaky tooling). The design brief: autonomous enough to be useful, supervised enough to be defensible.

### Skills Demonstrated

- **Multi-agent orchestration** — 9 specialist agents, each with its own system prompt, tool belt, and output schema; typed handoffs via a shared `HackSession` dataclass.
- **Dynamic routing** — the Planner agent reads recon metadata and emits a stage order + skip-list; the orchestrator honours it. Not a hardcoded DAG.
- **ReAct loop** — every agent runs *observe (tool output) → reason (LLM) → act (next tool)* with adaptive fallback (`run_tool_adaptive`) when a tool returns empty.
- **Tiered LLM cost management** — stage-aware model selection (Haiku for recon/enum/planning, Sonnet for web/exploit/privesc/report), measured in-session via `cost_summary()`.
- **Prompt caching** — Anthropic ephemeral cache on the system block; hit/miss counters surface at session end.
- **Checkpoint + resume** — every stage snapshots `session.json`; `--resume --stage privesc` picks up mid-pipeline. Checkpoint schema is risk-aware (low/medium/high/critical).
- **MITRE ATT&CK mapping** — keyword-indexed `tools/mitre_mapper.py` tags every finding with technique + tactic + URL for defender hand-off.
- **Portfolio metrics** — `~/.atlas/portfolio.json` is append-only; `python -m metrics` aggregates solve rate, avg duration, difficulty buckets, technique histogram.
- **Credential hygiene** — passwords never enter LLM context (`context_summary()` emits usernames only).
- **Hybrid Windows + Linux PrivEsc** — SUID / sudo / cron on Linux, token / unquoted service path / scheduled task on Windows; SSH + WinRM / Evil-WinRM transport.
- **Local-first fallback** — Ollama provider swaps in with one flag; zero cloud dependency when the homelab is up.

### Architecture

```
                      ┌─────────────────────────────────────┐
                      │             atlas.py CLI             │
                      │  (preflight · VPN check · routing)   │
                      └──────────────────┬───────────────────┘
                                         │
                                         ▼
                              ┌─────────────────────┐
                              │   ReconAgent        │  nmap + WhatWeb → ports, versions
                              │   (always first)    │
                              └──────────┬──────────┘
                                         │
                                         ▼
                              ┌─────────────────────┐
                              │   PlannerAgent      │  reads recon → emits MachineAttackPlan:
                              │   (dynamic routing) │   stage_order, skip_stages, tactics
                              └──────────┬──────────┘
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 ▼                       ▼                       ▼
      ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
      │ EnumerationAgent │    │     WebAgent     │    │   ExploitAgent   │
      │ smb · ldap · ftp │    │ gobuster · ffuf  │    │ searchsploit +   │
      │ hydra (last)     │    │ nikto · nuclei   │    │ LLM-driven PoC   │
      └────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘
               │  (loot files)          │                      │
               ▼                        │                      │
      ┌──────────────────┐              │                      │
      │ LootAnalyzer     │              │                      │
      │ (keys · creds)   │              │                      │
      └────────┬─────────┘              │                      │
               └────────────────────────┼──────────────────────┘
                                        ▼
                              ┌─────────────────────┐
                              │   PrivEscAgent      │  linpeas-style checks,
                              │   Linux + Windows   │  SSH / WinRM transport
                              └──────────┬──────────┘
                                         │
                                         ▼
                              ┌─────────────────────┐
                              │   ReporterAgent     │  writeup + MITRE map +
                              │                     │  ctf-lab commit
                              └──────────┬──────────┘
                                         │
                                         ▼
                              ┌─────────────────────┐
                              │  metrics.record_run │  → ~/.atlas/portfolio.json
                              └─────────────────────┘
```

Handoff is through one typed object: `HackSession`. Agents read `session.open_ports`, `session.web_ports`, `session.credentials`, `session.loot`, `session.attack_plan`; agents write new `Finding`s, `Credential`s, flag strings, and loot paths back. The orchestrator checkpoints `session.json` after every agent.

### Design Decisions & Trade-offs

| Decision                              | Why                                                                                              | Trade-off                                                                 |
|---------------------------------------|--------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|
| **9 specialist agents, not a monolith** | Each agent has a tight tool belt + narrow prompt; easier to test, cheaper per call, debuggable in isolation. | More orchestration code; a monolithic agent could in theory reason across stages better. |
| **Dynamic routing via Planner**       | Hardcoding `recon→enum→web→exploit→privesc` wastes time on Linux-only boxes (SMB enum pointless) or web-less boxes. | Planner can emit bad orders; mitigated by `_derive_stage_order` fallback to a sane default. |
| **Haiku for routine, Sonnet for hard** | Recon/enum/planning parse tool output — Haiku handles that for pennies. Exploit/privesc/report need the smarter model. | Two models to maintain prompts for; stage-model map lives in `llm.py`.    |
| **Human checkpoints by default**      | Autonomous offensive tools without oversight are a liability (scope, legality, destruction).     | Slower interactive runs. `--auto` + `--auto-risk` opts out explicitly.    |
| **Ephemeral prompt caching**          | System block repeats across every agent call; caching cuts cost ~80% on a full run.              | Cache lifetime is minutes — long gaps between agents re-pay the cost.     |
| **Hydra as last resort**              | Brute force burns time and leaves obvious logs; the Enumeration agent only reaches for it after default-cred lookups fail. | Skips genuine weak-password findings on boxes without known defaults.     |
| **No cloud dependency required**      | `--provider ollama` runs the whole pipeline against a local model on the homelab.                | Quality drop vs Claude Sonnet; schemas (`generate_json`) are more fragile.|
| **Append-only portfolio.json**        | Trivially mergeable, trivially diffable, no DB to run.                                           | Full-scan aggregation on every `atlas-stats`; fine until thousands of runs.|
| **Credentials never enter LLM context** | `HackSession.context_summary()` strips passwords/hashes; usernames only.                        | LLM can't reason about password complexity patterns — intentional.        |

### Metrics

- **9** specialist agents (Recon, Planner, Enumeration, Web, Exploit, LootAnalyzer, PrivEsc, Reporter, plus the orchestrator state machine itself).
- **194** passing tests across 11 modules (from 184 before the metrics module landed).
- **Portfolio tracking:** per-run record + aggregate solve rate, difficulty buckets, MITRE technique histogram — `~/.atlas/portfolio.json`.
- **Cost target:** under $0.50 per full easy/medium box using Claude tiered + caching; $0.00 using Ollama.
- **Resume granularity:** stage-level. Interrupt during privesc, re-launch with `--resume --stage privesc`, state is intact.

---

## Quick Start

```bash
git clone https://github.com/PyHackSecGP/p5-atlas
cd p5-atlas
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1. Connect HTB VPN first (download .ovpn from HTB, then):
sudo openvpn ~/path/to/your-htb.ovpn &

# 2. Set API key (or skip for Ollama)
export ANTHROPIC_API_KEY="sk-ant-..."

# 3. Run it
python atlas.py 10.10.11.100 --auto

# Alt: local Ollama on the homelab, no API cost
python atlas.py 10.10.11.100 --provider ollama --model hermes3:70b

# Resume
python atlas.py 10.10.11.100 --resume --stage privesc

# Audit past runs
python atlas.py --list-sessions
python -m metrics
```

> **Note:** ATLAS is built for HackTheBox machines and authorised security training labs. Only run it against systems you have explicit permission to test.

---

## Agent Reference

| Agent             | Stage          | Purpose                                                             | Tools                                                                 |
|-------------------|----------------|---------------------------------------------------------------------|-----------------------------------------------------------------------|
| **ReconAgent**    | `recon`        | Port scan, service/version detect, OS guess, flag web/SMB/SSH/WinRM | `nmap -sV -sC`, `whatweb`, NSE scripts                                |
| **PlannerAgent**  | (post-recon)   | Emit `MachineAttackPlan`: stage order, skip list, per-stage tactics | LLM-only, no tools                                                    |
| **EnumerationAgent** | `enumeration` | SMB shares, LDAP, FTP, SNMP, user lists; hydra as last resort      | `enum4linux`, `smbclient`, `netexec` (ex-crackmapexec), `ldapsearch`, `hydra` |
| **WebAgent**      | `web`          | Directory busting, tech fingerprint, template-based vuln scan      | `gobuster`, `ffuf`, `nikto`, `nuclei`                                 |
| **ExploitAgent**  | `exploit`      | Look up public exploits, LLM-adapt PoC to target, obtain shell     | `searchsploit`, LLM-driven PoC adaptation, `sshpass`                  |
| **LootAnalyzerAgent** | (post-enum) | Parse loot files for keys/creds/notes                              | LLM-only on downloaded files                                          |
| **PrivEscAgent**  | `privesc`      | Linux: sudo/SUID/cron/caps. Windows: tokens/services/schtasks       | SSH / Evil-WinRM, linpeas-style checks, LLM reasoning                 |
| **ReporterAgent** | `report`       | Writeup + MITRE ATT&CK mapping + `ctf-lab` git commit               | `tools/mitre_mapper.py`, markdown rendering, `git`                    |
| *(Orchestrator)*  | *(all)*        | Dynamic routing, checkpoints, session persistence, metrics record  | `atlas.py` state machine                                              |

---

## Examples

### 1. Easy Linux box, end-to-end

```bash
$ python atlas.py 10.10.11.100 --auto
# Preflight — VPN tun0 found, target responds to ping.
# [Recon] 22/ssh OpenSSH 8.2, 80/http Apache 2.4.41 "Simple Login App"
# [Planner] stage_order=[web, exploit, privesc, report]; skip=[enumeration]
# [Web] ffuf finds /admin, /uploads; nuclei flags default-login
# [Exploit] admin:admin logs in → PHP upload → reverse shell → www-data
# [Exploit] user flag: HTB{...}
# [PrivEsc] SUID /usr/bin/pkexec (CVE-2021-4034 PwnKit) → root
# [PrivEsc] root flag: HTB{...}
# [Report] writeup written, mapped T1190, T1505.003, T1068, committed.
```

### 2. Medium Windows box — dynamic route kicks in

```bash
$ python atlas.py 10.10.11.202 --auto --auto-risk high
# [Recon] 53/dns, 88/kerberos, 135/msrpc, 389/ldap, 445/smb, 3268/gc, 5985/winrm
# [Planner] machine_type=AD-DC, stage_order=[enumeration, exploit, privesc, report]; skip=[web]
# [Enumeration] enum4linux: domain=HTB.LOCAL, 14 users found
# [Enumeration] AS-REP roasting one user → cracked offline → svc_backup:P@ssw0rd!
# [Exploit] evil-winrm → svc_backup shell → user flag
# [PrivEsc] svc_backup has SeBackupPrivilege → extract SYSTEM/SAM → DCSync → root flag
# [Report] T1558.004 (AS-REP), T1003.003 (NTDS), T1550.002 (pass-the-hash)
```

### 3. Resume after interruption

```bash
# Ctrl-C during exploit stage, come back the next day:
$ python atlas.py 10.10.11.100 --resume --stage privesc
# Resuming: Jupiter (10.10.11.100)
# Stage: privesc | Ports: 7 | Creds: 2 | Findings: 11
```

### 4. Portfolio metrics output

```bash
$ python -m metrics
ATLAS Portfolio
===============
Total runs:        12
User flags:        10  (83.3%)
Root flags:        7   (58.3%)
Both flags:        7   (solve rate 58.3%)
Avg duration:      2103.4s

By difficulty:
  easy       4/4   (100% rooted)
  medium     3/6   (50% rooted)
  hard       0/2   (0% rooted)

Top MITRE techniques:
  T1190      8
  T1548      5
  T1136      3
```

---

## Technical Reference

### Install

Python side:

```bash
pip install -r requirements.txt
```

System tools ATLAS shells out to (install via your package manager):

```
nmap gobuster ffuf nikto nuclei netexec hydra exploitdb sshpass whatweb enum4linux smbclient ldap-utils
# Debian/Kali: sudo apt install nmap gobuster ffuf nikto nuclei hydra exploitdb sshpass whatweb enum4linux smbclient ldap-utils
# netexec: pipx install git+https://github.com/Pennyw0rth/NetExec
# evil-winrm (for Windows PrivEsc): gem install evil-winrm
```

Not every tool is required for every box — agents degrade gracefully when a binary is missing (ReconAgent fallback logs a warning rather than crashing).

### Config

Environment variables:

| Var                   | Purpose                                                    | Default                           |
|-----------------------|------------------------------------------------------------|-----------------------------------|
| `ANTHROPIC_API_KEY`   | Claude API auth (unneeded for `--provider ollama`)         | *(required for Claude)*           |
| `OLLAMA_HOST`         | Local Ollama endpoint                                      | `http://localhost:11434`          |
| `ATLAS_PORTFOLIO`     | Path to the portfolio JSON file                            | `~/.atlas/portfolio.json`         |

Also honoured: `--api-key` CLI flag overrides the env var; `--output` overrides the session directory.

### CLI Flags

```
atlas.py <target> [options]
atlas.py --list-sessions

Positional:
  target                 Target IP (required unless --list-sessions)

Provider / model:
  --provider {claude,ollama}   LLM backend (default: claude)
  --model MODEL                Override auto-tier model selection
  --api-key KEY                Claude API key (overrides $ANTHROPIC_API_KEY)

Session:
  --output DIR                 Override ~/atlas-sessions/<ip>/
  --resume                     Load existing session.json and continue
  --stage {recon,enumeration,web,exploit,privesc,report}
                               Which stage to start from (default: recon)
  --list-sessions              Print table of every past run, then exit

Autonomy:
  --auto                       Skip checkpoints up to --auto-risk
  --auto-risk {low,medium,high,critical}   Max auto-approved risk (default: medium)
```

### `--auto` Mode Risk Levels

Every checkpoint declares a risk level. In auto mode, checkpoints at or below `--auto-risk` are auto-approved. Everything above still prompts.

| Level      | Examples                                                                        |
|------------|---------------------------------------------------------------------------------|
| `low`      | nmap scan, `whatweb` fingerprint, read-only enumeration, non-destructive LFI test |
| `medium`   | directory busting at scale, nikto, default-cred login attempt, searchsploit lookup |
| `high`     | hydra brute force, writing a webshell, running an untrusted PoC, SUID exploit    |
| `critical` | editing system files for persistence, cron modification, DCSync, destructive priv-esc chain |

`--auto --auto-risk medium` is the typical lab setting: automation up to the point an exploit changes state on the box; human eyes on anything that writes to disk.

### `--no-checkpoints`, `--resume`

- `--auto --auto-risk critical` effectively means "no checkpoints" — supported but not recommended outside a disposable VM.
- `--resume` reads `~/atlas-sessions/<ip>/session.json` and skips completed stages. Combine with `--stage` to force a specific restart point.

### Session Persistence + Checkpoint Schema

Every stage writes `session.json` under `~/atlas-sessions/<ip-with-underscores>/`:

```json
{
  "target_ip": "10.10.11.227",
  "machine_name": "Keeper",
  "os_guess": "Linux",
  "current_stage": "privesc",
  "ports": [{"number": 22, "service": "ssh", "version": "OpenSSH 8.9p1"}],
  "credentials": [{"username": "lnorgaard", "service": "ssh"}],
  "findings": [{"title": "...", "severity": "high", "mitre_id": "T1552.004"}],
  "user_flag": "HTB{...}",
  "root_flag": "",
  "loot": ["/.../loot/RT30.sql"],
  "attack_plan": {
    "stage_order": ["web", "exploit", "privesc", "report"],
    "skip_stages": ["enumeration"],
    "primary_vector": "RT 4.4.4 default creds → SSH key in notes",
    "machine_difficulty": "easy",
    "machine_type": "linux-webapp"
  }
}
```

Checkpoint events are logged inline — not stored separately — because the agent that produced them has already written its result to `agent_results[]`.

### Portfolio Metrics

Every completed run appends one record to `~/.atlas/portfolio.json`:

```json
{
  "target": "10.10.11.227",
  "machine": "Keeper",
  "difficulty": "easy",
  "os": "Linux",
  "user_flag_captured": true,
  "root_flag_captured": true,
  "duration_sec": 1324.7,
  "timestamp": 1730239988,
  "agents_used": ["Recon", "Planner", "Web", "Exploit", "PrivEsc", "Reporter"],
  "mitre_techniques": ["T1078.001", "T1552.004", "T1053.003"]
}
```

Aggregate CLI:

```bash
python -m metrics        # pretty-printed summary
```

Override location with `ATLAS_PORTFOLIO=/custom/path.json`.

### LLM Tiers

Defined in `llm.py` as `STAGE_MODEL_MAP`:

| Stage          | Model                       | Why                                         |
|----------------|-----------------------------|---------------------------------------------|
| `recon`        | Claude Haiku (cheap)        | Parse nmap XML, classify services           |
| `enumeration`  | Claude Haiku (cheap)        | Diff output, extract users/shares           |
| `planning`     | Claude Haiku (cheap)        | Decide stage order from structured recon    |
| `web`          | Claude Sonnet (strategic)   | Reason about tech stack + vuln likelihood   |
| `exploit`      | Claude Sonnet (strategic)   | Adapt public PoCs to target specifics       |
| `privesc`      | Claude Sonnet (strategic)   | Multi-step reasoning across host artifacts  |
| `report`       | Claude Sonnet (strategic)   | Quality matters — this goes in the portfolio |

Haiku and Sonnet both use **ephemeral prompt caching** on the system block. `ClaudeProvider` tracks `cache_hits` / `cache_misses` / `total_calls` and prints a cost summary at session end.

Ollama is a drop-in replacement — recommended models: `hermes3:70b` for the full pipeline, smaller models for recon-only runs.

### MITRE ATT&CK Mapping

`tools/mitre_mapper.py` holds a keyword-indexed table of techniques: nmap → T1046, nikto/sqli/xss → T1190, SUID/pkexec → T1548.001, cron modification → T1053.003, AS-REP → T1558.004, DCSync → T1003.006, etc. The Reporter agent iterates over findings and tags each with technique ID, name, tactic, and the canonical attack.mitre.org URL.

### `ctf-lab` Writeup Commit Workflow

The Reporter agent, after writing the markdown report:

1. Looks for a sibling `ctf-lab/` repo on disk (configurable path).
2. Copies the writeup to `ctf-lab/writeups/<box-name>.md`.
3. Commits with a message like `writeup: <box-name> rooted via <primary vector>`.
4. Does **not** push — pushing is a human decision.

Per the project's HTB rule: *after every rooted HTB machine, writeup → commit → push, no exceptions.*

### Testing

```bash
pytest -q
# 194 passed
```

Tests cover: `models` dataclasses, state save/load, LLM JSON retry, checkpoint flow + auto-mode risk gating, MITRE mapper lookups, metrics aggregation, planner stage-order emission, privesc Linux + Windows paths, exploit adaptive-command flow, loot analysis, routing + skip logic.

### Extending

**Add a new agent:**

1. Create `agents/<name>.py` subclassing `BaseAgent`; set `NAME`, `STAGE`, `SYSTEM_PROMPT`.
2. Implement `run(self) -> AgentResult`.
3. Register in `atlas.py` `PIPELINE_AGENTS` and, if routable, in `DEFAULT_STAGE_ORDER`.
4. Add a `Stage` enum value in `models.py`.
5. Write a `tests/test_agents_<name>.py`.

**Add a tool wrapper:**

Call `tools.runner.run(cmd, timeout, log_dir)` — it logs stdout/stderr under the session output dir and returns a `ToolResult`. For LLM-adaptive execution (retry with LLM-suggested command on empty/failed output), use `self.run_tool_adaptive(cmd, timeout, fallback_context)` from inside an agent.

**Add an attack-plan template:**

Extend `PlannerAgent.ask_json` prompt with a new rule, or seed a prior-art plan into `MachineAttackPlan` for a specific `machine_type`.

---

## Why This Was Built

Three overlapping goals:

1. **HTB mastery at pace.** Solo play is slow because 70% of a box is mechanical. Delegate the mechanical layer, keep the human on the strategic layer.
2. **Learn agentic AI properly.** Reading papers about multi-agent systems is not the same as debugging one at 2am when the Planner routes to `web` on a machine with no web. The ladder of real design decisions — model choice, caching, checkpoints, routing, state persistence, cost tracking — is only visible from inside the build.
3. **Portfolio asset.** A hiring manager can click `python -m metrics` and see a solve-rate curve across difficulty tiers. That's a stronger signal than a CV bullet.

---

## FAQ

**Q: Isn't an autonomous offensive tool dangerous?**
A: Yes, which is why ATLAS is *supervised* automation by default. Checkpoints are the primary safety mechanism — every risky action pauses with a four-field panel (found / plan / why / look for) and risk level. `--auto` only auto-approves up to a configurable risk ceiling; high and critical always prompt. Run only against systems you own or are authorised to test.

**Q: Does this violate HackTheBox ToS?**
A: HTB permits automation on retired boxes and in private instances; policies on active boxes vary. ATLAS is intended for retired boxes, personal labs, and authorised training ranges. It is not for ranked seasonal play. Check HTB's current terms before using it on active content.

**Q: What's the typical cost per box?**
A: Under $0.50 for a full easy/medium run with Claude tiered + ephemeral caching. Hard boxes with lots of exploit iteration can hit $1–$2. Ollama runs are free (hardware already paid for). The `ClaudeProvider.cost_summary()` call at session end reports actual spend.

**Q: Can I run this fully offline?**
A: Yes — `--provider ollama --model hermes3:70b` (or similar) runs the entire pipeline against a local Ollama server. Quality drops on JSON-schema-heavy stages (Planner, Reporter) with smaller local models; the `generate_json` retry logic compensates somewhat.

**Q: How is Windows coverage?**
A: PrivEscAgent branches on `session.os_guess`. Linux path uses linpeas-style checks over SSH. Windows path uses Evil-WinRM where available (port 5985/5986), falls back to extracted credentials over SMB, and reasons about token privileges, unquoted service paths, scheduled task permissions, and `SeBackupPrivilege` → DCSync chains. AD-DC enumeration is covered in EnumerationAgent (enum4linux, netexec, ldapsearch, AS-REP roasting with hashcat).

**Q: What about data exfil or persistence?**
A: Out of scope. ATLAS captures flags and loot files (keys, credential-bearing docs). It does not plant backdoors, persist beyond the session, or exfiltrate target data elsewhere. The LootAnalyzer agent reads loot in-session to find leads for the next stage; it does not phone home.

**Q: Why Python 3.11+?**
A: Dataclass features, `from __future__ import annotations` behaviour, generic `|` union syntax, and `enum.StrEnum` ergonomics. 3.10 may work; 3.11 is the floor that's tested.

**Q: How do I know when a run is reproducible vs. flaky?**
A: `session.json` captures every tool invocation's raw output under `agent_results[].raw_outputs`. If a run fails, re-running with `--resume` picks up the saved state; if an LLM response caused divergence, the raw outputs give you the deterministic diff point.

---

## License / Note

Authorised labs only. Only run ATLAS against systems you own or have explicit written permission to test. The authors accept no responsibility for misuse. This project is a learning + portfolio artifact — HackTheBox, Proving Grounds, TryHackMe, and private training ranges are the intended environment.

Stack: Python 3.11 · Anthropic Claude (tiered Haiku / Sonnet with ephemeral caching) · Ollama · nmap · gobuster · ffuf · nikto · nuclei · netexec · hydra · searchsploit · sshpass · evil-winrm · rich
