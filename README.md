# ATLAS — Autonomous Team for LLM-Assisted Security

**Role:** Offensive Security / Security Engineer portfolio project  
**Stack:** Python 3.11 · nmap · gobuster · nikto · hydra · searchsploit · sshpass · Anthropic Claude (tiered) · Ollama

---

## Why I Built This Instead of Using an Existing Tool

**Pentera**, **NodeZero**, and **Horizon3.ai** are commercial autonomous pentest platforms. They cost $100k+/year and are used by large enterprise security teams. I didn't build this to compete with them — I built it to understand the full offensive chain that underlies them, so that when I'm working alongside one of those platforms, or scoping an engagement that uses them, I understand what they're actually doing at each stage.

Specifically, I needed hands-on understanding of:

- What nmap NSE vuln scripts actually detect and what their false-positive rate looks like in practice
- How hydra brute-force is structured — when to run it, against which services, with what word lists — and why running it wrong wastes the engagement
- How searchsploit maps service versions to exploit candidates, and what the LLM is actually adding when it filters those candidates
- How SSH-based post-exploitation enumeration works — id, sudo, SUID, capabilities, cron — and what the attack path looks like from a defender's perspective
- Where LLMs genuinely improve analyst throughput in offensive work, and where they create noise

Every stage of ATLAS was built to answer one of those questions. I now think about offensive tooling differently — not as a black box that produces findings, but as a pipeline where each stage has specific failure modes, blind spots, and tradeoffs. That's directly useful when evaluating commercial tools, scoping engagements, or building detections for the techniques those tools use.

---

## What It Does

Give it a target IP. It runs a full six-stage attack chain with real security tools, LLM reasoning at each stage, and human-in-the-loop checkpoints before any action is executed.

```
atlas.py <IP>
    │
    ├─ Recon         nmap fast scan + deep scan + NSE vuln scripts + WhatWeb
    ├─ Enumeration   enum4linux-ng · smbclient · ftp anon · ldapsearch · snmpwalk · hydra · netexec
    ├─ Web           nikto + gobuster + ffuf (parallel) · nuclei templates
    ├─ Exploit       searchsploit lookup → LLM plan → execute → flag detection
    ├─ PrivEsc       SSH post-shell: sudo · SUID · capabilities · cron · kernel · LinPEAS
    └─ Report        LLM writeup → MITRE ATT&CK table → git commit → push to GitHub + Forgejo
```

It captures user and root flags, auto-generates a writeup, maps every technique used to MITRE ATT&CK, and commits the writeup to a portfolio repository.

---

## Concrete Scenario: HTB Machine "Keeper"

A new HackTheBox machine goes live. Running ATLAS in auto mode:

```bash
atlas.py 10.10.11.227 --auto
```

**What happens:**

**Recon** finds SSH on 22 and HTTP on 80. WhatWeb identifies `Request Tracker 4.4.4` — a ticketing system. NSE vuln scripts don't find a direct CVE.

**Enumeration** — no SMB. Hydra against SSH returns nothing with the default wordlist.

**Web** — gobuster finds `/rt`. nikto flags the RT version. ffuf finds no hidden directories. The LLM analyses the findings: "Request Tracker 4.4.4 is known to ship with default credentials `root:password`. Check login before attempting exploitation."

**Exploit** — LLM plan: try default credentials on RT web interface. Shell: RT has a user profile with SSH private key in the "notes" field. Extract key, SSH as `lnorgaard`.

```
[exploit] User flag: HTB{5a4c2f3d...}
```

**PrivEsc** — `sudo -l` returns nothing. SUID check finds nothing unusual. Cron check: `/home/lnorgaard/rt-home-backup.sh` runs as root every 5 minutes. File is world-writable. LLM plan: append reverse shell to the script, wait.

```
[privesc] Root flag: HTB{9f1e7b2c...}
```

**Report** generates a writeup automatically and appends a MITRE ATT&CK table:

| Technique | Name | Tactic |
|---|---|---|
| T1592 | Gather Victim Host Information | Reconnaissance |
| T1078.001 | Valid Accounts: Default Accounts | Initial Access |
| T1005 | Data from Local System (SSH key exfil) | Collection |
| T1053.003 | Scheduled Task/Job: Cron | Privilege Escalation |

Writeup committed to `ctf-lab` repository, pushed to GitHub and Forgejo. Total time: 22 minutes.

---

## Human-in-the-Loop Design — Why It Matters

ATLAS is not fully autonomous by default. Every action that touches the target goes through a checkpoint:

```
╔══════════════════════════════════════════════════════════╗
║  CHECKPOINT: Exploit Stage                               ║
║  Found: RT 4.4.4 with possible default credentials      ║
║  Plan: attempt login root:password on http://10.10.11.227║
║  Risk: low                                               ║
╚══════════════════════════════════════════════════════════╝
  Approve? (y/n/skip)
```

The `--auto` flag exists for controlled lab environments. In a real engagement, the operator must approve each action — because the LLM reasoning can be wrong, and executing a high-risk action based on incorrect analysis is how you cause an incident instead of documenting one.

This architecture is a deliberate response to a real failure mode in autonomous pentest tools: they can execute actions that are out of scope, destructive, or legally problematic when run without supervision. Building the checkpoint system from scratch meant understanding exactly where those failure modes are and why.

---

## LLM Strategy — Tiered Model Usage

Not every stage needs the same model:

| Stage | Model | Reason |
|---|---|---|
| Recon / Enumeration | `claude-haiku-4-5` | Fast, cheap; parsing nmap output doesn't need deep reasoning |
| Exploit / PrivEsc | `claude-sonnet-4-6` | Complex reasoning; wrong plans have consequences |
| Report / Writeup | `claude-sonnet-4-6` | Quality matters; this goes in the portfolio |

**Prompt caching** is enabled on all system prompts. The tool descriptions, stage instructions, and output schemas are cached across agents. On a full 6-stage run, this reduces input token cost by ~80-90% — a meaningful difference when running multiple machines per day.

**Ollama fallback** (`--provider ollama --model hermes3:70b`) routes everything to a local GPU server for air-gapped runs or cost control.

---

## MITRE ATT&CK Mapping — Automatic, Not Manual

The reporter doesn't require structured input to generate the ATT&CK table. `tools/mitre_mapper.py` scans all session text — tool outputs, LLM summaries, findings, notes — for keywords that indicate specific techniques:

```python
(["sudo", "sudo -l", "sudoers"], AttackTechnique(
    "T1548.003", "Sudo and Sudo Caching", "Privilege Escalation", "TA0004", ...
)),
(["suid", "setuid", "suid binary"], AttackTechnique(
    "T1548.001", "Setuid and Setgid", "Privilege Escalation", "TA0004", ...
)),
```

Every writeup automatically ends with a technique table that maps the engagement to the ATT&CK framework. This is directly useful for defenders: the same table tells a blue team which detections to verify were in place.

---

## Architecture

```
atlas.py
  │
  ├─ preflight()              VPN check + ping
  ├─ llm.get_provider()       tiered Claude or Ollama
  └─ run_pipeline()
       │
       ├─ agents/recon.py         nmap + WhatWeb → LLM analysis
       ├─ agents/enumeration.py   enum4linux + hydra + netexec → LLM
       ├─ agents/web.py           nikto + gobuster + ffuf + nuclei → LLM
       ├─ agents/exploit.py       searchsploit → LLM plan → execute
       ├─ agents/privesc.py       SSH post-shell + LinPEAS → LLM
       └─ agents/reporter.py      LLM writeup + MITRE ATT&CK + git push

  checkpoint.py       human approval gate (bypassed in --auto for low/medium risk)
  state.py            full session persistence to ~/.atlas/sessions/
  tools/runner.py     subprocess wrapper with timeout + output capture
  tools/mitre_mapper.py  keyword → ATT&CK technique mapping
```

---

## Quick Start

```bash
git clone https://git.greenbladesec.com/gpsingh/p5-atlas
cd p5-atlas
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Requires HTB VPN connected
export ANTHROPIC_API_KEY="sk-ant-..."

# Interactive mode (approve each action)
python atlas.py 10.10.11.100

# Auto mode (approve low+medium automatically)
python atlas.py 10.10.11.100 --auto

# Local LLM (no API key needed)
python atlas.py 10.10.11.100 --provider ollama --model hermes3:70b

# Resume from a specific stage
python atlas.py 10.10.11.100 --resume --stage privesc

# See all past sessions
python atlas.py --list-sessions
```
