# ATLAS — Autonomous Team for LLM-Assisted Security

Security researchers test whether systems can be broken into — not to do harm, but to find weaknesses before attackers do. This is called **penetration testing** (or pentesting), and it's a critical part of how organisations stay secure.

ATLAS automates that process. Give it a target IP address, and it runs a complete attack chain — scanning for open services, testing for known vulnerabilities, attempting to gain access, trying to escalate to administrator privileges, and writing a professional report — all without a human driving it.

---

## What Problem Does This Solve?

A manual penetration test of a single system takes an experienced engineer 4-8 hours. For a team running security training labs or validating defences against known techniques, that time adds up fast.

ATLAS compresses that to 20-40 minutes for well-known attack patterns, using the same tools professional pentesters use — just orchestrated automatically, with an AI reasoning about what each tool's output means and deciding what to try next.

---

## See It In Action

**Scenario: A security team adds a new machine to their training lab to practice incident response.**

They run ATLAS against it to document the attack path their team should be able to detect:

```bash
python atlas.py 10.10.11.227 --auto
```

**What happens over the next 22 minutes:**

**1. Reconnaissance** — ATLAS scans the machine. Finds: SSH on port 22, a web application on port 80 running "Request Tracker 4.4.4" (a ticketing system).

**2. Research** — The AI analyses the findings: *"Request Tracker 4.4.4 is known to ship with default admin credentials. Check this before attempting more complex exploits."*

**3. Initial Access** — ATLAS tries `root:password` on the web interface. It works. Inside the ticketing system, a user's profile contains an SSH private key stored in the notes field. ATLAS extracts it.

```
[exploit] SSH access established as: lnorgaard
[exploit] User flag captured: HTB{5a4c2f3d...}
```

**4. Privilege Escalation** — ATLAS checks what administrator commands the user can run, what files have elevated permissions, and what automated tasks are scheduled. Finds: a backup script that runs as administrator every 5 minutes — and the regular user can modify it. ATLAS adds a command to the script and waits.

```
[privesc] Root shell obtained
[privesc] Root flag captured: HTB{9f1e7b2c...}
```

**5. Report** — ATLAS writes a professional writeup explaining every step, why it worked, and how defenders could have caught it. It maps each technique to the MITRE ATT&CK framework — the standard reference defenders use to build detections:

| Technique | What ATLAS Did | Tactic |
|---|---|---|
| T1078.001 | Used default credentials on the web app | Initial Access |
| T1005 | Extracted SSH key from application data | Collection |
| T1053.003 | Modified a scheduled cron job to get root | Privilege Escalation |

The writeup is automatically committed to a portfolio repository.

---

## Human Approval at Every Step

ATLAS does **not** run fully automatically by default. Before each action, it shows exactly what it found, what it plans to do, and why — and asks for approval:

```
╔══════════════════════════════════════════════════════════╗
║  CHECKPOINT: Exploit Stage                               ║
║  Found: Request Tracker 4.4.4, default credentials known ║
║  Plan: attempt login root:password                       ║
║  Risk: low                                               ║
╚══════════════════════════════════════════════════════════╝
  Approve? (y/n/skip)
```

The `--auto` flag turns on automatic approval for low and medium risk actions — useful in controlled training labs. High-risk actions always ask, even in auto mode.

This is the right design. Autonomous tools that act without human oversight can execute actions that are out of scope, legally problematic, or destructive. ATLAS is built for *supervised* automation — the AI does the thinking, the human approves the actions.

---

## What It Uses

Real professional security tools, automated:

| Stage | Tools | What it does |
|---|---|---|
| Reconnaissance | nmap, WhatWeb | Scan for open services and identify software versions |
| Enumeration | enum4linux, hydra, smbclient | Test file shares, try passwords, check for default creds |
| Web testing | nikto, gobuster, ffuf, nuclei | Find hidden pages, test for known web vulnerabilities |
| Exploitation | searchsploit + AI | Look up known exploits for found software versions |
| Privilege escalation | sudo check, SUID scan, cron analysis, LinPEAS | Find ways to go from regular user to administrator |
| Reporting | Claude / Ollama | Write up the full attack path with MITRE ATT&CK mapping |

---

## AI Cost Management

Not every stage needs the same AI capability:

- **Routine analysis** (reading nmap output, classifying services) uses Claude Haiku — fast and cheap
- **Critical reasoning** (planning an exploit, deciding privilege escalation approach) uses Claude Sonnet — more capable
- **Writing** (the final report) uses Claude Sonnet — quality matters for the portfolio

Prompt caching keeps repeated context (tool descriptions, stage instructions) from being re-processed on every AI call, cutting costs by ~80% on a full run. A local Ollama server on the homelab can run the whole thing with no API costs at all.

---

## Quick Start

```bash
git clone https://github.com/PyHackSecGP/p5-atlas
cd p5-atlas
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Connect to HackTheBox VPN first, then:
export ANTHROPIC_API_KEY="sk-ant-..."
python atlas.py 10.10.11.100 --auto

# Use local Ollama instead (no API key needed)
python atlas.py 10.10.11.100 --provider ollama --model hermes3:70b

# Resume a run that was interrupted
python atlas.py 10.10.11.100 --resume --stage privesc

# See every machine you've run ATLAS against
python atlas.py --list-sessions
```

> **Note:** This tool is built for HackTheBox machines and authorised security training labs. Only run it against systems you have explicit permission to test.

---

## Stack

Python 3.11 · Anthropic Claude (tiered Haiku/Sonnet) · Ollama · nmap · gobuster · nikto · ffuf · hydra · searchsploit · sshpass · rich
