# P5 — ATLAS: Writeup

## What It Is

ATLAS (Autonomous Team for LLM-Assisted Security) is an autonomous pentest pipeline for HackTheBox and CTF machines. Given a target IP, it runs a complete six-stage attack chain — Recon → Enumeration → Web → Exploit → PrivEsc → Report — using real security tools at each stage, piping their output through an LLM to reason about next steps, and pausing at human-in-the-loop checkpoints before any action is executed.

**It roots machines end-to-end.** The system captures user and root flags, auto-generates an HTB-quality writeup, and commits it to a git repository.

---

## Why I Built It

The 2024–2025 AI security landscape made one thing clear: automated offensive AI is no longer theoretical. LLM-assisted tools are changing the economics of both attack and defence. I built ATLAS to deeply understand that capability from first principles — not to use an existing framework, but to build the reasoning pipeline myself.

This is project P5 in my security engineering portfolio. It demonstrates:
- Real offensive security tool chain (nmap, gobuster, nikto, hydra, searchsploit, sshpass, LinPEAS)
- LLM reasoning integration for plan generation and finding analysis
- Multi-agent architecture with stage-specific agents
- Defensive design thinking: human checkpoints, configurable risk thresholds, auto mode
- Python async orchestration and state persistence

---

## Architecture

```
atlas.py
  │
  ├─ preflight()         VPN + ping check
  │
  └─ run_pipeline()
       │
       ├─ ReconAgent      nmap (fast + deep + NSE vuln scripts) → LLM analysis
       │                  WhatWeb banner grab
       │
       ├─ EnumerationAgent  enum4linux-ng (SMB/RPC)
       │                    smbclient share enumeration
       │                    ftp anonymous login
       │                    ldapsearch (AD)
       │                    snmpwalk
       │                    hydra brute (SSH/FTP when users found)
       │                    netexec / crackmapexec spray
       │
       ├─ WebAgent         nikto + gobuster + ffuf (parallel per target)
       │                   nuclei template scan
       │                   LLM analysis of all web findings
       │
       ├─ ExploitAgent     searchsploit lookup per service/version
       │                   LLM exploit plan generation
       │                   exploit execution + HTB flag detection
       │
       ├─ PrivEscAgent     SSH-based post-shell enumeration:
       │                   id, sudo -l, SUID, capabilities, cron, kernel
       │                   optional LinPEAS upload + parse
       │                   LLM privesc plan + execution
       │                   root flag capture
       │
       └─ ReporterAgent    LLM writeup generation
                           MITRE ATT&CK technique mapping
                           git commit + push to ctf-lab (GitHub + Forgejo)
```

---

## LLM Strategy

**Tiered model usage** minimises cost while keeping quality high:
- `claude-haiku-4-5` — cheap recon/enum analysis, service version lookup
- `claude-sonnet-4-6` — exploit planning, privilege escalation reasoning, writeup

**Prompt caching** on all system prompts: the tool descriptions, stage instructions, and output parsing schemas are cached across agents, cutting ~90% of input token cost on multi-stage runs.

**Ollama fallback**: `--provider ollama --model hermes3:70b` routes everything to claw-core (100.126.22.55:11434) for air-gapped or cost-sensitive runs.

---

## Checkpoint System

Every action that touches the target goes through a checkpoint:

```
╔═══════════════════════════════════════════╗
║  CHECKPOINT: Recon Stage                  ║
║  Found: nmap detected SSH (22), HTTP (80) ║
║  Plan: run gobuster + nikto on port 80    ║
║  Risk: low                                ║
╚═══════════════════════════════════════════╝
  Approve? (y/n/skip)
```

In `--auto` mode, checkpoints below the configured risk threshold are auto-approved. Only `high` risk actions require human confirmation by default.

---

## Human-in-the-Loop Design

ATLAS is deliberately not fully autonomous by default. The design philosophy: LLM does the reasoning, human approves the execution. This prevents:
- Scope creep (running tools against IPs outside the target)
- Accidental destructive actions (format disk, crypto)
- Trust blindly in LLM reasoning errors

The `--auto` flag exists for controlled lab environments where the operator has already reviewed the machine.

---

## MITRE ATT&CK Integration

The ReporterAgent maps session findings and tool outputs to MITRE ATT&CK techniques automatically, generating a technique table appended to every writeup:

```
| Technique  | Name                               | Tactic              |
|------------|------------------------------------|---------------------|
| T1046      | Network Service Discovery          | Reconnaissance      |
| T1190      | Exploit Public-Facing Application  | Initial Access      |
| T1110.001  | Brute Force: Password Guessing     | Credential Access   |
| T1548.001  | Setuid and Setgid                  | Privilege Escalation|
| T1053.003  | Cron                               | Privilege Escalation|
| T1005      | Data from Local System             | Collection          |
```

This mapping is keyword-based from all session text (tool outputs, findings, LLM summaries, notes) — no structured data required.

---

## Sample Run

```
$ atlas.py 10.10.11.100 --auto

 █████╗ ████████╗██╗      █████╗ ███████╗
██╔══██╗╚══██╔══╝██║     ██╔══██╗██╔════╝
...

[preflight]
  ✓  VPN interface: tun0
  ✓  Target 10.10.11.100 alive  RTT: 45.3ms

─── Stage: RECON ───────────────────────────────
[recon] Starting nmap fast scan...
[recon] nmap NSE vuln scripts...
[recon] WhatWeb 10.10.11.100...
[recon] LLM analysis...
[recon] Found: SSH/22 (OpenSSH 8.9), HTTP/80 (Apache 2.4.52), Custom/8888

─── Stage: ENUMERATION ─────────────────────────
[enum] No SMB ports — skipping enum4linux
[enum] Hydra SSH against found usernames...
[enum] Credential found: john:password123

─── Stage: WEB ─────────────────────────────────
[web] nikto + gobuster + ffuf on http://10.10.11.100...
[web] Found: /admin (200), /api/v1/ (401), /.git/ (200)
[web] LLM: .git exposure → git-dumper for source code
[web] Finding: Git repo exposed — source code recoverable

─── Stage: EXPLOIT ──────────────────────────────
[exploit] LLM plan: Use credentials from enumeration + .git source analysis
[exploit] SSH john:password123 → shell
[exploit] Flag: user.txt → HTB{c4pt4r3d_th3_us3r_fl4g}

─── Stage: PRIVESC ──────────────────────────────
[privesc] sudo -l: john can run /usr/bin/python3 as root
[privesc] LLM: sudo python3 → os.system('/bin/bash') → root
[privesc] Flag: root.txt → HTB{r00t3d_w1th_suD0}

─── ATLAS Session Complete ──────────────────────
  Machine      Machine
  User flag    HTB{c4pt4r3d_th3_us3r_fl4g}
  Root flag    HTB{r00t3d_w1th_suD0}
  ATT&CK       6 techniques — Reconnaissance, Initial Access, Lateral Movement...
  Writeup      /home/tony/projects/ctf-lab/htb/machine/2026-09-01-machine.md

[reporter] Committed to ctf-lab
[reporter] Pushed to github
[reporter] Pushed to origin (Forgejo)
```

---

## Session Persistence

Every run saves full state to `~/.atlas/sessions/<ip>-<timestamp>.json`:
- All agent results and raw tool outputs
- Credentials, findings, flags
- LLM reasoning chains

Resume from any stage: `atlas.py 10.10.11.100 --resume --stage privesc`

List all sessions: `atlas.py --list-sessions`

---

## Key Technical Decisions

**Why real tools rather than pure LLM?** LLMs hallucinate. A tool either finds a port or it doesn't. ATLAS uses LLMs to *reason* about tool output and *plan* next steps — not to replace tools. The tools are ground truth; the LLM is the analyst.

**Why checkpoints by default?** In a lab, `--auto` is fine. In a real engagement, you need a human deciding what actions to take. The checkpoint architecture makes ATLAS safe for both contexts — autonomous in the lab, supervised in prod.

**Why stage-by-stage rather than one giant LLM call?** Context management. Each stage gets fresh context with only relevant prior findings, not 50k tokens of raw nmap output. This makes LLM reasoning sharper and keeps cost low.

**Why commit every writeup to git?** Discipline. The value of CTF practice is in the learning, not the flags. Every machine in git means a portfolio of documented techniques, searchable by CVE or technique.

---

## Potential Extensions

- **Metasploit RPC integration** — auto-select and run MSF modules for confirmed vulns
- **CVE API lookup** — cross-reference service versions with NVD for immediate severity context
- **Web app fuzzing** — ffuf parameter fuzzing after directory discovery
- **AD-specific chain** — BloodHound collection → path analysis → LLM attack path
- **Discord/Telegram alerts** — push flag captures and checkpoint requests to mobile
