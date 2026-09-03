# ATLAS — Autonomous Team for LLM-Assisted Security

Autonomous penetration testing pipeline for HackTheBox/CTF machines. Runs a six-stage attack chain driven by Claude (Haiku + Sonnet) or local Ollama models, with human checkpoints before every destructive action.

```
Recon → Plan → Enumeration → Web → Exploit → PrivEsc → Report
```

## Features

- **Dynamic stage routing** — PlannerAgent builds a machine-specific attack plan after Recon; stages with no relevant targets are auto-skipped
- **ReAct exploit loop** — Reason → Act → Observe over up to 10 iterations; LLM interprets output and selects next action
- **Tiered LLM strategy** — Haiku for cheap recon/enum analysis, Sonnet for high-stakes exploit/privesc reasoning
- **Prompt caching** — system blocks cached via `cache_control: ephemeral`; reduces input token cost ~80% on a full run
- **Human checkpoints** — every tool execution is shown with intent, command, and risk level; `--auto` mode auto-approves at or below a configured risk threshold
- **Loot analysis** — files downloaded from shares are scanned with regex + LLM deep extraction for credentials, keys, and connection strings
- **LinPEAS local serving** — LinPEAS cached locally and served over HTTP on tun0; no target internet dependency
- **Parallel enumeration** — SSH post-exploitation commands and web tools run in parallel via `concurrent.futures`
- **Session persistence** — full `HackSession` state serialised to JSON; resume from any stage
- **MITRE ATT&CK mapping** — 28 techniques across 9 tactics, keyword-matched from session text; Markdown table in every report
- **Ollama fallback** — `--provider ollama --model hermes3:70b` for air-gapped / cost-free operation

## Architecture

```
atlas.py                    # Orchestrator — dynamic stage routing
├── agents/
│   ├── base.py             # BaseAgent — checkpoint, ask, ask_json, run_tool_adaptive
│   ├── planner.py          # PlannerAgent — MachineAttackPlan after Recon
│   ├── recon.py            # nmap fast+full, NSE vuln scripts, WhatWeb
│   ├── enumeration.py      # SMB, FTP, LDAP, SNMP, Hydra, netexec — parallel
│   ├── web.py              # nikto, gobuster, ffuf, nuclei — parallel per target
│   ├── exploit.py          # searchsploit + ReAct loop (10 iterations)
│   ├── loot_analyzer.py    # regex pre-filter + LLM extraction on downloaded files
│   ├── privesc.py          # SSH enum (parallel), LinPEAS (local HTTP), LLM vectors
│   └── reporter.py         # LLM writeup + MITRE ATT&CK table + git push
├── tools/
│   ├── runner.py           # run(), run_parallel() — subprocess wrappers
│   └── mitre_mapper.py     # keyword → ATT&CK technique mapping
├── models.py               # HackSession, Port, Finding, Credential, MachineAttackPlan
├── state.py                # JSON serialisation / deserialisation
├── llm.py                  # ClaudeProvider (cached), OllamaProvider, get_provider()
└── checkpoint.py           # Human-in-the-loop gate, auto mode, risk levels
```

## Requirements

```
Python 3.11+
anthropic>=0.40.0
requests>=2.31.0
rich>=13.7.0
```

External tools (must be on PATH for full functionality):
`nmap`, `whatweb`, `enum4linux-ng`, `smbclient`, `hydra`, `netexec`, `nikto`, `gobuster`, `ffuf`, `nuclei`, `searchsploit`, `sshpass`, `evil-winrm`

## Setup

```bash
git clone <repo>
cd p5-atlas
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...   # or use --provider ollama
```

## Usage

```bash
# Full run from recon
python atlas.py 10.10.11.100

# Resume from a specific stage
python atlas.py 10.10.11.100 --resume --stage exploit

# Auto mode (no prompts for low/medium risk actions)
python atlas.py 10.10.11.100 --auto --auto-risk medium

# Local Ollama (no API key needed)
python atlas.py 10.10.11.100 --provider ollama --model hermes3:70b

# List saved sessions
python atlas.py --list-sessions
```

## LLM Strategy

| Stage | Model | Rationale |
|---|---|---|
| Recon, Enumeration | Haiku | Pattern recognition on tool output — no deep reasoning needed |
| Plan, Web | Haiku | Routing and web analysis — fast iteration matters |
| Exploit, PrivEsc | Sonnet | High-stakes decisions — wrong plan wastes time or causes damage |
| Report | Sonnet | Quality matters for the portfolio writeup |

## Checkpoint System

Before every tool execution against the target:

```
╭──────────────────────────────── Exploit ─────────────────────────────────╮
│ FOUND:  nmap NSE detected ms17-010 on port 445                           │
│ PLAN:   python 42315.py 10.10.11.100                                     │
│ WHY:    confirmed vulnerable SMB version, no auth required               │
│ RISK:   high                                                             │
│ Approve? [y/n/skip/modify/abort]:                                        │
╰──────────────────────────────────────────────────────────────────────────╯
```

`--auto --auto-risk medium` auto-approves all `low` and `medium` risk actions; `high` and `critical` always prompt.

## Tests

```bash
python -m pytest tests/ -q
```

184 tests covering models, state serialisation, LLM retry logic, checkpoint auto mode, MITRE mapper, and all agent helpers.

## MITRE ATT&CK Coverage

28 techniques across 9 tactics extracted from session text via keyword matching. Included in every generated report.

| Tactic | Example Techniques |
|---|---|
| Reconnaissance | T1046 Network Service Discovery |
| Credential Access | T1110.001 Brute Force, T1003 Credential Dumping |
| Lateral Movement | T1021.002 SMB/Windows Admin Shares, T1021.004 SSH |
| Privilege Escalation | T1548.001 Setuid, T1548.003 Sudo |
| Execution | T1059.004 Unix Shell, T1059.001 PowerShell |
| Collection | T1005 Data from Local System |

## Session State

All sessions persist to `~/.atlas/sessions/<ip>-<timestamp>/session.json`. Fields include ports, credentials, findings, loot paths, flags, agent results, and the attack plan. Resume from any stage:

```bash
python atlas.py 10.10.11.100 --resume --stage privesc
```

## Related Projects

- [P4 Mini-CRS](https://github.com/PyHackSecGP/p4-mini-crs) — AI pentest report assistant
- [P2 Threat Model Generator](https://github.com/PyHackSecGP/p2-threat-model-generator) — LLM-powered threat modelling
