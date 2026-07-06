# ATLAS — Autonomous Team for LLM-Assisted Security

Autonomous pentest pipeline for HTB/CTF machines. Runs **Recon → Enumeration → Web → Exploit → PrivEsc → Report** with LLM reasoning at each stage and human-in-the-loop checkpoints before every action.

## Architecture

```
atlas.py  →  Recon → Enumeration → Web → Exploit → PrivEsc → Report
              ↓         ↓            ↓       ↓         ↓
           nmap+NSE  enum4linux+   nikto+   search-  SUID/sudo/
           vuln     hydra brute   gobuster  sploit   cron/caps
           parallel  parallel     parallel  +LLM    (SSH exec)
```

Each agent runs tools in parallel where possible, pipes output to the LLM for analysis, and pauses at checkpoints for human approval — unless `--auto` is set.

## Features

- **Six-stage pipeline** — Recon, Enumeration, Web, Exploit, **PrivEsc**, Report
- **Tiered LLM** — Haiku for cheap recon/enum, Sonnet for exploit/privesc planning
- **Prompt caching** — system prompts cached across agents (~90% cost reduction)
- **Retry + backoff** — resilient to API rate limits and 5xx errors
- **NSE vuln scripts** — free CVE detection (EternalBlue, Shellshock, Heartbleed, ms08-067)
- **Hydra brute-force** — auto-runs against SSH/FTP when usernames are enumerated
- **SSH-based PrivEsc** — post-shell enum + exploitation via sshpass, optional LinPEAS
- **Parallel tool execution** — nikto+gobuster, per-service enum
- **Session save/resume** — full state persistence including agent results
- **`--auto` mode** — autonomous below configurable risk threshold
- **`--list-sessions`** — portfolio view of every machine attacked

## Usage

```bash
# Interactive (default) — pause at every checkpoint
atlas.py 10.10.11.100

# Autonomous mode — auto-approve low+medium risk, prompt for high
atlas.py 10.10.11.100 --auto
atlas.py 10.10.11.100 --auto --auto-risk high

# Local claw-core LLM instead of Claude API
atlas.py 10.10.11.100 --provider ollama --model hermes3:70b

# Resume from a specific stage
atlas.py 10.10.11.100 --resume --stage privesc

# See every past run
atlas.py --list-sessions
```

## Stages

| Stage | Tools | Notes |
|---|---|---|
| Recon | nmap (fast+deep), nmap NSE vuln, whatweb | vuln scripts find low-hanging CVEs |
| Enumeration | enum4linux-ng, smbclient, ftp, ldapsearch, snmpwalk, **hydra** | hydra fires when usernames enumerated |
| Web | nikto, gobuster, ffuf | parallel per target |
| Exploit | searchsploit + LLM plan → execute | HTB flag auto-detect (`HTB{...}`, 32-hex) |
| **PrivEsc** | SSH: `id`, sudo, SUID, caps, cron, kernel, LinPEAS | root flag auto-capture |
| Report | LLM writeup → markdown | commits to ctf-lab if present |

## Stack

- Python 3.11+
- Anthropic Claude API (prompt caching enabled) / Ollama at claw-core
- `nmap`, `whatweb`, `gobuster`, `nikto`, `ffuf`, `enum4linux-ng`, `smbclient`, `ldapsearch`, `snmpwalk`, `hydra`, `sshpass`, `searchsploit`
- `rich` (terminal UI)

## Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Kali has these by default; on other distros install:
sudo apt install nmap gobuster nikto ffuf enum4linux-ng smbclient \
                 ldap-utils snmp hydra sshpass exploitdb

export ANTHROPIC_API_KEY="sk-ant-..."
```

## Output

Each run creates `~/atlas-sessions/<ip>/`:

- `*.txt` — raw tool output logs
- `session.json` — full machine state (ports, creds, findings, agent results)
- `writeup/<date>-<machine>.md` — HTB writeup (or committed to ctf-lab)
- `atlas_privesc.sh` — enum script if no SSH creds available (fallback path)

## Auto mode risk levels

`--auto-risk` controls how much autonomy ATLAS gets. Everything above the threshold still pauses for approval.

| Level | Behaviour |
|---|---|
| `low` | Approves scans only (nmap, whatweb, enum). Every exploit still prompts. |
| `medium` (default) | Approves scans + gobuster/nikto/hydra. Exploits and privesc still prompt. |
| `high` | Approves exploits too. Only critical-risk actions prompt. |
| `critical` | Full autopilot. Use responsibly. |

## Checkpoints

Every action shows:

- **FOUND** — what the agent discovered
- **PLAN** — what it will do next
- **WHY** — reasoning for the plan
- **LOOK FOR** — what output would indicate success
- **COMMAND** — exact command it will run

You choose: `a`=approve, `s`=skip, `m`=modify command, `q`=quit.

## HTB workflow

```bash
# Spawn machine on HTB, get IP
atlas.py 10.10.11.X --auto --auto-risk medium

# ATLAS runs recon → NSE finds EternalBlue → exploit stage
# → shell → PrivEsc runs SUID enum → GTFOBins hit → root
# → writeup saved to ctf-lab → committed
```
