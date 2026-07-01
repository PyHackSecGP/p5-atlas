# ATLAS — Autonomous Team for LLM-Assisted Security

Autonomous pentest pipeline for HTB/CTF machines. Runs recon → enumeration → web → exploit → report with LLM reasoning at each stage and human-in-the-loop checkpoints before every action.

## Architecture

```
atlas.py  →  ReconAgent → EnumerationAgent → WebAgent → ExploitAgent → ReporterAgent
                ↓               ↓                ↓
           nmap (parallel    all services     nikto + gobuster
           whatweb)          in parallel      in parallel
```

Each agent runs tools, passes output to claw-core for LLM analysis, and pauses at checkpoints for human approval before proceeding.

## Usage

```bash
# Basic — Ollama (local claw-core)
python atlas.py 10.10.11.100

# Claude API
python atlas.py 10.10.11.100 --provider claude --model claude-sonnet-4-6

# Resume from a specific stage
python atlas.py 10.10.11.100 --stage web

# Skip checkpoints (autonomous mode — use carefully)
python atlas.py 10.10.11.100 --auto
```

## Stages

| Stage | Tools | Parallel? |
|---|---|---|
| Recon | nmap (fast + deep), whatweb | whatweb across all ports |
| Enumeration | enum4linux-ng, smbclient, ftp, ldapsearch, snmpwalk | all services simultaneously |
| Web | nikto, gobuster, ffuf | nikto + gobuster per target |
| Exploit | LLM-guided, searchsploit, metasploit | — |
| Report | Full Markdown writeup | — |

## Stack

- Python 3.11+
- Ollama / Claude API (configurable)
- nmap, whatweb, gobuster, nikto, ffuf, enum4linux-ng, smbclient, ldapsearch, snmpwalk
- rich (terminal UI)
- concurrent.futures (parallel tool execution)

## Setup

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Ensure tools are installed (Kali has all of these by default)
which nmap gobuster nikto ffuf enum4linux-ng
```

## Output

Each run creates `output/<target-ip>/`:
- `*.txt` — raw tool output logs
- `report.md` — full pentest report
- `session.json` — machine state (credentials found, ports, findings)
