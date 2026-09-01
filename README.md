# ATLAS — Autonomous Pentest Pipeline: Interview Prep Notes

---

## 30-Second Pitch (memorise this)

"I built an autonomous penetration testing pipeline for HackTheBox machines. It runs a six-stage attack chain — recon with nmap and NSE vuln scripts, enumeration with enum4linux and hydra, web testing with nikto and gobuster, exploit planning via searchsploit and LLM, SSH-based privilege escalation, and auto-generated writeups with MITRE ATT&CK mapping. It uses tiered LLMs — Haiku for cheap recon analysis, Sonnet for exploit and privesc reasoning — with prompt caching to cut API costs ~80%. Human checkpoints before every action unless you enable auto mode."

---

## Q: Why did you build this instead of using Metasploit / Pentera / NodeZero?

I didn't build it to replace those tools. I built it to understand the full offensive chain at the code level — what each stage is actually doing, where the failure modes are, and what the LLM is genuinely adding vs. just producing noise.

Specifically I needed to understand:
- What nmap NSE vuln scripts detect vs. what they miss — and their false positive rate
- How hydra brute-force should be structured — when to run it, which services, what word lists
- How searchsploit maps service versions to exploits — and why LLM filtering of those results is actually useful
- What SSH post-exploitation enumeration looks like from a defender's perspective — what artifacts it leaves
- Where in the pipeline LLMs help vs. where they hallucinate and break things

Now when I look at output from Pentera or Metasploit, I understand what each stage did and why.

---

## Q: Walk me through the pipeline stages.

**1. Recon**
- nmap fast scan (top 1000 ports) + full scan (all 65535)
- nmap NSE vuln scripts: detect EternalBlue (ms17-010), Shellshock, Heartbleed, ms08-067
- WhatWeb for web tech fingerprinting
- LLM analyses all output → identifies high-value targets

**2. Enumeration**
- SMB: enum4linux-ng + smbclient share enumeration
- FTP: anonymous login attempt
- LDAP: ldapsearch for AD environments
- SNMP: snmpwalk community string enumeration
- Hydra: brute-force SSH/FTP when usernames discovered
- netexec: credential spraying, SMB signing check

**3. Web**
- nikto: web vuln scanner (outdated software, misconfigs, default files)
- gobuster: directory brute-force
- ffuf: parameter fuzzing, vhost enumeration
- nuclei: template-based vuln detection
- All run in parallel per target

**4. Exploit**
- searchsploit: look up exploits by service/version string
- LLM: filter candidates, generate execution plan
- Execute plan → detect HTB flag pattern (`HTB{...}`, 32-char hex)

**5. PrivEsc**
- SSH into box with found credentials
- Enumerate: `id`, `sudo -l`, SUID binaries, Linux capabilities, cron jobs, writable scripts
- Optional LinPEAS upload and parse
- LLM: analyse findings, generate privesc plan, execute
- Capture root flag

**6. Report**
- LLM writes full HTB-style writeup
- `tools/mitre_mapper.py` keyword-matches session text → ATT&CK technique table
- Commits to ctf-lab repo, pushes to GitHub and Forgejo

---

## Q: How does the checkpoint system work?

Every action that runs against the target goes through a checkpoint:

```
FOUND: nmap NSE detected ms17-010 on port 445
PLAN: run EternalBlue exploit (searchsploit 42315)
WHY: confirmed vulnerable version, SMB accessible, no auth required
RISK: high
Approve? (y/n/skip/modify)
```

In `--auto` mode, actions at or below the configured risk threshold are auto-approved. Default: low and medium auto-approve, high always prompts.

Why checkpoints matter: LLMs make mistakes. An autonomous tool that executes a high-risk action on wrong reasoning can cause an incident — hitting an out-of-scope IP, running a destructive exploit, locking out an account. The checkpoint forces a human to verify the reasoning before execution. In a lab, `--auto` is fine. In a real engagement, every action is reviewed.

---

## Q: Explain the tiered LLM strategy.

| Stage | Model | Why |
|---|---|---|
| Recon / Enumeration | Claude Haiku | Fast, cheap; reading nmap output is pattern matching, not reasoning |
| Exploit / PrivEsc | Claude Sonnet | Higher stakes — wrong plan wastes time or causes damage |
| Report | Claude Sonnet | Quality matters for the portfolio writeup |

**Prompt caching**: system prompts (tool descriptions, stage instructions, output schemas) are cached across agents. Same content sent once, re-used for all agents in the run. Cuts ~80-90% of input token cost on a full 6-stage run.

**Ollama fallback**: `--provider ollama --model hermes3:70b` routes everything to local GPU server. Free, air-gapped, no API key.

---

## Q: How does the MITRE ATT&CK mapping work?

`tools/mitre_mapper.py` scans all session text — tool outputs, LLM summaries, findings, notes — for keywords. No structured data needed.

Example:
```python
(["sudo", "sudo -l"], AttackTechnique("T1548.003", "Sudo and Sudo Caching", ...))
(["suid", "setuid"],  AttackTechnique("T1548.001", "Setuid and Setgid", ...))
(["hydra", "brute"],  AttackTechnique("T1110.001", "Brute Force: Password Guessing", ...))
```

The mapper covers 28 techniques across 9 tactics: Reconnaissance, Initial Access, Credential Access, Lateral Movement, Discovery, Privilege Escalation, Execution, Persistence, Collection.

Every writeup ends with a technique table. This is useful for defenders: the same table shows which detections should have fired and can be used to validate coverage.

---

## Q: What is enum4linux? What does it find?

enum4linux is an SMB/RPC enumeration tool (wrapper around Samba utilities). It queries:
- Domain/workgroup name
- User list (via RPC)
- Share names and permissions
- Password policy (lockout threshold, complexity requirements)
- OS information

Useful when SMB is open — which is common on Windows targets and legacy Linux. The output tells you usernames to target with hydra, shares to mount and browse, and domain info for AD attacks.

---

## Q: What's the difference between gobuster and ffuf?

**gobuster**: directory/file brute-force. Give it a wordlist, it tries every word as a URL path. Fast, simple, reliable. Good for initial discovery.

**ffuf**: more flexible fuzzer. Can fuzz any part of a request — URL paths, headers, parameters, POST body. Used for:
- Vhost enumeration: `ffuf -H "Host: FUZZ.target.htb"` — finds subdomains
- Parameter fuzzing: `ffuf -u http://target/page?FUZZ=value` — finds hidden params
- POST body fuzzing: form input fuzzing

Both use wordlists. ffuf is more powerful but requires more configuration.

---

## Q: How does SSH-based privilege escalation work in ATLAS?

After getting a shell (SSH credentials from enumeration or exploit), the PrivEsc agent runs commands over SSH:

1. `id` — what user am I, what groups
2. `sudo -l` — what can this user run as root
3. `find / -perm -4000 2>/dev/null` — SUID binaries (run as owner, usually root)
4. `getcap -r / 2>/dev/null` — Linux capabilities (fine-grained privilege escalation)
5. `cat /etc/crontab` + writable script check — cron jobs running as root
6. `uname -r` — kernel version for kernel exploit candidates
7. Optional: upload and run LinPEAS, parse its output

LLM receives all this output and reasons about which finding is the best privesc path.

---

## Key technical facts to have ready

- **Stage count**: 6 — Recon, Enumeration, Web, Exploit, PrivEsc, Report
- **LLM models**: Haiku (recon/enum), Sonnet (exploit/privesc/report), Ollama (local fallback)
- **Cost reduction**: prompt caching ~80-90% input token savings
- **Checkpoint risk levels**: low / medium / high / critical
- **Tools**: nmap, whatweb, enum4linux-ng, smbclient, hydra, netexec, nikto, gobuster, ffuf, nuclei, searchsploit, sshpass, LinPEAS
- **Session persistence**: `~/.atlas/sessions/<ip>-<timestamp>.json` — resume from any stage
- **ATT&CK coverage**: 28 techniques, 9 tactics
- **Commercial equivalents**: Pentera, NodeZero, Horizon3.ai, Metasploit Pro

---

## Q: What would you improve or add?

- **Metasploit RPC integration** — currently uses searchsploit + manual exploit execution; MSF RPC would let ATLAS select and run modules programmatically with staged payloads
- **CVE API lookup** — cross-reference discovered service versions with NVD API for immediate severity and patch status
- **AD-specific chain** — BloodHound ingestor + path analysis + LLM attack path selection for Active Directory environments
- **Web app fuzzing** — ffuf parameter fuzzing depth after initial directory discovery (currently only vhost enumeration via ffuf)

---

## What I'd say if asked "what was the hardest part?"

Getting the parallel tool execution and LLM reasoning to work together reliably. In the Web stage, nikto, gobuster, and ffuf run in parallel. Each produces different output formats. The LLM has to receive all three outputs and reason about them as a unified picture — not treat each tool's output in isolation. Getting the prompt structure right so the LLM produced useful, actionable plans rather than generic recommendations required a lot of iteration. Also the vhost ffuf issue: initially used a hardcoded filter size of 0, which produced massive false-positive results. Fixed by probing a random subdomain first to get the baseline response size, then filtering against that.

---

## What I learned about LLMs in offensive security

**Where they help:**
- Filtering searchsploit results (20 candidates → 2 worth trying)
- Reasoning about what privesc finding to prioritise when you have 5 options
- Writing the post-engagement writeup in consistent, clear format

**Where they fail:**
- Generating exploit code that actually works — too many environment-specific variables
- Reasoning about timing-based attacks
- Understanding binary exploitation (ROP chains, heap grooming) — needs structured symbolic analysis, not text generation

The pattern: LLMs are good at *ranking and explaining* findings, bad at *generating working exploit code*. Use them as an analyst's assistant, not as an exploit developer.
