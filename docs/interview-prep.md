# ATLAS — Interview Prep

Reference for explaining P5-ATLAS in technical interviews.

---

## 30-Second Pitch

"I built an autonomous penetration testing pipeline for HackTheBox machines. It runs a six-stage attack chain — recon with nmap and NSE vuln scripts, enumeration with enum4linux and hydra, web testing with nikto and gobuster, exploit planning via searchsploit and LLM, SSH-based privilege escalation, and auto-generated writeups with MITRE ATT&CK mapping. It uses tiered LLMs — Haiku for cheap recon analysis, Sonnet for exploit and privesc reasoning — with prompt caching to cut API costs ~80%. Human checkpoints before every action unless you enable auto mode."

---

## Q: Why did you build this instead of using Metasploit / Pentera / NodeZero?

I didn't build it to replace those tools. I built it to understand the full offensive chain at the code level — what each stage is actually doing, where the failure modes are, and what the LLM is genuinely adding vs. just producing noise.

Specifically I needed to understand:
- What nmap NSE vuln scripts detect vs. what they miss — and their false positive rate
- How hydra brute-force should be structured — when to run it, which services, what wordlists
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

**2. Plan**
- PlannerAgent runs immediately after Recon
- Receives port/service list, OS guess, web target count
- Outputs `MachineAttackPlan`: stage_order, skip_stages, stage_tactics, primary_vector, difficulty
- Auto-skips "web" if no HTTP/HTTPS ports exist regardless of LLM output

**3. Enumeration**
- SMB: enum4linux-ng + smbclient share enumeration
- FTP: anonymous login attempt
- LDAP: ldapsearch for AD environments (full user list, descriptions, mail)
- SNMP: snmpwalk community string enumeration
- Hydra: brute-force SSH/FTP when usernames discovered
- netexec: credential spraying, SMB signing check
- LootAnalyzerAgent: regex pre-filter + LLM deep extraction on downloaded files

**4. Web**
- nikto: web vuln scanner (outdated software, misconfigs, default files)
- gobuster: directory brute-force
- ffuf: parameter fuzzing, vhost enumeration
- nuclei: template-based vuln detection
- All run in parallel per target

**5. Exploit**
- searchsploit: look up exploits by service/version string
- ReAct loop: up to 10 iterations of Reason → Act → Observe
- LLM interprets output after each command, decides next action
- Detects HTB flag pattern (`HTB{...}`, 32-char hex)

**6. PrivEsc**
- SSH into box with found credentials
- Enumerate in parallel: `id`, `sudo -l`, SUID binaries, capabilities, cron jobs, writable scripts
- LinPEAS served locally over HTTP on tun0 — no target internet dependency
- LLM: analyse findings, generate privesc plan, execute vectors
- Capture root flag → immediate jump to Report

**7. Report**
- LLM writes full HTB-style writeup
- `tools/mitre_mapper.py` keyword-matches session text → ATT&CK technique table
- Commits to ctf-lab repo, pushes to GitHub and Forgejo

---

## Q: How does the checkpoint system work?

Every action that runs against the target goes through a checkpoint:

```
╭──────────────────────────────── Exploit ─────────────────────────────────╮
│ FOUND:  nmap NSE detected ms17-010 on port 445                           │
│ PLAN:   python 42315.py 10.10.11.100                                     │
│ WHY:    confirmed vulnerable SMB version, no auth required               │
│ RISK:   high                                                             │
│ Approve? [y/n/skip/modify/abort]:                                        │
╰──────────────────────────────────────────────────────────────────────────╯
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

## Q: What is the ReAct loop?

ReAct (Reason → Act → Observe) replaces the single "generate exploit plan → execute" approach:

```python
for iteration in range(10):
    # REASON: LLM decides next action given full attempt history
    next_action = ask_json(prompt_with_history)  # action, command, reasoning, risk, timeout

    # ACT: checkpoint + run command
    result = run(next_action["command"], timeout=next_action["timeout"])

    # OBSERVE: check for shell/flag, add to history for next iteration
    attempt_history.append(f"[{iteration}] CMD: {cmd}\nOUT: {result[:300]}")

    # LLM interprets output to steer next iteration
    interpretation = ask(f"What did this output mean? What to try next?")
```

This means if the first exploit fails (wrong version, patched, misconfigured), the LLM sees the error output and adapts — tries a different exploit, adjusts parameters, or pivots to a different attack vector. A single-shot planner would have failed and stopped.

---

## Q: How does the LootAnalyzer work?

Files downloaded from SMB shares (or other sources) go into `session.loot`. LootAnalyzerAgent processes them in two passes:

**Pass 1 — Regex pre-filter:**
```python
_QUICK_PATTERNS = [
    (re.compile(r'password\s*[=:]\s*["\']?(\S+)', re.I), "password"),
    (re.compile(r'-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY', re.I), "ssh_key"),
    (re.compile(r'(?:mysql|postgresql)://([^:]+):([^@]+)@', re.I), "db_url"),
    ...
]
```

SSH private keys: immediately added as `Credential` without waiting for LLM.

**Pass 2 — LLM deep extraction:** Files with pattern hits (or interesting filenames: `config`, `backup`, `creds`, `.env`) sent to LLM. LLM extracts all credentials, hashes, connection strings, and attack vectors — context-aware, handles encoded values, split credentials, config file formats.

Files > 500KB are skipped. Max 8 files per LLM call to avoid prompt size limits.

---

## Q: How does the MITRE ATT&CK mapping work?

`tools/mitre_mapper.py` scans all session text — tool outputs, LLM summaries, findings, notes — for keywords. No structured data needed.

```python
(["sudo", "sudo -l"], AttackTechnique("T1548.003", "Sudo and Sudo Caching", ...))
(["suid", "setuid"],  AttackTechnique("T1548.001", "Setuid and Setgid", ...))
(["hydra", "brute"],  AttackTechnique("T1110.001", "Brute Force: Password Guessing", ...))
(["nmap"],            AttackTechnique("T1046", "Network Service Discovery", ...))
```

The mapper covers 28 techniques across 9 tactics: Reconnaissance, Initial Access, Credential Access, Lateral Movement, Discovery, Privilege Escalation, Execution, Persistence, Collection.

Techniques are deduplicated and sorted by tactic ID. Every writeup ends with a technique table. This is useful for defenders: the same table shows which detections should have fired and can be used to validate coverage.

---

## Q: How does session persistence work?

`HackSession` is a Python dataclass. `state.py` serialises it to JSON and deserialises it:

```python
state.save(session, "~/.atlas/sessions/10.10.11.100/session.json")
session = state.load("~/.atlas/sessions/10.10.11.100/session.json")
```

All nested objects serialise to dicts. `MachineAttackPlan` is a separate dataclass, serialised as a nested object. Enums (Stage, Severity) serialise by `.value`. On load, all types are reconstructed from the JSON dict.

Resume from any stage: `python atlas.py 10.10.11.100 --resume --stage privesc`

---

## Q: What is enum4linux? What does it find?

enum4linux is an SMB/RPC enumeration tool (wrapper around Samba utilities). It queries:
- Domain/workgroup name
- User list (via RPC)
- Share names and permissions
- Password policy (lockout threshold, complexity requirements)
- OS information

Useful when SMB is open — common on Windows targets and legacy Linux. The output gives usernames to target with hydra, shares to mount and browse, and domain info for AD attacks.

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

After getting a shell (SSH credentials from enumeration or exploit), the PrivEsc agent runs commands over SSH in parallel:

1. `id` — what user am I, what groups
2. `sudo -l` — what can this user run as root
3. `find / -perm -4000 2>/dev/null` — SUID binaries (run as owner, usually root)
4. `getcap -r / 2>/dev/null` — Linux capabilities (fine-grained privilege escalation)
5. `cat /etc/crontab` + writable script check — cron jobs running as root
6. `uname -r` — kernel version for kernel exploit candidates
7. Optional: LinPEAS cached locally, served over HTTP from tun0 IP, fetched and executed on target

LLM receives all output and reasons about which finding is the best privesc path. Top vectors executed with checkpoints; `_is_root()` checks output for `uid=0(root)`, `NT AUTHORITY\SYSTEM`, or `BUILTIN\Administrators`.

---

## Q: What bugs did you find and fix?

**1. Silent JSON failure** — `generate_json()` originally returned `{"raw": raw_text}` on parse failure and continued. Every downstream agent expecting a structured plan would silently receive garbage. Fixed with a 3-retry loop + `RuntimeError` on exhaustion.

**2. `_detect_shell()` false positive** — Pattern `r"[0-9a-f]{32}"` was used to detect shell access (flag-like output), but it also matched NTLM hashes, SSH fingerprints, and MD5 checksums, causing false shell detection. Removed from shell detection; kept only in `_extract_flag()`.

**3. Evil-winrm duplicate `-e` flag** — Command had `-e /tmp -e ''` (duplicate flag). evil-winrm would throw a parse error. Fixed to minimal invocation.

**4. `_is_root()` wrong patterns** — Shell prompt patterns (`r"# $"`, `r"#\s*$"`) never match in SSH batch command output because there's no interactive prompt. Removed; kept only `uid=0(root)`, `NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`.

**5. LinPEAS internet dependency** — Target fetching LinPEAS from GitHub fails on isolated HTB networks. Fixed to cache locally on first download and serve from attacker machine over HTTP on tun0.

**6. Linear pipeline** — `run_pipeline()` ignored the LLM's `next_stage` recommendation, always running all stages in fixed order. Fixed with PlannerAgent + `_derive_stage_order()`.

---

## Q: What would you improve or add?

- **Metasploit RPC integration** — currently uses searchsploit + manual exploit execution; MSF RPC would let ATLAS select and run modules programmatically with staged payloads
- **CVE API lookup** — cross-reference discovered service versions with NVD API for immediate severity and patch status
- **AD-specific chain** — BloodHound ingestor + path analysis + LLM attack path selection for Active Directory environments
- **Web app fuzzing depth** — ffuf parameter fuzzing after initial directory discovery (currently only vhost enumeration)
- **Credential spraying with lockout awareness** — netexec spraying should track lockout policy from enum4linux and pace attempts accordingly

---

## Q: What was the hardest part?

Two things:

**1. Parallel tool execution + LLM synthesis.** In the Web stage, nikto, gobuster, and ffuf run in parallel. Each produces different output formats. The LLM has to receive all three outputs and reason about them as a unified picture. Getting the prompt structure right so the LLM produced actionable plans (not generic recommendations) required significant iteration.

**2. False positive suppression.** The `_detect_shell()` function originally triggered on NTLM hashes because they're 32-character hex strings — the same pattern as many HTB flags. Also triggered on nmap port lines (which contain strings like `22/tcp open`). Required careful pattern design: only trigger on `uid=0(root)`, `/bin/bash` in passwd lines, `uname` output, and Windows version strings — never on bare hex patterns.

---

## Key Numbers to Know

| Metric | Value |
|---|---|
| Pipeline stages | 7 (Recon, Plan, Enum, Web, Exploit, PrivEsc, Report) |
| ReAct loop iterations | up to 10 |
| ATT&CK techniques mapped | 28 |
| ATT&CK tactics covered | 9 |
| LLM cost reduction via caching | ~80% |
| Test count | 184 |
| Loot file size limit | 500 KB |
| Max files per LLM loot call | 8 |
| Parallel SSH enum workers | min(10, task count) |

---

## What I Learned About LLMs in Offensive Security

**Where they help:**
- Filtering searchsploit results (20 candidates → 2 worth trying)
- Reasoning about what privesc finding to prioritise when you have 5 options
- Writing the post-engagement writeup in consistent, clear format
- Interpreting ambiguous tool output (exit codes, partial responses, encoding issues)

**Where they fail:**
- Generating exploit code that actually works — too many environment-specific variables
- Reasoning about timing-based attacks
- Understanding binary exploitation (ROP chains, heap grooming) — needs structured symbolic analysis, not text generation
- Knowing when a tool is timing out vs. genuinely hanging

The pattern: LLMs are good at *ranking and explaining* findings, bad at *generating working exploit code*. Use them as an analyst's assistant, not as an exploit developer.
