"""Map ATLAS findings and stages to MITRE ATT&CK techniques."""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class AttackTechnique:
    id: str
    name: str
    tactic: str
    tactic_id: str
    url: str


_TECHNIQUE_DB: list[tuple[list[str], AttackTechnique]] = [
    # Reconnaissance
    (["nmap", "scan", "port scan", "recon"], AttackTechnique(
        "T1046", "Network Service Discovery", "Reconnaissance", "TA0043",
        "https://attack.mitre.org/techniques/T1046/")),
    (["dns", "subdomain", "nslookup", "dig"], AttackTechnique(
        "T1590.002", "DNS", "Reconnaissance", "TA0043",
        "https://attack.mitre.org/techniques/T1590/002/")),
    (["whatweb", "banner grab", "version detect"], AttackTechnique(
        "T1592", "Gather Victim Host Information", "Reconnaissance", "TA0043",
        "https://attack.mitre.org/techniques/T1592/")),

    # Initial Access / Web
    (["gobuster", "dirb", "ffuf", "directory", "path traversal", "lfi"], AttackTechnique(
        "T1083", "File and Directory Discovery", "Discovery", "TA0007",
        "https://attack.mitre.org/techniques/T1083/")),
    (["nikto", "web vuln", "sql injection", "sqli", "xss", "rce", "exploit public"], AttackTechnique(
        "T1190", "Exploit Public-Facing Application", "Initial Access", "TA0001",
        "https://attack.mitre.org/techniques/T1190/")),
    (["upload", "file upload", "webshell", "shell upload"], AttackTechnique(
        "T1505.003", "Server Software Component: Web Shell", "Persistence", "TA0003",
        "https://attack.mitre.org/techniques/T1505/003/")),

    # Credential Access / Brute Force
    (["brute", "hydra", "spray", "password guess", "credential stuff"], AttackTechnique(
        "T1110.001", "Brute Force: Password Guessing", "Credential Access", "TA0006",
        "https://attack.mitre.org/techniques/T1110/001/")),
    (["hash", "ntlm", "lm hash", "dump hash", "hashdump"], AttackTechnique(
        "T1003", "OS Credential Dumping", "Credential Access", "TA0006",
        "https://attack.mitre.org/techniques/T1003/")),
    (["default password", "default cred", "admin:admin", "root:root"], AttackTechnique(
        "T1078.001", "Valid Accounts: Default Accounts", "Initial Access", "TA0001",
        "https://attack.mitre.org/techniques/T1078/001/")),

    # Lateral Movement
    (["ssh", "sshpass"], AttackTechnique(
        "T1021.004", "Remote Services: SSH", "Lateral Movement", "TA0008",
        "https://attack.mitre.org/techniques/T1021/004/")),
    (["smb", "psexec", "wmiexec", "netexec"], AttackTechnique(
        "T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement", "TA0008",
        "https://attack.mitre.org/techniques/T1021/002/")),
    (["winrm", "evil-winrm", "5985", "5986"], AttackTechnique(
        "T1021.006", "Remote Services: Windows Remote Management", "Lateral Movement", "TA0008",
        "https://attack.mitre.org/techniques/T1021/006/")),

    # Privilege Escalation
    (["suid", "setuid", "suid binary"], AttackTechnique(
        "T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid", "Privilege Escalation", "TA0004",
        "https://attack.mitre.org/techniques/T1548/001/")),
    (["sudo", "sudo -l", "sudoers"], AttackTechnique(
        "T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation", "TA0004",
        "https://attack.mitre.org/techniques/T1548/003/")),
    (["cron", "crontab", "cronjob", "scheduled task"], AttackTechnique(
        "T1053.003", "Scheduled Task/Job: Cron", "Privilege Escalation", "TA0004",
        "https://attack.mitre.org/techniques/T1053/003/")),
    (["capabilities", "cap_net_admin", "cap_sys_admin", "getcap"], AttackTechnique(
        "T1548", "Abuse Elevation Control Mechanism: Linux Capabilities", "Privilege Escalation", "TA0004",
        "https://attack.mitre.org/techniques/T1548/")),
    (["kernel exploit", "dirty cow", "dirtycow", "polkit", "pkexec"], AttackTechnique(
        "T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", "TA0004",
        "https://attack.mitre.org/techniques/T1068/")),
    (["path hijack", "write path", "path injection"], AttackTechnique(
        "T1574.007", "Hijack Execution Flow: Path Interception by PATH Environment Variable",
        "Privilege Escalation", "TA0004",
        "https://attack.mitre.org/techniques/T1574/007/")),
    (["linpeas", "linenum", "post exploit", "privesc", "priv esc"], AttackTechnique(
        "T1087", "Account Discovery", "Discovery", "TA0007",
        "https://attack.mitre.org/techniques/T1087/")),

    # Execution
    (["reverse shell", "revshell", "nc -e", "bash -i", "mkfifo"], AttackTechnique(
        "T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution", "TA0002",
        "https://attack.mitre.org/techniques/T1059/004/")),
    (["powershell", "cmd.exe", "wscript"], AttackTechnique(
        "T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution", "TA0002",
        "https://attack.mitre.org/techniques/T1059/001/")),
    (["searchsploit", "metasploit", "exploit", "cve-"], AttackTechnique(
        "T1203", "Exploitation for Client Execution", "Execution", "TA0002",
        "https://attack.mitre.org/techniques/T1203/")),

    # Exfiltration / Collection
    (["flag", "user.txt", "root.txt", "proof.txt"], AttackTechnique(
        "T1005", "Data from Local System", "Collection", "TA0009",
        "https://attack.mitre.org/techniques/T1005/")),
    (["enum4linux", "ldap", "domain enum", "ad enum", "bloodhound"], AttackTechnique(
        "T1018", "Remote System Discovery", "Discovery", "TA0007",
        "https://attack.mitre.org/techniques/T1018/")),
    (["snmp", "snmpwalk"], AttackTechnique(
        "T1602", "Data from Configuration Repository", "Collection", "TA0009",
        "https://attack.mitre.org/techniques/T1602/")),
]


def map_findings_to_attack(
    findings: list,
    agent_results: list,
    notes: list[str],
) -> list[AttackTechnique]:
    """Return deduplicated ATT&CK techniques observed during the session."""
    all_text = " ".join([
        *[f.title.lower() + " " + f.description.lower() for f in findings],
        *[ar.summary.lower() for ar in agent_results],
        *[n.lower() for n in notes],
    ])

    seen_ids: set[str] = set()
    techniques: list[AttackTechnique] = []

    for keywords, technique in _TECHNIQUE_DB:
        if technique.id in seen_ids:
            continue
        if any(kw in all_text for kw in keywords):
            techniques.append(technique)
            seen_ids.add(technique.id)

    # Sort by tactic_id
    return sorted(techniques, key=lambda t: t.tactic_id)


def format_attack_table_markdown(techniques: list[AttackTechnique]) -> str:
    """Render a MITRE ATT&CK technique table in Markdown."""
    if not techniques:
        return ""

    lines = [
        "## MITRE ATT&CK Techniques Observed",
        "",
        "| Technique | Name | Tactic |",
        "|-----------|------|--------|",
    ]
    for t in techniques:
        lines.append(f"| [{t.id}]({t.url}) | {t.name} | {t.tactic} ({t.tactic_id}) |")

    return "\n".join(lines)
