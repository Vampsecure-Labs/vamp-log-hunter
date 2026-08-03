<h1 align="center">vamp-log-hunter</h1>
<p align="center">
  <strong>Forensic log analyzer that detects Indicators of Compromise across 14 attack categories</strong><br>
  <em>VampSecure Labs · Security Research Division</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey?style=flat-square">
  <img src="https://img.shields.io/badge/license-research%20only-red?style=flat-square">
  <img src="https://img.shields.io/badge/VampSecure-Labs-8B0000?style=flat-square">
</p>

---

## Overview

`vamp-log-hunter` is a forensic log analysis tool for detecting Indicators of Compromise (IoC) in system logs. It processes nginx, Apache, `auth.log`, syslog, and journald logs line-by-line — without loading full files into memory — and correlates events across 14 attack categories ranging from SSH brute force and SQL injection to webshell access and anomalous nocturnal activity. Each finding carries remediation steps and structured evidence lines ready for inclusion in client security reports.

Built-in threat intelligence covers known scanner IP ranges (Shodan, Censys, GreyNoise, Tor exit nodes) and automatically tags findings whose source IPs match those ranges.

## Features

- **14 IoC categories**: SSH brute force, web brute force (4xx flood), directory scanning, SQL injection, XSS, path traversal / LFI, webshell access, sensitive file enumeration (`.env`, `.git`, `wp-config`, etc.), scanner User-Agent detection, `sudo`/`su` privilege escalation, suspicious cron jobs, direct root SSH login, known-scanner IP correlation, and anomalous nocturnal traffic (02:00–05:59)
- **Known-scanner intelligence**: built-in IP and CIDR database for Shodan, Censys, GreyNoise, SecurityTrails, Masscan, and Tor exit nodes — findings from those sources are automatically labelled
- **Multi-format log support**: nginx / Apache Combined Log Format, syslog, auth.log (gzip-compressed `.log.gz` handled transparently); stdin pipe via `--file -`
- **Configurable thresholds** for brute-force event counts (`--threshold-brute`) and directory scan path counts (`--threshold-scan`)
- **Time-window filtering** with `--last-hours` to focus on recent events without reprocessing full logs
- **Top offensive IPs table** summarizing total event counts per source with scanner tag
- **JSON export** — structured schema with full finding metadata: severity, category, source IPs, first/last seen timestamps, evidence lines, and remediation
- **Standalone dark-theme HTML report** — zero CDN dependencies; KPI summary bar + sortable findings table + detailed expandable cards
- **Unified VSL client report** (HTML/PDF) via `--report-html` / `--report-pdf` flags
- Rich console output with color-coded severity panels and a top-IPs summary table

## Requirements

```
pip install -r requirements.txt
```

| Package | Version |
|---------|---------|
| `rich`  | >= 13.7.0 |

Standard library: `argparse`, `gzip`, `ipaddress`, `json`, `re`, `sys`, `collections`, `datetime`, `pathlib`.

## Installation

```bash
git clone https://github.com/belky-me/vamp-log-hunter.git
cd vamp-log-hunter
pip install -r requirements.txt
```

## Usage

```bash
python vamp_log_hunter.py --help
```

```
usage: vamp_log_hunter.py [-h] [--file FILE] [--log-type {nginx,apache,auth,syslog,journald,auto}]
                           [--log-dir DIR] [--last-hours N] [--threshold-brute N]
                           [--threshold-scan N] [--json FILE] [--html FILE] [-v]
```

### Examples

**Scan all logs in `/var/log` (auto-discovery):**
```bash
python vamp_log_hunter.py
```

**Analyze specific log files:**
```bash
python vamp_log_hunter.py --file /var/log/nginx/access.log \
                           --file /var/log/auth.log
```

**Focus on the last 24 hours, lower brute-force threshold to 5 events:**
```bash
python vamp_log_hunter.py --last-hours 24 --threshold-brute 5
```

**Export JSON and standalone dark-theme HTML report:**
```bash
python vamp_log_hunter.py --json report.json --html report.html
```

**Read from stdin (pipe):**
```bash
cat /var/log/nginx/access.log | python vamp_log_hunter.py --file -
```

**Analyze a gzip-compressed rotated log:**
```bash
python vamp_log_hunter.py --file /var/log/nginx/access.log.1.gz
```

## IoC Category Reference

| ID | Category | Log Source |
|----|----------|-----------|
| LOG-001 | SSH brute force | auth.log / syslog |
| LOG-002 | Web brute force (4xx flood) | nginx / apache |
| LOG-003 | Directory enumeration (unique 404s) | nginx / apache |
| LOG-004 | SQL injection in URI | nginx / apache |
| LOG-005 | XSS payload in URI | nginx / apache |
| LOG-006 | Path traversal / LFI | nginx / apache |
| LOG-007 | Webshell access or RCE parameter | nginx / apache |
| LOG-008 | Sensitive file access | nginx / apache |
| LOG-009 | Scanner User-Agent | nginx / apache |
| LOG-010 | sudo / su privilege escalation | auth.log / syslog |
| LOG-011 | Suspicious cron job commands | syslog |
| LOG-012 | Direct root SSH login | auth.log |
| LOG-013 | Known-scanner IP | nginx / apache |
| LOG-014 | Anomalous nocturnal activity (02:00–05:59) | nginx / apache / auth |

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console (Rich) | _(default)_ | Severity-ordered panels with evidence, IPs, timestamps, and remediation |
| JSON | `--json FILE` | Full structured export with all finding fields |
| HTML | `--html FILE` | Standalone dark-theme report with KPI bar and finding cards |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No IoC found |
| `1` | One or more IoC findings detected |

## Part of VampSecure Labs Toolkit

This tool is part of the **VampSecure Labs Security Toolkit** — a collection of research-grade security tools for authorized penetration testing and red/blue team exercises.

- Full toolkit: [github.com/belky-me](https://github.com/belky-me)
- Orchestrator: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division  
For authorized security testing only.
