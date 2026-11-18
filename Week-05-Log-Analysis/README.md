# Week 5: Log Extraction & Auth Failure Aggregation

## 1. Objective
Engineer a standalone Python log parser using standard libraries (`re`, `csv`, `json`, `collections`) to ingest genuine Linux authentication telemetry (`/var/log/auth.log`) from the Metasploitable2 target, extract threat indicators via Regular Expressions, aggregate failed login anomalies, and export structured reports for SOC triage.

## 2. RegEx Pattern Design
The parser uses named capture groups to extract timestamps, targeted usernames (matching both `Failed password` and `Invalid user` SSH events), and source IPv4 addresses:

```regex
^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(?:Failed password for (?:invalid user\s+)?|Invalid user\s+)(?P<username>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})

```

## 3. Execution & Results

```bash
python log_analyzer.py

```

* **Total Failed Events Parsed:** 7
* **Top Attacking IP:** `192.168.245.1` (7 attempts)
* **Targeted Usernames:** `admin` (3), `test` (1), `oracle` (1), `guest` (1), `ubuntu` (1)

## 4. Deliverables & Outputs

* `log_analyzer.py` — Core Python log parser and frequency aggregator.
* `auth.log` — Genuine `/var/log/auth.log` telemetry extracted from Metasploitable2.
* `top_attacking_ips.csv` — Ranked source IPs by failed login volume.
* `targeted_usernames.csv` — Frequency breakdown of targeted user accounts.
* `threat_report.json` — Combined structured JSON output for SIEM/SOC ingestion.
