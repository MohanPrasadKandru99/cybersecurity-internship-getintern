# Automated Incident Alerting & Brute-Force Detection Report

**Generated:** 2026-11-24 00:16:45 UTC  
**Engine Version:** 1.0.0  
**Detection Window:** 60s sliding window  
**Velocity Threshold:** 10 failed attempts  

---

## 1. Executive Summary

During telemetry ingestion, the detection engine processed **112 total log lines**, identifying **22 failed authentication events**. Correlating these events across sliding 60-second time windows revealed **1 confirmed brute-force incident(s)** requiring immediate SOC containment.

| Severity | Incident Count | Containment Action Required |
| :--- | :---: | :--- |
| 🔴 **CRITICAL** | 0 | Immediate firewall isolation + Privileged account credential rotation |
| 🟠 **HIGH** | 1 | Perimeter IP blacklist + SOC horizontal spray audit |
| 🟡 **MEDIUM** | 0 | Standard firewall blocklist addition + 24hr monitoring |

## 2. Active Incidents Overview

| Alert ID | Attacking IP | Severity | Attack Type | Window Peak | Total Fails | Target Accounts |
| :--- | :--- | :---: | :--- | :---: | :---: | :--- |
| `SEC-ALERT-20261024-001` | `192.168.245.1` | **HIGH** | Horizontal Password Spraying | 15 | 15 | `admin1` (1), `admin2` (1), `admin3` (1) *(+12 more)* |

## 3. Incident Drilldown & Forensics

### Incident `SEC-ALERT-20261024-001` — 192.168.245.1
- **Severity:** `HIGH`
- **Classification:** Horizontal Password Spraying
- **Attack Start Time:** `2026-10-24 04:15:43`
- **Threshold Breach Time:** `2026-10-24 04:15:44`
- **Attack End Time:** `2026-10-24 04:15:45`
- **Attack Duration:** 2.0 seconds
- **Peak Sliding Window Rate:** 15 attempts / 60s
- **Total Attempts in Campaign:** 15
- **Targeted User Accounts:**
  - `admin1`: 1 attempt(s)
  - `admin2`: 1 attempt(s)
  - `admin3`: 1 attempt(s)
  - `admin4`: 1 attempt(s)
  - `admin5`: 1 attempt(s)
  - `admin6`: 1 attempt(s)
  - `admin7`: 1 attempt(s)
  - `admin8`: 1 attempt(s)
  - `admin9`: 1 attempt(s)
  - `admin10`: 1 attempt(s)
  - `admin11`: 1 attempt(s)
  - `admin12`: 1 attempt(s)
  - `admin13`: 1 attempt(s)
  - `admin14`: 1 attempt(s)
  - `admin15`: 1 attempt(s)
- **Sample Log Evidence:**
```syslog
Oct 24 04:15:43 metasploitable sshd[6146]: Invalid user admin1 from 192.168.245.1
Oct 24 04:15:43 metasploitable sshd[6148]: Invalid user admin2 from 192.168.245.1
Oct 24 04:15:43 metasploitable sshd[6150]: Invalid user admin3 from 192.168.245.1
Oct 24 04:15:43 metasploitable sshd[6152]: Invalid user admin4 from 192.168.245.1
```
- **Recommended Mitigation Commands:**
```bash
# UFW Rule:
ufw insert 1 deny from 192.168.245.1 to any port 22 proto tcp comment 'SEC-ALERT-20261024-001-Containment'
# iptables Rule:
iptables -I INPUT 1 -s 192.168.245.1 -p tcp --dport 22 -j DROP -m comment --comment 'SEC-ALERT-20261024-001-Containment'
```

## 4. MITRE ATT&CK® Mapping

| Technique ID | Technique Name | Tactic | Observed Behavior |
| :--- | :--- | :--- | :--- |
| **T1110.001** | Password Guessing | Credential Access | Rapid authentication attempts against single specific usernames (`root`, `sysadmin`). |
| **T1110.003** | Password Spraying | Credential Access | Multi-account iteration testing common credentials across varied user accounts. |
| **T1078** | Valid Accounts | Initial Access / Persistence | Attempts to compromise legitimate system credentials. |

## 5. SOC Analyst Remediation Workflow

1. **Containment:** Execute the auto-generated `firewall_blocklist.sh` script on boundary/host firewalls.
2. **Verification:** Inspect active firewall rules using `ufw status numbered` or `iptables -L INPUT -v -n`.
3. **Identity Verification:** Confirm no successful logins occurred from the attacking IPs (`grep 'Accepted' /var/log/auth.log`).
4. **Credential Rotation:** If any targeted account is an active enterprise user, flag for mandatory password reset.

