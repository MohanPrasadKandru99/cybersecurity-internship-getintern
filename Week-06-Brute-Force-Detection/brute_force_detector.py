#!/usr/bin/env python3
"""
Automated Incident Alerting & Brute-Force Detection Engine
==========================================================
Week 6 Milestone Project - Cybersecurity Internship Track

Core Functionality:
- Sliding Time-Window Correlation: Group failed authentication events per source IP
  using rolling deque-based sliding windows.
- Configurable Threshold Engine: Dynamic threshold parameters for attempt volume,
  time windows, privileged account targeting, and behavioral risk scoring.
- Structured Alert Output: Generates machine-readable `security_alert.json` and
  executive markdown `incident_summary.md`.
- Automated Mitigation List: Exports ready-to-apply UFW and iptables containment rules.
"""

import re
import json
import argparse
from datetime import datetime, timedelta
from collections import deque, defaultdict, Counter
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set


# =====================================================================
# CONFIGURABLE THRESHOLD ENGINE & DEFAULTS
# =====================================================================
DEFAULT_CONFIG = {
    "engine_name": "Automated Incident Alerting & Brute-Force Detection Engine",
    "version": "1.0.0",
    "log_file": "auth.log",
    "threshold": 10,
    "window_seconds": 60,
    "cooldown_seconds": 120,
    "privileged_usernames": [
        "root",
        "admin",
        "administrator",
        "wheel",
        "toor",
        "superuser",
        "oracle",
        "postgres",
        "mysql",
        "master",
        "sysadmin"
    ],
    "severity_scoring": {
        "critical_attempt_threshold": 30,
        "high_attempt_threshold": 20,
        "spraying_unique_user_threshold": 3,
        "privileged_account_escalation": True
    },
    "mitigation": {
        "ufw_action": "deny",
        "iptables_target": "DROP",
        "target_port": 22,
        "protocol": "tcp",
        "rule_comment": "SOC-ALERT-BruteForce-Containment"
    },
    "output_files": {
        "alert_json": "security_alert.json",
        "incident_summary": "incident_summary.md",
        "blocklist_script": "firewall_blocklist.sh",
        "blocklist_ips": "blocklist_ips.txt"
    }
}

# Module-level defaults for backward compatibility
LOG_FILE = DEFAULT_CONFIG["log_file"]
THRESHOLD = DEFAULT_CONFIG["threshold"]
WINDOW_SECONDS = DEFAULT_CONFIG["window_seconds"]
LOG_YEAR = datetime.now().year


class AuthEvent:
    """Represents a single parsed authentication event."""

    def __init__(
        self,
        timestamp: datetime,
        raw_timestamp: str,
        source_ip: str,
        username: str,
        port: Optional[int] = None,
        event_type: str = "failed_password",
        raw_line: str = ""
    ):
        self.timestamp = timestamp
        self.raw_timestamp = raw_timestamp
        self.source_ip = source_ip
        self.username = username
        self.port = port
        self.event_type = event_type
        self.raw_line = raw_line.strip()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "raw_timestamp": self.raw_timestamp,
            "source_ip": self.source_ip,
            "username": self.username,
            "port": self.port,
            "event_type": self.event_type,
            "raw_line": self.raw_line
        }


class IncidentAlert:
    """Represents a correlated security incident for an attacking IP."""

    def __init__(
        self,
        alert_id: str,
        source_ip: str,
        start_time: datetime,
        first_alert_time: datetime,
        end_time: datetime,
        threshold: int,
        window_seconds: int
    ):
        self.alert_id = alert_id
        self.source_ip = source_ip
        self.start_time = start_time
        self.first_alert_time = first_alert_time
        self.end_time = end_time
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.events: List[AuthEvent] = []
        self.peak_window_attempts: int = 0
        self.last_event_time: datetime = start_time
        self.severity: str = "MEDIUM"
        self.attack_type: str = "SSH Brute-Force"
        self.mitigation_rules: Dict[str, str] = {}

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.end_time - self.start_time).total_seconds())

    @property
    def total_attempts(self) -> int:
        return len(self.events)

    @property
    def targeted_usernames(self) -> Dict[str, int]:
        counts = Counter(e.username for e in self.events)
        return dict(counts.most_common())

    @property
    def unique_usernames(self) -> List[str]:
        return sorted(list(set(e.username for e in self.events)))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "source_ip": self.source_ip,
            "severity": self.severity,
            "attack_type": self.attack_type,
            "attack_start_time": self.start_time.isoformat(),
            "trigger_time": self.first_alert_time.isoformat(),
            "attack_end_time": self.end_time.isoformat(),
            "duration_seconds": round(self.duration_seconds, 2),
            "total_failed_attempts": self.total_attempts,
            "peak_window_attempts": self.peak_window_attempts,
            "detection_parameters": {
                "threshold": self.threshold,
                "window_seconds": self.window_seconds
            },
            "targeted_usernames": self.targeted_usernames,
            "unique_targeted_count": len(self.unique_usernames),
            "firewall_mitigation": self.mitigation_rules,
            "sample_evidence": [e.raw_line for e in self.events[:5]]
        }


class LogParser:
    """Parses authentication logs using regular expressions and datetime."""

    # Matches syslog format: Nov 23 14:15:10 or ISO 8601 timestamps
    SYSLOG_TS_PATTERN = re.compile(
        r"^(?P<syslog_ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})"
    )
    ISO_TS_PATTERN = re.compile(
        r"^(?P<iso_ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    )

    # Core SSH failure patterns
    # Pattern 1: Failed password for [invalid user ]<user> from <ip> [port <port>]
    PATTERNS = [
        re.compile(
            r"sshd\[\d+\]:\s+Failed password for (?:invalid user\s+)?(?P<username>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:\.]+)(?:\s+port\s+(?P<port>\d+))?"
        ),
        # Pattern 2: Invalid user <user> from <ip> [port <port>]
        re.compile(
            r"sshd\[\d+\]:\s+Invalid user\s+(?P<username>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:\.]+)(?:\s+port\s+(?P<port>\d+))?"
        ),
        # Pattern 3: Failed none for <user> from <ip>
        re.compile(
            r"sshd\[\d+\]:\s+Failed none for\s+(?P<username>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:\.]+)(?:\s+port\s+(?P<port>\d+))?"
        ),
        # Pattern 4: Connection closed by authenticating user <user> <ip>
        re.compile(
            r"sshd\[\d+\]:\s+Connection closed by authenticating user\s+(?P<username>\S+)\s+(?P<ip>[0-9a-fA-F:\.]+)(?:\s+port\s+(?P<port>\d+))?"
        ),
        # Pattern 5: PAM authentication failure; rhost=<ip> user=<user>
        re.compile(
            r"sshd\[\d+\]:\s+pam_unix\(sshd:auth\):\s+authentication failure;.*?\brhost=(?P<ip>[0-9a-fA-F:\.]+).*?\buser=(?P<username>\S+)"
        )
    ]

    def __init__(self, reference_year: Optional[int] = None):
        self.reference_year = reference_year or datetime.now().year

    def parse_timestamp(self, line: str) -> Tuple[Optional[datetime], Optional[str]]:
        """Extract and parse timestamp from log line, preventing deprecation warnings."""
        # Try Syslog timestamp first
        syslog_match = self.SYSLOG_TS_PATTERN.match(line)
        if syslog_match:
            raw_ts = syslog_match.group("syslog_ts")
            normalized_ts = re.sub(r"\s+", " ", raw_ts.strip())
            try:
                dt = datetime.strptime(f"{self.reference_year} {normalized_ts}", "%Y %b %d %H:%M:%S")
                return dt, raw_ts
            except ValueError:
                pass

        # Try ISO timestamp
        iso_match = self.ISO_TS_PATTERN.match(line)
        if iso_match:
            raw_ts = iso_match.group("iso_ts")
            try:
                clean_iso = raw_ts.replace(" ", "T")
                if clean_iso.endswith("Z"):
                    clean_iso = clean_iso[:-1]
                dt = datetime.fromisoformat(clean_iso)
                return dt, raw_ts
            except ValueError:
                pass

        return None, None

    def parse_line(self, line: str) -> Optional[AuthEvent]:
        """Parse a single line from an authentication log."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        dt, raw_ts = self.parse_timestamp(line)
        if not dt or not raw_ts:
            return None

        for pattern in self.PATTERNS:
            match = pattern.search(line)
            if match:
                groups = match.groupdict()
                username = groups.get("username", "unknown").strip()
                ip = groups.get("ip", "").strip()
                port = int(groups["port"]) if groups.get("port") else None

                ip = ip.rstrip(".,;")
                username = username.rstrip(".,;")

                if not ip:
                    continue

                return AuthEvent(
                    timestamp=dt,
                    raw_timestamp=raw_ts,
                    source_ip=ip,
                    username=username,
                    port=port,
                    event_type="failed_login",
                    raw_line=line
                )

        return None

    def parse_file(self, filepath: Path) -> Tuple[List[AuthEvent], int]:
        """Parse entire log file and return chronologically sorted events."""
        events = []
        total_lines = 0

        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                total_lines += 1
                event = self.parse_line(line)
                if event:
                    events.append(event)

        events.sort(key=lambda e: e.timestamp)
        return events, total_lines


class BruteForceDetector:
    """Sliding Time-Window Correlation and Anomaly Detection Engine."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.threshold = config.get("threshold", 10)
        self.window_seconds = config.get("window_seconds", 60)
        self.cooldown_seconds = config.get("cooldown_seconds", 120)
        self.privileged_users = set(
            u.lower() for u in config.get("privileged_usernames", [])
        )
        self.severity_cfg = config.get("severity_scoring", {})
        self.mitigation_cfg = config.get("mitigation", {})

        self.sliding_windows: Dict[str, deque] = defaultdict(deque)
        self.active_incidents: Dict[str, IncidentAlert] = {}
        self.closed_incidents: List[IncidentAlert] = []
        self._alert_counter = 0

    def _generate_alert_id(self, event_time: datetime) -> str:
        self._alert_counter += 1
        return f"SEC-ALERT-{event_time.strftime('%Y%m%d')}-{self._alert_counter:03d}"

    def _generate_mitigation_rules(self, ip: str, alert_id: str) -> Dict[str, str]:
        port = self.mitigation_cfg.get("target_port", 22)
        proto = self.mitigation_cfg.get("protocol", "tcp")
        comment = f"{alert_id}-Containment"

        ufw_cmd = f"ufw insert 1 deny from {ip} to any port {port} proto {proto} comment '{comment}'"
        iptables_cmd = f"iptables -I INPUT 1 -s {ip} -p {proto} --dport {port} -j DROP -m comment --comment '{comment}'"

        return {
            "ufw": ufw_cmd,
            "iptables": iptables_cmd
        }

    def _assess_incident_severity_and_type(self, incident: IncidentAlert) -> Tuple[str, str]:
        """Calculates severity level and classifies attack type."""
        targeted = incident.targeted_usernames
        unique_users_count = len(targeted)
        peak_rate = incident.peak_window_attempts

        targeted_privileged = [
            u for u in targeted.keys() if u.lower() in self.privileged_users
        ]
        has_privileged = len(targeted_privileged) > 0
        privileged_attempts = sum(targeted[u] for u in targeted_privileged)

        spraying_threshold = self.severity_cfg.get("spraying_unique_user_threshold", 3)
        crit_threshold = self.severity_cfg.get("critical_attempt_threshold", 30)
        high_threshold = self.severity_cfg.get("high_attempt_threshold", 20)

        # Classification
        if unique_users_count >= spraying_threshold:
            attack_type = "Horizontal Password Spraying"
        elif has_privileged:
            attack_type = "Targeted Privileged Account Brute-Force"
        else:
            attack_type = "Targeted Single-User SSH Brute-Force"

        # Severity
        if (privileged_attempts >= self.threshold) or (peak_rate >= crit_threshold):
            severity = "CRITICAL"
        elif (unique_users_count >= spraying_threshold) or (peak_rate >= high_threshold) or has_privileged:
            severity = "HIGH"
        elif peak_rate >= self.threshold:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return severity, attack_type

    def process_event(self, event: AuthEvent) -> Optional[IncidentAlert]:
        """Evaluates an AuthEvent against the sliding time window for event.source_ip."""
        ip = event.source_ip
        t_curr = event.timestamp
        window = self.sliding_windows[ip]

        # 1. Add current event to IP window deque
        window.append((t_curr, event))

        # 2. Sliding window eviction: Pop events outside rolling window
        window_delta = timedelta(seconds=self.window_seconds)
        while window and (t_curr - window[0][0]) > window_delta:
            window.popleft()

        current_window_count = len(window)

        # 3. Handle Active Incident State
        if ip in self.active_incidents:
            incident = self.active_incidents[ip]
            cooldown_delta = timedelta(seconds=self.cooldown_seconds)

            if (t_curr - incident.last_event_time) > cooldown_delta:
                self._finalize_incident(incident)
                del self.active_incidents[ip]
            else:
                incident.events.append(event)
                incident.end_time = t_curr
                incident.last_event_time = t_curr
                if current_window_count > incident.peak_window_attempts:
                    incident.peak_window_attempts = current_window_count

                incident.severity, incident.attack_type = self._assess_incident_severity_and_type(incident)
                return None

        # 4. Check if threshold breached in the current sliding window
        if current_window_count >= self.threshold:
            alert_id = self._generate_alert_id(t_curr)
            start_time = window[0][0]
            first_alert_time = t_curr

            new_incident = IncidentAlert(
                alert_id=alert_id,
                source_ip=ip,
                start_time=start_time,
                first_alert_time=first_alert_time,
                end_time=t_curr,
                threshold=self.threshold,
                window_seconds=self.window_seconds
            )

            for _, w_event in window:
                new_incident.events.append(w_event)

            new_incident.peak_window_attempts = current_window_count
            new_incident.last_event_time = t_curr
            new_incident.mitigation_rules = self._generate_mitigation_rules(ip, alert_id)
            new_incident.severity, new_incident.attack_type = self._assess_incident_severity_and_type(new_incident)

            self.active_incidents[ip] = new_incident
            return new_incident

        return None

    def _finalize_incident(self, incident: IncidentAlert):
        incident.severity, incident.attack_type = self._assess_incident_severity_and_type(incident)
        self.closed_incidents.append(incident)

    def finalize(self) -> List[IncidentAlert]:
        for incident in self.active_incidents.values():
            self._finalize_incident(incident)
        self.active_incidents.clear()

        self.closed_incidents.sort(key=lambda inc: inc.start_time)
        return self.closed_incidents


class AlertReporter:
    """Generates structured outputs: JSON alerts, markdown summary, and firewall rules."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config

    def export_json(
        self,
        incidents: List[IncidentAlert],
        output_path: Path,
        total_lines: int,
        total_events: int,
        unique_ips: int
    ):
        """Generates machine-readable security_alert.json."""
        summary = {
            "total_log_lines_analyzed": total_lines,
            "total_failed_events_parsed": total_events,
            "unique_source_ips_seen": unique_ips,
            "total_incidents_detected": len(incidents),
            "critical_incidents": sum(1 for inc in incidents if inc.severity == "CRITICAL"),
            "high_incidents": sum(1 for inc in incidents if inc.severity == "HIGH"),
            "medium_incidents": sum(1 for inc in incidents if inc.severity == "MEDIUM"),
            "low_incidents": sum(1 for inc in incidents if inc.severity == "LOW"),
            "unique_malicious_ips": sorted(list(set(inc.source_ip for inc in incidents)))
        }

        output_data = {
            "metadata": {
                "engine": self.config.get("engine_name", "Detection Engine"),
                "version": self.config.get("version", "1.0.0"),
                "generated_at": datetime.now().isoformat(),
                "configuration": {
                    "threshold": self.config.get("threshold", 10),
                    "window_seconds": self.config.get("window_seconds", 60),
                    "cooldown_seconds": self.config.get("cooldown_seconds", 120),
                    "privileged_usernames": self.config.get("privileged_usernames", [])
                },
                "summary": summary
            },
            "alerts": [inc.to_dict() for inc in incidents]
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=4)

    def export_markdown_summary(
        self,
        incidents: List[IncidentAlert],
        output_path: Path,
        total_lines: int,
        total_events: int
    ):
        """Generates human-readable incident_summary.md for SOC analysts."""
        lines = []
        lines.append("# Automated Incident Alerting & Brute-Force Detection Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
        lines.append(f"**Engine Version:** {self.config.get('version', '1.0.0')}  ")
        lines.append(f"**Detection Window:** {self.config.get('window_seconds', 60)}s sliding window  ")
        lines.append(f"**Velocity Threshold:** {self.config.get('threshold', 10)} failed attempts  ")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## 1. Executive Summary")
        lines.append("")
        lines.append(
            f"During telemetry ingestion, the detection engine processed **{total_lines} total log lines**, "
            f"identifying **{total_events} failed authentication events**. Correlating these events across "
            f"sliding {self.config.get('window_seconds', 60)}-second time windows revealed "
            f"**{len(incidents)} confirmed brute-force incident(s)** requiring immediate SOC containment."
        )
        lines.append("")

        crit_count = sum(1 for inc in incidents if inc.severity == "CRITICAL")
        high_count = sum(1 for inc in incidents if inc.severity == "HIGH")
        med_count = sum(1 for inc in incidents if inc.severity == "MEDIUM")

        lines.append("| Severity | Incident Count | Containment Action Required |")
        lines.append("| :--- | :---: | :--- |")
        lines.append(f"| 🔴 **CRITICAL** | {crit_count} | Immediate firewall isolation + Privileged account credential rotation |")
        lines.append(f"| 🟠 **HIGH** | {high_count} | Perimeter IP blacklist + SOC horizontal spray audit |")
        lines.append(f"| 🟡 **MEDIUM** | {med_count} | Standard firewall blocklist addition + 24hr monitoring |")
        lines.append("")

        lines.append("## 2. Active Incidents Overview")
        lines.append("")
        if not incidents:
            lines.append("No brute-force incidents exceeded configured thresholds.")
        else:
            lines.append("| Alert ID | Attacking IP | Severity | Attack Type | Window Peak | Total Fails | Target Accounts |")
            lines.append("| :--- | :--- | :---: | :--- | :---: | :---: | :--- |")
            for inc in incidents:
                accounts_str = ", ".join(f"`{u}` ({c})" for u, c in list(inc.targeted_usernames.items())[:3])
                if len(inc.targeted_usernames) > 3:
                    accounts_str += f" *(+{len(inc.targeted_usernames) - 3} more)*"
                lines.append(
                    f"| `{inc.alert_id}` | `{inc.source_ip}` | **{inc.severity}** | {inc.attack_type} | {inc.peak_window_attempts} | {inc.total_attempts} | {accounts_str} |"
                )
            lines.append("")

        lines.append("## 3. Incident Drilldown & Forensics")
        lines.append("")
        for inc in incidents:
            lines.append(f"### Incident `{inc.alert_id}` — {inc.source_ip}")
            lines.append(f"- **Severity:** `{inc.severity}`")
            lines.append(f"- **Classification:** {inc.attack_type}")
            lines.append(f"- **Attack Start Time:** `{inc.start_time.strftime('%Y-%m-%d %H:%M:%S')}`")
            lines.append(f"- **Threshold Breach Time:** `{inc.first_alert_time.strftime('%Y-%m-%d %H:%M:%S')}`")
            lines.append(f"- **Attack End Time:** `{inc.end_time.strftime('%Y-%m-%d %H:%M:%S')}`")
            lines.append(f"- **Attack Duration:** {inc.duration_seconds:.1f} seconds")
            lines.append(f"- **Peak Sliding Window Rate:** {inc.peak_window_attempts} attempts / {inc.window_seconds}s")
            lines.append(f"- **Total Attempts in Campaign:** {inc.total_attempts}")
            lines.append("- **Targeted User Accounts:**")
            for u, c in inc.targeted_usernames.items():
                priv_tag = " *(PRIVILEGED)*" if u.lower() in [p.lower() for p in self.config.get("privileged_usernames", [])] else ""
                lines.append(f"  - `{u}`: {c} attempt(s){priv_tag}")
            lines.append("- **Sample Log Evidence:**")
            lines.append("```syslog")
            for sample in inc.events[:4]:
                lines.append(sample.raw_line)
            lines.append("```")
            lines.append("- **Recommended Mitigation Commands:**")
            lines.append("```bash")
            lines.append(f"# UFW Rule:")
            lines.append(inc.mitigation_rules.get("ufw", ""))
            lines.append(f"# iptables Rule:")
            lines.append(inc.mitigation_rules.get("iptables", ""))
            lines.append("```")
            lines.append("")

        lines.append("## 4. MITRE ATT&CK® Mapping")
        lines.append("")
        lines.append("| Technique ID | Technique Name | Tactic | Observed Behavior |")
        lines.append("| :--- | :--- | :--- | :--- |")
        lines.append("| **T1110.001** | Password Guessing | Credential Access | Rapid authentication attempts against single specific usernames (`root`, `sysadmin`). |")
        lines.append("| **T1110.003** | Password Spraying | Credential Access | Multi-account iteration testing common credentials across varied user accounts. |")
        lines.append("| **T1078** | Valid Accounts | Initial Access / Persistence | Attempts to compromise legitimate system credentials. |")
        lines.append("")

        lines.append("## 5. SOC Analyst Remediation Workflow")
        lines.append("")
        lines.append("1. **Containment:** Execute the auto-generated `firewall_blocklist.sh` script on boundary/host firewalls.")
        lines.append("2. **Verification:** Inspect active firewall rules using `ufw status numbered` or `iptables -L INPUT -v -n`.")
        lines.append("3. **Identity Verification:** Confirm no successful logins occurred from the attacking IPs (`grep 'Accepted' /var/log/auth.log`).")
        lines.append("4. **Credential Rotation:** If any targeted account is an active enterprise user, flag for mandatory password reset.")
        lines.append("")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def export_firewall_blocklist(
        self,
        incidents: List[IncidentAlert],
        script_path: Path,
        ip_list_path: Path
    ):
        """Generates executable bash script and plain IP list for firewall containment."""
        unique_ips = sorted(list(set(inc.source_ip for inc in incidents)))

        with open(ip_list_path, "w", encoding="utf-8") as f:
            for ip in unique_ips:
                f.write(f"{ip}\n")

        port = self.config.get("mitigation", {}).get("target_port", 22)
        proto = self.config.get("mitigation", {}).get("protocol", "tcp")

        script_lines = [
            "#!/usr/bin/env bash",
            "# =====================================================================",
            "# AUTOMATED SOC FIREWALL CONTAINMENT BLOCKLIST",
            f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"# Engine: {self.config.get('engine_name', 'Brute-Force Detection Engine')}",
            f"# Total Malicious Source IPs: {len(unique_ips)}",
            "# =====================================================================",
            "set -euo pipefail",
            "",
            "# Ensure root execution",
            "if [ \"$(id -u)\" -ne 0 ]; then",
            "    echo \"[!] Error: This containment script must be executed as root (sudo).\" >&2",
            "    exit 1",
            "fi",
            "",
            "echo \"[*] Initiating SOC Brute-Force Host Containment...\"",
            ""
        ]

        script_lines.append("# Check firewall tooling")
        script_lines.append("HAS_UFW=false")
        script_lines.append("HAS_IPTABLES=false")
        script_lines.append("if command -v ufw >/dev/null 2>&1 && ufw status | grep -qw 'active'; then HAS_UFW=true; fi")
        script_lines.append("if command -v iptables >/dev/null 2>&1; then HAS_IPTABLES=true; fi")
        script_lines.append("")

        # Section 1: UFW Rules
        script_lines.append("echo \"[*] Applying UFW perimeter rules...\"")
        script_lines.append("if [ \"$HAS_UFW\" = true ]; then")
        for inc in incidents:
            ip = inc.source_ip
            comment = f"{inc.alert_id}-Containment"
            script_lines.append(f"    # {inc.alert_id} | {inc.severity} | {inc.attack_type}")
            script_lines.append(f"    ufw insert 1 deny from {ip} to any port {port} proto {proto} comment '{comment}' || true")
        script_lines.append("    echo \"[+] UFW rules successfully applied.\"")
        script_lines.append("else")
        script_lines.append("    echo \"[-] UFW inactive or not installed; skipping UFW insert.\"")
        script_lines.append("fi")
        script_lines.append("")

        # Section 2: iptables Rules
        script_lines.append("echo \"[*] Applying iptables kernel packet filters...\"")
        script_lines.append("if [ \"$HAS_IPTABLES\" = true ]; then")
        for inc in incidents:
            ip = inc.source_ip
            comment = f"{inc.alert_id}-Containment"
            script_lines.append(f"    # {inc.alert_id} | {inc.severity}")
            script_lines.append(f"    if ! iptables -C INPUT -s {ip} -p {proto} --dport {port} -j DROP 2>/dev/null; then")
            script_lines.append(f"        iptables -I INPUT 1 -s {ip} -p {proto} --dport {port} -j DROP -m comment --comment '{comment}'")
            script_lines.append(f"        echo \"  [+] Blocked {ip} (iptables port {port})\"")
            script_lines.append("    else")
            script_lines.append(f"        echo \"  [~] Rule for {ip} already present in iptables; skipping.\"")
            script_lines.append("    fi")
        script_lines.append("    echo \"[+] iptables rules successfully applied.\"")
        script_lines.append("fi")
        script_lines.append("")

        # Verification and Rollback instructions
        script_lines.append("echo \"\"")
        script_lines.append(f"echo \"[✓] Containment complete. All {len(unique_ips)} attacking IP(s) blocked.\"")
        script_lines.append("echo \"[i] Verification commands:\"")
        script_lines.append("echo \"    ufw status numbered\"")
        script_lines.append(f"echo \"    iptables -L INPUT -v -n | grep -E '{'|'.join(re.escape(ip) for ip in unique_ips) if unique_ips else 'DROP'}'\"")
        script_lines.append("")
        script_lines.append("# =====================================================================")
        script_lines.append("# ROLLBACK / UNBLOCK INSTRUCTIONS (Execute manually if false-positive):")
        for inc in incidents:
            ip = inc.source_ip
            script_lines.append(f"# sudo ufw delete deny from {ip} to any port {port} proto {proto}")
            script_lines.append(f"# sudo iptables -D INPUT -s {ip} -p {proto} --dport {port} -j DROP")
        script_lines.append("# =====================================================================")

        with open(script_path, "w", encoding="utf-8") as f:
            f.write("\n".join(script_lines) + "\n")


# Backward compatibility helper functions
def parse_timestamp(ts_str: str, year: int = 2026) -> datetime:
    normalized = re.sub(r"\s+", " ", ts_str.strip())
    return datetime.strptime(f"{year} {normalized}", "%Y %b %d %H:%M:%S")


def determine_severity(attempt_count: int) -> str:
    if attempt_count >= 25:
        return "CRITICAL"
    elif attempt_count >= 15:
        return "HIGH"
    return "MEDIUM"


def detect_brute_force(filepath: str, threshold: int = 10, window_seconds: int = 60) -> List[Dict[str, Any]]:
    config = dict(DEFAULT_CONFIG)
    config["threshold"] = threshold
    config["window_seconds"] = window_seconds

    parser = LogParser(reference_year=LOG_YEAR)
    events, _ = parser.parse_file(Path(filepath))

    detector = BruteForceDetector(config)
    for event in events:
        detector.process_event(event)

    incidents = detector.finalize()
    return [inc.to_dict() for inc in incidents]


def export_outputs(alerts: List[Dict[str, Any]]):
    report = {
        "generated_at": datetime.now().isoformat(),
        "log_source": LOG_FILE,
        "detection_rule": f"Exceeding {THRESHOLD} failed SSH logins within {WINDOW_SECONDS} seconds",
        "total_alerts": len(alerts),
        "alerts": alerts
    }
    with open("security_alert.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)


def load_config(config_path: Optional[Path]) -> Dict[str, Any]:
    """Loads JSON config file or falls back to defaults."""
    config = dict(DEFAULT_CONFIG)
    if config_path and config_path.is_file():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
                config.update(user_cfg)
        except Exception as e:
            print(f"[!] Warning: Failed to parse config file {config_path}: {e}. Using defaults.")
    return config


def main():
    parser = argparse.ArgumentParser(
        description="Automated Incident Alerting & Brute-Force Detection Engine"
    )
    parser.add_argument(
        "--log",
        "-l",
        type=Path,
        default=Path("auth.log"),
        help="Path to authentication log file (default: auth.log)"
    )
    parser.add_argument(
        "--config",
        "-c",
        type=Path,
        default=Path("config.json"),
        help="Path to configuration JSON file (default: config.json)"
    )
    parser.add_argument(
        "--threshold",
        "-t",
        type=int,
        default=None,
        help="Override failed login threshold (e.g. 10)"
    )
    parser.add_argument(
        "--window",
        "-w",
        type=int,
        default=None,
        help="Override sliding window duration in seconds (e.g. 60)"
    )
    parser.add_argument(
        "--year",
        "-y",
        type=int,
        default=None,
        help="Reference year for syslog timestamps without year (default: current year)"
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=None,
        help="Path for security_alert.json output"
    )
    parser.add_argument(
        "--output-summary",
        type=Path,
        default=None,
        help="Path for incident_summary.md output"
    )
    parser.add_argument(
        "--output-blocklist",
        type=Path,
        default=None,
        help="Path for firewall_blocklist.sh output"
    )

    args = parser.parse_args()

    # 1. Load Configuration
    config = load_config(args.config)
    if args.threshold is not None:
        config["threshold"] = args.threshold
    if args.window is not None:
        config["window_seconds"] = args.window

    # Output file paths
    out_files = config.get("output_files", {})
    json_path = args.output_json or Path(out_files.get("alert_json", "security_alert.json"))
    summary_path = args.output_summary or Path(out_files.get("incident_summary", "incident_summary.md"))
    blocklist_path = args.output_blocklist or Path(out_files.get("blocklist_script", "firewall_blocklist.sh"))
    ips_path = Path(out_files.get("blocklist_ips", "blocklist_ips.txt"))

    print("=====================================================================")
    print(f"[*] {config.get('engine_name', 'Brute-Force Detection Engine')}")
    print(f"[*] Threshold: >= {config['threshold']} attempts within a {config['window_seconds']}-second window")
    print(f"[*] Target Telemetry: {args.log}")
    print("=====================================================================")

    if not args.log.is_file():
        print(f"[!] Error: Target log file '{args.log}' not found.")
        return 1

    # 2. Ingest and Parse Log File
    log_parser = LogParser(reference_year=args.year)
    events, total_lines = log_parser.parse_file(args.log)
    print(f"[+] Ingested {total_lines} raw log lines.")
    print(f"[+] Extracted {len(events)} failed authentication event(s).")

    # 3. Execute Sliding Time-Window Correlation
    detector = BruteForceDetector(config)
    for event in events:
        detector.process_event(event)

    incidents = detector.finalize()
    unique_attacking_ips = set(e.source_ip for e in events)

    print(f"[+] Correlation complete: {len(incidents)} active brute-force incident(s) detected.\n")

    # 4. Display Incident Findings
    if incidents:
        print("--- ACTIVE SECURITY INCIDENTS DETECTED ---")
        for inc in incidents:
            print(f"[{inc.severity}] {inc.alert_id} | Attacker IP: {inc.source_ip}")
            print(f"    Type: {inc.attack_type}")
            print(f"    Timeline: {inc.start_time.strftime('%H:%M:%S')} -> {inc.end_time.strftime('%H:%M:%S')} ({inc.duration_seconds:.1f}s)")
            print(f"    Peak Velocity: {inc.peak_window_attempts} attempts / {inc.window_seconds}s window (Total: {inc.total_attempts})")
            print(f"    Targeted Accounts: {dict(inc.targeted_usernames)}")
            print(f"    Mitigation: {inc.mitigation_rules.get('ufw')}")
            print()
    else:
        print("[i] No source IP breached the configured threshold.")

    # 5. Export Structured Outputs
    reporter = AlertReporter(config)
    reporter.export_json(incidents, json_path, total_lines, len(events), len(unique_attacking_ips))
    reporter.export_markdown_summary(incidents, summary_path, total_lines, len(events))
    reporter.export_firewall_blocklist(incidents, blocklist_path, ips_path)

    print("--- GENERATED SOC ARTIFACTS ---")
    print(f"[+] Machine-readable Alert JSON: {json_path}")
    print(f"[+] Executive Incident Summary:  {summary_path}")
    print(f"[+] Firewall Containment Script: {blocklist_path}")
    print(f"[+] Plaintext Blocklist IPs:     {ips_path}")
    print("=====================================================================")

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main() or 0)
