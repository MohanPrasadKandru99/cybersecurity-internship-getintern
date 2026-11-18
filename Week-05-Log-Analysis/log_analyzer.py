import re
import csv
import json
from collections import Counter

# Input log file (change to '/var/log/auth.log' if running directly on Linux)
LOG_FILE = "auth.log"

# RegEx pattern to match SSH failed password events (both valid and invalid users)
AUTH_FAIL_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+(?:Failed password for (?:invalid user\s+)?|Invalid user\s+)"
    r"(?P<username>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

def parse_auth_log(filepath):
    extracted_events = []
    ip_counter = Counter()
    user_counter = Counter()

    with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            match = AUTH_FAIL_PATTERN.search(line)
            if match:
                event = match.groupdict()
                extracted_events.append(event)
                ip_counter[event["ip"]] += 1
                user_counter[event["username"]] += 1

    return extracted_events, ip_counter, user_counter

def export_reports(ip_counter, user_counter):
    top_10_ips = ip_counter.most_common(10)
    top_users = user_counter.most_common()

    # 1. Export Top 10 Attacking IPs to CSV
    with open("top_attacking_ips.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Rank", "Source_IP", "Failed_Attempts"])
        for rank, (ip, count) in enumerate(top_10_ips, start=1):
            writer.writerow([rank, ip, count])

    # 2. Export Targeted Usernames to CSV
    with open("targeted_usernames.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Username", "Failed_Attempts"])
        for user, count in top_users:
            writer.writerow([user, count])

    # 3. Export Combined Threat Summary to JSON
    threat_summary = {
        "total_failed_attempts": sum(ip_counter.values()),
        "unique_attacking_ips": len(ip_counter),
        "top_10_attacking_ips": [
            {"rank": r, "ip": ip, "attempts": c} for r, (ip, c) in enumerate(top_10_ips, start=1)
        ],
        "targeted_usernames": [
            {"username": u, "attempts": c} for u, c in top_users
        ]
    }
    with open("threat_report.json", "w", encoding="utf-8") as f:
        json.dump(threat_summary, f, indent=4)

    return top_10_ips, top_users

if __name__ == "__main__":
    print(f"[*] Ingesting telemetry from {LOG_FILE}...")
    events, ip_counts, user_counts = parse_auth_log(LOG_FILE)
    top_ips, top_users = export_reports(ip_counts, user_counts)

    print(f"[+] Parsed {len(events)} failed authentication events.\n")

    print("--- TOP 10 ATTACKING IPS ---")
    for rank, (ip, count) in enumerate(top_ips, start=1):
        print(f"{rank:>2}. {ip:<16} -> {count} failed attempts")

    print("\n--- TARGETED USERNAMES ---")
    for user, count in top_users:
        print(f" - {user:<12} -> {count} attempts")

    print("\n[+] Reports exported: top_attacking_ips.csv, targeted_usernames.csv, threat_report.json")