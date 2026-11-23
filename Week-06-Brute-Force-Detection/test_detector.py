#!/usr/bin/env python3
"""
Unit and Integration Test Suite for Brute-Force Detection Engine
================================================================
Tests cover:
- Syslog and ISO 8601 timestamp parsing (including deprecation prevention)
- Regex pattern extraction (valid/invalid users, IPv4/IPv6, ports)
- Sliding time-window rolling deque eviction
- Fixed-window defeat (boundary-spanning attack detection)
- Configurable threshold enforcement
- Incident consolidation and cooldown behavior
- Multi-tier severity and MITRE attack classification
- Firewall blocklist and machine-readable JSON exports
"""

import unittest
import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from brute_force_detector import (
    LogParser,
    AuthEvent,
    BruteForceDetector,
    AlertReporter,
    DEFAULT_CONFIG
)


class TestLogParser(unittest.TestCase):
    """Test log parsing and timestamp extraction."""

    def setUp(self):
        self.parser = LogParser(reference_year=2026)

    def test_syslog_timestamp_double_digit(self):
        line = "Nov 23 14:15:10 metasploitable sshd[4010]: Failed password for root from 192.168.245.130 port 38100 ssh2"
        event = self.parser.parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.timestamp, datetime(2026, 11, 23, 14, 15, 10))
        self.assertEqual(event.source_ip, "192.168.245.130")
        self.assertEqual(event.username, "root")
        self.assertEqual(event.port, 38100)

    def test_syslog_timestamp_single_digit(self):
        line = "Nov  5 09:02:01 metasploitable sshd[1200]: Failed password for admin from 10.0.0.5 port 2222 ssh2"
        event = self.parser.parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.timestamp, datetime(2026, 11, 5, 9, 2, 1))
        self.assertEqual(event.source_ip, "10.0.0.5")
        self.assertEqual(event.username, "admin")

    def test_iso_timestamp(self):
        line = "2026-11-23T14:15:10.123456+00:00 server sshd[4010]: Failed password for invalid user tester from 172.16.0.40 port 45100 ssh2"
        event = self.parser.parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.username, "tester")
        self.assertEqual(event.source_ip, "172.16.0.40")

    def test_invalid_user_format(self):
        line = "Nov 23 14:20:01 server sshd[5001]: Failed password for invalid user hacker from 192.168.1.100 port 50000 ssh2"
        event = self.parser.parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.username, "hacker")
        self.assertEqual(event.source_ip, "192.168.1.100")

    def test_invalid_user_short_format(self):
        line = "Nov 23 14:20:01 server sshd[5001]: Invalid user guest from 192.168.1.105 port 50002"
        event = self.parser.parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.username, "guest")
        self.assertEqual(event.source_ip, "192.168.1.105")

    def test_pam_failure_format(self):
        line = "Nov 23 14:21:00 server sshd[5010]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.200  user=sysadmin"
        event = self.parser.parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.username, "sysadmin")
        self.assertEqual(event.source_ip, "192.168.1.200")

    def test_ignore_legitimate_logins_and_noise(self):
        line1 = "Nov 23 08:30:12 server sshd[1020]: Accepted publickey for ubuntu from 192.168.1.10 port 41200 ssh2"
        line2 = "Nov 23 08:30:12 server sshd[1020]: pam_unix(sshd:session): session opened for user ubuntu"
        line3 = "# Some comment line in log"
        self.assertIsNone(self.parser.parse_line(line1))
        self.assertIsNone(self.parser.parse_line(line2))
        self.assertIsNone(self.parser.parse_line(line3))


class TestSlidingWindowCorrelation(unittest.TestCase):
    """Test sliding window calculation, eviction, and threshold logic."""

    def setUp(self):
        self.config = dict(DEFAULT_CONFIG)
        self.config["threshold"] = 5
        self.config["window_seconds"] = 30
        self.config["cooldown_seconds"] = 60
        self.detector = BruteForceDetector(self.config)
        self.base_time = datetime(2026, 11, 23, 12, 0, 0)

    def _make_event(self, ip: str, username: str, seconds_offset: int) -> AuthEvent:
        ts = self.base_time + timedelta(seconds=seconds_offset)
        return AuthEvent(
            timestamp=ts,
            raw_timestamp=ts.strftime("%b %d %H:%M:%S"),
            source_ip=ip,
            username=username,
            port=2222,
            raw_line=f"Failed password for {username} from {ip}"
        )

    def test_below_threshold_does_not_alert(self):
        # 4 events in 20s (threshold is 5)
        for i in range(4):
            event = self._make_event("10.0.0.1", "user1", i * 5)
            alert = self.detector.process_event(event)
            self.assertIsNone(alert)

        incidents = self.detector.finalize()
        self.assertEqual(len(incidents), 0)

    def test_threshold_reached_triggers_alert(self):
        # 5 events in 20s (reaches threshold of 5)
        for i in range(5):
            event = self._make_event("10.0.0.2", "user2", i * 4)
            self.detector.process_event(event)

        incidents = self.detector.finalize()
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.source_ip, "10.0.0.2")
        self.assertEqual(inc.total_attempts, 5)
        self.assertEqual(inc.peak_window_attempts, 5)

    def test_sliding_window_eviction(self):
        # Events spread out so that window of 30s never holds >= 5 events:
        for i in range(6):
            event = self._make_event("10.0.0.3", "user3", i * 12)
            self.detector.process_event(event)

        incidents = self.detector.finalize()
        self.assertEqual(len(incidents), 0)

    def test_fixed_window_defeat_detected_by_sliding_window(self):
        # Crosses minute boundary: 4 at t=50..58, 3 at t=62..70
        events = [
            self._make_event("10.0.0.4", "target", 50),
            self._make_event("10.0.0.4", "target", 52),
            self._make_event("10.0.0.4", "target", 55),
            self._make_event("10.0.0.4", "target", 58),
            self._make_event("10.0.0.4", "target", 62),
            self._make_event("10.0.0.4", "target", 66),
            self._make_event("10.0.0.4", "target", 70)
        ]
        for e in events:
            self.detector.process_event(e)

        incidents = self.detector.finalize()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].source_ip, "10.0.0.4")
        self.assertGreaterEqual(incidents[0].peak_window_attempts, 5)

    def test_cooldown_and_campaign_separation(self):
        # Campaign 1: 5 events at t=0..10
        for i in range(5):
            self.detector.process_event(self._make_event("10.0.0.5", "admin", i * 2))

        # Pause 150 seconds (cooldown is 60s)
        # Campaign 2: 5 events at t=160..170
        for i in range(5):
            self.detector.process_event(self._make_event("10.0.0.5", "admin", 160 + i * 2))

        incidents = self.detector.finalize()
        self.assertEqual(len(incidents), 2)
        self.assertEqual(incidents[0].alert_id != incidents[1].alert_id, True)


class TestSeverityAndMitigation(unittest.TestCase):
    """Test severity scoring, MITRE classification, and firewall generation."""

    def setUp(self):
        self.config = dict(DEFAULT_CONFIG)
        self.config["threshold"] = 5
        self.config["window_seconds"] = 60
        self.reporter = AlertReporter(self.config)

    def test_horizontal_password_spraying_detection(self):
        detector = BruteForceDetector(self.config)
        base = datetime(2026, 11, 23, 10, 0, 0)
        users = ["userA", "userB", "userC", "userD", "userE"]

        for i, u in enumerate(users):
            ev = AuthEvent(
                timestamp=base + timedelta(seconds=i * 5),
                raw_timestamp="Nov 23 10:00:00",
                source_ip="192.168.100.50",
                username=u,
                port=22,
                raw_line=f"Failed password for invalid user {u} from 192.168.100.50"
            )
            detector.process_event(ev)

        incidents = detector.finalize()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].attack_type, "Horizontal Password Spraying")
        self.assertIn(incidents[0].severity, ["HIGH", "CRITICAL"])
        self.assertEqual(len(incidents[0].unique_usernames), 5)

    def test_privileged_account_critical_severity(self):
        detector = BruteForceDetector(self.config)
        base = datetime(2026, 11, 23, 11, 0, 0)

        for i in range(6):
            ev = AuthEvent(
                timestamp=base + timedelta(seconds=i * 3),
                raw_timestamp="Nov 23 11:00:00",
                source_ip="192.168.100.99",
                username="root",
                port=22,
                raw_line="Failed password for root from 192.168.100.99"
            )
            detector.process_event(ev)

        incidents = detector.finalize()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0].severity, "CRITICAL")
        self.assertEqual(incidents[0].attack_type, "Targeted Privileged Account Brute-Force")

    def test_artifact_export_integrity(self):
        detector = BruteForceDetector(self.config)
        base = datetime(2026, 11, 23, 12, 0, 0)
        for i in range(5):
            detector.process_event(
                AuthEvent(
                    timestamp=base + timedelta(seconds=i * 2),
                    raw_timestamp="Nov 23 12:00:00",
                    source_ip="172.16.50.25",
                    username="testuser",
                    port=22,
                    raw_line="Failed password for testuser from 172.16.50.25"
                )
            )
        incidents = detector.finalize()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            json_file = tmp / "alert.json"
            summary_file = tmp / "summary.md"
            blocklist_file = tmp / "blocklist.sh"
            ips_file = tmp / "ips.txt"

            self.reporter.export_json(incidents, json_file, 100, 5, 1)
            self.reporter.export_markdown_summary(incidents, summary_file, 100, 5)
            self.reporter.export_firewall_blocklist(incidents, blocklist_file, ips_file)

            # 1. Validate JSON
            self.assertTrue(json_file.exists())
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["metadata"]["summary"]["total_incidents_detected"], 1)
            self.assertEqual(data["alerts"][0]["source_ip"], "172.16.50.25")
            self.assertIn("ufw", data["alerts"][0]["firewall_mitigation"])

            # 2. Validate Summary
            self.assertTrue(summary_file.exists())
            summary_content = summary_file.read_text(encoding="utf-8")
            self.assertIn("172.16.50.25", summary_content)
            self.assertIn("MITRE ATT&CK", summary_content)

            # 3. Validate Firewall Script
            self.assertTrue(blocklist_file.exists())
            blocklist_content = blocklist_file.read_text(encoding="utf-8")
            self.assertIn("ufw insert 1 deny from 172.16.50.25", blocklist_content)
            self.assertIn("iptables -I INPUT 1 -s 172.16.50.25", blocklist_content)
            self.assertIn("ROLLBACK / UNBLOCK INSTRUCTIONS", blocklist_content)

            # 4. Validate IP list
            self.assertTrue(ips_file.exists())
            self.assertEqual(ips_file.read_text(encoding="utf-8").strip(), "172.16.50.25")


if __name__ == "__main__":
    unittest.main()
