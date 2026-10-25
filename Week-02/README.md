# Week 02
# Week 2: Port Auditing, Service Fingerprinting & Attack Surface Mapping

## 1. Executive Summary

Following the Layer 2 and Layer 3 network mapping phase, this milestone transitions into vulnerability management by auditing exposed services on the identified target node (`192.168.245.3`). Systematic TCP and UDP socket scans were executed alongside service fingerprinting to extract application daemon banners, identifying legacy protocols and unencrypted services that present a high-risk attack surface.

### Scope & Target Details

* **Attacker Node (Kali Linux):** `192.168.245.4`

* **Target Node (Metasploitable2):** `192.168.245.3`

## 2. Structured TCP/UDP Port Auditing

To classify port states accurately without overwhelming the target network, stealth SYN and targeted UDP scans were deployed.

### TCP SYN Stealth Scan (All 65,535 Ports)

Executed a half-open TCP handshake sweep to bypass basic stateful logging while comprehensively identifying all listening sockets.

```
sudo nmap -sS -p- -v 192.168.245.3 -oN tcp_audit.txt

```

### UDP Scan (Top 100 Ports)

Audited connectionless protocols targeting the top 100 most common UDP ports to identify services like DNS, SNMP, and TFTP.

```
sudo nmap -sU --top-ports 100 -v 192.168.245.3 -oN udp_audit.txt

```

## 3. Service Fingerprinting & Banner Grabbing

To evaluate the exact daemons running behind the open ports, an aggressive service enumeration and default script scan was executed. This phase successfully extracted application headers and flagged multiple unencrypted, legacy protocols.

```
sudo nmap -sV -sC -p- 192.168.245.3 -oN service_fingerprint.txt

```

**Key Findings:**

* **Legacy Protocols Identified:** Telnet (Port 23) and FTP (Port 21) are actively listening, allowing cleartext transmission of credentials.

* **Vulnerable Daemons:** Highly deprecated versions of `vsftpd` and `UnrealIRCd` were fingerprinted on the target.

## 5. Deliverables & Logging

All raw scan outputs verifying the telemetry in this report have been captured and archived.

```
Week-02-Port-Auditing/
├── logs/
│   ├── tcp_audit.txt
│   ├── udp_audit.txt
│   └── service_fingerprint.txt
└── README.md