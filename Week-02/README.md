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

## 4. Attack Surface Risk Matrix

The following matrix synthesizes the scan telemetry, mapping exposed services to their inherent risk levels and outlining immediate remediation strategies.

| **Host IP** | **Port** | **Service** | **Version** | **Inherent Risk Level** | **Remediation Strategy** | 
| `192.168.245.3` | 21/TCP | FTP | vsftpd 2.3.4 | **High** | Contains a known malicious backdoor (CVE-2011-2523). Upgrade daemon and enforce FTPS/SFTP. | 
| `192.168.245.3` | 22/TCP | SSH | OpenSSH 4.7p1 | **Medium** | Legacy version vulnerable to user enumeration. Upgrade to the latest stable OpenSSH release. | 
| `192.168.245.3` | 23/TCP | Telnet | Linux telnetd | **High** | Cleartext protocol. Disable the Telnet service entirely and mandate SSH for remote administration. | 
| `192.168.245.3` | 25/TCP | SMTP | Postfix smtpd | **Medium** | Open mail relay risks. Enforce strict authentication and TLS encryption for transport. | 
| `192.168.245.3` | 80/TCP | HTTP | Apache 2.2.8 | **Medium** | Outdated web server exposing multiple vectors. Patch to current Apache release and deploy WAF. | 
| `192.168.245.3` | 3632/TCP | distccd | distccd v1 | **High** | Allows remote arbitrary code execution (CVE-2004-2687). Disable service or restrict access strictly to trusted IPs via firewall. | 

```
Week-02-Port-Auditing/
├── logs/
│   ├── tcp_audit.txt
│   ├── udp_audit.txt
│   └── service_fingerprint.txt
└── README.md