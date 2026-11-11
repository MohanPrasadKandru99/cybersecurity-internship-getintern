# Cybersecurity Internship: 8-Week Track

This repository documents an eight-week cybersecurity internship track through weekly reports, scan evidence, screenshots, and a Linux hardening script. The work so far covers sandboxed network discovery, service and port auditing, a Linux security inspection checklist, and automated OS hardening.

## Track Overview

| Week | Focus | Status |
| --- | --- | --- |
| 01 | [Network topology mapping and active host discovery](Week-01-Network-Topology-Mapping/README.md) | Complete |
| 02 | [Port auditing, service fingerprinting, and attack surface mapping](Week-02/README.md) | Complete |
| 03 | [Basic Linux security inspection and audit checklist](Week-03/README.md) | Complete |
| 04 | [Automated OS hardening and remediation](Week-04-OS-Hardening/README.md) | Complete |
| 05 | To be defined | Planned |
| 06 | To be defined | Planned |
| 07 | To be defined | Planned |
| 08 | To be defined | Planned |

## Repository Contents

- **Week 01:** Lab network boundaries, host inventory, topology diagram, and ARP/ICMP discovery evidence.
- **Week 02:** TCP and UDP audit results, service fingerprints, and an attack-surface risk matrix.
- **Week 03:** Commands and guidance for checking sensitive file permissions, effective SSH settings, and world-writable files in `/tmp`. The checks still need to be run and verified on a Linux host.
- **Week 04:** A Bash hardening script and execution guidance for SSH, UFW, legacy services, permissions, and SUID/SGID auditing. Review its assumptions and test it on a disposable system before use; it can interrupt access or remove services.
