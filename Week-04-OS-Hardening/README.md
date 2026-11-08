# Week 4: Automated OS Hardening & Remediation

## Objective

Develop a standalone Bash automation script (`harden_linux.sh`) to remediate
system misconfigurations, secure the SSH daemon, isolate services using
firewall rules, and rectify insecure file permissions.

## Execution Instructions

Upload the script to the target Linux node and execute it with root privileges:

```sh
chmod +x harden_linux.sh
sudo ./harden_linux.sh
```

Review the target system and ensure you have console or other recovery access
before running the script. It disables SSH password authentication, resets UFW
rules to allow only SSH, HTTP, and HTTPS inbound, and purges selected legacy
services. These changes can interrupt access or remove services. Test on a
disposable VM/snapshot first, and verify that key-based SSH access works before
relying on the new configuration.

## Hardening Actions Performed

- **SSH hardening:** Backs up `/etc/ssh/sshd_config`, disables root login,
  disables password authentication, and disables empty passwords.
- **Firewall (UFW):** Resets existing UFW rules, denies inbound traffic by
  default, allows outbound traffic, and allows inbound SSH, HTTP, and HTTPS.
- **Legacy service removal:** Purges `telnetd`, `rsh-server`,
  `rsh-redone-server`, and `xinetd`.
- **Permissions rectification:** Sets `/etc/passwd` to mode `644` and
  `/etc/shadow` to mode `640`, enforces the sticky bit on `/tmp`, and removes
  other-write permission from regular files in `/tmp`.
- **SUID/SGID audit:** Writes a listing of SUID/SGID files to
  `/var/log/suid_audit.log` for manual review.

The script targets Debian/Ubuntu-style systems with `apt-get` and UFW. Review
its assumptions and confirm service names and firewall behavior on the target
distribution before execution.
