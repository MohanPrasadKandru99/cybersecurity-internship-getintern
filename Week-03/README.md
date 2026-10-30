# Week 3: Basic Linux Security Inspection & Audit Checklist

## Objective

Inspect sensitive file permissions, effective SSH authentication settings, and world-writable files in `/tmp` on a Linux host.

Run these checks on the host being audited. This report was prepared in a Windows workspace without access to that Linux host, so the results below are pending verification.

## Inspection Commands

```sh
ls -l /etc/shadow /etc/passwd
sudo grep -Ei '^[[:space:]]*(PermitRootLogin|PasswordAuthentication)[[:space:]]+' /etc/ssh/sshd_config
sudo sshd -T | grep -E '^(permitrootlogin|passwordauthentication) '
sudo find /tmp -type f -perm -0002 -print
```

For file permissions, confirm ordinary users cannot read or write `/etc/shadow` and cannot write `/etc/passwd`. The exact secure modes can vary by distribution.

For SSH, review the effective settings reported by `sshd -T`, rather than relying only on uncommented lines in the configuration file. `PermitRootLogin no` is generally preferred. Disable password authentication only after confirming administrators can sign in using an approved alternative, such as SSH keys.

Review each world-writable file before changing it; temporary files may be in active use. Do not apply blanket permission changes.

## Findings

| Item Checked | Current Status | Risk (Safe/Insecure) | Recommended Fix |
| --- | --- | --- | --- |
| `/etc/shadow` permissions (`ls -l`) | Not checked; requires access to the Linux host | Not assessed | Confirm ordinary users cannot read or write it; retain distribution-appropriate ownership and permissions. |
| `/etc/passwd` permissions (`ls -l`) | Not checked; requires access to the Linux host | Not assessed | Confirm ordinary users cannot write it; retain distribution-appropriate ownership and permissions. |
| SSH root login and password authentication (`sshd -T`) | Not checked; requires access to the Linux host | Not assessed | Prefer `PermitRootLogin no`; set password authentication according to policy and only disable it after verifying an alternative admin login works. |
| World-writable files in `/tmp` (`find ... -perm -0002`) | Not checked; requires access to the Linux host | Not assessed | Review each result and remove unnecessary world-write access using the appropriate owner and permissions. |
