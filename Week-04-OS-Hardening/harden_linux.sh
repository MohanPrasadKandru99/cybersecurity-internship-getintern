#!/bin/bash
# GetIntern Week 4: Automated OS Hardening & Remediation Script
# Note: Must be executed with root/sudo privileges

echo "[*] Starting Automated OS Hardening Process..."

# ---------------------------------------------------------
# 1. SSH Daemon Hardening
# ---------------------------------------------------------
echo "[*] Securing SSH Configuration..."
SSHD_CONFIG="/etc/ssh/sshd_config"
cp $SSHD_CONFIG "${SSHD_CONFIG}.bak" # Backup original config

# Enforce key-based auth, disable root login, disable empty passwords
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' $SSHD_CONFIG
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' $SSHD_CONFIG
sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' $SSHD_CONFIG

# Restart SSH service to apply changes
systemctl restart sshd || service ssh restart
echo "[+] SSH Hardening Applied."

# ---------------------------------------------------------
# 2. Firewall & Service Isolation
# ---------------------------------------------------------
echo "[*] Configuring UFW Firewall Rules..."
# Ensure UFW is installed
apt-get update && apt-get install -y ufw > /dev/null 2>&1

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw --force enable
echo "[+] Firewall rules enforced (Default Deny Inbound, Allow Outbound, SSH/HTTP/HTTPS allowed)."

echo "[*] Removing Legacy Insecure Services..."
apt-get purge -y telnetd rsh-server rsh-redone-server xinetd > /dev/null 2>&1
echo "[+] Legacy services (telnet, rsh) purged."

# ---------------------------------------------------------
# 3. Permissions & Privilege Rectification
# ---------------------------------------------------------
echo "[*] Securing Sensitive File Permissions..."
chown root:root /etc/passwd /etc/shadow
chmod 644 /etc/passwd
chmod 640 /etc/shadow
echo "[+] /etc/passwd and /etc/shadow secured."

echo "[*] Rectifying World-Writable Paths..."
# Enforce sticky bit on /tmp
chmod +t /tmp
# Remove write permissions for 'others' on files in /tmp
find /tmp -type f -perm -0002 -exec chmod o-w {} \;
echo "[+] World-writable paths secured."

echo "[*] Auditing SUID/SGID Binaries..."
# Find all SUID/SGID binaries and save to a log file for manual review
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null > /var/log/suid_audit.log
echo "[+] SUID/SGID audit complete. Results saved to /var/log/suid_audit.log."

echo "[*] OS Hardening Complete!"
