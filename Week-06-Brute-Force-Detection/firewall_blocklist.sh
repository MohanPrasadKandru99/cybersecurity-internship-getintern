#!/usr/bin/env bash
# =====================================================================
# AUTOMATED SOC FIREWALL CONTAINMENT BLOCKLIST
# Generated: 2026-11-24 00:16:45 UTC
# Engine: Automated Incident Alerting & Brute-Force Detection Engine
# Total Malicious Source IPs: 1
# =====================================================================
set -euo pipefail

# Ensure root execution
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: This containment script must be executed as root (sudo)." >&2
    exit 1
fi

echo "[*] Initiating SOC Brute-Force Host Containment..."

# Check firewall tooling
HAS_UFW=false
HAS_IPTABLES=false
if command -v ufw >/dev/null 2>&1 && ufw status | grep -qw 'active'; then HAS_UFW=true; fi
if command -v iptables >/dev/null 2>&1; then HAS_IPTABLES=true; fi

echo "[*] Applying UFW perimeter rules..."
if [ "$HAS_UFW" = true ]; then
    # SEC-ALERT-20261024-001 | HIGH | Horizontal Password Spraying
    ufw insert 1 deny from 192.168.245.1 to any port 22 proto tcp comment 'SEC-ALERT-20261024-001-Containment' || true
    echo "[+] UFW rules successfully applied."
else
    echo "[-] UFW inactive or not installed; skipping UFW insert."
fi

echo "[*] Applying iptables kernel packet filters..."
if [ "$HAS_IPTABLES" = true ]; then
    # SEC-ALERT-20261024-001 | HIGH
    if ! iptables -C INPUT -s 192.168.245.1 -p tcp --dport 22 -j DROP 2>/dev/null; then
        iptables -I INPUT 1 -s 192.168.245.1 -p tcp --dport 22 -j DROP -m comment --comment 'SEC-ALERT-20261024-001-Containment'
        echo "  [+] Blocked 192.168.245.1 (iptables port 22)"
    else
        echo "  [~] Rule for 192.168.245.1 already present in iptables; skipping."
    fi
    echo "[+] iptables rules successfully applied."
fi

echo ""
echo "[✓] Containment complete. All 1 attacking IP(s) blocked."
echo "[i] Verification commands:"
echo "    ufw status numbered"
echo "    iptables -L INPUT -v -n | grep -E '192\.168\.245\.1'"

# =====================================================================
# ROLLBACK / UNBLOCK INSTRUCTIONS (Execute manually if false-positive):
# sudo ufw delete deny from 192.168.245.1 to any port 22 proto tcp
# sudo iptables -D INPUT -s 192.168.245.1 -p tcp --dport 22 -j DROP
# =====================================================================
