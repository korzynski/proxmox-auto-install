#!/bin/bash
exec > >(tee -a /var/log/first-boot-hardening.log) 2>&1
set -euxo pipefail

# ========= customize these =========
ALLOWED_V4="82.140.161.179/32, 10.55.55.0/24"                  # authorized IPs
ALLOWED_V6=""                                   # or e.g. "2001:db8::123/128"
# ===================================

echo "[hardening] starting pre-network hardening"

# 1) Lock root password immediately
if passwd -S root | grep -qv 'L '; then
  passwd -l root || true
  echo "[hardening] root password locked"
fi

# 2) SSH hardening: key-only, no password auth
if ! grep -qE '^[#[:space:]]*PasswordAuthentication no' /etc/ssh/sshd_config; then
  sed -i -E \
    -e 's/^[#[:space:]]*PasswordAuthentication.*/PasswordAuthentication no/' \
    -e 's/^[#[:space:]]*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' \
    -e 's/^[#[:space:]]*UsePAM.*/UsePAM yes/' \
    /etc/ssh/sshd_config
fi

# Allow root over keys only. To block root SSH entirely, change to "PermitRootLogin no".
if grep -qE "^[#[:space:]]*PermitRootLogin" /etc/ssh/sshd_config; then
  sed -i "s/^[#[:space:]]*PermitRootLogin.*/PermitRootLogin prohibit-password/" /etc/ssh/sshd_config
else
  printf "\nPermitRootLogin prohibit-password\n" >> /etc/ssh/sshd_config
fi

systemctl restart ssh || systemctl restart sshd || true
echo "[hardening] sshd hardened"

# 3) bind Proxmox GUI to localhost
if grep -q '^LISTEN_IPS' /etc/default/pveproxy; then
sed -i 's/^LISTEN_IPS=.*/LISTEN_IPS=127.0.0.1/' /etc/default/pveproxy
else
echo 'LISTEN_IPS=127.0.0.1' >> /etc/default/pveproxy
fi
systemctl restart pveproxy || true
echo "[hardening] GUI bound to localhost"

# 3b) switch to no-subscription repo if not already done
# (you can remove this if you have a subscription)
export DEBIAN_FRONTEND=noninteractive
sed -i 's|^deb https://enterprise.proxmox.com|# &|' /etc/apt/sources.list.d/pve-enterprise.list 2>/dev/null || true
cat >/etc/apt/sources.list.d/pve-no-subscription.list <<'EOF'
deb http://download.proxmox.com/debian/pve trixie pve-no-subscription
EOF

# 4) nftables allowlist firewall for 22 and 8006
apt-get update
apt-get -y install nftables fail2ban

cat >/etc/nftables.conf <<EOF
flush ruleset
table inet filter {
  sets {
    allowed4 { type ipv4_addr; flags interval; elements = { $ALLOWED_V4 } }
    allowed6 { type ipv6_addr; flags interval; elements = { $ALLOWED_V6 } }
  }
  chains {
    input {
      type filter hook input priority 0; policy drop;

      # basic hygiene
      iif lo accept
      ct state established,related accept

      # ICMP is useful for troubleshooting; trim if you prefer stricter
      ip protocol icmp type { echo-request, echo-reply } ip saddr @allowed4 accept
      ip6 nexthdr icmpv6 type { echo-request, echo-reply } ip6 saddr @allowed6 accept

      # SSH 22
      tcp dport 22 ip saddr @allowed4 accept
      tcp dport 22 ip6 saddr @allowed6 accept

      # Proxmox GUI 8006
      tcp dport 8006 ip saddr @allowed4 accept
      tcp dport 8006 ip6 saddr @allowed6 accept

      # everything else drops by default
      drop
    }
    forward { type filter hook forward priority 0; policy drop; }
    output  { type filter hook output  priority 0; policy accept; }
  }
}
EOF

systemctl enable nftables
systemctl restart nftables || true
echo "[hardening] nftables allowlist active"

# 5) Fail2ban (uses nftables)
export DEBIAN_FRONTEND=noninteractive

# Global defaults for nftables + sane timings
cat >/etc/fail2ban/jail.local <<'JEOF'
[DEFAULT]
banaction = nftables-multiport
banaction_allports = nftables-allports
backend = systemd
findtime = 10m
bantime  = 1h
maxretry = 6
# Log to syslog by default; journal backend reads systemd journal

[sshd]
enabled  = true
port     = 22
filter   = sshd
logpath  = %(sshd_log)s
maxretry = 6
findtime = 10m
bantime  = 2h

# protect Proxmox web (pveproxy) brute attempts.
[pveproxy]
enabled  = true
port     = 8006
filter   = pveproxy
logpath  = /var/log/pveproxy/access.log
maxretry = 8
findtime = 10m
bantime  = 2h
JEOF

# Optional pveproxy filter (only if you enable the jail above)
cat >/etc/fail2ban/filter.d/pveproxy.conf <<'FEOF'
[Definition]
failregex = ^<HOST> - - \[.*\] "POST /api2/json/access/ticket HTTP/1\.[01]" 401
ignoreregex =
FEOF

systemctl enable --now fail2ban
echo "[hardening] fail2ban enabled"

echo "[hardening] done"
touch /var/lib/proxmox-first-boot.d/network-online-hardening.ok