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

# 3) bind Proxmox GUI to localhost (reliable on PVE 9+ via systemd override)
mkdir -p /etc/default
cat >/etc/default/pveproxy <<'EOF'
LISTEN_IP="127.0.0.1"
EOF
systemctl restart pveproxy || true
echo "[hardening] GUI bound to localhost (systemd override)"

# 4) switch to no-subscription repo if not already done
# --- Safe repo switch (handles .list and .sources) 

# Quarantine enterprise/Ceph entries regardless of naming/format
mkdir -p /etc/apt/sources.list.d/disabled
for f in /etc/apt/sources.list.d/*; do
  # Skip non-files
  [ -f "$f" ] || continue
  if grep -qi 'enterprise\.proxmox\.com' "$f"; then
    mv -f "$f" /etc/apt/sources.list.d/disabled/
    continue
  fi
  if echo "$f" | grep -qi 'ceph'; then
    # If it references enterprise, quarantine as well
    if grep -qi 'enterprise\.proxmox\.com' "$f"; then
      mv -f "$f" /etc/apt/sources.list.d/disabled/
    fi
  fi
done

# Enable no-subscription PVE 9 repo (Debian 13 "trixie")
cat >/etc/apt/sources.list.d/pve-no-subscription.list <<'EOF'
deb http://download.proxmox.com/debian/pve trixie pve-no-subscription
EOF

echo "[hardening] switched to no-subscription repo"

# 5) nftables + fail2ban setup

# install and enable nftables + fail2ban
export DEBIAN_FRONTEND=noninteractive
apt-get clean
apt-get -o Acquire::Retries=3 update
apt-get -y install nftables fail2ban

systemctl enable --now nftables fail2ban

# Build nftables ruleset
build_rules() {
  nft -j list ruleset >/dev/null 2>&1 || true
  nft -f - <<'EOF'
flush ruleset
add table inet filter
add set inet filter allowed4 { type ipv4_addr; flags interval; }
add set inet filter allowed6 { type ipv6_addr; flags interval; }

add chain inet filter input   { type filter hook input   priority 0; policy drop; }
add chain inet filter forward { type filter hook forward priority 0; policy drop; }
add chain inet filter output  { type filter hook output  priority 0; policy accept; }

# hygiene
add rule inet filter input iifname "lo" accept
add rule inet filter input ct state established,related accept
EOF

  # Populate sets
  if [[ -n "$ALLOWED_V4" ]]; then
    NFTV4=$(printf '%s\n' "$ALLOWED_V4" | tr ',' '\n' | awk '{$1=$1};1' | paste -sd, -)
    nft add element inet filter allowed4 "{ ${NFTV4} }"
  fi

  if [[ -n "$ALLOWED_V6" ]]; then
    NFTV6=$(printf '%s\n' "$ALLOWED_V6" | tr ',' '\n' | awk '{$1=$1};1' | paste -sd, -)
    nft add element inet filter allowed6 "{ ${NFTV6} }"
  fi

  # ICMP rules (only add v6 if we actually have allowed6 members)
  nft add rule inet filter input ip protocol icmp icmp type { echo-request, echo-reply } ip saddr @allowed4 accept
  if [[ -n "$ALLOWED_V6" ]]; then
    nft add rule inet filter input ip6 nexthdr icmpv6 icmpv6 type { echo-request, echo-reply } ip6 saddr @allowed6 accept
  fi

  # SSH and GUI
  nft add rule inet filter input tcp dport 22    ip saddr @allowed4 accept
  nft add rule inet filter input tcp dport 8006  ip saddr @allowed4 accept
  if [[ -n "$ALLOWED_V6" ]]; then
    nft add rule inet filter input tcp dport 22    ip6 saddr @allowed6 accept
    nft add rule inet filter input tcp dport 8006  ip6 saddr @allowed6 accept
  fi
}

# Validate by exporting and re-parsing (dry run)
apply_rules() {
  TMP=/tmp/nft-rules.$$; trap 'rm -f "$TMP"' EXIT
  nft list ruleset > "$TMP"
  nft -c -f "$TMP"      # parse-check
  nft -f "$TMP"         # apply
  nft -c -f /etc/nftables.conf && systemctl reload nftables
}

build_rules
apply_rules

# build fail2ban config
mkdir -p /etc/fail2ban
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
mkdir -p /etc/fail2ban/filter.d
cat >/etc/fail2ban/filter.d/pveproxy.conf <<'FEOF'
[Definition]
failregex = ^<HOST> - - \[.*\] "POST /api2/json/access/ticket HTTP/1\.[01]" 401
ignoreregex =
FEOF

fail2ban-client reload

nft list ruleset | head -n 60
fail2ban-client status sshd
echo "[hardening] nftables + fail2ban installed and running"

echo "[hardening] done"
touch /var/lib/proxmox-first-boot.d/network-online-hardening.ok