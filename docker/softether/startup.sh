#!/bin/bash
# Start SoftEther VPN Server and configure it for IKEv1/L2TP PSK testing.
set -e

SE_PSK="${SE_PSK:-secret}"
SE_USER="${SE_USER:-test}"
SE_PASS="${SE_PASS:-secret}"
SE_HUB="${SE_HUB:-VPN}"
MGMT_PASS="admin"

cd /opt/vpnserver

echo "[startup] Starting SoftEther VPN Server …"
./vpnserver start

# Wait for management port (TCP 443) to become available
for i in $(seq 1 20); do
    if ./vpncmd localhost:443 /SERVER /CMD About >/dev/null 2>&1; then
        echo "[startup] Server ready (attempt $i)"
        break
    fi
    sleep 1
done

# ── Initial configuration (idempotent) ────────────────────────────────────
echo "[startup] Configuring server …"

./vpncmd localhost:443 /SERVER /CMD \
    ServerPasswordSet "${MGMT_PASS}" 2>/dev/null || true

./vpncmd localhost:443 /SERVER /PASSWORD:"${MGMT_PASS}" /CMD \
    HubCreate "${SE_HUB}" /PASSWORD: 2>/dev/null || true

./vpncmd localhost:443 /SERVER /PASSWORD:"${MGMT_PASS}" /VIRTUALHOST:"${SE_HUB}" /CMD \
    UserCreate "${SE_USER}" /GROUP: /REALNAME:"test" /NOTE: 2>/dev/null || true

./vpncmd localhost:443 /SERVER /PASSWORD:"${MGMT_PASS}" /VIRTUALHOST:"${SE_HUB}" /CMD \
    UserPasswordSet "${SE_USER}" /PASSWORD:"${SE_PASS}" 2>/dev/null || true

# Enable L2TP/IPSec with the configured PSK
./vpncmd localhost:443 /SERVER /PASSWORD:"${MGMT_PASS}" /CMD \
    IPsecEnable \
        /L2TP:yes \
        /L2TPRAW:no \
        /ETHERIP:no \
        /PSK:"${SE_PSK}" \
        /DEFAULTHUB:"${SE_HUB}"

echo "[startup] IPSec/L2TP enabled  PSK=${SE_PSK}  hub=${SE_HUB}  user=${SE_USER}"
echo "[startup] IKE listening on UDP 500 / 4500"

# Tail the server log so the container stays alive and logs are visible
mkdir -p /opt/vpnserver/server_log
tail -F /opt/vpnserver/server_log/*.log 2>/dev/null || \
    tail -F /opt/vpnserver/server_log/vpn_*.log 2>/dev/null &

# Keep container alive; restart vpnserver if it dies
while true; do
    if ! ./vpncmd localhost:443 /SERVER /PASSWORD:"${MGMT_PASS}" /CMD About >/dev/null 2>&1; then
        echo "[startup] Server died — restarting"
        ./vpnserver start
        sleep 3
    fi
    sleep 5
done
