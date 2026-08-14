#!/usr/bin/env bash
#
# RECON Reverse IP Lookup - Ubuntu 24.04 LTS installer.
#
# Run as root FROM the directory that contains app.py, static/, requirements.txt:
#     sudo bash setup.sh
#
# Installs into /opt/recon, writes results to /var/www/recon/results, and runs
# the app as a hardened, memory-capped (<250 MB) systemd service.
#
set -euo pipefail

APP_DIR=/opt/recon
WWW_DIR=/var/www/recon
RESULTS_DIR="$WWW_DIR/results"
SERVICE_USER=recon
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run as root  ->  sudo bash setup.sh" >&2
  exit 1
fi

echo "[*] Installing system packages ..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 python3-venv python3-pip openssl

echo "[*] Creating service user '$SERVICE_USER' ..."
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

echo "[*] Deploying application to $APP_DIR ..."
mkdir -p "$APP_DIR"
cp -f  "$SRC_DIR/app.py"          "$APP_DIR/"
cp -f  "$SRC_DIR/requirements.txt" "$APP_DIR/"
rm -rf "$APP_DIR/static"
cp -r  "$SRC_DIR/static"          "$APP_DIR/"

echo "[*] Creating results directory $RESULTS_DIR ..."
mkdir -p "$RESULTS_DIR"

echo "[*] Building Python virtualenv ..."
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/.venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

echo "[*] Configuring environment file ..."
ENV_FILE="$APP_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  GEN_PASS="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)"
  cp "$SRC_DIR/.env.example" "$ENV_FILE"
  sed -i "s|^RECON_PASS=.*|RECON_PASS=${GEN_PASS}|" "$ENV_FILE"
  echo ""
  echo "    ==> Generated credentials:  admin / ${GEN_PASS}"
  echo "    ==> Stored in $ENV_FILE (edit to customise)"
  echo ""
else
  echo "    Existing $ENV_FILE kept."
fi
chmod 600 "$ENV_FILE"

echo "[*] Setting ownership & permissions ..."
chown -R "$SERVICE_USER":"$SERVICE_USER" "$APP_DIR" "$WWW_DIR"

echo "[*] Installing systemd unit ..."
cat > /etc/systemd/system/recon.service <<UNIT
[Unit]
Description=RECON Reverse IP Lookup
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=$APP_DIR/.venv/bin/uvicorn app:app --host \${RECON_HOST} --port \${RECON_PORT} --workers 1
Restart=on-failure
RestartSec=3

# ---- resource cap: keep the 1 GB VPS healthy (hard-kill above 250 MB) ----
MemoryMax=250M
MemoryHigh=200M
CPUQuota=85%

# ---- sandbox hardening ----
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$WWW_DIR
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable recon.service >/dev/null 2>&1 || true
systemctl restart recon.service

sleep 2
echo ""
if systemctl is-active --quiet recon.service; then
  echo "[+] recon.service is RUNNING."
else
  echo "[!] recon.service failed to start. Inspect with: journalctl -u recon -n 40 --no-pager"
fi
cat <<'NEXT'

============================================================================
 DEPLOYMENT COMPLETE
============================================================================
 The service listens on 127.0.0.1:8000 by default (loopback only).

 !! SECURITY: HTTP Basic Auth protects the API, but Basic credentials are
    sent base64-encoded, NOT encrypted. You MUST terminate TLS in front of
    this service before exposing it publicly. Recommended: nginx + certbot.

 --- Put TLS + reverse proxy in front (recommended) --------------------------
   sudo apt-get install -y nginx certbot python3-certbot-nginx

   sudo tee /etc/nginx/sites-available/recon >/dev/null <<'NGINX'
   server {
       listen 80;
       server_name YOUR.DOMAIN.com;
       location / {
           proxy_pass http://127.0.0.1:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   NGINX

   sudo ln -sf /etc/nginx/sites-available/recon /etc/nginx/sites-enabled/recon
   sudo nginx -t && sudo systemctl reload nginx
   sudo certbot --nginx -d YOUR.DOMAIN.com          # provisions HTTPS

 --- Useful commands ---------------------------------------------------------
   systemctl status recon         # service state
   journalctl -u recon -f         # live logs
   nano /opt/recon/.env           # change credentials / limits (then restart)
   systemctl restart recon        # apply config changes

 Results are saved to /var/www/recon/results/*.txt
============================================================================
NEXT


