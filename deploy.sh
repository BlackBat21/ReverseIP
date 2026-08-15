#!/usr/bin/env bash
#
# RECON Reverse IP Lookup - one-line VPS deployer.
#
# Host this file in your GitHub repo (next to app.py, static/, requirements.txt,
# .env.example) and deploy on a fresh Ubuntu 24.04 VPS with ONE command:
#
#   # public HTTPS deployment (nginx + Let's Encrypt TLS + firewall):
#   curl -fsSL https://raw.githubusercontent.com/BlackBat21/ReverseIP/main/deploy.sh \
#     | sudo bash -s -- --domain recon.example.com --email you@example.com
#
#   # loopback-only install (no public exposure, prints manual TLS steps):
#   curl -fsSL https://raw.githubusercontent.com/BlackBat21/ReverseIP/main/deploy.sh | sudo bash
#
# The repo must be PUBLIC (a piped one-liner cannot prompt for git credentials).
# For a private repo, embed a token in --repo, e.g.
#   --repo https://<TOKEN>@github.com/BlackBat21/ReverseIP.git
#
set -euo pipefail

# ----------------------------------------------------------------------------
# EDIT THIS ONCE: point it at YOUR repository (or pass --repo / RECON_REPO=...).
# ----------------------------------------------------------------------------
REPO_URL="${RECON_REPO:-https://github.com/BlackBat21/ReverseIP.git}"
BRANCH="${RECON_BRANCH:-main}"
SUBDIR="${RECON_SUBDIR:-.}"          # path to app.py inside the repo (default: root)

# ---- deployment targets ----
APP_DIR=/opt/recon
WWW_DIR=/var/www/recon
RESULTS_DIR="$WWW_DIR/results"
SERVICE_USER=recon
BUILD_DIR="$APP_DIR/src"

# ---- optional TLS/proxy config (from args or env) ----
DOMAIN="${RECON_DOMAIN:-}"
EMAIL="${RECON_EMAIL:-}"
ENABLE_TLS=1

# ---- arg parsing ----
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2;;
    --email)  EMAIL="${2:-}";  shift 2;;
    --repo)   REPO_URL="${2:-}"; shift 2;;
    --branch) BRANCH="${2:-}"; shift 2;;
    --subdir) SUBDIR="${2:-}"; shift 2;;
    --no-tls) ENABLE_TLS=0; shift;;
    -h|--help)
      echo "Usage: deploy.sh [--domain d] [--email e] [--repo url] [--branch b] [--subdir p] [--no-tls]"; exit 0;;
    *) echo "Unknown option: $1" >&2; exit 1;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run as root  ->  curl ... | sudo bash" >&2
  exit 1
fi
if [[ "$REPO_URL" == *YOUR_GITHUB_USER* || -z "$REPO_URL" ]]; then
  echo "ERROR: set your repo. Edit REPO_URL in deploy.sh, or pass --repo <url> / RECON_REPO=<url>." >&2
  exit 1
fi
if [[ "$ENABLE_TLS" -eq 1 && -n "$DOMAIN" && -z "$EMAIL" ]]; then
  echo "[i] No --email given; certbot will register without a recovery email." >&2
fi

echo "[*] Installing system packages ..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y git python3 python3-venv python3-pip openssl

echo "[*] Fetching application from $REPO_URL ($BRANCH) ..."
mkdir -p "$APP_DIR"
# Git 2.35.2+ refuses to operate on a repo owned by another user. After the
# first install $BUILD_DIR is owned by the service account, but this script
# runs git as root - so mark it safe (idempotently) before touching it.
if [[ -d "$BUILD_DIR/.git" ]] \
   && ! git config --global --get-all safe.directory 2>/dev/null | grep -qxF "$BUILD_DIR"; then
  git config --global --add safe.directory "$BUILD_DIR"
fi
if [[ -d "$BUILD_DIR/.git" ]]; then
  git -C "$BUILD_DIR" remote set-url origin "$REPO_URL"
  git -C "$BUILD_DIR" fetch --depth 1 origin "$BRANCH"
  git -C "$BUILD_DIR" checkout -f "$BRANCH"
  git -C "$BUILD_DIR" reset --hard "origin/$BRANCH"
else
  rm -rf "$BUILD_DIR"
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$BUILD_DIR"
fi

SRC="$BUILD_DIR/$SUBDIR"
for f in app.py requirements.txt .env.example static; do
  if [[ ! -e "$SRC/$f" ]]; then
    echo "ERROR: '$f' not found in repo (subdir '$SUBDIR'). Check --subdir." >&2
    exit 1
  fi
done
echo "[*] Creating service user '$SERVICE_USER' ..."
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

echo "[*] Deploying application to $APP_DIR ..."
cp -f "$SRC/app.py"           "$APP_DIR/"
cp -f "$SRC/requirements.txt" "$APP_DIR/"
rm -rf "$APP_DIR/static"
cp -r "$SRC/static"           "$APP_DIR/"
mkdir -p "$RESULTS_DIR"

echo "[*] Building Python virtualenv ..."
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/.venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

echo "[*] Configuring environment file ..."
ENV_FILE="$APP_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  GEN_PASS="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)"
  cp "$SRC/.env.example" "$ENV_FILE"
  sed -i "s|^RECON_PASS=.*|RECON_PASS=${GEN_PASS}|" "$ENV_FILE"
  CREDS_MSG="admin / ${GEN_PASS}"
else
  CREDS_MSG="(existing $ENV_FILE kept - credentials unchanged)"
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

# ---------------------------------------------------------------------------
# Optional: nginx reverse proxy + Let's Encrypt TLS + firewall (public deploy)
# ---------------------------------------------------------------------------
if [[ -n "$DOMAIN" && "$ENABLE_TLS" -eq 1 ]]; then
  echo "[*] Configuring firewall, nginx, and TLS for $DOMAIN ..."
  apt-get install -y nginx certbot python3-certbot-nginx ufw

  # Allow SSH BEFORE enabling the firewall so we never lock ourselves out.
  ufw allow OpenSSH        >/dev/null 2>&1 || true
  ufw allow 'Nginx Full'   >/dev/null 2>&1 || true
  ufw --force enable       >/dev/null 2>&1 || true

  cat > /etc/nginx/sites-available/recon <<NGINX
server {
    listen 80;
    server_name $DOMAIN;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
NGINX
  ln -sf /etc/nginx/sites-available/recon /etc/nginx/sites-enabled/recon
  rm -f /etc/nginx/sites-enabled/default
  nginx -t && systemctl reload nginx

  if [[ -n "$EMAIL" ]]; then
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect \
      || echo "[!] certbot failed - is the DNS A record for $DOMAIN pointed at this VPS?"
  else
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect \
      || echo "[!] certbot failed - is the DNS A record for $DOMAIN pointed at this VPS?"
  fi
fi
# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
if systemctl is-active --quiet recon.service; then
  echo "[+] recon.service is RUNNING."
else
  echo "[!] recon.service failed to start. Inspect: journalctl -u recon -n 40 --no-pager"
fi

if [[ -n "$DOMAIN" && "$ENABLE_TLS" -eq 1 ]]; then
  URL="https://$DOMAIN"
else
  URL="http://127.0.0.1:8000  (loopback only - add TLS before exposing publicly)"
fi

echo ""
echo "============================================================================"
echo " DEPLOYMENT COMPLETE"
echo "============================================================================"
echo " URL:         $URL"
echo " Login:       $CREDS_MSG"
echo " Env file:    $APP_DIR/.env      (edit, then: systemctl restart recon)"
echo " Results dir: $RESULTS_DIR"
echo " Logs:        journalctl -u recon -f"
echo "----------------------------------------------------------------------------"

if [[ -z "$DOMAIN" || "$ENABLE_TLS" -ne 1 ]]; then
cat <<'NEXT'
 The service is bound to 127.0.0.1:8000 (not reachable from the internet).
 HTTP Basic Auth is base64-encoded, NOT encrypted - terminate TLS in front
 before exposing it. Re-run with a domain to do this automatically:

   curl -fsSL <raw-deploy.sh-url> | sudo bash -s -- --domain YOUR.DOMAIN.com --email you@example.com

 (Point the domain's DNS A record at this VPS first.)
NEXT
fi
echo "============================================================================"
