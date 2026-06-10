#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${FREEWAF_APP_DIR:-/opt/freewaf}"
ENV_DIR="${FREEWAF_ENV_DIR:-/etc/freewaf}"
ENV_FILE="${ENV_DIR}/freewaf.env"
SERVICE_FILE="/etc/systemd/system/freewaf.service"
NGINX_INCLUDE="/etc/nginx/conf.d/freewaf.conf"
ADMIN_PORT="${ADMIN_PORT:-7001}"
DEMO_ORIGIN_PORT="${DEMO_ORIGIN_PORT:-9090}"
ENABLE_DEMO_ORIGIN="${ENABLE_DEMO_ORIGIN:-true}"
REPO_URL="${FREEWAF_REPO_URL:-}"
REPO_BRANCH="${FREEWAF_REPO_BRANCH:-main}"

log() {
  printf '\n[freewaf] %s\n' "$*" >&2
}

fail() {
  printf '\n[freewaf] ERROR: %s\n' "$*" >&2
  exit 1
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    fail "Run as root: sudo bash install.sh"
  fi
}

detect_os() {
  if [ ! -r /etc/os-release ]; then
    fail "Cannot detect operating system"
  fi

  . /etc/os-release
  case "${ID}:${VERSION_ID}" in
    debian:12|debian:13|ubuntu:24.04)
      log "Detected supported OS: ${PRETTY_NAME}"
      ;;
    *)
      if [ "${FREEWAF_ALLOW_UNSUPPORTED:-false}" = "true" ]; then
        log "Unsupported OS (${PRETTY_NAME:-unknown}); continuing because FREEWAF_ALLOW_UNSUPPORTED=true"
      else
        fail "Supported OS: Debian 12, Debian 13, Ubuntu 24.04. Detected: ${PRETTY_NAME:-unknown}"
      fi
      ;;
  esac
}

apt_install_base() {
  export DEBIAN_FRONTEND=noninteractive
  log "Installing system packages"
  apt-get update
  apt-get install -y \
    ca-certificates \
    curl \
    git \
    gnupg \
    nginx \
    openssl \
    python3 \
    python3-venv \
    rsync \
    certbot \
    python3-certbot-nginx
}

node_major() {
  if ! command -v node >/dev/null 2>&1; then
    echo 0
    return
  fi
  node -p "Number(process.versions.node.split('.')[0])" 2>/dev/null || echo 0
}

install_nodejs() {
  local major
  major="$(node_major)"
  if [ "$major" -ge 20 ] 2>/dev/null; then
    log "Node.js $(node -v) is already installed"
    return
  fi

  log "Installing Node.js from distro packages"
  apt-get install -y nodejs npm || true
  major="$(node_major)"
  if [ "$major" -ge 20 ] 2>/dev/null; then
    log "Node.js $(node -v) is ready"
    return
  fi

  log "Distro Node.js is too old for Vite; installing Node.js 22 from NodeSource"
  install -d -m 0755 /etc/apt/keyrings
  rm -f /etc/apt/keyrings/nodesource.gpg /etc/apt/sources.list.d/nodesource.list
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
  chmod 0644 /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list
  apt-get update
  apt-get install -y nodejs

  major="$(node_major)"
  if [ "$major" -lt 20 ] 2>/dev/null; then
    fail "Node.js 20+ is required, got $(node -v 2>/dev/null || echo missing)"
  fi
}

source_dir() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [ -f "${script_dir}/backend/run.py" ] && [ -f "${script_dir}/frontend/package.json" ]; then
    echo "$script_dir"
    return
  fi

  if [ -n "$REPO_URL" ]; then
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    log "Cloning ${REPO_URL} (${REPO_BRANCH})"
    git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$tmp_dir/freewaf"
    echo "$tmp_dir/freewaf"
    return
  fi

  fail "Run this installer from a FreeWAF checkout, or set FREEWAF_REPO_URL=https://..."
}

copy_app() {
  local src="$1"
  log "Installing application to ${APP_DIR}"
  install -d -m 0755 "$APP_DIR"
  rsync -a --delete \
    --exclude ".git/" \
    --exclude ".claude/" \
    --exclude ".research/" \
    --exclude "node_modules/" \
    --exclude "frontend/node_modules/" \
    --exclude "frontend/dist/" \
    --exclude "data/state.json" \
    --exclude "logs/" \
    --exclude "nginx/certs/*" \
    --exclude "nginx/generated/*" \
    --exclude ".env" \
    "$src"/ "$APP_DIR"/

  install -d -m 0755 "$APP_DIR/data" "$APP_DIR/logs" "$APP_DIR/nginx/generated" "$APP_DIR/nginx/certs" "$APP_DIR/public/static"
  if [ ! -f "$APP_DIR/nginx/generated/freewaf.conf" ]; then
    printf '# FreeWAF generated config placeholder.\n# Use the admin panel Settings -> Nginx Config -> Write Config.\n' \
      > "$APP_DIR/nginx/generated/freewaf.conf"
  fi
}

build_frontend() {
  log "Building React dashboard"
  cd "$APP_DIR/frontend"
  npm ci
  npm run build
  rm -rf "$APP_DIR/frontend/node_modules"
}

install_geoip_database() {
  local geoip_dir="/var/lib/freewaf/geoip"
  local geoip_file="${geoip_dir}/dbip-country-lite.csv.gz"
  local year month url tmp_file
  year="$(date +%Y)"
  month="$(date +%m)"
  url="https://download.db-ip.com/free/dbip-country-lite-${year}-${month}.csv.gz"
  tmp_file="$(mktemp)"

  log "Downloading DB-IP country database"
  install -d -m 0755 "$geoip_dir"
  if curl -fsSL --retry 3 --connect-timeout 15 "$url" -o "$tmp_file" && gzip -t "$tmp_file"; then
    install -m 0644 "$tmp_file" "$geoip_file"
    printf '%s\n' "$url" > "${geoip_file}.source"
  else
    log "GeoIP database download failed; country statistics will show Unknown until ${geoip_file} exists"
  fi
  rm -f "$tmp_file"
}

write_env() {
  log "Writing ${ENV_FILE}"
  install -d -m 0755 "$ENV_DIR"
  cat > "$ENV_FILE" <<EOF
ADMIN_PORT=${ADMIN_PORT}
DEMO_ORIGIN_PORT=${DEMO_ORIGIN_PORT}
ENABLE_DEMO_ORIGIN=${ENABLE_DEMO_ORIGIN}
DATA_FILE=${APP_DIR}/data/state.json
NGINX_OUTPUT_FILE=${APP_DIR}/nginx/generated/freewaf.conf
NGINX_ACCESS_LOG=${APP_DIR}/logs/freewaf_access.log
NGINX_SITE_LOG_DIR=${APP_DIR}/logs/freewaf
NGINX_CERT_DIR=${APP_DIR}/nginx/certs
NGINX_TEST_CMD="/usr/sbin/nginx -t"
NGINX_RELOAD_CMD="/usr/sbin/nginx -s reload"
NGINX_AUTO_WRITE=false
NGINX_AUTH_FILE=
NGINX_HAS_BROTLI=false
NGINX_CHAOS_CHALLENGE_URL=
NGINX_FREEWAF_STATIC_DIR=
NGINX_STATIC_ROOT=${APP_DIR}/public/static
CERTBOT_CMD=/usr/bin/certbot
CERTBOT_AUTH_METHOD=nginx
CERTBOT_WEBROOT=/var/www/html
CERTBOT_LIVE_DIR=/etc/letsencrypt/live
IP_GROUP_AUTO_SYNC=true
IP_GROUP_SYNC_INTERVAL_SECONDS=86400
IP_GROUP_SYNC_CHECK_SECONDS=3600
IP_GROUP_REFERENCE_TIMEOUT=20
IP_GROUP_REFERENCE_MAX_BYTES=20971520
IP_GROUP_EXTERNALIZE_COUNT=5000
IP_GROUP_EXTERNALIZE_BYTES=262144
STATS_LOG_SCAN_LIMIT=50000
STATS_LOG_SCAN_MAX=250000
GEOIP_DB_FILE=/var/lib/freewaf/geoip/dbip-country-lite.csv.gz
EOF
  chmod 0600 "$ENV_FILE"
}

refresh_nginx_config() {
  log "Refreshing generated Nginx config"
  set -a
  # shellcheck source=/dev/null
  . "$ENV_FILE"
  set +a

  (
    cd "$APP_DIR"
    PYTHONPATH="${APP_DIR}/backend" /usr/bin/python3 - <<'PY'
from pathlib import Path

from freewaf.nginx import write_nginx_config
from freewaf.store import Store, resolve_data_file

root_dir = Path.cwd()
store = Store(resolve_data_file(root_dir))
store.init()
output_file = write_nginx_config(root_dir, store.get_state())
print(output_file)
PY
  )
}

write_systemd() {
  log "Writing systemd service"
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=FreeWAF Admin Panel
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/bin/python3 ${APP_DIR}/backend/run.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable freewaf
}

write_nginx_include() {
  log "Writing Nginx include ${NGINX_INCLUDE}"
  install -d -m 0755 /etc/nginx/conf.d
  cat > "$NGINX_INCLUDE" <<EOF
# FreeWAF generated configuration is included inside nginx http {}.
include ${APP_DIR}/nginx/generated/freewaf.conf;
EOF
  nginx -t
  systemctl enable nginx
  systemctl reload nginx || systemctl restart nginx
}

start_service() {
  log "Starting FreeWAF"
  systemctl restart freewaf
  systemctl --no-pager --full status freewaf || true
  if ! systemctl is-active --quiet freewaf; then
    fail "FreeWAF service did not start. Check: journalctl -u freewaf -n 100 --no-pager"
  fi
}

print_done() {
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [ -n "$ip" ] || ip="SERVER_IP"
  cat <<EOF

FreeWAF installed.

Open:
  http://${ip}:${ADMIN_PORT}

First login:
  Create the first admin account in the browser.

Useful commands:
  systemctl status freewaf
  journalctl -u freewaf -f
  nginx -t

EOF
}

main() {
  require_root
  detect_os
  apt_install_base
  install_nodejs
  local src
  src="$(source_dir)"
  copy_app "$src"
  build_frontend
  install_geoip_database
  write_env
  refresh_nginx_config
  write_systemd
  write_nginx_include
  start_service
  print_done
}

main "$@"
