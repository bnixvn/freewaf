#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${FREEWAF_APP_DIR:-/opt/freewaf}"
ENV_DIR="${FREEWAF_ENV_DIR:-/etc/freewaf}"
ENV_FILE="${ENV_DIR}/freewaf.env"
SERVICE_FILE="/etc/systemd/system/freewaf.service"
HEALTHCHECK_SCRIPT="/usr/local/sbin/freewaf-healthcheck"
HEALTHCHECK_SERVICE="/etc/systemd/system/freewaf-healthcheck.service"
HEALTHCHECK_TIMER="/etc/systemd/system/freewaf-healthcheck.timer"
NGINX_INCLUDE="/etc/nginx/conf.d/freewaf.conf"
NGINX_UPLOAD_LIMIT_INCLUDE="/etc/nginx/conf.d/00-upload-size.conf"
NGINX_CLIENT_MAX_BODY_SIZE="${FREEWAF_NGINX_CLIENT_MAX_BODY_SIZE:-512M}"
LOGROTATE_FILE="/etc/logrotate.d/freewaf"
CERTBOT_DEPLOY_HOOK="/etc/letsencrypt/renewal-hooks/deploy/freewaf-nginx-reload"
ADMIN_PORT="${ADMIN_PORT:-7001}"
DEMO_ORIGIN_PORT="${DEMO_ORIGIN_PORT:-9090}"
ENABLE_DEMO_ORIGIN="${ENABLE_DEMO_ORIGIN:-true}"
REPO_URL="${FREEWAF_REPO_URL:-}"
REPO_BRANCH="${FREEWAF_REPO_BRANCH:-main}"
SKIP_SERVICE_RESTART="${FREEWAF_SKIP_SERVICE_RESTART:-false}"
ENABLE_MODSECURITY="${FREEWAF_ENABLE_MODSECURITY:-true}"
COMODO_RULES_FILE="${FREEWAF_COMODO_RULES_FILE:-}"
NGINX_HAS_MODSECURITY=false

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
    logrotate \
    nginx \
    openssl \
    python3 \
    python3-venv \
    rsync \
    certbot \
    python3-certbot-nginx \
    python3-certbot-dns-cloudflare
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

install_modsecurity() {
  local modsec_dir="/etc/freewaf/modsecurity"
  local owasp_setup="/etc/modsecurity/crs/crs-setup.conf"
  local owasp_rules_dir="/usr/share/modsecurity-crs/rules"
  local module_file="/usr/lib/nginx/modules/ngx_http_modsecurity_module.so"

  if [ "$ENABLE_MODSECURITY" != "true" ]; then
    log "Skipping ModSecurity because FREEWAF_ENABLE_MODSECURITY is not true"
    return
  fi

  if ! apt-cache show libnginx-mod-http-modsecurity >/dev/null 2>&1; then
    log "ModSecurity Nginx package is unavailable on this OS; native Nginx protection remains active"
    return
  fi

  log "Installing ModSecurity and OWASP CRS payload protection"
  if ! apt-get install -y libnginx-mod-http-modsecurity modsecurity-crs; then
    log "ModSecurity installation failed; native Nginx protection remains active"
    return
  fi

  install -d -m 0755 "$modsec_dir"
  install -d -o www-data -g www-data -m 0750 /var/cache/modsecurity
  touch /var/log/nginx/freewaf_modsecurity_audit.log
  chown www-data:adm /var/log/nginx/freewaf_modsecurity_audit.log 2>/dev/null || chown www-data:www-data /var/log/nginx/freewaf_modsecurity_audit.log
  chmod 0640 /var/log/nginx/freewaf_modsecurity_audit.log

  cat > "${modsec_dir}/base.conf" <<'EOF'
SecRequestBodyAccess On
SecRequestBodyNoFilesLimit 1048576
SecRequestBodyLimitAction Reject
SecResponseBodyAccess Off
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog /var/log/nginx/freewaf_modsecurity_audit.log
SecTmpDir /var/cache/modsecurity
SecDataDir /var/cache/modsecurity
EOF

  cat > "${modsec_dir}/cms-custom.conf" <<'EOF'
# FreeWAF focused CMS rules for WordPress, WHMCS, Laravel, and CodeIgniter.
SecRule REQUEST_URI "@rx (?i)(?:^|/)(?:wp-config\.php|xmlrpc\.php|wp-admin/install\.php|wp-admin/setup-config\.php|wp-content/(?:debug\.log|uploads/.*\.php)|\.env|\.git/|composer\.(?:json|lock)|vendor/phpunit|storage/(?:logs|framework|debugbar)|bootstrap/cache|application/(?:config|logs|cache)|system/|writable/logs|configuration\.php)(?:$|[?/#])" "id:760001,phase:1,deny,status:403,log,msg:'FreeWAF CMS sensitive path access'"
SecRule ARGS_NAMES|ARGS|REQUEST_COOKIES "@rx (?i)(?:wp-config\.php|php://(?:input|filter)|expect://|phar://|storage/logs|vendor/phpunit|/etc/passwd|\.env)" "id:760002,phase:2,deny,status:403,log,msg:'FreeWAF CMS sensitive reference in input'"
SecRule REQUEST_URI "@rx (?i)(?:/wp-login\.php|/wp-admin/|/wp-json/|/xmlrpc\.php|/admin(?:/|$)|/clientarea\.php|/cart\.php|/index\.php)" "id:760003,phase:1,pass,nolog,setvar:tx.freewaf_cms_path=1"
SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(?:wpscan|sqlmap|nikto|acunetix|nuclei|masscan|zgrab|python-requests)" "id:760004,phase:1,deny,status:403,log,msg:'FreeWAF CMS scanner user-agent'"
EOF

  printf 'Include %s\n' "${modsec_dir}/base.conf" > "${modsec_dir}/cms-only.conf"
  if [ -f "$owasp_setup" ] && [ -d "$owasp_rules_dir" ]; then
    printf 'Include %s\n' "$owasp_setup" >> "${modsec_dir}/cms-only.conf"
    if [ -f /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf ]; then
      printf 'Include %s\n' /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf >> "${modsec_dir}/cms-only.conf"
    fi
    for rule_file in \
      REQUEST-901-INITIALIZATION.conf \
      REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf \
      REQUEST-905-COMMON-EXCEPTIONS.conf \
      REQUEST-930-APPLICATION-ATTACK-LFI.conf \
      REQUEST-931-APPLICATION-ATTACK-RFI.conf \
      REQUEST-932-APPLICATION-ATTACK-RCE.conf \
      REQUEST-933-APPLICATION-ATTACK-PHP.conf \
      REQUEST-941-APPLICATION-ATTACK-XSS.conf \
      REQUEST-942-APPLICATION-ATTACK-SQLI.conf \
      REQUEST-949-BLOCKING-EVALUATION.conf; do
      if [ -f "${owasp_rules_dir}/${rule_file}" ]; then
        printf 'Include %s\n' "${owasp_rules_dir}/${rule_file}" >> "${modsec_dir}/cms-only.conf"
      fi
    done
    printf 'Include %s\n' "${modsec_dir}/cms-custom.conf" >> "${modsec_dir}/cms-only.conf"
    cp "${modsec_dir}/cms-only.conf" "${modsec_dir}/owasp-crs.conf"
  else
    log "OWASP CRS package layout is incomplete; check ${owasp_setup} and ${owasp_rules_dir}"
    cp "${modsec_dir}/base.conf" "${modsec_dir}/owasp-crs.conf"
  fi

  if [ -n "$COMODO_RULES_FILE" ] && [ -f "$COMODO_RULES_FILE" ]; then
    printf 'Include %s\n' "${modsec_dir}/base.conf" > "${modsec_dir}/comodo.conf"
    printf 'Include %s\n' "$COMODO_RULES_FILE" >> "${modsec_dir}/comodo.conf"
    log "Using Comodo rules from ${COMODO_RULES_FILE}"
  elif [ -f "${modsec_dir}/owasp-crs.conf" ]; then
    cp "${modsec_dir}/owasp-crs.conf" "${modsec_dir}/comodo.conf"
    log "No Comodo rules file supplied; Comodo selection will safely fall back to OWASP CRS"
  else
    printf 'Include %s\n' "${modsec_dir}/base.conf" > "${modsec_dir}/comodo.conf"
    log "No Comodo or OWASP rules file found; ModSecurity will inspect bodies without a managed ruleset"
  fi

  if [ -f "$module_file" ]; then
    NGINX_HAS_MODSECURITY=true
  else
    log "ModSecurity package installed, but ${module_file} was not found"
  fi
}

write_env() {
  log "Writing ${ENV_FILE}"
  local challenge_secret="${FREEWAF_CHALLENGE_SECRET:-}"
  if [ -z "$challenge_secret" ] && [ -f "$ENV_FILE" ]; then
    challenge_secret="$(sed -n 's/^FREEWAF_CHALLENGE_SECRET=//p' "$ENV_FILE" | head -n 1)"
  fi
  if [ -z "$challenge_secret" ]; then
    challenge_secret="$(openssl rand -hex 32)"
  fi
  install -d -m 0755 "$ENV_DIR"
  cat > "$ENV_FILE" <<EOF
ADMIN_PORT=${ADMIN_PORT}
DEMO_ORIGIN_PORT=${DEMO_ORIGIN_PORT}
ENABLE_DEMO_ORIGIN=${ENABLE_DEMO_ORIGIN}
FREEWAF_CHALLENGE_SECRET=${challenge_secret}
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
NGINX_HAS_MODSECURITY=${NGINX_HAS_MODSECURITY}
NGINX_MODSECURITY_CMS_RULES_FILE=/etc/freewaf/modsecurity/cms-only.conf
NGINX_MODSECURITY_COMODO_RULES_FILE=/etc/freewaf/modsecurity/comodo.conf
NGINX_MODSECURITY_OWASP_RULES_FILE=/etc/freewaf/modsecurity/owasp-crs.conf
NGINX_CHAOS_CHALLENGE_URL=
NGINX_FREEWAF_STATIC_DIR=
NGINX_STATIC_ROOT=${APP_DIR}/public/static
CERTBOT_CMD=/usr/bin/certbot
CERTBOT_AUTH_METHOD=webroot
CERTBOT_WEBROOT=/var/www/html
CERTBOT_LIVE_DIR=/etc/letsencrypt/live
CERTBOT_CREDENTIALS_DIR=/etc/freewaf/certbot
CERTBOT_CLOUDFLARE_PROPAGATION_SECONDS=60
IP_GROUP_AUTO_SYNC=true
IP_GROUP_SYNC_INTERVAL_SECONDS=86400
IP_GROUP_SYNC_CHECK_SECONDS=3600
IP_GROUP_REFERENCE_TIMEOUT=20
IP_GROUP_REFERENCE_MAX_BYTES=20971520
IP_GROUP_EXTERNALIZE_COUNT=5000
IP_GROUP_EXTERNALIZE_BYTES=262144
STATS_LOG_SCAN_LIMIT=50000
STATS_LOG_SCAN_MAX=250000
STATS_RECENT_LOG_LIMIT=1000
STATS_RECENT_LOG_MAX=10000
FREEWAF_LOG_TAIL_MIN_ENTRIES=1000
FREEWAF_LOG_TAIL_MAX_ENTRIES=10000
FREEWAF_LOG_TAIL_MAX_BYTES=16777216
STATS_RETENTION_DAYS=7
GEOIP_DB_FILE=/var/lib/freewaf/geoip/dbip-country-lite.csv.gz
EOF
  chmod 0600 "$ENV_FILE"
}

write_logrotate() {
  log "Writing ${LOGROTATE_FILE}"
  cat > "$LOGROTATE_FILE" <<EOF
${APP_DIR}/logs/freewaf_access.log ${APP_DIR}/logs/freewaf/accesslog_* ${APP_DIR}/logs/freewaf/errorlog_* {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    dateext
    olddir ${APP_DIR}/logs/freewaf/rotated
    createolddir 0750 www-data adm
    create 0640 www-data adm
    sharedscripts
    postrotate
        if command -v nginx >/dev/null 2>&1; then
            nginx -s reopen >/dev/null 2>&1 || true
        fi
    endscript
}
EOF
}

write_certbot_deploy_hook() {
  log "Writing ${CERTBOT_DEPLOY_HOOK}"
  install -d -m 0755 "$(dirname "$CERTBOT_DEPLOY_HOOK")"
  cat > "$CERTBOT_DEPLOY_HOOK" <<'EOF'
#!/usr/bin/env bash
set -eu
/usr/sbin/nginx -t
/usr/bin/systemctl reload nginx
EOF
  chmod 0755 "$CERTBOT_DEPLOY_HOOK"
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
Restart=always
RestartSec=3s
TimeoutStartSec=120s
TimeoutStopSec=30s
KillSignal=SIGTERM
FinalKillSignal=SIGKILL

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable freewaf
}

write_healthcheck() {
  log "Writing FreeWAF healthcheck"
  cat > "$HEALTHCHECK_SCRIPT" <<EOF
#!/bin/sh
set -eu
URL="\${FREEWAF_HEALTH_URL:-https://127.0.0.1:${ADMIN_PORT}/api/health}"
if /usr/bin/curl -skfsS --connect-timeout 2 --max-time 8 "\$URL" >/dev/null; then
  exit 0
fi
/usr/bin/systemd-cat -t freewaf-healthcheck -p warning echo "FreeWAF panel healthcheck failed; restarting freewaf.service"
/usr/bin/systemctl restart freewaf.service
EOF
  chmod 0755 "$HEALTHCHECK_SCRIPT"

  cat > "$HEALTHCHECK_SERVICE" <<EOF
[Unit]
Description=FreeWAF panel healthcheck
After=network-online.target freewaf.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${HEALTHCHECK_SCRIPT}
EOF

  cat > "$HEALTHCHECK_TIMER" <<EOF
[Unit]
Description=Run FreeWAF panel healthcheck every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=15s
Unit=freewaf-healthcheck.service

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now freewaf-healthcheck.timer
}

write_nginx_include() {
  log "Writing Nginx include ${NGINX_INCLUDE}"
  install -d -m 0755 /etc/nginx/conf.d
  cat > "$NGINX_UPLOAD_LIMIT_INCLUDE" <<EOF
client_max_body_size ${NGINX_CLIENT_MAX_BODY_SIZE};
EOF
  cat > "$NGINX_INCLUDE" <<EOF
# FreeWAF generated configuration is included inside nginx http {}.
include ${APP_DIR}/nginx/generated/freewaf.conf;
EOF
  install -d -m 0755 /etc/systemd/system/nginx.service.d
  cat > /etc/systemd/system/nginx.service.d/freewaf-restart.conf <<'EOF'
[Service]
Restart=on-failure
RestartSec=5s
EOF
  systemctl daemon-reload
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
  install_modsecurity
  write_env
  write_logrotate
  write_certbot_deploy_hook
  refresh_nginx_config
  write_systemd
  write_healthcheck
  write_nginx_include
  if [ "$SKIP_SERVICE_RESTART" = "true" ]; then
    log "Skipping FreeWAF service restart because FREEWAF_SKIP_SERVICE_RESTART=true"
  else
    start_service
  fi
  print_done
}

main "$@"
