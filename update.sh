#!/usr/bin/env bash
# FreeWAF quick-update: pull latest code, regenerate nginx config, reload.
# Usage: sudo bash update.sh
set -Eeuo pipefail

APP_DIR="${FREEWAF_APP_DIR:-/opt/freewaf}"
ENV_DIR="${FREEWAF_ENV_DIR:-/etc/freewaf}"
ENV_FILE="${ENV_DIR}/freewaf.env"
REPO_URL="${FREEWAF_UPDATE_REPO_URL:-https://github.com/bnixvn/freewaf.git}"
REPO_BRANCH="${FREEWAF_UPDATE_BRANCH:-main}"

# --- helpers ---------------------------------------------------------------

log()  { printf '\n[freewaf-update] %s\n' "$*" >&2; }
fail() { printf '\n[freewaf-update] ERROR: %s\n' "$*" >&2; exit 1; }

read_env() {
  local key="$1" default="$2" value=""
  if [ -f "$ENV_FILE" ]; then
    value="$(awk -F= -v k="$key" '$1==k{sub(/^[^=]*=/,"");print;exit}' "$ENV_FILE")"
    value="${value%\"}"; value="${value#\"}"
  fi
  printf '%s\n' "${value:-$default}"
}

require_root() {
  [ "$(id -u)" -eq 0 ] || fail "Run as root: sudo bash update.sh"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

wait_for_port() {
  local port="$1" attempts=0
  while [ $attempts -lt 30 ]; do
    if curl -sfk "https://127.0.0.1:${port}/api/health" >/dev/null 2>&1       || curl -sf "http://127.0.0.1:${port}/api/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    attempts=$((attempts + 1))
  done
  return 1
}

ensure_git_repo() {
  cd "$APP_DIR"
  if [ -d .git ]; then
    # Verify remote points to the right repo
    local current_url
    current_url="$(git remote get-url origin 2>/dev/null || true)"
    if [ "$current_url" != "$REPO_URL" ]; then
      log "Fixing git remote: ${current_url} -> ${REPO_URL}"
      git remote set-url origin "$REPO_URL" 2>/dev/null || git remote add origin "$REPO_URL"
    fi
    return 0
  fi

  # No .git directory — initialise from existing files
  log "No git repo found in ${APP_DIR}, initialising..."
  git init
  git remote add origin "$REPO_URL"
  # Stash any local changes so reset --hard works
  git add -A 2>/dev/null || true
  git commit -m "local state before update" --allow-empty 2>/dev/null || true
  git fetch origin "$REPO_BRANCH" --depth 1 || fail "Cannot reach ${REPO_URL}. Check DNS/network: ping github.com"
  git checkout -B "$REPO_BRANCH" "origin/${REPO_BRANCH}"
}

# --- main ------------------------------------------------------------------

main() {
  require_root
  require_cmd git
  require_cmd curl

  local admin_port
  admin_port="$(read_env ADMIN_PORT 7001)"

  # 1. Ensure git repo exists and pull latest code
  log "Pulling latest code from ${REPO_URL} (${REPO_BRANCH})"
  ensure_git_repo

  cd "$APP_DIR"
  git fetch origin "$REPO_BRANCH" --depth 1 || fail "git fetch failed. Check DNS: ping github.com"
  git reset --hard "origin/${REPO_BRANCH}"
  local revision
  revision="$(git rev-parse --short HEAD)"
  log "Updated to revision ${revision}"

  # 2. Rebuild frontend if needed
  if [ -f frontend/package.json ]; then
    local rebuild_frontend=false
    if [ ! -d frontend/dist ] || [ frontend/package.json -nt frontend/dist/index.html ]; then
      rebuild_frontend=true
    # package.json rarely changes on a source-only edit (a new component, a
    # tweaked form) - also rebuild whenever anything under src/ is newer
    # than the last build output, or those edits would silently never ship.
    elif [ -n "$(find frontend/src -newer frontend/dist/index.html -print -quit 2>/dev/null)" ]; then
      rebuild_frontend=true
    fi
    if [ "$rebuild_frontend" = true ]; then
      log "Rebuilding frontend..."
      cd frontend
      npm ci --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund
      npm run build
      cd "$APP_DIR"
    fi
  fi

  # 3. Ensure FREEWAF_MODSECURITY_DISABLED is set
  if [ -f "$ENV_FILE" ]; then
    if ! grep -q '^FREEWAF_MODSECURITY_DISABLED=' "$ENV_FILE"; then
      log "Adding FREEWAF_MODSECURITY_DISABLED=true to env file"
      echo 'FREEWAF_MODSECURITY_DISABLED=true' >> "$ENV_FILE"
    fi
  fi

  # 3b. Guard against a flood filling the disk: a spam/attack burst can log
  # gigabytes of *blocked* requests in minutes. `daily` (even with `maxsize`
  # layered on) only ever rotates once per calendar day - logrotate's own
  # "already rotated" bookkeeping refuses a second pass no matter how big the
  # file gets afterward - so a multi-hour flood still fills the disk before
  # midnight. Pure `size` has no such per-day limit: every check rotates the
  # file again if it is still over the cap. Idempotent: also cleans up a
  # `daily`+`maxsize` combo left by an older run of this same step.
  local logrotate_conf="/etc/logrotate.d/freewaf"
  if [ -f "$logrotate_conf" ] && ! grep -q "^\s*size 500M\s*\$" "$logrotate_conf"; then
    log "Switching ${logrotate_conf} to size-based rotation (500M cap)"
    sed -i -e '/^\s*daily\s*$/d' -e '/^\s*maxsize/d' -e '/^\s*size 500M\s*$/d' "$logrotate_conf"
    sed -i '/{$/a\    size 500M' "$logrotate_conf"
  fi
  # Plain `dateext` names every same-day rotation of a file identically, so
  # only the first same-day `size` rotation actually succeeds - every one
  # after it collides on that filename, logrotate skips the rename but still
  # marks the file rotated, and it grows unbounded again right past the cap.
  # Epoch-second names never collide no matter how many times a flood
  # rotates a file in one day.
  if [ -f "$logrotate_conf" ] && ! grep -q '^\s*dateformat' "$logrotate_conf"; then
    log "Adding dateformat -%s to ${logrotate_conf} (unique names per rotation, not per day)"
    sed -i '/^\s*dateext\s*$/a\    dateformat -%s' "$logrotate_conf"
  fi
  # `rotate 7` used to reliably mean "~7 days of history" back when rotation
  # only happened once a day; size-triggered rotation can now fire many times
  # in one busy day, so `rotate 7` alone could mean anywhere from a few hours
  # to several weeks depending on traffic. `maxage` bounds it by calendar time
  # instead, restoring the original retention intent.
  if [ -f "$logrotate_conf" ] && ! grep -q '^\s*maxage' "$logrotate_conf"; then
    log "Adding maxage 7 to ${logrotate_conf}"
    sed -i '/^\s*rotate 7\s*$/a\    maxage 7' "$logrotate_conf"
  fi
  # 3c. Same story for nginx's own connection ceiling. The distro default
  # (`worker_connections 768;`, no `worker_rlimit_nofile` at all) caps out at
  # 768 concurrent connections per worker with no headroom to raise it - seen
  # live under a traffic flood: nginx logged "768 worker_connections are not
  # enough", and after only raising the connection count (without also
  # raising the file descriptor limit) "accept4() failed (24: Too many open
  # files)" instead. Every site on the box went down, flood target or not.
  # A full restart (not reload) is required for the raised systemd
  # LimitNOFILE to actually reach nginx's master process.
  local nginx_restart_needed=false
  if [ -f /etc/nginx/nginx.conf ]; then
    local nginx_conf_backup
    nginx_conf_backup="$(mktemp)"
    cp -a /etc/nginx/nginx.conf "$nginx_conf_backup"
    if ! grep -q "worker_rlimit_nofile" /etc/nginx/nginx.conf; then
      log "Adding worker_rlimit_nofile to /etc/nginx/nginx.conf"
      sed -i '/^worker_processes/a worker_rlimit_nofile 65536;' /etc/nginx/nginx.conf
      nginx_restart_needed=true
    fi
    if grep -qE 'worker_connections\s+[0-9]+;' /etc/nginx/nginx.conf && ! grep -q 'worker_connections 4096;' /etc/nginx/nginx.conf; then
      log "Raising worker_connections in /etc/nginx/nginx.conf to 4096"
      sed -i 's/worker_connections\s*[0-9]\+;/worker_connections 4096;/' /etc/nginx/nginx.conf
      nginx_restart_needed=true
    fi
    if [ "$nginx_restart_needed" = true ] && command -v nginx >/dev/null 2>&1 && ! nginx -t >/dev/null 2>&1; then
      log "WARNING: nginx -t failed after raising connection limits; reverting nginx.conf"
      cp -a "$nginx_conf_backup" /etc/nginx/nginx.conf
      nginx_restart_needed=false
    fi
    rm -f "$nginx_conf_backup"
  fi
  local nginx_service_override=/etc/systemd/system/nginx.service.d/freewaf-restart.conf
  if [ -f "$nginx_service_override" ] && ! grep -q '^LimitNOFILE=' "$nginx_service_override"; then
    log "Adding LimitNOFILE=65536 to ${nginx_service_override}"
    sed -i '/^\[Service\]/a LimitNOFILE=65536' "$nginx_service_override"
    systemctl daemon-reload
    nginx_restart_needed=true
  fi
  if [ "$nginx_restart_needed" = true ] && command -v nginx >/dev/null 2>&1; then
    if nginx -t 2>&1; then
      log "Restarting Nginx to apply the raised connection/file-descriptor limits"
      systemctl restart nginx
    else
      log "WARNING: nginx -t failed after raising connection limits; left the running config untouched"
    fi
  fi

  if [ -f "$logrotate_conf" ] && [ ! -f /etc/systemd/system/freewaf-logrotate-check.timer ]; then
    log "Installing freewaf-logrotate-check timer (checks the size cap every 15min)"
    cat > /etc/systemd/system/freewaf-logrotate-check.service <<EOF
[Unit]
Description=Check FreeWAF logs against the logrotate size cap between runs

[Service]
Type=oneshot
ExecStart=/usr/sbin/logrotate ${logrotate_conf}
EOF
    cat > /etc/systemd/system/freewaf-logrotate-check.timer <<'EOF'
[Unit]
Description=Run the FreeWAF logrotate size-cap check every 15 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
AccuracySec=1min
Unit=freewaf-logrotate-check.service

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now freewaf-logrotate-check.timer
  fi

  # 4. Restart freewaf service
  log "Restarting freewaf service..."
  systemctl restart freewaf
  sleep 2

  if ! systemctl is-active --quiet freewaf; then
    fail "freewaf.service failed to start. Check: journalctl -u freewaf -n 50"
  fi
  log "freewaf service is running"

  # 5. Wait for admin API
  log "Waiting for admin API on port ${admin_port}..."
  if ! wait_for_port "$admin_port"; then
    fail "Admin API not responding on port ${admin_port}"
  fi

  # 6. Regenerate nginx config + test + reload
  log "Regenerating nginx config..."

  # Drop the stock Debian/Ubuntu site: its `listen 80 default_server` collides
  # with FreeWAF's catch-all default server for unknown hosts.
  for stale in /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/default-modsecurity.conf; do
    if [ -e "$stale" ] || [ -L "$stale" ]; then
      log "Disabling stock Nginx site ${stale}"
      rm -f "$stale"
    fi
  done

  # Regenerate directly from the stored state. The admin API needs auth, so a
  # plain curl to /api/nginx/apply silently 401s and leaves a stale bundle.
  local regen_ok=true
  (
    cd "$APP_DIR"
    if [ -f "$ENV_FILE" ]; then set -a; . "$ENV_FILE"; set +a; fi
    PYTHONPATH="${APP_DIR}/backend" python3 - <<'PY'
from pathlib import Path
from freewaf.nginx import write_nginx_config
from freewaf.store import Store, resolve_data_file
root = Path.cwd()
store = Store(resolve_data_file(root)); store.init()
write_nginx_config(root, store.get_state())
PY
  ) || regen_ok=false

  if command -v nginx >/dev/null 2>&1; then
    if nginx -t 2>&1; then
      nginx -s reload 2>&1 && log "Nginx config regenerated and reloaded"
    else
      fail "nginx -t failed after regenerating config. Check: nginx -t"
    fi
  fi
  [ "$regen_ok" = true ] || log "WARNING: config regeneration reported an error; nginx kept the previous bundle"

  log "=========================================="
  log "FreeWAF updated to ${revision}"
  local server_ip
  server_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  log "Admin panel: http://${server_ip}:${admin_port}"
  log "=========================================="
}

main "$@"
