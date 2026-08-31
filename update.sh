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
    if [ ! -d frontend/dist ] || [ frontend/package.json -nt frontend/dist/index.html ]; then
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
