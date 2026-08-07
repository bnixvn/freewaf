#!/usr/bin/env bash
# Quick upgrade: pull latest code, rebuild frontend, rewrite nginx config, reload.
# Usage: sudo bash upgrade.sh
set -Eeuo pipefail

APP_DIR="${FREEWAF_APP_DIR:-/opt/freewaf}"
ADMIN_PORT="${ADMIN_PORT:-7001}"
ADMIN_URL="http://127.0.0.1:${ADMIN_PORT}"

log()  { printf '\n[upgrade] %s\n' "$*" >&2; }
fail() { printf '\n[upgrade] ERROR: %s\n' "$*" >&2; exit 1; }

# ── 1. Pre-flight ──────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || fail "Run as root: sudo bash upgrade.sh"
command -v git     >/dev/null 2>&1 || fail "git not found"
command -v node    >/dev/null 2>&1 || fail "node not found"
command -v npm     >/dev/null 2>&1 || fail "npm not found"
command -v nginx   >/dev/null 2>&1 || fail "nginx not found"

cd "$APP_DIR"

# ── 2. Pull latest code ───────────────────────────────────────────
log "Pulling latest code..."
git fetch origin main
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" = "$REMOTE" ]; then
  log "Already up-to-date ($LOCAL)"
else
  git reset --hard origin/main
  log "Updated: $LOCAL -> $REMOTE"
fi

# ── 3. Rebuild frontend ───────────────────────────────────────────
log "Building frontend..."
cd "$APP_DIR/frontend"
npm ci --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund
npm run build
log "Frontend built."

# ── 4. Restart FreeWAF backend ────────────────────────────────────
log "Restarting FreeWAF service..."
if systemctl is-active --quiet freewaf; then
  systemctl restart freewaf
  sleep 2
elif systemctl is-enabled --quiet freewaf 2>/dev/null; then
  systemctl start freewaf
  sleep 2
else
  log "freewaf.service not found, skipping service restart"
fi

# ── 5. Rewrite nginx config via API ───────────────────────────────
log "Rewriting nginx config..."
RESPONSE=$(curl -sf -X POST "${ADMIN_URL}/api/nginx/apply" \
  -H "Content-Type: application/json" \
  -d '{"test":true,"reload":true}' 2>&1) || true

if echo "$RESPONSE" | grep -q '"ok":true'; then
  log "Nginx config rewritten and reloaded successfully."
else
  log "Warning: Could not reach FreeWAF API at ${ADMIN_URL}"
  log "Falling back to direct nginx reload..."
  if nginx -t 2>&1; then
    nginx -s reload
    log "Nginx reloaded."
  else
    fail "nginx -t failed. Check config manually."
  fi
fi

# ── 6. Verify ─────────────────────────────────────────────────────
log "Nginx status:"
nginx -t 2>&1 && log "Nginx config OK" || fail "Nginx config test failed"

log "FreeWAF service:"
systemctl is-active --quiet freewaf && log "freewaf.service is running" || log "freewaf.service is not running (check manually)"

log "Upgrade complete!"
