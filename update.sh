#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${FREEWAF_APP_DIR:-/opt/freewaf}"
ENV_DIR="${FREEWAF_ENV_DIR:-/etc/freewaf}"
REPO_URL="${FREEWAF_UPDATE_REPO_URL:-https://github.com/bnixvn/freewaf.git}"
REPO_BRANCH="${FREEWAF_UPDATE_BRANCH:-main}"
SOURCE_DIR="${FREEWAF_UPDATE_SOURCE_DIR:-}"
SKIP_SERVICE_RESTART="${FREEWAF_SKIP_SERVICE_RESTART:-false}"
UPDATE_TMP_DIR=""

cleanup() {
  if [ -n "$UPDATE_TMP_DIR" ]; then
    rm -rf "$UPDATE_TMP_DIR"
  fi
}

trap cleanup EXIT

log() {
  printf '\n[freewaf-update] %s\n' "$*" >&2
}

fail() {
  printf '\n[freewaf-update] ERROR: %s\n' "$*" >&2
  exit 1
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    fail "Run as root: sudo bash update.sh"
  fi
}

is_allowed_repo() {
  case "$REPO_URL" in
    https://github.com/bnixvn/freewaf.git|https://github.com/bnixvn/freewaf|git@github.com:bnixvn/freewaf.git)
      return 0
      ;;
  esac

  local item
  local allowed_repos="${FREEWAF_UPDATE_ALLOWED_REPOS:-}"
  IFS=',' read -r -a repo_items <<< "$allowed_repos"
  for item in "${repo_items[@]}"; do
    if [ "$(printf '%s' "$item" | xargs)" = "$REPO_URL" ]; then
      return 0
    fi
  done
  return 1
}

resolve_source_dir() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  if [ -n "$SOURCE_DIR" ]; then
    SOURCE_DIR="$(cd "$SOURCE_DIR" && pwd)"
    return
  fi

  if [ -f "${script_dir}/install.sh" ] && [ -f "${script_dir}/backend/run.py" ] && [ "$script_dir" != "$APP_DIR" ]; then
    SOURCE_DIR="$script_dir"
    return
  fi

  command -v git >/dev/null 2>&1 || fail "git is required to download the update"
  UPDATE_TMP_DIR="$(mktemp -d -t freewaf-update.XXXXXX)"
  SOURCE_DIR="${UPDATE_TMP_DIR}/freewaf"
  log "Cloning ${REPO_URL} (${REPO_BRANCH})"
  git clone --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$SOURCE_DIR"
}

validate_source() {
  [ -f "${SOURCE_DIR}/install.sh" ] || fail "Update source does not contain install.sh"
  [ -f "${SOURCE_DIR}/backend/run.py" ] || fail "Update source does not contain backend/run.py"
  [ -f "${SOURCE_DIR}/frontend/package.json" ] || fail "Update source does not contain frontend/package.json"
}

main() {
  require_root
  is_allowed_repo || fail "FREEWAF_UPDATE_REPO_URL is not an approved FreeWAF repository"
  resolve_source_dir
  validate_source

  local revision
  revision="$(git -C "$SOURCE_DIR" rev-parse HEAD 2>/dev/null || printf 'unknown')"
  log "Installing revision ${revision} into ${APP_DIR}"

  FREEWAF_APP_DIR="$APP_DIR" \
  FREEWAF_ENV_DIR="$ENV_DIR" \
  FREEWAF_REPO_URL= \
  FREEWAF_SKIP_SERVICE_RESTART=true \
    bash "${SOURCE_DIR}/install.sh"

  if command -v nginx >/dev/null 2>&1; then
    nginx -t
  fi

  if [ "$SKIP_SERVICE_RESTART" = "true" ]; then
    log "FreeWAF service restart deferred to the update controller"
  else
    systemctl restart freewaf
    systemctl is-active --quiet freewaf || fail "freewaf.service did not become active"
    log "FreeWAF update completed and service restarted"
  fi
}

main "$@"
