#!/usr/bin/env bash
set -euo pipefail

log() { echo "[$(date +%H:%M:%S)] $*"; }

install_claude() {
  log "claude: start"
  if command -v claude >/dev/null 2>&1; then
    log "claude: already installed"
    return
  fi
  curl -fsSL https://claude.ai/install.sh | bash
  log "claude: done"
}

setup_lefthook() {
  log "lefthook: start"
  if [ ! -f package.json ]; then
    log "lefthook: skip (no package.json)"
    return
  fi
  if [ ! -f lefthook.yml ] && [ ! -f lefthook.yaml ] && [ ! -f .lefthook.yml ]; then
    log "lefthook: skip (no lefthook config)"
    return
  fi
  if ! pnpm exec lefthook --version >/dev/null 2>&1; then
    log "lefthook: skip (binary not found — add lefthook to devDependencies)"
    return
  fi
  pnpm exec lefthook install
  log "lefthook: done"
}

main() {
  install_claude
  setup_lefthook
}

main "$@"