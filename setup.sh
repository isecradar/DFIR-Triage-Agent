#!/usr/bin/env bash
# =============================================================================
#  DFIR Triage Agent - setup / update (WSL)
#  Thin wrapper: makes sure python3 exists, then runs installer.py (stdlib only).
#  installer.py installs requirements.txt (incl. numpy + Pillow for RDP cache
#  reconstruction and psutil for the CPU monitor) - re-run after updating.
#  All options are passed through - see: ./setup.sh --help
# =============================================================================
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found - installing it with apt (sudo password required)"
  sudo apt-get update -qq && sudo apt-get install -y -qq python3
fi
exec python3 -I "$DIR/installer.py" "$@"
