#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

find_python() {
  local candidate
  for candidate in python3.13 python3.12 python3.11 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && \
       "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
      command -v "$candidate"
      return 0
    fi
  done
  return 1
}

if [[ ! -x .venv/bin/python ]]; then
  PYTHON_BIN="$(find_python)" || {
    echo "[error] Python 3.11+ is required. Install python3 and python3-venv."
    exit 1
  }
  echo "[stari] Creating local environment with $PYTHON_BIN..."
  "$PYTHON_BIN" -m venv .venv
  echo "[stari] Installing STARI and dependencies (first launch only)..."
  .venv/bin/python -m pip install --disable-pip-version-check -e .
fi

exec .venv/bin/python -m stari "$@"
