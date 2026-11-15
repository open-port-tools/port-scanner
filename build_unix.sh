#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ -z "${PYTHON_BIN:-}" ]; then
  if [ -x "/opt/homebrew/bin/python3.12" ]; then
    PYTHON_BIN="/opt/homebrew/bin/python3.12"
  else
    PYTHON_BIN="python3"
  fi
fi

echo "=== Async Port Scanner: macOS / Linux Binary Builder ==="
echo "Using Python: $($PYTHON_BIN --version)"

TARGET_VER="$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
VENV_DIR=".venv-build-${TARGET_VER}"

if [ ! -d "$VENV_DIR" ]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip
python -m pip install pyinstaller
python -m unittest discover -s tests -v
python build_executable.py --mode all --clean-build

echo
echo "Build complete. Output files in ./dist/"
ls -la dist/
