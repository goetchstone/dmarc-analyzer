#!/bin/bash
# Builds "DMARC Analyzer.app" — a self-contained macOS app bundle.
# Run on the Mac itself:   ./build_app.sh
# Optional:                ./build_app.sh --install   (also copies to /Applications)
#
# The bundle includes its own Python runtime, dnspython, and tkinterdnd2.
# End result needs nothing installed on the machine that runs it.
set -euo pipefail
cd "$(dirname "$0")"

# ── Preflight ────────────────────────────────────────────────────────────────
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "ERROR: This builds a macOS app and must run on macOS." >&2
    exit 1
fi

PY=python3
if ! command -v "$PY" >/dev/null; then
    echo "ERROR: python3 not found. Install from https://python.org or via Homebrew." >&2
    exit 1
fi

if ! "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
    echo "ERROR: Python 3.9+ required. Found: $("$PY" --version)" >&2
    exit 1
fi

if ! "$PY" -c "import tkinter" 2>/dev/null; then
    cat >&2 <<'EOF'
ERROR: Your python3 has no tkinter, so the GUI cannot be bundled.
Fix one of these ways:
  - Install Python from python.org (its installer includes Tk), OR
  - Homebrew users:  brew install python-tk
Then re-run this script.
EOF
    exit 1
fi

TKVER=$("$PY" -c "import tkinter; print(tkinter.TkVersion)")
echo "Using $("$PY" --version) with Tk $TKVER"
if [[ "$TKVER" == "8.5" ]]; then
    echo "WARNING: Tk 8.5 (Apple's legacy build) renders poorly on modern macOS."
    echo "         Strongly consider building with python.org Python (Tk 8.6+)."
fi

# ── Clean build venv ─────────────────────────────────────────────────────────
echo "Creating build environment…"
rm -rf build_venv build dist
"$PY" -m venv build_venv
# shellcheck disable=SC1091
source build_venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet dnspython tkinterdnd2 "pyinstaller>=6.0"

# ── Build ────────────────────────────────────────────────────────────────────
echo "Building app bundle (1–2 minutes)…"
pyinstaller --noconfirm --log-level WARN "DMARC Analyzer.spec"
deactivate

APP="dist/DMARC Analyzer.app"
if [[ ! -d "$APP" ]]; then
    echo "ERROR: Build finished but $APP was not produced. See output above." >&2
    exit 1
fi

SIZE=$(du -sh "$APP" | cut -f1)
echo
echo "Built: $APP  ($SIZE)"

# ── Optional install ─────────────────────────────────────────────────────────
if [[ "${1:-}" == "--install" ]]; then
    echo "Copying to /Applications…"
    rm -rf "/Applications/DMARC Analyzer.app"
    ditto "$APP" "/Applications/DMARC Analyzer.app"
    echo "Installed: /Applications/DMARC Analyzer.app"
else
    echo "To install:  ./build_app.sh --install"
    echo "Or drag '$APP' to /Applications yourself."
fi

echo
echo "Note: the app is unsigned. It runs fine on THIS Mac (locally built apps"
echo "carry no quarantine flag). If you copy it to another Mac, Gatekeeper will"
echo "block first launch — right-click the app > Open, or run:"
echo "  xattr -dr com.apple.quarantine '/Applications/DMARC Analyzer.app'"
