#!/usr/bin/env bash
# VaultForge desktop launcher (Linux / macOS). Needs Python 3 with tkinter.
#   Debian/Ubuntu: sudo apt install python3-tk
cd "$(dirname "$0")"
exec python3 VaultForge_Desktop.py "$@"
