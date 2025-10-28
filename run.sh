#!/bin/bash
# API Guardian - Quick launcher script

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Run API Guardian from the script's directory
cd "$SCRIPT_DIR"
python3 apiguardian.py "$@"
