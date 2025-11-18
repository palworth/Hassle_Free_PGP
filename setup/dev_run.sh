#!/bin/bash
# Hassle Free PGP - Developer Quick Start
# For developers: Run the app locally for testing

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "Run this first: python3 -m venv venv && source venv/bin/activate && pip install -r setup/requirements.txt"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Run the application using the src package layout
export PYTHONPATH="src:${PYTHONPATH:-}"
python -m hassle_free_pgp.app "$@"

