#!/usr/bin/env bash

set -euo pipefail

# Directories you know are safe to ignore (add more if needed)
IGNORE_DIRS=(
  ".git"
  ".github"
  "venv"
  "__pycache__"
  "tests/fixtures"  # if you later add test keys, whitelist them here
)

IGNORE_FILES=(
  "check_for_keys.sh"
)

GREP_ARGS=()
for d in "${IGNORE_DIRS[@]}"; do
  GREP_ARGS+=("--exclude-dir=$d")
done
for f in "${IGNORE_FILES[@]}"; do
  GREP_ARGS+=("--exclude=$f")
done

PATTERNS=(
  "BEGIN PGP PRIVATE KEY BLOCK"
  "BEGIN OPENSSH PRIVATE KEY"
  "BEGIN RSA PRIVATE KEY"
  "BEGIN DSA PRIVATE KEY"
  "BEGIN EC PRIVATE KEY"
)

FOUND=0

for p in "${PATTERNS[@]}"; do
  if grep -RIn "${GREP_ARGS[@]}" -- "$p" .; then
    echo "❌ Found possible private key pattern: $p"
    FOUND=1
  fi
done

if [ "$FOUND" -ne 0 ]; then
  echo "❌ Potential private key material committed — refusing to pass CI."
  exit 1
fi

echo "✅ No private key patterns found."

