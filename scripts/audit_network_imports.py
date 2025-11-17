#!/usr/bin/env python3
"""
Security audit script to detect network-related imports and usage.

This script scans the codebase and dependencies for:
- Network module imports (socket, http, urllib, requests, etc.)
- Network function calls
- Potential telemetry or auto-update mechanisms
"""
import os
import re
import sys
from pathlib import Path


# Network-related patterns to search for
NETWORK_PATTERNS = [
    r'import\s+socket',
    r'from\s+socket\s+import',
    r'import\s+http',
    r'from\s+http\s+import',
    r'import\s+urllib',
    r'from\s+urllib\s+import',
    r'import\s+urllib2',
    r'from\s+urllib2\s+import',
    r'import\s+urllib3',
    r'from\s+urllib3\s+import',
    r'import\s+requests',
    r'from\s+requests\s+import',
    r'import\s+httplib',
    r'from\s+httplib\s+import',
    r'import\s+ftplib',
    r'from\s+ftplib\s+import',
    r'import\s+telnetlib',
    r'from\s+telnetlib\s+import',
    r'import\s+websocket',
    r'from\s+websocket\s+import',
    r'import\s+websockets',
    r'from\s+websockets\s+import',
]

# Function call patterns
NETWORK_CALL_PATTERNS = [
    r'socket\.',
    r'http\.',
    r'urllib\.',
    r'requests\.',
    r'urllib3\.',
]

# Suspicious patterns (telemetry, auto-update, etc.)
SUSPICIOUS_PATTERNS = [
    r'telemetry',
    r'analytics',
    r'auto.?update',
    r'check.*update',
    r'version.*check',
    r'keyserver',
    r'upload.*key',
    r'download.*key',
]


def scan_file(file_path: Path) -> list:
    """
    Scan a Python file for network-related patterns.

    Returns:
        List of tuples (line_number, line_content, pattern_matched)
    """
    matches = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        return [(0, f"Error reading file: {e}", None)]

    for line_num, line in enumerate(lines, 1):
        line_lower = line.lower()

        # Check import patterns
        for pattern in NETWORK_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                matches.append((line_num, line.rstrip(), pattern))

        # Check function call patterns
        for pattern in NETWORK_CALL_PATTERNS:
            if re.search(pattern, line):
                matches.append((line_num, line.rstrip(), pattern))

        # Check suspicious patterns
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, line_lower):
                matches.append((line_num, line.rstrip(), pattern))

    return matches


def scan_directory(directory: Path, exclude_dirs: set = None) -> dict:
    """
    Scan a directory recursively for Python files.

    Args:
        directory: Directory to scan
        exclude_dirs: Set of directory names to exclude (e.g., {'__pycache__', '.git'})

    Returns:
        Dictionary mapping file paths to lists of matches
    """
    if exclude_dirs is None:
        exclude_dirs = {'__pycache__', '.git', '.venv', 'venv', 'env', '.env'}

    results = {}

    for root, dirs, files in os.walk(directory):
        # Exclude directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        for file in files:
            if file.endswith('.py'):
                file_path = Path(root) / file
                matches = scan_file(file_path)
                if matches:
                    results[str(file_path)] = matches

    return results


def main():
    """Main audit function."""
    print("=" * 70)
    print("Network Import Security Audit")
    print("=" * 70)

    # Get project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent

    print(f"\nScanning project: {project_root}")
    print("Excluding: __pycache__, .git, venv, .venv, env, .env\n")

    # Scan project code (exclude scripts directory itself to avoid false positives)
    project_code = project_root / 'crypto'
    project_gui = project_root / 'gui'
    project_storage = project_root / 'storage'
    project_app = project_root / 'app.py'

    all_results = {}

    if project_code.exists():
        results = scan_directory(project_code)
        all_results.update(results)

    if project_gui.exists():
        results = scan_directory(project_gui)
        all_results.update(results)

    if project_storage.exists():
        results = scan_directory(project_storage)
        all_results.update(results)

    if project_app.exists():
        matches = scan_file(project_app)
        if matches:
            all_results[str(project_app)] = matches

    # Report results
    if not all_results:
        print("✓ No network-related imports or suspicious patterns found in project code!")
        print("\nNote: This script only scans the project code.")
        print("To audit dependencies, install them and scan the site-packages directory.")
        return 0
    else:
        print("⚠ WARNING: Potential network-related code detected:\n")
        for file_path, matches in all_results.items():
            print(f"\nFile: {file_path}")
            print("-" * 70)
            for line_num, line_content, pattern in matches:
                print(f"  Line {line_num}: {line_content}")
                print(f"    Pattern: {pattern}")

        print("\n" + "=" * 70)
        print("⚠ Please review the above matches manually.")
        print("Some may be false positives (e.g., comments, strings).")
        return 1


if __name__ == "__main__":
    sys.exit(main())
