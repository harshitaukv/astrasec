#!/usr/bin/env bash
# Run the independent red-team evaluation and write reports/redteam_report.md and reports/redteam_latest.json
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m astrasec redteam
