#!/usr/bin/env bash
# Install dependencies and train the models. Run once after unpacking.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m pip install -r requirements.txt
python3 -m training.train_all
echo "Ready. Start the dashboard with: scripts/serve.sh"
