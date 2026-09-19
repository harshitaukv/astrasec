#!/usr/bin/env bash
# Regenerate the dataset, cross-validate the candidate classifiers and write models/ and models/metrics.json.
# Add --fast for a quicker (less thorough) run. Takes about 20 seconds.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m training.train_all "$@"
