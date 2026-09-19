#!/usr/bin/env bash
# Run the automated test suite (about 25 seconds). Tests use a private copy of the models and an in-memory database.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m pytest tests -q "$@"
