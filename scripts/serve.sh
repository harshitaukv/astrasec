#!/usr/bin/env bash
# Start the API and dashboard at http://127.0.0.1:8000  (API docs at /docs)
#   ASTRASEC_API_KEY=secret scripts/serve.sh      require an X-API-Key header
#   ASTRASEC_LLM=ollama scripts/serve.sh          use a local Llama 3.1 (needs `ollama pull llama3.1`)
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 -m astrasec serve --port "${PORT:-8000}" "$@"
