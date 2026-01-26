#!/usr/bin/env bash
set -euo pipefail

URL="${URL:-${1:-http://localhost:3001/private/view}}"
PRIVATE_PATH="${PRIVATE_PATH:?Set PRIVATE_PATH like /private/kitap/foo.pdf}"
API_KEY="${API_KEY:?Set API_KEY (x-api-key header value)}"

for i in 1 2 3; do
  echo "Attempt $i -> $URL ($PRIVATE_PATH)"
  curl -sS -o /dev/null \
    -w "status=%{http_code} time=%{time_total}s\\n" \
    -X POST "$URL" \
    -H "content-type: application/json" \
    -H "x-api-key: $API_KEY" \
    --data "{\"path\":\"$PRIVATE_PATH\"}"
done

