#!/usr/bin/env bash
# Expose the local Vault UI on a public ngrok URL (for demos and automated audits).
#   scripts/share.sh          # tunnel to the UI on :8080; Ctrl-C closes it
#   scripts/share.sh 9000     # tunnel to another local port, e.g. the S3 API
# The UI has no sign-in: anyone with the URL is admin. Close the tunnel when done.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=${1:-8080}
SCHEME=https
if [[ ${VAULT_PLAIN_HTTP:-} == 1 ]]; then SCHEME=http; fi

command -v ngrok >/dev/null || { echo "ngrok not found: brew install ngrok && ngrok config add-authtoken <token>" >&2; exit 1; }
curl -sk -o /dev/null "$SCHEME://127.0.0.1:$PORT/" || { echo "nothing on $SCHEME://127.0.0.1:$PORT; run 'make demo' first" >&2; exit 1; }

mkdir -p data/logs
# The gateway's certificate comes from Vault's private CA, which ngrok skips verifying on local upstreams.
ngrok http "$SCHEME://127.0.0.1:$PORT" --log=stdout >data/logs/ngrok.log 2>&1 &
NGROK=$!
trap 'kill $NGROK 2>/dev/null' EXIT

URL=
for _ in $(seq 1 30); do
  URL=$(curl -s http://127.0.0.1:4040/api/tunnels | grep -o '"public_url":"https://[^"]*"' | head -1 | cut -d'"' -f4) || true
  [[ -n $URL ]] && break
  kill -0 $NGROK 2>/dev/null || { echo "ngrok exited:" >&2; tail -5 data/logs/ngrok.log >&2; exit 1; }
  sleep 0.5
done
[[ -n $URL ]] || { echo "ngrok gave no URL; see data/logs/ngrok.log" >&2; exit 1; }

echo
echo "Public URL:  $URL"
echo "Forwarding:  $SCHEME://127.0.0.1:$PORT   (inspector http://127.0.0.1:4040)"
echo "Anyone with this URL has admin access. Ctrl-C to close the tunnel."
wait $NGROK
