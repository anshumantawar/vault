#!/usr/bin/env bash
# Local Vault cluster as real processes: 3 meta (Raft) + 5 nodes in 3 zones + 1 gateway.
# Every process talks mutual TLS; S3 and the UI are served over HTTPS.
#   scripts/demo.sh up | down | status
#   scripts/demo.sh kill <name>       # kill -9, e.g. n2, m1, gateway
#   scripts/demo.sh start <name>      # restart one process (data is kept)
#   scripts/demo.sh add-node <id> <zone>   # e.g. add-node n6 z4 (certificates exist for n1..n9)
# VAULT_PLAIN_HTTP=1 serves S3/UI as plain HTTP on 127.0.0.1 (gRPC stays mutual TLS).
set -euo pipefail
cd "$(dirname "$0")/.."

DATA=${VAULT_DATA:-data}
BIN=$DATA/vault
CERTS=$DATA/certs
META=127.0.0.1:7001,127.0.0.1:7002,127.0.0.1:7003
PEERS=m1=127.0.0.1:7101,m2=127.0.0.1:7102,m3=127.0.0.1:7103

# The bootstrap admin: generated once, kept in $DATA/admin.env (0600).
mkdir -p "$DATA"
if [[ ! -f $DATA/admin.env ]]; then
  umask 077
  printf 'VAULT_ACCESS_KEY=%s\nVAULT_SECRET_KEY=%s\n' vaultadmin "$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)" >"$DATA/admin.env"
fi
set -a; . "$DATA/admin.env"; set +a

SCHEME=https PLAIN=
if [[ ${VAULT_PLAIN_HTTP:-} == 1 ]]; then SCHEME=http PLAIN=-plain-http; fi

args() {
  case $1 in
    m[1-3]) local i=${1#m}; echo "meta -id $1 -grpc 127.0.0.1:700$i -raft 127.0.0.1:710$i -dir $DATA/$1 -tls-dir $CERTS -peers $PEERS" ;;
    n[1-9]) local i=${1#n}; echo "node -id $1 -addr 127.0.0.1:910$i -zone ${2:-z$(( (i - 1) % 3 + 1 ))} -dir $DATA/$1 -tls-dir $CERTS -meta $META" ;;
    gateway) echo "gateway -id gateway -s3 127.0.0.1:9000 -ui 127.0.0.1:8080 -tls-dir $CERTS -meta $META $PLAIN" ;;
    *) echo "unknown process $1" >&2; exit 1 ;;
  esac
}

start() {
  mkdir -p "$DATA/logs"
  # shellcheck disable=SC2046
  nohup "$BIN" $(args "$@") >>"$DATA/logs/$1.log" 2>&1 &
  echo $! >"$DATA/$1.pid"
  echo "started $1 (pid $!)"
}

stop() {
  local f=$DATA/$1.pid
  [[ -f $f ]] && kill "${2:--TERM}" "$(cat "$f")" 2>/dev/null || true
  rm -f "$f"
}

case ${1:-} in
  up)
    go build -o "$BIN" ./cmd/vault
    "$BIN" certs -dir "$CERTS" -meta m1,m2,m3 -nodes n1,n2,n3,n4,n5,n6,n7,n8,n9 -gateways gateway
    for p in m1 m2 m3 n1 n2 n3 n4 n5 gateway; do start $p; done
    cat <<EOF

UI:  $SCHEME://127.0.0.1:8080   sign in with the admin keys below
S3:  $SCHEME://127.0.0.1:9000   logs in $DATA/logs

Admin keys (also in $DATA/admin.env):
  access key  $VAULT_ACCESS_KEY
  secret key  $VAULT_SECRET_KEY

export AWS_ENDPOINT_URL=$SCHEME://127.0.0.1:9000 AWS_CA_BUNDLE=$CERTS/ca.pem AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=$VAULT_ACCESS_KEY AWS_SECRET_ACCESS_KEY=$VAULT_SECRET_KEY
aws s3 mb s3://photos

Browsers don't know Vault's private CA. Trust it once (macOS asks for your password):
  security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db $CERTS/ca.pem
EOF
    ;;
  down)
    for f in "$DATA"/*.pid; do [[ -e $f ]] && stop "$(basename "$f" .pid)"; done
    echo "stopped" ;;
  status)
    for f in "$DATA"/*.pid; do
      [[ -e $f ]] || continue
      n=$(basename "$f" .pid)
      if kill -0 "$(cat "$f")" 2>/dev/null; then echo "$n up"; else echo "$n dead"; fi
    done ;;
  kill) stop "$2" -KILL; echo "killed $2" ;;
  start) start "$2" ;;
  add-node) start "$2" "${3:-z4}" ;;
  *) sed -n '2,9p' "$0"; exit 2 ;;
esac
