#!/usr/bin/env bash
# Local Vault cluster as real processes: 3 meta (Raft) + 5 nodes in 3 zones + 1 gateway.
#   scripts/demo.sh up | down | status
#   scripts/demo.sh kill <name>       # kill -9, e.g. n2, m1, gateway
#   scripts/demo.sh start <name>      # restart one process (data is kept)
#   scripts/demo.sh add-node <id> <zone>   # e.g. add-node n6 z4
set -euo pipefail
cd "$(dirname "$0")/.."

DATA=${VAULT_DATA:-data}
BIN=$DATA/vault
export VAULT_ACCESS_KEY=${VAULT_ACCESS_KEY:-vaultadmin}
export VAULT_SECRET_KEY=${VAULT_SECRET_KEY:-vaultsecret}
META=127.0.0.1:7001,127.0.0.1:7002,127.0.0.1:7003
PEERS=m1=127.0.0.1:7101,m2=127.0.0.1:7102,m3=127.0.0.1:7103

args() {
  case $1 in
    m[1-3]) local i=${1#m}; echo "meta -id $1 -grpc 127.0.0.1:700$i -raft 127.0.0.1:710$i -dir $DATA/$1 -peers $PEERS" ;;
    n[1-9]) local i=${1#n}; echo "node -id $1 -addr 127.0.0.1:910$i -zone ${2:-z$(( (i - 1) % 3 + 1 ))} -dir $DATA/$1 -meta $META" ;;
    gateway) echo "gateway -s3 127.0.0.1:9000 -ui 127.0.0.1:8080 -meta $META" ;;
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
    mkdir -p "$DATA"
    go build -o "$BIN" ./cmd/vault
    for p in m1 m2 m3 n1 n2 n3 n4 n5 gateway; do start $p; done
    cat <<EOF

UI:  http://127.0.0.1:8080
S3:  http://127.0.0.1:9000   (logs in $DATA/logs)

export AWS_ACCESS_KEY_ID=$VAULT_ACCESS_KEY AWS_SECRET_ACCESS_KEY=$VAULT_SECRET_KEY AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url http://127.0.0.1:9000 s3 mb s3://photos
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
  *) sed -n '2,7p' "$0"; exit 2 ;;
esac
