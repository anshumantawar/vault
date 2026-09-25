# Vault

Fault-tolerant distributed object storage in Go (hackathon, 24-48h, 2-4 people).
Objects are split into 4 MB chunks named by their SHA-256. Chunks are immutable and replicated
across nodes; the only mutable state is the per-key manifest pointer held by the coordinator.

Full design and demo script: `~/.claude/plans/pasted-content-id-ef9e-we-re-building-recursive-bee.md`.

## Layout
- `proto/vault.proto`: the whole contract (`Node` and `Coordinator` gRPC services)
- `gen/`: generated code, committed. Never hand-edit; run `make proto`
- `main.go`: subcommands `vault coordinator` / `vault node`
- `coordinator.go`: gRPC Coordinator svc + browser HTTP handlers, metadata + WAL, rendezvous placement
- `node.go`: gRPC Node svc, on-disk chunk store, scrubber, fault-injection interceptor
- `repair.go`: heartbeat monitor, repairer, rebalancer, MTTR stats
- `ui/index.html`: dashboard, `go:embed`ed, vanilla JS polling `/api/status`

## Commands
- `make proto`: regenerate `gen/` (needs `protoc`, `protoc-gen-go`, `protoc-gen-go-grpc`)
- `go test -race ./...`: end-to-end cluster tests (kill / corrupt / partition / coordinator restart)
- `./demo.sh`: coordinator + 5 nodes, dashboard at http://localhost:8000

## Ports
Coordinator gRPC `:7000`, HTTP/dashboard `:8000`. Nodes gRPC `:9001`+.

## Rules
- Deps: stdlib + `google.golang.org/grpc` + `google.golang.org/protobuf` only. Ask before adding anything.
- Chunks are never modified in place. A chunk file whose hash doesn't match its name is corrupt.
- Every metadata change is appended to the WAL and fsynced **before** acking the client.
- Node→node traffic goes through `PushChunk` so partitions are real, not simulated at the coordinator.
- Every outbound RPC has a deadline (default 2s). `codes.Unavailable` means try the next replica; `codes.DataLoss` means corruption, so queue a repair.
- Fault injection lives only in the node's gRPC interceptor. Don't sprinkle fault checks in handlers.
- Known shortcuts get a `ponytail:` comment naming the ceiling and the upgrade path
  (e.g. single coordinator → Raft; global metadata lock → per-key locks).

## Skills (project-scoped, `.claude/skills/`)
`golang-grpc`, `golang-testing`, `protobuf`. Use them when touching the proto, services, or tests.
