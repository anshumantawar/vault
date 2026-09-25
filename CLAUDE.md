# Vault

S3-compatible, fault-tolerant distributed object storage in Go (hackathon).
Objects are cut into 4 MB chunks named by their SHA-256. Chunks are immutable and replicated
across zone-labelled nodes; the only mutable state is metadata, held by a 3-member Raft group.

Design and demo script: `~/.claude/plans/pasted-content-id-ef9e-we-re-building-recursive-bee.md`.

## Processes (one binary: `vault meta | node | gateway`)
- **meta** (`internal/meta`): Raft FSM in memory + JSON snapshots, `MetaService`.
  The leader alone runs the loops in `loops.go`: failure detection (3 s), repair/rebalance/trim (`reconcile`), GC.
- **node** (`internal/node`): chunk files `dir/chunks/ab/cd/<sha>`, `NodeService`, scrubber,
  fault-injection interceptor (the *only* place faults are applied).
- **gateway** (`internal/gateway`): stateless S3 API (`s3.go`, `sigv4.go`, `body.go`) and templ UI
  (`ui.go`, `ui/views.templ`). Streams bytes directly to nodes; meta sees metadata only.
- Shared: `internal/placement` (rendezvous hashing across zones), `internal/wire` (mutual-TLS pool, caller
  identity from the peer certificate, per-RPC role rules), `internal/pki` (private CA + per-process certs).

## Security model
- **Inside the cluster:** every gRPC call and all Raft traffic is mutual TLS 1.3 against a private CA
  (`vault certs`). A certificate's CN is the process id, its OU the role (`meta` | `node` | `gateway`).
  Identity comes only from the verified certificate (`wire.Caller`), never from request fields or headers.
- **Authorization:** each service has a default-deny `wire.Rules` table (method → roles). Nodes may only
  heartbeat/report as themselves; only `meta` may delete or push chunks; only gateways touch metadata and faults.
- **Tenants:** users (access key + secret) live in the Raft state; buckets have an `owner`. The gateway
  checks `canUse` on every S3 and UI bucket/object access; admins see all, empty-owner (legacy) buckets are admin-only.
- **UI:** sign-in with S3 keys → HMAC-signed, HttpOnly, SameSite=Strict session cookie. `signedIn` guards user
  routes, `adminOnly` guards Stats, Present, Users, fault injection and demo actions. S3 + UI are HTTPS;
  `-plain-http` is refused unless every listener is loopback.
- Known ceilings are marked `ponytail:` (secrets stored unencrypted in Raft snapshots, per-gateway session key,
  no per-IP login lockout).

## Generated code (never hand-edit)
- `gen/vault/v1/` from `proto/vault/v1/vault.proto` (`buf generate`)
- `internal/gateway/ui/views_templ.go` from `views.templ` (`templ generate`)
Run `make gen` after editing either source.

## Commands
- `make test`: vet + `go test -race` (includes `TestCluster`, a full in-process cluster, ~20 s; `make test-short` skips it)
- `make demo` / `make down`: local cluster as real processes (`scripts/demo.sh`, logs in `data/logs/`)
- `scripts/demo.sh kill n2|m1|gateway`, `start <name>`, `add-node n6 z4`
- `vault certs -dir data/certs -meta m1,m2,m3 -nodes n1,... -gateways gateway` (demo.sh does this; the CA is reused)
- Admin keys: generated on first `demo.sh up` into `data/admin.env` (0600). S3 from a shell:
  `set -a; . data/admin.env; set +a; export AWS_ENDPOINT_URL=https://127.0.0.1:9000 AWS_CA_BUNDLE=data/certs/ca.pem AWS_ACCESS_KEY_ID=$VAULT_ACCESS_KEY AWS_SECRET_ACCESS_KEY=$VAULT_SECRET_KEY AWS_DEFAULT_REGION=us-east-1`

## Go toolchain gotcha
`/opt/homebrew/bin/go` (1.27, brew-installed) shadows goenv's 1.26.2 while `GOROOT` points at 1.26.2,
which breaks builds. The Makefile prepends `~/.goenv/shims`; do the same in ad-hoc shells.

## Ports (local demo)
S3 `:9000`, UI `:8080`, meta gRPC `:7001-7003`, Raft `:7101-7103`, nodes `:9101+`.

## Rules
- Deps: stdlib, grpc, protobuf, templ, hashicorp/raft (+raft-boltdb). Ask before adding anything.
- Every new RPC needs an entry in its service's `wire.Rules` (unlisted = denied); every new UI route must be
  wrapped in `signedIn` or `adminOnly`, and every bucket-scoped handler must call `g.authorize`.
- Every mutation of metadata goes through `propose` → `state.apply`; `apply` must stay deterministic
  (use `command.Now`, never `time.Now()`).
- Chunks are never modified in place; nodes verify the hash on every write and read and quarantine mismatches.
- Deleting chunk files uses `if_written_before` + tombstones (see `needRetry`) so GC can't race a concurrent upload.
- Every outbound RPC has a deadline. `Unavailable` → try the next replica/member; `DataLoss`/`NotFound` from a
  holder → `ReportCorrupt` so repair replaces that copy.
- Meta returns S3 error codes as gRPC status messages (`NoSuchKey`, `BucketNotEmpty`, …); gateway maps them in `writeErr`.
- Known shortcuts carry a `ponytail:` comment naming the ceiling and upgrade path.

## Skills (project-scoped, `.claude/skills/`)
`golang-grpc`, `golang-testing`, `protobuf`.
