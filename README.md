# Vault

S3-compatible, fault-tolerant distributed object storage in Go.

Objects are cut into 4 MB chunks named by their SHA-256. Chunks are immutable and replicated across
zone-labelled storage nodes; the only mutable state is metadata, held by a 3-member Raft group. Kill a node,
corrupt a chunk or partition a zone and the cluster detects it and repairs itself.

## Architecture

One binary, three roles:

| Process   | Package            | Job |
|-----------|--------------------|-----|
| `meta`    | `internal/meta`    | Raft group storing buckets, objects, chunk holders and users in bbolt. The leader runs failure detection, incremental repair and GC. |
| `node`    | `internal/node`    | Stores chunk files, verifies every hash on write and read, quarantines corrupt copies, scrubs in the background. |
| `gateway` | `internal/gateway` | Stateless S3 API (SigV4) and the web UI. Streams bytes straight to nodes; meta only sees metadata. |

Shared packages: `placement` (rendezvous hashing across zones), `wire` (mutual-TLS gRPC pool and per-RPC
role rules), `pki` (private CA and per-process certificates).

### Security

- Every gRPC call and all Raft traffic is mutual TLS 1.3 against a private CA. A caller's identity and role
  come only from its verified certificate, and each service has a default-deny method → role table.
- S3 requests are authenticated with AWS SigV4; buckets belong to a user and are checked on every access.
- The web UI has no sign-in: it acts as the bootstrap admin and listens on loopback by default.

## Quick start

Requires Go 1.26.

```sh
make demo        # 3 meta + 5 nodes in 3 zones + 1 gateway, as local processes
open https://127.0.0.1:8080
make down
```

The demo generates a private CA in `data/certs`. Trust it once so the browser accepts the UI:

```sh
security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db data/certs/ca.pem
```

Create S3 keys in the UI's **Users** app, then use any S3 client:

```sh
export AWS_ENDPOINT_URL=https://127.0.0.1:9000 AWS_CA_BUNDLE=data/certs/ca.pem AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=<access key> AWS_SECRET_ACCESS_KEY=<secret key>
aws s3 mb s3://photos && aws s3 cp cat.jpg s3://photos/
```

Chaos from the shell: `scripts/demo.sh kill n2`, `scripts/demo.sh start n2`, `scripts/demo.sh add-node n6 z4`.
A scaled topology (two gateways behind a load balancer) is in `deploy/docker-compose.yml`.

## Development

```sh
make test        # go vet + go test -race, including TestCluster (a full in-process cluster, ~20 s)
make test-short  # skips TestCluster
make lint        # gofmt, go vet, staticcheck
make cover       # coverage summary
make gen         # regenerate protobuf and templ code after editing .proto or .templ files
```

Generated code lives in `gen/vault/v1/` and `internal/gateway/ui/views_templ.go`; never edit it by hand.
