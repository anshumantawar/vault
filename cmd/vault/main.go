// Command vault runs one Vault process (a meta member, a storage node or a
// gateway) or issues the certificates they authenticate each other with.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"vault/internal/gateway"
	"vault/internal/meta"
	"vault/internal/node"
	"vault/internal/pki"
	"vault/internal/wire"
)

const usage = `usage: vault <certs|meta|node|gateway> [flags]

  vault certs   -dir data/certs -meta m1,m2,m3 -nodes n1,n2,n3 -gateways gateway [-hosts extra.example.com]
  vault meta    -id m1 -grpc 127.0.0.1:7001 -raft 127.0.0.1:7101 -dir data/m1 -tls-dir data/certs \
                -peers m1=127.0.0.1:7101,m2=127.0.0.1:7102,m3=127.0.0.1:7103
  vault node    -id n1 -addr 127.0.0.1:9101 -zone z1 -dir data/n1 -tls-dir data/certs -meta 127.0.0.1:7001,...
  vault gateway -id gateway -s3 127.0.0.1:9000 -ui 127.0.0.1:8080 -tls-dir data/certs -meta 127.0.0.1:7001,...

Every process authenticates with mutual TLS using <tls-dir>/<id>.pem.
The gateway's bootstrap admin comes from VAULT_ACCESS_KEY / VAULT_SECRET_KEY.
`

func split(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	tlsDir := fs.String("tls-dir", "data/certs", "directory with ca.pem and this process's <id>.pem / <id>-key.pem")
	loadTLS := func(id string) *wire.TLS {
		t, err := wire.LoadTLS(*tlsDir, id)
		if err != nil {
			log.Fatal(err)
		}
		return t
	}

	var err error
	switch os.Args[1] {
	case "certs":
		dir := fs.String("dir", "data/certs", "output directory (the CA is created once and reused)")
		metas := fs.String("meta", "m1,m2,m3", "meta member ids")
		nodes := fs.String("nodes", "n1,n2,n3,n4,n5", "storage node ids")
		gws := fs.String("gateways", "gateway", "gateway ids")
		hosts := fs.String("hosts", "", "extra DNS names or IPs for every certificate")
		fs.Parse(os.Args[2:])
		var specs []pki.Spec
		for role, ids := range map[string]string{pki.RoleMeta: *metas, pki.RoleNode: *nodes, pki.RoleGateway: *gws} {
			for _, id := range split(ids) {
				specs = append(specs, pki.Spec{Name: id, Role: role, Hosts: split(*hosts)})
			}
		}
		if err = pki.Generate(*dir, specs); err == nil {
			log.Printf("certificates in %s (keys are 0600; keep ca-key.pem private)", *dir)
		}
	case "meta":
		id := fs.String("id", "m1", "member id (must match its certificate)")
		grpcAddr := fs.String("grpc", "127.0.0.1:7001", "gRPC listen address")
		raftAddr := fs.String("raft", "127.0.0.1:7101", "raft listen/advertise address")
		dir := fs.String("dir", "data/m1", "data directory")
		peers := fs.String("peers", "m1=127.0.0.1:7101", "all members as id=raftAddr,...")
		fs.Parse(os.Args[2:])
		pm := map[string]string{}
		for _, p := range split(*peers) {
			k, v, ok := strings.Cut(p, "=")
			if !ok {
				log.Fatalf("bad -peers entry %q", p)
			}
			pm[k] = v
		}
		err = meta.Run(ctx, meta.Config{ID: *id, GRPCAddr: *grpcAddr, RaftAddr: *raftAddr, Dir: *dir, Peers: pm, TLS: loadTLS(*id)})
	case "node":
		id := fs.String("id", "n1", "node id (must match its certificate)")
		addr := fs.String("addr", "127.0.0.1:9101", "gRPC listen and advertise address")
		zone := fs.String("zone", "z1", "failure domain")
		dir := fs.String("dir", "data/n1", "data directory")
		metaAddrs := fs.String("meta", "127.0.0.1:7001", "meta members' gRPC addresses, comma separated")
		fs.Parse(os.Args[2:])
		err = node.Run(ctx, node.Config{ID: *id, Addr: *addr, Zone: *zone, Dir: *dir, MetaAddrs: split(*metaAddrs), TLS: loadTLS(*id)})
	case "gateway":
		id := fs.String("id", "gateway", "gateway id (must match its certificate)")
		s3 := fs.String("s3", "127.0.0.1:9000", "S3 API listen address")
		uiAddr := fs.String("ui", "127.0.0.1:8080", "web UI listen address (empty disables)")
		metaAddrs := fs.String("meta", "127.0.0.1:7001", "meta members' gRPC addresses, comma separated")
		plain := fs.Bool("plain-http", false, "serve S3 and the UI without TLS (loopback addresses only)")
		fs.Parse(os.Args[2:])
		ak, sk := os.Getenv("VAULT_ACCESS_KEY"), os.Getenv("VAULT_SECRET_KEY") // optional bootstrap admin keys
		err = gateway.Run(ctx, gateway.Config{S3Addr: *s3, UIAddr: *uiAddr, MetaAddrs: split(*metaAddrs), AccessKey: ak, SecretKey: sk, TLS: loadTLS(*id), PlainHTTP: *plain})
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}
