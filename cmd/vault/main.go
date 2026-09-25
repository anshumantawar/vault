// Command vault runs one Vault process: a meta member, a storage node or a gateway.
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
)

const usage = `usage: vault <meta|node|gateway> [flags]

  vault meta    -id m1 -grpc 127.0.0.1:7001 -raft 127.0.0.1:7101 -dir data/m1 \
                -peers m1=127.0.0.1:7101,m2=127.0.0.1:7102,m3=127.0.0.1:7103
  vault node    -id n1 -addr 127.0.0.1:9101 -zone z1 -dir data/n1 -meta 127.0.0.1:7001,127.0.0.1:7002,127.0.0.1:7003
  vault gateway -s3 127.0.0.1:9000 -ui 127.0.0.1:8080 -meta 127.0.0.1:7001,127.0.0.1:7002,127.0.0.1:7003

Gateway credentials come from VAULT_ACCESS_KEY / VAULT_SECRET_KEY.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	var err error
	switch os.Args[1] {
	case "meta":
		id := fs.String("id", "m1", "member id")
		grpcAddr := fs.String("grpc", "127.0.0.1:7001", "gRPC listen address")
		raftAddr := fs.String("raft", "127.0.0.1:7101", "raft listen/advertise address")
		dir := fs.String("dir", "data/m1", "data directory")
		peers := fs.String("peers", "m1=127.0.0.1:7101", "all members as id=raftAddr,...")
		fs.Parse(os.Args[2:])
		pm := map[string]string{}
		for _, p := range strings.Split(*peers, ",") {
			k, v, ok := strings.Cut(p, "=")
			if !ok {
				log.Fatalf("bad -peers entry %q", p)
			}
			pm[k] = v
		}
		err = meta.Run(ctx, meta.Config{ID: *id, GRPCAddr: *grpcAddr, RaftAddr: *raftAddr, Dir: *dir, Peers: pm})
	case "node":
		id := fs.String("id", "n1", "node id")
		addr := fs.String("addr", "127.0.0.1:9101", "gRPC listen and advertise address")
		zone := fs.String("zone", "z1", "failure domain")
		dir := fs.String("dir", "data/n1", "data directory")
		metaAddrs := fs.String("meta", "127.0.0.1:7001", "meta members' gRPC addresses, comma separated")
		fs.Parse(os.Args[2:])
		err = node.Run(ctx, node.Config{ID: *id, Addr: *addr, Zone: *zone, Dir: *dir, MetaAddrs: strings.Split(*metaAddrs, ",")})
	case "gateway":
		s3 := fs.String("s3", "127.0.0.1:9000", "S3 API listen address")
		uiAddr := fs.String("ui", "127.0.0.1:8080", "web UI listen address (empty disables)")
		metaAddrs := fs.String("meta", "127.0.0.1:7001", "meta members' gRPC addresses, comma separated")
		fs.Parse(os.Args[2:])
		ak, sk := os.Getenv("VAULT_ACCESS_KEY"), os.Getenv("VAULT_SECRET_KEY")
		if ak == "" || sk == "" {
			log.Fatal("set VAULT_ACCESS_KEY and VAULT_SECRET_KEY")
		}
		err = gateway.Run(ctx, gateway.Config{S3Addr: *s3, UIAddr: *uiAddr, MetaAddrs: strings.Split(*metaAddrs, ","), AccessKey: ak, SecretKey: sk})
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}
