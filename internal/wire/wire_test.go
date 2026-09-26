package wire

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"vault/internal/pki"
)

func certDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	err := pki.Generate(dir, []pki.Spec{{Name: "n1", Role: pki.RoleNode}, {Name: "gw", Role: pki.RoleGateway}})
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// callerCtx is an incoming-call context whose peer presented t's certificate.
func callerCtx(t *TLS) context.Context {
	leaf, _ := x509.ParseCertificate(t.Cert.Certificate[0])
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}}})
}

func TestLoadTLS(t *testing.T) {
	dir := certDir(t)
	n1, err := LoadTLS(dir, "n1")
	if err != nil {
		t.Fatal(err)
	}
	if n1.Self != (pki.Identity{Role: pki.RoleNode, ID: "n1"}) {
		t.Errorf("identity = %+v", n1.Self)
	}
	if n1.Server.ClientAuth != tls.RequireAndVerifyClientCert || n1.Server.MinVersion != tls.VersionTLS13 {
		t.Error("server config must require verified client certificates over TLS 1.3")
	}
	// A certificate copied under another process's name is refused.
	os.Rename(filepath.Join(dir, "gw.pem"), filepath.Join(dir, "n2.pem"))
	os.Rename(filepath.Join(dir, "gw-key.pem"), filepath.Join(dir, "n2-key.pem"))
	if _, err := LoadTLS(dir, "n2"); err == nil {
		t.Error("loaded a certificate issued to another process")
	}
	if _, err := LoadTLS(t.TempDir(), "n1"); err == nil {
		t.Error("loaded TLS from an empty directory")
	}
}

func TestRulesCheck(t *testing.T) {
	dir := certDir(t)
	node, _ := LoadTLS(dir, "n1")
	gw, _ := LoadTLS(dir, "gw")
	const (
		heartbeat = "/vault.v1.MetaService/Heartbeat"
		putObject = "/vault.v1.MetaService/PutObject"
	)
	rules := Rules{heartbeat: {pki.RoleNode}, putObject: {pki.RoleGateway}}

	for _, tc := range []struct {
		name   string
		ctx    context.Context
		method string
		want   codes.Code
	}{
		{"allowed role", callerCtx(node), heartbeat, codes.OK},
		{"wrong role", callerCtx(node), putObject, codes.PermissionDenied},
		{"other allowed role", callerCtx(gw), putObject, codes.OK},
		{"unlisted method", callerCtx(gw), "/vault.v1.MetaService/Unknown", codes.PermissionDenied},
		{"no peer", context.Background(), heartbeat, codes.Unauthenticated},
		{"unverified peer", peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{}}), heartbeat, codes.Unauthenticated},
	} {
		if got := status.Code(rules.check(tc.ctx, tc.method)); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestBufPool(t *testing.T) {
	b := GetBuf()
	if len(*b) != 0 || cap(*b) < ChunkSize {
		t.Fatalf("GetBuf: len %d cap %d", len(*b), cap(*b))
	}
	*b = append(*b, 1, 2, 3)
	PutBuf(b)
	if b2 := GetBuf(); len(*b2) != 0 {
		t.Errorf("recycled buffer not reset: len %d", len(*b2))
	}
}
