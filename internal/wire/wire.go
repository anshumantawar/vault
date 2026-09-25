// Package wire holds the gRPC plumbing shared by every Vault process: mutual
// TLS, caller identity taken from the peer's certificate, per-RPC role
// authorization and a connection pool.
package wire

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"vault/internal/pki"
)

// FrameSize is the payload size of one streamed chunk frame.
const FrameSize = 256 << 10

// ChunkSize is how objects are cut. Must stay below MaxChunkSize.
const ChunkSize = 4 << 20

// MaxChunkSize is the largest chunk a node accepts.
const MaxChunkSize = 16 << 20

// TLS is one process's certificate material.
type TLS struct {
	Self   pki.Identity
	CAs    *x509.CertPool
	Cert   tls.Certificate
	Server *tls.Config // gRPC/Raft servers: client certificates required
	Client *tls.Config // gRPC/Raft clients: present our certificate, verify theirs
	HTTPS  *tls.Config // public HTTPS listeners: server certificate only
}

// LoadTLS reads dir/ca.pem and dir/<name>.pem + dir/<name>-key.pem.
func LoadTLS(dir, name string) (*TLS, error) {
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, fmt.Errorf("TLS: %w (create certificates with `vault certs`)", err)
	}
	cas := x509.NewCertPool()
	if !cas.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("TLS: ca.pem holds no certificate")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, name+".pem"), filepath.Join(dir, name+"-key.pem"))
	if err != nil {
		return nil, fmt.Errorf("TLS: %w (create certificates with `vault certs`)", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	t := &TLS{Self: pki.IdentityOf(leaf), CAs: cas, Cert: cert}
	if t.Self.ID != name {
		return nil, fmt.Errorf("TLS: %s.pem is issued to %q", name, t.Self.ID)
	}
	t.Server = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    cas,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	t.Client = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		RootCAs:      cas,
	}
	t.HTTPS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	return t, nil
}

// ServerCreds and the pool's dial options make every gRPC hop mutual TLS.
func (t *TLS) ServerCreds() grpc.ServerOption {
	return grpc.Creds(credentials.NewTLS(t.Server))
}

// Caller returns the verified identity of an incoming call's peer.
func Caller(ctx context.Context) (pki.Identity, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return pki.Identity{}, false
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 || len(ti.State.PeerCertificates) == 0 {
		return pki.Identity{}, false
	}
	return pki.IdentityOf(ti.State.PeerCertificates[0]), true
}

// Rules maps a full gRPC method name to the roles allowed to call it.
// Methods not listed are denied.
type Rules map[string][]string

func (r Rules) check(ctx context.Context, method string) error {
	id, ok := Caller(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no verified client certificate")
	}
	if !slices.Contains(r[method], id.Role) {
		return status.Errorf(codes.PermissionDenied, "%s %q may not call %s", id.Role, id.ID, method)
	}
	return nil
}

// Interceptors enforce r on every unary and streaming call.
func (r Rules) Interceptors() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			if err := r.check(ctx, info.FullMethod); err != nil {
				return nil, err
			}
			return h(ctx, req)
		}),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			if err := r.check(ss.Context(), info.FullMethod); err != nil {
				return err
			}
			return h(srv, ss)
		}),
	}
}

// Pool keeps one mutual-TLS client connection per address.
type Pool struct {
	creds credentials.TransportCredentials
	mu    sync.Mutex
	conns map[string]*grpc.ClientConn
}

func NewPool(t *TLS) *Pool {
	return &Pool{creds: credentials.NewTLS(t.Client), conns: map[string]*grpc.ClientConn{}}
}

func (p *Pool) Get(addr string) (*grpc.ClientConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.conns[addr]; ok {
		return c, nil
	}
	c, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(p.creds),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxChunkSize+1<<20)),
	)
	if err != nil {
		return nil, err
	}
	p.conns[addr] = c
	return c, nil
}

func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.Close()
	}
	p.conns = map[string]*grpc.ClientConn{}
}

// chunkBufs recycles chunk-sized buffers so steady-state reads and writes
// allocate nothing per chunk.
var chunkBufs = sync.Pool{New: func() any { b := make([]byte, 0, ChunkSize); return &b }}

// GetBuf returns an empty buffer with room for a chunk. Return it with PutBuf.
func GetBuf() *[]byte { return chunkBufs.Get().(*[]byte) }

// PutBuf recycles b; oversized buffers are left to the GC.
func PutBuf(b *[]byte) {
	if cap(*b) > MaxChunkSize {
		return
	}
	*b = (*b)[:0]
	chunkBufs.Put(b)
}
