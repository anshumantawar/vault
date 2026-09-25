// Package wire holds the gRPC plumbing shared by every Vault process:
// a connection pool and the caller identity used for partition simulation.
package wire

import (
	"context"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// FrameSize is the payload size of one streamed chunk frame.
const FrameSize = 256 << 10

// ChunkSize is how objects are cut. Must stay below MaxChunkSize.
const ChunkSize = 4 << 20

// MaxChunkSize is the largest chunk a node accepts.
const MaxChunkSize = 16 << 20

const fromKey = "x-vault-from"

// WithFrom tags an outgoing call with the caller's id ("n1", "gateway", "meta").
func WithFrom(ctx context.Context, id string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, fromKey, id)
}

// From returns the caller id of an incoming call, or "".
func From(ctx context.Context) string {
	if v := metadata.ValueFromIncomingContext(ctx, fromKey); len(v) > 0 {
		return v[0]
	}
	return ""
}

// Pool keeps one client connection per address.
type Pool struct {
	mu    sync.Mutex
	conns map[string]*grpc.ClientConn
}

func NewPool() *Pool { return &Pool{conns: map[string]*grpc.ClientConn{}} }

// ponytail: plaintext gRPC; add mTLS before running outside one trusted network.
func (p *Pool) Get(addr string) (*grpc.ClientConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.conns[addr]; ok {
		return c, nil
	}
	c, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
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
