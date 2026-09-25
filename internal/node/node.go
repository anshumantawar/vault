// Package node is a Vault storage node: an on-disk chunk store behind the
// NodeService gRPC API, with a background scrubber and fault injection.
package node

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	vaultv1 "vault/gen/vault/v1"
	"vault/internal/meta"
	"vault/internal/wire"
)

const maxChunk = wire.MaxChunkSize

type Config struct {
	ID        string
	Addr      string // listen and advertise address
	Zone      string
	Dir       string
	MetaAddrs []string
	// ScrubBytesPerSec limits background re-hashing.
	ScrubBytesPerSec int64
}

type fault struct {
	down        bool
	partitioned []string
	slowMs      uint32
}

type server struct {
	vaultv1.UnimplementedNodeServiceServer
	cfg   Config
	store *store
	pool  *wire.Pool
	meta  *meta.Client

	mu    sync.RWMutex
	fault fault
}

// Run serves the node until ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	st, err := openStore(cfg.Dir)
	if err != nil {
		return err
	}
	if cfg.ScrubBytesPerSec == 0 {
		cfg.ScrubBytesPerSec = 64 << 20
	}
	pool := wire.NewPool()
	defer pool.Close()
	s := &server{cfg: cfg, store: st, pool: pool, meta: meta.NewClient(cfg.MetaAddrs, pool, cfg.ID)}

	lis, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return err
	}
	gs := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxChunk+1<<20),
		grpc.UnaryInterceptor(s.unaryFault),
		grpc.StreamInterceptor(s.streamFault),
	)
	vaultv1.RegisterNodeServiceServer(gs, s)

	go s.heartbeatLoop(ctx)
	go s.scrubLoop(ctx)
	go func() {
		<-ctx.Done()
		gs.Stop() // hard stop: in-flight calls fail, like a crash
	}()
	log.Printf("node %s (zone %s) serving on %s, data in %s", cfg.ID, cfg.Zone, cfg.Addr, cfg.Dir)
	err = gs.Serve(lis)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// ---- fault injection: the only place faults are applied ----

func (s *server) check(ctx context.Context, method string) error {
	if method == vaultv1.NodeService_SetFault_FullMethodName {
		return nil
	}
	s.mu.RLock()
	f := s.fault
	s.mu.RUnlock()
	if f.down {
		return status.Error(codes.Unavailable, "node is down")
	}
	if from := wire.From(ctx); from != "" && slices.Contains(f.partitioned, from) {
		return status.Errorf(codes.Unavailable, "partitioned from %s", from)
	}
	if f.slowMs > 0 {
		select {
		case <-time.After(time.Duration(f.slowMs) * time.Millisecond):
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		}
	}
	return nil
}

func (s *server) unaryFault(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	if err := s.check(ctx, info.FullMethod); err != nil {
		return nil, err
	}
	return h(ctx, req)
}

func (s *server) streamFault(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	if err := s.check(ss.Context(), info.FullMethod); err != nil {
		return err
	}
	return h(srv, ss)
}

// cannotReach reports whether this node is partitioned from peer (outbound side).
func (s *server) cannotReach(peer string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fault.down || slices.Contains(s.fault.partitioned, peer)
}

// ---- NodeService ----

type frameReader struct {
	stream vaultv1.NodeService_PutChunkServer
	buf    []byte
	sha    string
}

func (r *frameReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		m, err := r.stream.Recv()
		if err != nil {
			return 0, err // io.EOF ends the chunk
		}
		if r.sha == "" {
			r.sha = m.GetSha256()
		}
		r.buf = m.GetData()
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (s *server) PutChunk(stream vaultv1.NodeService_PutChunkServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	sha := first.GetSha256()
	if !validSHA(sha) {
		return status.Error(codes.InvalidArgument, "invalid sha256")
	}
	r := &frameReader{stream: stream, buf: first.GetData(), sha: sha}
	mtime, err := s.store.put(sha, r)
	if errors.Is(err, errCorrupt) {
		return status.Error(codes.DataLoss, "received bytes do not match sha256")
	}
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	return stream.SendAndClose(&vaultv1.PutChunkResponse{WrittenAt: mtime.UnixNano()})
}

func (s *server) read(sha string) ([]byte, error) {
	if !validSHA(sha) {
		return nil, status.Error(codes.InvalidArgument, "invalid sha256")
	}
	b, err := s.store.get(sha)
	switch {
	case errors.Is(err, errCorrupt):
		go s.reportCorrupt(sha)
		return nil, status.Error(codes.DataLoss, "chunk failed verification")
	case errors.Is(err, fs.ErrNotExist):
		return nil, status.Error(codes.NotFound, "no such chunk")
	case err != nil:
		return nil, status.Error(codes.Internal, err.Error())
	}
	return b, nil
}

func (s *server) GetChunk(req *vaultv1.GetChunkRequest, stream vaultv1.NodeService_GetChunkServer) error {
	b, err := s.read(req.GetSha256())
	if err != nil {
		return err
	}
	for len(b) > 0 {
		n := min(len(b), wire.FrameSize)
		if err := stream.Send(&vaultv1.GetChunkResponse{Data: b[:n]}); err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func (s *server) DeleteChunk(_ context.Context, req *vaultv1.DeleteChunkRequest) (*vaultv1.DeleteChunkResponse, error) {
	if !validSHA(req.GetSha256()) {
		return nil, status.Error(codes.InvalidArgument, "invalid sha256")
	}
	var before time.Time
	if req.GetIfWrittenBefore() > 0 {
		before = time.Unix(0, req.GetIfWrittenBefore())
	}
	if err := s.store.delete(req.GetSha256(), before); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &vaultv1.DeleteChunkResponse{}, nil
}

func (s *server) PushChunk(ctx context.Context, req *vaultv1.PushChunkRequest) (*vaultv1.PushChunkResponse, error) {
	if s.cannotReach(req.GetTargetId()) {
		return nil, status.Errorf(codes.Unavailable, "%s cannot reach %s", s.cfg.ID, req.GetTargetId())
	}
	b, err := s.read(req.GetSha256())
	if err != nil {
		return nil, err
	}
	at, err := SendChunk(ctx, s.pool, s.cfg.ID, req.GetTargetAddr(), req.GetSha256(), b)
	if err != nil {
		return nil, err
	}
	return &vaultv1.PushChunkResponse{WrittenAt: at}, nil
}

// SendChunk streams one chunk to the node at addr and returns its written_at.
func SendChunk(ctx context.Context, pool *wire.Pool, from, addr, sha string, b []byte) (int64, error) {
	conn, err := pool.Get(addr)
	if err != nil {
		return 0, status.Error(codes.Unavailable, err.Error())
	}
	stream, err := vaultv1.NewNodeServiceClient(conn).PutChunk(wire.WithFrom(ctx, from))
	if err != nil {
		return 0, err
	}
	for first := true; first || len(b) > 0; first = false {
		n := min(len(b), wire.FrameSize)
		m := &vaultv1.PutChunkRequest{Data: b[:n]}
		if first {
			m.Sha256 = sha
		}
		if err := stream.Send(m); err != nil {
			if err == io.EOF {
				break // server closed early; CloseAndRecv has the real error
			}
			return 0, err
		}
		b = b[n:]
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return 0, err
	}
	return resp.GetWrittenAt(), nil
}

// FetchChunk reads one chunk from the node at addr and verifies its hash.
func FetchChunk(ctx context.Context, pool *wire.Pool, from, addr, sha string) ([]byte, error) {
	conn, err := pool.Get(addr)
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	stream, err := vaultv1.NewNodeServiceClient(conn).GetChunk(wire.WithFrom(ctx, from), &vaultv1.GetChunkRequest{Sha256: sha})
	if err != nil {
		return nil, err
	}
	var b []byte
	for {
		m, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		b = append(b, m.GetData()...)
		if len(b) > maxChunk {
			return nil, status.Error(codes.DataLoss, "chunk too large")
		}
	}
	if !matches(sha, b) {
		return nil, status.Error(codes.DataLoss, "chunk failed verification in transit")
	}
	return b, nil
}

func (s *server) SetFault(_ context.Context, req *vaultv1.SetFaultRequest) (*vaultv1.SetFaultResponse, error) {
	s.mu.Lock()
	s.fault = fault{down: req.GetDown(), partitioned: req.GetPartitionedFrom(), slowMs: req.GetSlowMs()}
	s.mu.Unlock()
	log.Printf("node %s fault: down=%v partitioned=%v slow=%dms", s.cfg.ID, req.GetDown(), req.GetPartitionedFrom(), req.GetSlowMs())
	if !req.GetCorrupt() {
		return &vaultv1.SetFaultResponse{}, nil
	}
	sha := req.GetCorruptSha256()
	if sha == "" {
		var all []string
		s.store.walk(func(sha string, _ fs.FileInfo) { all = append(all, sha) })
		if len(all) == 0 {
			return nil, status.Error(codes.FailedPrecondition, "no chunks to corrupt")
		}
		sha = all[rand.IntN(len(all))]
	}
	if !validSHA(sha) {
		return nil, status.Error(codes.InvalidArgument, "invalid sha256")
	}
	if err := s.store.corrupt(sha); err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	log.Printf("node %s corrupted chunk %s", s.cfg.ID, sha[:12])
	return &vaultv1.SetFaultResponse{CorruptedSha256: sha}, nil
}

// ---- background loops ----

func (s *server) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if s.cannotReach("meta") {
			continue
		}
		s.mu.RLock()
		f := s.fault
		s.mu.RUnlock()
		n := &vaultv1.Node{
			Id: s.cfg.ID, Addr: s.cfg.Addr, Zone: s.cfg.Zone,
			UsedBytes: s.store.used.Load(), ChunkCount: s.store.count.Load(),
			PartitionedFrom: f.partitioned, SlowMs: f.slowMs,
		}
		err := s.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) error {
			_, err := c.Heartbeat(ctx, &vaultv1.HeartbeatRequest{Node: n})
			return err
		})
		if err != nil && ctx.Err() == nil {
			log.Printf("node %s heartbeat: %v", s.cfg.ID, err)
		}
	}
}

func (s *server) reportCorrupt(sha string) {
	log.Printf("node %s: chunk %s is corrupt, quarantined", s.cfg.ID, sha[:12])
	if s.cannotReach("meta") {
		return // the repairer will notice the missing copy once reachable
	}
	s.meta.Call(context.Background(), func(ctx context.Context, c vaultv1.MetaServiceClient) error {
		_, err := c.ReportCorrupt(ctx, &vaultv1.ReportCorruptRequest{Sha256: sha, NodeId: s.cfg.ID})
		return err
	})
}

// scrubLoop re-hashes every chunk at a limited rate, forever.
func (s *server) scrubLoop(ctx context.Context) {
	for ctx.Err() == nil {
		var shas []string
		s.store.walk(func(sha string, _ fs.FileInfo) { shas = append(shas, sha) })
		for _, sha := range shas {
			if ctx.Err() != nil {
				return
			}
			if s.cannotReach("") { // down: pause
				time.Sleep(time.Second)
				continue
			}
			start := time.Now()
			b, err := s.store.get(sha)
			if errors.Is(err, errCorrupt) {
				s.reportCorrupt(sha)
			}
			// Sleep so we average at most ScrubBytesPerSec.
			budget := time.Duration(float64(len(b)) / float64(s.cfg.ScrubBytesPerSec) * float64(time.Second))
			time.Sleep(max(budget-time.Since(start), time.Millisecond))
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}
