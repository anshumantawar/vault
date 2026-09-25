// Package gateway is the stateless front door: the S3 API and the web UI.
// It streams object bytes straight to storage nodes and keeps only
// metadata traffic on the meta group.
package gateway

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	vaultv1 "vault/gen/vault/v1"
	"vault/internal/meta"
	"vault/internal/node"
	"vault/internal/placement"
	"vault/internal/wire"
)

type Config struct {
	S3Addr    string
	UIAddr    string // empty disables the UI
	MetaAddrs []string
	AccessKey string
	SecretKey string
}

type Gateway struct {
	cfg   Config
	pool  *wire.Pool
	meta  *meta.Client
	nodes atomic.Pointer[[]*vaultv1.Node]

	faultMu sync.Mutex
	faults  map[string]*vaultv1.SetFaultRequest // UI-issued fault state per node

	hist *history // Stats app timeline; only sampled when the UI is enabled
}

const from = "gateway"

// Run serves the S3 API (and UI) until ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	pool := wire.NewPool()
	defer pool.Close()
	g := &Gateway{cfg: cfg, pool: pool, meta: meta.NewClient(cfg.MetaAddrs, pool, from), faults: map[string]*vaultv1.SetFaultRequest{}, hist: &history{}}
	g.nodes.Store(&[]*vaultv1.Node{})
	go g.refreshNodes(ctx)

	servers := []*http.Server{{Addr: cfg.S3Addr, Handler: http.HandlerFunc(g.serveS3)}}
	if cfg.UIAddr != "" {
		servers = append(servers, &http.Server{Addr: cfg.UIAddr, Handler: g.uiHandler()})
		go g.sampleLoop(ctx)
	}
	errc := make(chan error, len(servers))
	for _, srv := range servers {
		srv.BaseContext = func(net.Listener) context.Context { return ctx }
		go func() { errc <- srv.ListenAndServe() }()
	}
	log.Printf("gateway: S3 on http://%s, UI on http://%s", cfg.S3Addr, cfg.UIAddr)
	select {
	case <-ctx.Done():
		for _, srv := range servers {
			srv.Close()
		}
		return nil
	case err := <-errc:
		return err
	}
}

func (g *Gateway) refreshNodes(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		var resp *vaultv1.ListNodesResponse
		err := g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) (err error) {
			resp, err = c.ListNodes(ctx, &vaultv1.ListNodesRequest{})
			return err
		})
		if err == nil {
			ns := resp.GetNodes()
			g.nodes.Store(&ns)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (g *Gateway) nodeByID() map[string]*vaultv1.Node {
	m := map[string]*vaultv1.Node{}
	for _, n := range *g.nodes.Load() {
		m[n.Id] = n
	}
	return m
}

// ---- write path ----

type written struct {
	chunks []*vaultv1.Chunk
	size   int64
	md5    string
}

// writeObject cuts r into chunks and stores each on the bucket's replica
// count of nodes, needing write_quorum acks per chunk.
// ponytail: one chunk in flight at a time (replicas in parallel); pipeline
// chunks if single-stream upload throughput matters.
func (g *Gateway) writeObject(ctx context.Context, b *vaultv1.Bucket, r io.Reader) (written, error) {
	var w written
	h := md5.New()
	buf := make([]byte, wire.ChunkSize)
	for {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			data := buf[:n]
			h.Write(data)
			sum := sha256.Sum256(data)
			sha := hex.EncodeToString(sum[:])
			holders, at, werr := g.writeChunk(ctx, sha, data, int(b.GetReplicas()), int(b.GetWriteQuorum()))
			if werr != nil {
				return w, werr
			}
			w.chunks = append(w.chunks, &vaultv1.Chunk{Sha256: sha, Size: int64(n), Holders: holders, WrittenAt: at})
			w.size += int64(n)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			var se *s3Error
			if errors.As(err, &se) {
				return w, err
			}
			return w, errS3("IncompleteBody", "%v", err)
		}
	}
	w.md5 = hex.EncodeToString(h.Sum(nil))
	return w, nil
}

// writeChunk sends one chunk to its placement targets in parallel, then to
// further nodes in placement order until it has `replicas` copies or runs out.
func (g *Gateway) writeChunk(ctx context.Context, sha string, data []byte, replicas, quorum int) ([]string, int64, error) {
	var alive []placement.Node
	byID := g.nodeByID()
	for _, n := range byID {
		if n.Alive {
			alive = append(alive, placement.Node{ID: n.Id, Zone: n.Zone})
		}
	}
	order := placement.Order(sha, alive)

	var holders []string
	var minAt int64
	send := func(targets []placement.Node) {
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, t := range targets {
			wg.Go(func() {
				cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				at, err := node.SendChunk(cctx, g.pool, from, byID[t.ID].Addr, sha, data)
				if err != nil {
					log.Printf("gateway: put %.12s on %s: %v", sha, t.ID, status.Convert(err).Message())
					return
				}
				mu.Lock()
				holders = append(holders, t.ID)
				if minAt == 0 || at < minAt {
					minAt = at
				}
				mu.Unlock()
			})
		}
		wg.Wait()
	}
	first := order[:min(replicas, len(order))]
	send(first)
	for _, t := range order[len(first):] {
		if len(holders) >= replicas {
			break
		}
		send([]placement.Node{t})
	}
	if len(holders) < quorum {
		return nil, 0, errS3("ServiceUnavailable", "only %d of %d required replicas acknowledged", len(holders), quorum)
	}
	return holders, minAt, nil
}

// ---- read path ----

// readRange writes bytes [start, end] of o to w, verifying every chunk and
// falling back across replicas.
func (g *Gateway) readRange(ctx context.Context, o *vaultv1.Object, start, end int64, w io.Writer) error {
	var off int64
	for _, c := range o.GetChunks() {
		cs, ce := off, off+c.GetSize()-1
		off += c.GetSize()
		if ce < start || cs > end {
			continue
		}
		data, err := g.fetchChunk(ctx, c)
		if err != nil {
			return err
		}
		lo, hi := max(start, cs)-cs, min(end, ce)-cs
		if _, err := w.Write(data[lo : hi+1]); err != nil {
			return err
		}
	}
	return nil
}

func (g *Gateway) fetchChunk(ctx context.Context, c *vaultv1.Chunk) ([]byte, error) {
	byID := g.nodeByID()
	holders := slices.Clone(c.GetHolders())
	// Live nodes first; a node we think is dead is still worth a last try.
	slices.SortStableFunc(holders, func(a, b string) int {
		return boolInt(byID[b] != nil && byID[b].Alive) - boolInt(byID[a] != nil && byID[a].Alive)
	})
	for _, h := range holders {
		n := byID[h]
		if n == nil {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		data, err := node.FetchChunk(cctx, g.pool, from, n.Addr, c.GetSha256())
		cancel()
		if err == nil {
			return data, nil
		}
		if code := status.Code(err); code == codes.DataLoss || code == codes.NotFound {
			// That copy is bad or gone: tell the meta so repair replaces it.
			go g.reportBad(c.GetSha256(), h)
		}
		log.Printf("gateway: read %.12s from %s: %v", c.GetSha256(), h, status.Convert(err).Message())
	}
	return nil, errS3("ServiceUnavailable", "no healthy replica of chunk %.12s reachable", c.GetSha256())
}

func (g *Gateway) reportBad(sha, nodeID string) {
	g.meta.Call(context.Background(), func(ctx context.Context, c vaultv1.MetaServiceClient) error {
		_, err := c.ReportCorrupt(ctx, &vaultv1.ReportCorruptRequest{Sha256: sha, NodeId: nodeID})
		return err
	})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---- meta helpers ----

func (g *Gateway) getBucket(ctx context.Context, name string) (*vaultv1.Bucket, error) {
	var b *vaultv1.Bucket
	err := g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) error {
		resp, err := c.GetBucket(ctx, &vaultv1.GetBucketRequest{Name: name})
		b = resp.GetBucket()
		return err
	})
	return b, err
}

func (g *Gateway) getObject(ctx context.Context, bucket, key string) (*vaultv1.Object, error) {
	var o *vaultv1.Object
	err := g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) error {
		resp, err := c.GetObject(ctx, &vaultv1.GetObjectRequest{Bucket: bucket, Key: key})
		o = resp.GetObject()
		return err
	})
	return o, err
}

// putObject stores r as bucket/key; shared by S3 PutObject and UI uploads.
func (g *Gateway) putObject(ctx context.Context, bucket, key, contentType string, userMeta map[string]string, r io.Reader) (*vaultv1.Object, error) {
	b, err := g.getBucket(ctx, bucket)
	if err != nil {
		return nil, err
	}
	w, err := g.writeObject(ctx, b, r)
	if err != nil {
		return nil, err
	}
	o := &vaultv1.Object{Bucket: bucket, Key: key, Size: w.size, Etag: w.md5, ContentType: contentType, UserMeta: userMeta, Chunks: w.chunks}
	err = g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) error {
		resp, err := c.CommitObject(ctx, &vaultv1.CommitObjectRequest{Object: o})
		if err == nil && len(resp.GetRetrySha256()) > 0 {
			// GC raced us on a shared chunk; clients retry on SlowDown.
			return errS3("SlowDown", "chunk collected during upload, please retry")
		}
		return err
	})
	return o, err
}
