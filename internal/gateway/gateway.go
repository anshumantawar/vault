// Package gateway is the stateless front door: the S3 API and the web UI.
// It streams object bytes straight to storage nodes and keeps only
// metadata traffic on the meta group.
package gateway

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	"vault/internal/pki"
	"vault/internal/placement"
	"vault/internal/wire"
)

type Config struct {
	S3Addr    string
	UIAddr    string // empty disables the UI
	MetaAddrs []string
	// AccessKey/SecretKey are the bootstrap admin, created in the cluster's
	// user table on first start. Other users are managed in the Users app.
	AccessKey string
	SecretKey string
	TLS       *wire.TLS // gateway certificate: mutual TLS inside, HTTPS outside
	// PlainHTTP serves S3 and the UI without TLS. Only allowed on loopback.
	PlainHTTP bool
}

type Gateway struct {
	cfg   Config
	pool  *wire.Pool
	meta  *meta.Client
	nodes atomic.Pointer[[]*vaultv1.Node]
	users users

	faultMu sync.Mutex
	faults  map[string]*vaultv1.SetFaultRequest // UI-issued fault state per node

	hist *history // Stats app timeline; only sampled when the UI is enabled
}

// Run serves the S3 API (and UI) until ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	if cfg.TLS == nil || cfg.TLS.Self.Role != pki.RoleGateway {
		return errors.New("gateway needs a gateway certificate")
	}
	// The bootstrap admin is created once; later starts keep the stored secret.
	// Without a secret the UI still works; S3 clients use keys from the Users app.
	if cfg.AccessKey == "" {
		cfg.AccessKey = "vaultadmin"
	}
	if cfg.SecretKey == "" {
		cfg.SecretKey = rand.Text()
	}
	if len(cfg.AccessKey) < 8 || len(cfg.SecretKey) < 16 {
		return errors.New("admin access key must be ≥ 8 characters and secret ≥ 16")
	}
	if cfg.PlainHTTP {
		for _, a := range []string{cfg.S3Addr, cfg.UIAddr} {
			if a != "" && !isLoopback(a) {
				return fmt.Errorf("plain HTTP is only allowed on loopback, not %s", a)
			}
		}
	}
	pool := wire.NewPool(cfg.TLS)
	defer pool.Close()
	g := &Gateway{cfg: cfg, pool: pool, meta: meta.NewClient(cfg.MetaAddrs, pool), faults: map[string]*vaultv1.SetFaultRequest{}, hist: &history{}}
	g.nodes.Store(&[]*vaultv1.Node{})
	go g.refreshNodes(ctx)
	go g.usersLoop(ctx)

	servers := []*http.Server{{Addr: cfg.S3Addr, Handler: http.HandlerFunc(g.serveS3)}}
	if cfg.UIAddr != "" {
		servers = append(servers, &http.Server{Addr: cfg.UIAddr, Handler: g.uiHandler()})
		go g.sampleLoop(ctx)
	}
	scheme := "https"
	if cfg.PlainHTTP {
		scheme = "http"
	}
	errc := make(chan error, len(servers))
	for _, srv := range servers {
		srv.BaseContext = func(net.Listener) context.Context { return ctx }
		srv.ReadHeaderTimeout = 10 * time.Second
		if cfg.PlainHTTP {
			go func() { errc <- srv.ListenAndServe() }()
			continue
		}
		srv.TLSConfig = cfg.TLS.HTTPS.Clone() // net/http edits it (HTTP/2 setup): one copy per server
		go func() { errc <- srv.ListenAndServeTLS("", "") }()
	}
	log.Printf("gateway %s: S3 on %s://%s, UI on %s://%s", cfg.TLS.Self.ID, scheme, cfg.S3Addr, scheme, cfg.UIAddr)
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

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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

// pipeline is how many chunks of one object are written or fetched at once.
// Memory per request is bounded by pipeline × ChunkSize (pooled buffers).
const pipeline = 4

// writeObject cuts r into chunks and stores each on the bucket's replica
// count of nodes, needing write_quorum acks per chunk. Up to `pipeline`
// chunks are in flight at once; reading and MD5 stay in order on this goroutine.
func (g *Gateway) writeObject(ctx context.Context, b *vaultv1.Bucket, r io.Reader) (written, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		w       written
		h       = md5.New()
		slots   = make(chan struct{}, pipeline)
		wg      sync.WaitGroup
		errOnce sync.Once
		failed  error
	)
	fail := func(err error) {
		errOnce.Do(func() { failed = err; cancel() })
	}
	for ctx.Err() == nil {
		buf := wire.GetBuf()
		n, err := io.ReadFull(r, (*buf)[:wire.ChunkSize])
		if n > 0 {
			data := (*buf)[:n]
			h.Write(data)
			c := &vaultv1.Chunk{Size: int64(n)}
			w.chunks = append(w.chunks, c) // filled in by the worker; order is fixed here
			w.size += int64(n)
			slots <- struct{}{}
			wg.Go(func() {
				defer func() { wire.PutBuf(buf); <-slots }()
				sum := sha256.Sum256(data)
				c.Sha256 = hex.EncodeToString(sum[:])
				holders, at, werr := g.writeChunk(ctx, c.Sha256, data, int(b.GetReplicas()), int(b.GetWriteQuorum()))
				if werr != nil {
					fail(werr)
					return
				}
				c.Holders, c.WrittenAt = holders, at
			})
		} else {
			wire.PutBuf(buf)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			var se *s3Error
			if !errors.As(err, &se) {
				err = errS3("IncompleteBody", "%v", err)
			}
			fail(err)
		}
	}
	wg.Wait()
	if failed != nil {
		return w, failed
	}
	if err := ctx.Err(); err != nil {
		return w, err
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
				at, err := node.SendChunk(cctx, g.pool, byID[t.ID].Addr, sha, data)
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
// falling back across replicas. The next `pipeline` chunks are fetched while
// earlier ones are written, always in order.
func (g *Gateway) readRange(ctx context.Context, o *vaultv1.Object, start, end int64, w io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type piece struct {
		lo, hi int64
		buf    *[]byte
		data   []byte
		err    error
		ready  chan struct{}
	}
	queue := make(chan *piece, pipeline) // bounds chunks in flight
	go func() {
		defer close(queue)
		var off int64
		for _, c := range o.GetChunks() {
			cs, ce := off, off+c.GetSize()-1
			off += c.GetSize()
			if ce < start || cs > end {
				continue
			}
			p := &piece{lo: max(start, cs) - cs, hi: min(end, ce) - cs, buf: wire.GetBuf(), ready: make(chan struct{})}
			select {
			case queue <- p:
			case <-ctx.Done():
				wire.PutBuf(p.buf)
				return
			}
			go func() {
				p.data, p.err = g.fetchChunk(ctx, c, *p.buf)
				close(p.ready)
			}()
		}
	}()
	var werr error
	for p := range queue {
		<-p.ready
		if werr == nil && p.err != nil {
			werr = p.err
		}
		if werr == nil {
			*p.buf = p.data
			if _, err := w.Write(p.data[p.lo : p.hi+1]); err != nil {
				werr = err
			}
		}
		wire.PutBuf(p.buf)
		if werr != nil {
			cancel() // stop fetching; drain what's queued
		}
	}
	return werr
}

// fetchChunk reads c from its holders into buf, live holders first.
func (g *Gateway) fetchChunk(ctx context.Context, c *vaultv1.Chunk, buf []byte) ([]byte, error) {
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
		data, err := node.FetchChunk(cctx, g.pool, n.Addr, c.GetSha256(), buf)
		cancel()
		if err == nil {
			return data, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
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
