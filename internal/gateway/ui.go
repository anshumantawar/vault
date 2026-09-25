package gateway

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	vaultv1 "vault/gen/vault/v1"
	"vault/internal/gateway/ui"
)

// uiHandler serves Vault OS, the browser desktop. It is unauthenticated.
// ponytail: bind the UI to localhost only; add auth before exposing it.
func (g *Gateway) uiHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(ui.Static)))
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { ui.Desktop().Render(r.Context(), w) })
	mux.HandleFunc("GET /app/pulse", g.appPulse)
	mux.HandleFunc("GET /app/files", g.appFiles)
	mux.HandleFunc("POST /app/files/bucket", g.appCreateBucket)
	mux.HandleFunc("POST /app/files/dropbucket", g.appDropBucket)
	mux.HandleFunc("POST /app/files/upload", g.appUpload)
	mux.HandleFunc("POST /app/files/delete", g.appDelete)
	mux.HandleFunc("GET /app/view", g.appView)
	mux.HandleFunc("GET /app/stats", func(w http.ResponseWriter, r *http.Request) { ui.StatsApp().Render(r.Context(), w) })
	mux.HandleFunc("GET /app/stats/live", g.appStatsLive)
	mux.HandleFunc("GET /app/connect", func(w http.ResponseWriter, r *http.Request) {
		ui.ConnectApp(g.cfg.S3Addr, g.cfg.AccessKey).Render(r.Context(), w)
	})
	mux.HandleFunc("GET /app/present", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		ui.PresentApp(ui.DeckAt(n)).Render(r.Context(), w)
	})
	mux.HandleFunc("POST /ui/demo/heal", g.demoHeal)
	mux.HandleFunc("POST /ui/demo/setup", g.demoSetup)
	mux.HandleFunc("POST /ui/demo/readall", g.demoReadAll)
	mux.HandleFunc("GET /ui/leader", g.uiLeader)
	mux.HandleFunc("POST /ui/nodes/{id}/{action}", g.uiFault)
	mux.HandleFunc("POST /ui/meta/stepdown", g.uiStepDown)
	mux.HandleFunc("GET /obj/{bucket}/{key...}", g.uiObject)
	// Blocks cross-site form posts (CSRF) against the unauthenticated UI.
	return http.NewCrossOriginProtection().Handler(mux)
}

func errMsg(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ---- Files ----

func policyLabel(b *vaultv1.Bucket) string {
	return fmt.Sprintf("%d copies · %d acks", b.GetReplicas(), b.GetWriteQuorum())
}

// filesView lists one bucket directory, or all buckets when bucket is "".
func (g *Gateway) filesView(ctx context.Context, bucket, prefix string) ui.Files {
	f := ui.Files{Bucket: bucket, Prefix: prefix}
	if bucket == "" {
		var resp *vaultv1.ListBucketsResponse
		err := g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) (err error) {
			resp, err = c.ListBuckets(ctx, &vaultv1.ListBucketsRequest{})
			return err
		})
		f.Err = errMsg(err)
		for _, b := range resp.GetBuckets() {
			f.Buckets = append(f.Buckets, ui.Bucket{Name: b.GetName(), Policy: policyLabel(b)})
		}
		return f
	}
	b, err := g.getBucket(ctx, bucket)
	if err != nil {
		f.Err = err.Error()
		return f
	}
	f.Policy = policyLabel(b)
	var resp *vaultv1.ListObjectsResponse
	err = g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) (err error) {
		resp, err = c.ListObjects(ctx, &vaultv1.ListObjectsRequest{Bucket: bucket, Prefix: prefix, Delimiter: "/", MaxKeys: 1000})
		return err
	})
	f.Err = errMsg(err)
	f.Folders = resp.GetCommonPrefixes()
	for _, o := range resp.GetObjects() {
		f.Objects = append(f.Objects, objectView(o))
	}
	return f
}

func objectView(o *vaultv1.Object) ui.Object {
	return ui.Object{
		Bucket: o.GetBucket(), Key: o.GetKey(), Name: path.Base(o.GetKey()),
		Size: ui.Bytes(o.GetSize()), Type: o.GetContentType(),
		Modified: time.Unix(0, o.GetModifiedAt()).Format("Jan 2 15:04:05"),
	}
}

func (g *Gateway) renderFiles(w http.ResponseWriter, r *http.Request, bucket, prefix string, err error) {
	f := g.filesView(r.Context(), bucket, prefix)
	if err != nil {
		f.Err = err.Error()
	}
	ui.FilesApp(f).Render(r.Context(), w)
}

func (g *Gateway) appFiles(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	g.renderFiles(w, r, q.Get("bucket"), q.Get("prefix"), nil)
}

func (g *Gateway) appCreateBucket(w http.ResponseWriter, r *http.Request) {
	n, wq, err := parsePolicy(r.FormValue("policy"))
	if err == nil {
		err = g.createBucket(r.Context(), r.FormValue("name"), n, wq)
	}
	g.renderFiles(w, r, "", "", err)
}

func (g *Gateway) appDropBucket(w http.ResponseWriter, r *http.Request) {
	b := r.URL.Query().Get("bucket")
	if err := g.deleteBucket(r.Context(), b); err != nil {
		g.renderFiles(w, r, b, "", err)
		return
	}
	g.renderFiles(w, r, "", "", nil)
}

// appUpload streams each file of a multipart form straight into Vault,
// under the folder being viewed.
func (g *Gateway) appUpload(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	bucket, prefix := q.Get("bucket"), q.Get("prefix")
	mr, err := r.MultipartReader()
	if err != nil {
		g.renderFiles(w, r, bucket, prefix, err)
		return
	}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			g.renderFiles(w, r, bucket, prefix, err)
			return
		}
		name := path.Base(part.FileName())
		if part.FormName() != "files" || name == "." || name == "/" {
			continue
		}
		ct := part.Header.Get("Content-Type")
		if ct == "" || ct == "application/octet-stream" {
			if t := mime.TypeByExtension(path.Ext(name)); t != "" {
				ct = t
			}
		}
		if _, err := g.putObject(r.Context(), bucket, prefix+name, ct, nil, part); err != nil {
			g.renderFiles(w, r, bucket, prefix, fmt.Errorf("%s: %w", name, err))
			return
		}
	}
	g.renderFiles(w, r, bucket, prefix, nil)
}

func (g *Gateway) appDelete(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if err := g.deleteObject(r.Context(), q.Get("bucket"), q.Get("key")); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("HX-Trigger", "vault:changed") // every open Files window reloads
}

func (g *Gateway) appView(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	o, err := g.getObject(r.Context(), q.Get("bucket"), q.Get("key"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	nodes := g.nodeByID()
	v := ui.Viewer{Object: objectView(o), ETag: o.GetEtag()}
	for i, c := range o.GetChunks() {
		ci := ui.ChunkInfo{N: i + 1, SHA: c.GetSha256(), Size: ui.Bytes(c.GetSize())}
		for _, h := range c.GetHolders() {
			ci.Holders = append(ci.Holders, ui.Holder{ID: h, Alive: nodes[h] != nil && nodes[h].Alive})
		}
		v.Chunks = append(v.Chunks, ci)
	}
	ui.ViewerApp(v).Render(r.Context(), w)
}

// ---- Stats ----

const heatmapRows = 96

func (g *Gateway) appPulse(w http.ResponseWriter, r *http.Request) {
	ui.Pulse(g.clusterView(r.Context(), 0)).Render(r.Context(), w)
}

func (g *Gateway) appStatsLive(w http.ResponseWriter, r *http.Request) {
	ui.StatsLive(g.clusterView(r.Context(), heatmapRows)).Render(r.Context(), w)
}

func (g *Gateway) clusterView(ctx context.Context, maxChunks uint32) ui.Cluster {
	var c ui.Cluster
	var wg sync.WaitGroup
	if maxChunks > 0 {
		wg.Go(func() { c.Raft = g.raftViews(ctx) })
	}
	var st *vaultv1.ClusterStatusResponse
	err := g.meta.Call(ctx, func(ctx context.Context, mc vaultv1.MetaServiceClient) (err error) {
		st, err = mc.ClusterStatus(ctx, &vaultv1.ClusterStatusRequest{MaxChunks: maxChunks})
		return err
	})
	wg.Wait()
	if err != nil {
		c.Err = err.Error()
		return c
	}

	var ids []string
	alive := map[string]bool{}
	for _, n := range st.GetNodes() {
		ids = append(ids, n.GetId())
		alive[n.GetId()] = n.GetAlive()
	}
	g.faultMu.Lock()
	for _, n := range st.GetNodes() {
		v := ui.Node{
			ID: n.GetId(), Zone: n.GetZone(), Addr: n.GetAddr(), Alive: n.GetAlive(),
			Partitioned: n.GetPartitionedFrom(), SlowMs: n.GetSlowMs(),
			Used: ui.Bytes(n.GetUsedBytes()), Chunks: n.GetChunkCount(),
		}
		if f := g.faults[n.GetId()]; f != nil {
			v.Down, v.Partitioned, v.SlowMs = f.GetDown(), f.GetPartitionedFrom(), f.GetSlowMs()
		}
		for _, p := range append(slices.Clone(ids), "meta", "gateway") {
			if p != n.GetId() {
				v.Peers = append(v.Peers, p)
			}
		}
		c.Nodes = append(c.Nodes, v)
	}
	g.faultMu.Unlock()

	for _, ch := range st.GetChunks() {
		row := ui.ChunkRow{SHA: ch.GetSha256(), State: "ok"}
		live := 0
		for _, id := range ids {
			cell := ui.CellNone
			if slices.Contains(ch.GetHolders(), id) {
				cell = ui.CellStale
				if alive[id] {
					cell = ui.CellOK
					live++
				}
			}
			row.Cells = append(row.Cells, cell)
		}
		switch {
		case live == 0:
			row.State = "lost"
		case live < int(ch.GetWant()):
			row.State = "degraded"
		}
		c.Rows = append(c.Rows, row)
	}

	c.MoreChunks = st.GetTotalChunks() - int64(len(st.GetChunks()))
	c.Objects, c.TotalChunks, c.Under, c.Lost = st.GetObjects(), st.GetTotalChunks(), st.GetUnderReplicated(), st.GetLost()
	c.Repairs, c.Rebalances = st.GetRepairs(), st.GetRebalances()
	c.Logical, c.Raw = ui.Bytes(st.GetLogicalBytes()), ui.Bytes(st.GetRawBytes())
	c.Overhead = "–"
	if st.GetLogicalBytes() > 0 {
		c.Overhead = fmt.Sprintf("%.2f×", float64(st.GetRawBytes())/float64(st.GetLogicalBytes()))
	}
	c.MTTR = "–"
	if st.GetLastMttrMs() > 0 {
		c.MTTR = (time.Duration(st.GetLastMttrMs()) * time.Millisecond).Round(100 * time.Millisecond).String()
	}
	if ds := st.GetDegradedSince(); ds > 0 {
		c.Healing = time.Since(time.Unix(0, ds)).Round(time.Second).String()
	}
	return c
}

// raftViews asks every meta member directly, so Stats shows followers and dead members too.
func (g *Gateway) raftViews(ctx context.Context) []ui.Raft {
	addrs := g.meta.Addrs()
	out := make([]ui.Raft, len(addrs))
	var wg sync.WaitGroup
	for i, a := range addrs {
		wg.Go(func() {
			out[i] = ui.Raft{ID: a}
			conn, err := g.pool.Get(a)
			if err != nil {
				return
			}
			cctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()
			rs, err := vaultv1.NewMetaServiceClient(conn).RaftStatus(cctx, &vaultv1.RaftStatusRequest{})
			if err != nil {
				return
			}
			out[i] = ui.Raft{ID: rs.GetId(), State: rs.GetState(), Leader: rs.GetLeaderId(), Term: rs.GetTerm(), Index: rs.GetLastIndex(), Up: true}
		})
	}
	wg.Wait()
	return out
}

// ---- chaos controls ----

func (g *Gateway) uiFault(w http.ResponseWriter, r *http.Request) {
	id, action := r.PathValue("id"), r.PathValue("action")
	n := g.nodeByID()[id]
	if n == nil {
		http.Error(w, "unknown node", http.StatusNotFound)
		return
	}
	g.faultMu.Lock()
	f := g.faults[id]
	if f == nil {
		f = &vaultv1.SetFaultRequest{PartitionedFrom: n.GetPartitionedFrom(), SlowMs: n.GetSlowMs()}
		g.faults[id] = f
	}
	switch action {
	case "kill":
		f.Down = true
	case "revive":
		f.Down = false
	case "slow":
		if f.SlowMs > 0 {
			f.SlowMs = 0
		} else {
			f.SlowMs = 800
		}
	case "partition":
		peer := r.URL.Query().Get("peer")
		if i := slices.Index(f.PartitionedFrom, peer); i >= 0 {
			f.PartitionedFrom = slices.Delete(f.PartitionedFrom, i, i+1)
		} else if peer != "" {
			f.PartitionedFrom = append(f.PartitionedFrom, peer)
		}
	case "corrupt":
	default:
		g.faultMu.Unlock()
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	req := &vaultv1.SetFaultRequest{Down: f.Down, PartitionedFrom: slices.Clone(f.PartitionedFrom), SlowMs: f.SlowMs, Corrupt: action == "corrupt"}
	g.faultMu.Unlock()

	conn, err := g.pool.Get(n.GetAddr())
	if err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		_, err = vaultv1.NewNodeServiceClient(conn).SetFault(ctx, req)
		cancel()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	fmt.Fprintf(w, "%s: %s applied", id, action)
}

func (g *Gateway) uiStepDown(w http.ResponseWriter, r *http.Request) {
	err := g.meta.Call(r.Context(), func(ctx context.Context, c vaultv1.MetaServiceClient) error {
		_, err := c.StepDown(ctx, &vaultv1.StepDownRequest{})
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	fmt.Fprint(w, "leadership handed to another member")
}

// ---- Present demo actions ----

// demoHeal clears every injected fault (kill, slow, cut links) on every node.
func (g *Gateway) demoHeal(w http.ResponseWriter, r *http.Request) {
	g.faultMu.Lock()
	clear(g.faults)
	g.faultMu.Unlock()
	healed, failed := 0, 0
	for _, n := range *g.nodes.Load() {
		conn, err := g.pool.Get(n.GetAddr())
		if err == nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			_, err = vaultv1.NewNodeServiceClient(conn).SetFault(ctx, &vaultv1.SetFaultRequest{})
			cancel()
		}
		if err != nil {
			failed++
			continue
		}
		healed++
	}
	fmt.Fprintf(w, "cleared faults on %d nodes", healed)
	if failed > 0 {
		fmt.Fprintf(w, " (%d unreachable: processes that were really stopped need restarting)", failed)
	}
}

func (g *Gateway) demoSetup(w http.ResponseWriter, r *http.Request) {
	err := g.createBucket(r.Context(), "photos", 3, 2)
	if err != nil && !strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	fmt.Fprint(w, "bucket “photos” ready (3 copies, 2 acks); upload into it from Files or the aws CLI")
}

// demoReadAll reads every object end to end; each chunk's SHA-256 is verified on the way.
func (g *Gateway) demoReadAll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var buckets *vaultv1.ListBucketsResponse
	err := g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) (err error) {
		buckets, err = c.ListBuckets(ctx, &vaultv1.ListBucketsRequest{})
		return err
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	var objects, failed int
	var bytes int64
	start := time.Now()
	for _, b := range buckets.GetBuckets() {
		after := ""
		for {
			var page *vaultv1.ListObjectsResponse
			err := g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) (err error) {
				page, err = c.ListObjects(ctx, &vaultv1.ListObjectsRequest{Bucket: b.GetName(), StartAfter: after, MaxKeys: 1000})
				return err
			})
			if err != nil {
				failed++
				break
			}
			for _, o := range page.GetObjects() {
				objects++
				full, err := g.getObject(ctx, b.GetName(), o.GetKey())
				if err == nil && full.GetSize() > 0 {
					err = g.readRange(ctx, full, 0, full.GetSize()-1, io.Discard)
				}
				if err != nil {
					failed++
					continue
				}
				bytes += full.GetSize()
			}
			if !page.GetTruncated() {
				break
			}
			after = page.GetNextStartAfter()
		}
	}
	if failed > 0 {
		fmt.Fprintf(w, "read %d objects: %d FAILED", objects, failed)
		return
	}
	fmt.Fprintf(w, "read %d objects (%s) in %s: every chunk verified", objects, ui.Bytes(bytes), time.Since(start).Round(time.Millisecond))
}

// uiLeader prints the Raft leader's id, for `scripts/demo.sh kill $(curl …/ui/leader)`.
func (g *Gateway) uiLeader(w http.ResponseWriter, r *http.Request) {
	for _, rv := range g.raftViews(r.Context()) {
		if rv.State == "Leader" {
			fmt.Fprint(w, rv.ID)
			return
		}
	}
	http.Error(w, "no leader", http.StatusServiceUnavailable)
}

// uiObject serves an object's bytes to the browser (previews, thumbnails, downloads).
func (g *Gateway) uiObject(w http.ResponseWriter, r *http.Request) {
	o, err := g.getObject(r.Context(), r.PathValue("bucket"), r.PathValue("key"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	start, end, partial, err := parseRange(r.Header.Get("Range"), o.GetSize())
	if err != nil {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", o.GetSize()))
		http.Error(w, err.Error(), http.StatusRequestedRangeNotSatisfiable)
		return
	}
	h := w.Header()
	h.Set("Content-Type", o.GetContentType())
	h.Set("Accept-Ranges", "bytes")    // lets <video> and <audio> seek
	h.Set("Cache-Control", "no-store") // so the demo really re-reads through failures
	h.Set("X-Content-Type-Options", "nosniff")
	if strings.Contains(o.GetContentType(), "html") || strings.Contains(o.GetContentType(), "svg") || strings.Contains(o.GetContentType(), "javascript") {
		// Uploaded markup must not run script in the UI's origin.
		h.Set("Content-Security-Policy", "sandbox")
	}
	h.Set("Content-Length", fmt.Sprint(max(end-start+1, 0)))
	if partial {
		h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, o.GetSize()))
		w.WriteHeader(http.StatusPartialContent)
	}
	if o.GetSize() > 0 {
		if err := g.readRange(r.Context(), o, start, end, w); err != nil {
			panic(http.ErrAbortHandler)
		}
	}
}
