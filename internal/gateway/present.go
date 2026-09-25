package gateway

import (
	"context"
	"fmt"
	"html"
	"io"
	"math/rand/v2"
	"net/http"
	"slices"
	"strings"
	"time"

	vaultv1 "vault/gen/vault/v1"
	"vault/internal/gateway/ui"
)

// say writes a short, HTML-escaped reply for a slide's result line.
func say(w http.ResponseWriter, format string, a ...any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, html.EscapeString(fmt.Sprintf(format, a...)))
}

// presentLive renders a slide's live panel: health, raft, bars, arch or recap.
func (g *Gateway) presentLive(w http.ResponseWriter, r *http.Request) {
	l := g.liveView(r.Context())
	var c interface {
		Render(context.Context, io.Writer) error
	}
	switch r.URL.Query().Get("w") {
	case "raft":
		c = ui.LiveRaft(l)
	case "bars":
		c = ui.LiveBars(l)
	case "arch":
		c = ui.LiveArch(l)
	case "recap":
		c = ui.LiveRecap(l)
	default:
		c = ui.LiveHealth(l)
	}
	w.Header().Set("Cache-Control", "no-store")
	c.Render(r.Context(), w)
}

var eventIcons = map[string]string{"bad": "✕", "good": "✓", "chaos": "⚡", "info": "•"}

func (g *Gateway) liveView(ctx context.Context) ui.Live {
	var l ui.Live
	samples, events, raft := g.hist.window(time.Now().Add(-time.Minute).UnixMilli())
	l.Raft = raft
	slices.SortFunc(l.Raft, func(a, b ui.Raft) int { return strings.Compare(a.ID, b.ID) })
	for i := len(events) - 1; i >= 0 && len(l.Events) < 4; i-- {
		e := events[i]
		l.Events = append(l.Events, ui.LiveEvent{Time: time.UnixMilli(e.T).Format("15:04:05"), Kind: e.Kind, Icon: eventIcons[e.Kind], Text: e.Text})
	}

	// sparkline of pieces missing a copy over the last minute
	l.SparkMax = 4
	for _, s := range samples {
		l.SparkMax = max(l.SparkMax, s.Degraded+s.Lost)
	}
	var pts []string
	for i, s := range samples {
		x := 240.0
		if len(samples) > 1 {
			x = float64(i) / float64(len(samples)-1) * 240
		}
		y := 42 - float64(s.Degraded+s.Lost)/float64(l.SparkMax)*38
		pts = append(pts, fmt.Sprintf("%.1f,%.1f", x, y))
	}
	l.Spark = strings.Join(pts, " ")

	var st *vaultv1.ClusterStatusResponse
	err := g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) (err error) {
		st, err = c.ClusterStatus(ctx, &vaultv1.ClusterStatusRequest{})
		return err
	})
	if err != nil {
		l.Err = err.Error()
		return l
	}
	zones := map[string]*ui.Zone{}
	for _, n := range st.GetNodes() {
		ln := ui.LiveNode{ID: n.GetId(), Zone: n.GetZone(), State: g.nodeState(n), Chunks: n.GetChunkCount()}
		l.Nodes = append(l.Nodes, ln)
		l.MaxChunks = max(l.MaxChunks, ln.Chunks)
		if zones[ln.Zone] == nil {
			zones[ln.Zone] = &ui.Zone{Name: ln.Zone}
		}
		zones[ln.Zone].Nodes = append(zones[ln.Zone].Nodes, ln)
	}
	for _, z := range zones {
		l.Zones = append(l.Zones, *z)
	}
	slices.SortFunc(l.Zones, func(a, b ui.Zone) int { return strings.Compare(a.Name, b.Name) })

	l.Missing, l.Lost, l.Total = st.GetUnderReplicated(), st.GetLost(), st.GetTotalChunks()
	l.Objects, l.Repairs = st.GetObjects(), st.GetRepairs()
	l.Pct = "100%"
	if l.Total > 0 {
		l.Pct = fmt.Sprintf("%g%%", float64(int((l.Total-l.Missing-l.Lost)*1000/l.Total))/10)
	}
	l.MTTR = "–"
	if st.GetLastMttrMs() > 0 {
		l.MTTR = (time.Duration(st.GetLastMttrMs()) * time.Millisecond).Round(100 * time.Millisecond).String()
	}
	if ds := st.GetDegradedSince(); ds > 0 {
		l.Healing = time.Since(time.Unix(0, ds)).Round(time.Second).String()
	}
	l.Stored = ui.Bytes(st.GetLogicalBytes())
	l.Overhead = "–"
	if st.GetLogicalBytes() > 0 {
		l.Overhead = fmt.Sprintf("%.2f×", float64(st.GetRawBytes())/float64(st.GetLogicalBytes()))
	}
	return l
}

// pickNode chooses a demo victim: a healthy node holding the most pieces.
func (g *Gateway) pickNode() *vaultv1.Node {
	var best *vaultv1.Node
	for _, n := range *g.nodes.Load() {
		if g.nodeState(n) != "up" {
			continue
		}
		if best == nil || n.GetChunkCount() > best.GetChunkCount() || n.GetChunkCount() == best.GetChunkCount() && n.GetId() < best.GetId() {
			best = n
		}
	}
	return best
}

func (g *Gateway) demoCrash(w http.ResponseWriter, r *http.Request) {
	n := g.pickNode()
	if n == nil {
		say(w, "Every server is already down or cut off. Press “Bring servers back” first.")
		return
	}
	if _, err := g.applyFault(r.Context(), n.GetId(), "kill", ""); err != nil {
		say(w, "Could not crash %s: %v", n.GetId(), err)
		return
	}
	say(w, "Crashed %s, which held %d pieces. Watch them get copied again below.", n.GetId(), n.GetChunkCount())
}

func (g *Gateway) demoCorrupt(w http.ResponseWriter, r *http.Request) {
	n := g.pickNode()
	if n == nil || n.GetChunkCount() == 0 {
		say(w, "No healthy server holds any pieces yet. Save a sample file first.")
		return
	}
	sha, err := g.applyFault(r.Context(), n.GetId(), "corrupt", "")
	if err != nil {
		say(w, "Could not damage a piece on %s: %v", n.GetId(), err)
		return
	}
	say(w, "Flipped one byte inside piece %.8s on %s. No error was reported. Now press “Open every file”.", sha, n.GetId())
}

func (g *Gateway) demoPartition(w http.ResponseWriter, r *http.Request) {
	n := g.pickNode()
	if n == nil {
		say(w, "Every server is already down or cut off. Press “Heal the network” first.")
		return
	}
	if _, err := g.applyFault(r.Context(), n.GetId(), "partition", "meta"); err != nil {
		say(w, "Could not cut %s off: %v", n.GetId(), err)
		return
	}
	say(w, "Cut %s off from the librarians. It is still running, but they can no longer hear it.", n.GetId())
}

// demoSample saves a fresh 9 MiB file (three pieces) into the "demo" bucket
// and shows where each piece landed. It overwrites the same key each time,
// so the old copies are cleaned up instead of piling up.
func (g *Gateway) demoSample(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := g.createBucket(ctx, "demo", 3, 2); err != nil && !strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") {
		say(w, "Could not prepare the demo bucket: %v", err)
		return
	}
	const size = 9 << 20
	seed := [32]byte{}
	copy(seed[:], time.Now().String())
	body := io.LimitReader(rand.NewChaCha8(seed), size)
	start := time.Now()
	o, err := g.putObject(ctx, "demo", "sample.bin", "application/octet-stream", nil, body)
	if err != nil {
		say(w, "Saving failed: %v", err)
		return
	}
	g.hist.log("info", "You saved a %s sample file", ui.Bytes(size))
	nodes := g.nodeByID()
	res := ui.SampleResult{Name: "demo/sample.bin", Size: fmt.Sprintf("%s in %s", ui.Bytes(size), time.Since(start).Round(time.Millisecond))}
	for i, c := range o.GetChunks() {
		p := ui.SamplePiece{N: i + 1, Fingerprint: c.GetSha256()[:8]}
		for _, h := range c.GetHolders() {
			ln := ui.LiveNode{ID: h, State: "up"}
			if n := nodes[h]; n != nil {
				ln.Zone = n.GetZone()
			}
			p.Holders = append(p.Holders, ln)
		}
		res.Pieces = append(res.Pieces, p)
	}
	ui.SampleView(res).Render(ctx, w)
}
