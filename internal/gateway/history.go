package gateway

import (
	"context"
	"fmt"
	"sync"
	"time"

	vaultv1 "vault/gen/vault/v1"
	"vault/internal/gateway/ui"
)

// History feeds the Stats app: one cluster sample per second for the last
// 15 minutes, plus a human-readable event log derived from the changes.
// ponytail: per-gateway and in memory; each gateway shows what it has seen since it started.
const (
	historyLen = 15 * 60
	eventsLen  = 200
)

type sample struct {
	T        int64             `json:"t"` // unix ms
	Degraded int64             `json:"d"` // chunks missing a copy
	Lost     int64             `json:"l"` // chunks with no live copy
	Nodes    map[string]string `json:"n"` // node id → up | impaired | down
}

type event struct {
	T    int64  `json:"t"`
	Kind string `json:"k"` // bad | good | info | chaos
	Text string `json:"text"`
}

type history struct {
	mu      sync.Mutex
	samples []sample
	events  []event
	raft    []ui.Raft

	// previous observation, for turning changes into events
	seen     bool
	nodes    map[string]string
	degraded int64
	lost     int64
	objects  int64
	leader   string
	mttr     int64
	metaDown bool
}

func (h *history) log(kind, format string, a ...any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logLocked(kind, fmt.Sprintf(format, a...))
}

func (h *history) logLocked(kind, text string) {
	h.events = append(h.events, event{T: time.Now().UnixMilli(), Kind: kind, Text: text})
	if len(h.events) > eventsLen {
		h.events = h.events[len(h.events)-eventsLen:]
	}
}

// nodeState folds liveness and injected faults into one lane state.
func (g *Gateway) nodeState(n *vaultv1.Node) string {
	g.faultMu.Lock()
	f := g.faults[n.GetId()]
	g.faultMu.Unlock()
	switch {
	case !n.GetAlive() || f.GetDown():
		return "down"
	case len(f.GetPartitionedFrom()) > 0 || f.GetSlowMs() > 0 || len(n.GetPartitionedFrom()) > 0 || n.GetSlowMs() > 0:
		return "impaired"
	}
	return "up"
}

func (g *Gateway) sampleLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		g.sampleOnce(ctx)
	}
}

func (g *Gateway) sampleOnce(ctx context.Context) {
	h := g.hist
	var st *vaultv1.ClusterStatusResponse
	err := g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) (err error) {
		st, err = c.ClusterStatus(ctx, &vaultv1.ClusterStatusRequest{})
		return err
	})
	raft := g.raftViews(ctx)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.raft = raft
	if err != nil {
		if !h.metaDown {
			h.logLocked("bad", "Metadata group unreachable")
			h.metaDown = true
		}
		return
	}
	if h.metaDown {
		h.logLocked("good", "Metadata group reachable again")
		h.metaDown = false
	}

	s := sample{T: time.Now().UnixMilli(), Degraded: st.GetUnderReplicated(), Lost: st.GetLost(), Nodes: map[string]string{}}
	for _, n := range st.GetNodes() {
		s.Nodes[n.GetId()] = g.nodeState(n)
	}
	leader, term := "", uint64(0)
	for _, r := range raft {
		if r.State == "Leader" {
			leader, term = r.ID, r.Term
		}
	}

	if h.seen {
		for id, state := range s.Nodes {
			prev, ok := h.nodes[id]
			switch {
			case !ok:
				h.logLocked("info", fmt.Sprintf("%s joined the cluster", id))
			case prev == state:
			case state == "down":
				h.logLocked("bad", fmt.Sprintf("%s went offline", id))
			case state == "impaired":
				h.logLocked("bad", fmt.Sprintf("%s is impaired (slow or cut off)", id))
			case prev == "down":
				h.logLocked("good", fmt.Sprintf("%s is back online", id))
			default:
				h.logLocked("good", fmt.Sprintf("%s is healthy again", id))
			}
		}
		switch {
		case s.Degraded > 0 && h.degraded == 0:
			h.logLocked("bad", fmt.Sprintf("%d pieces lost a copy, repairing", s.Degraded))
		case s.Degraded == 0 && h.degraded > 0 && s.Lost == 0:
			h.logLocked("good", fmt.Sprintf("All copies rebuilt in %s", (time.Duration(st.GetLastMttrMs())*time.Millisecond).Round(100*time.Millisecond)))
		}
		if s.Lost > 0 && h.lost == 0 {
			h.logLocked("bad", fmt.Sprintf("%d pieces have no live copy", s.Lost))
		}
		if d := st.GetObjects() - h.objects; d > 0 {
			h.logLocked("info", fmt.Sprintf("%d object%s written", d, plural(d)))
		} else if d < 0 {
			h.logLocked("info", fmt.Sprintf("%d object%s deleted", -d, plural(-d)))
		}
		if leader != "" && h.leader != "" && leader != h.leader {
			h.logLocked("info", fmt.Sprintf("%s elected metadata leader (term %d)", leader, term))
		}
	}
	h.seen = true
	h.nodes, h.degraded, h.lost, h.objects, h.mttr = s.Nodes, s.Degraded, s.Lost, st.GetObjects(), st.GetLastMttrMs()
	if leader != "" {
		h.leader = leader
	}
	h.samples = append(h.samples, s)
	if len(h.samples) > historyLen {
		h.samples = h.samples[len(h.samples)-historyLen:]
	}
}

func plural(n int64) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// window returns samples and events newer than since (unix ms).
func (h *history) window(since int64) ([]sample, []event, []ui.Raft) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := []sample{}
	for _, x := range h.samples {
		if x.T >= since {
			s = append(s, x)
		}
	}
	e := []event{}
	for _, x := range h.events {
		if x.T >= since {
			e = append(e, x)
		}
	}
	return s, e, append([]ui.Raft{}, h.raft...)
}
