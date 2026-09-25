package meta

import (
	"context"
	"log"
	"maps"
	"slices"
	"time"

	"github.com/hashicorp/raft"

	vaultv1 "vault/gen/vault/v1"
	"vault/internal/placement"
)

const (
	maxRepairs = 16 // concurrent repair copies
	maxMoves   = 4  // concurrent rebalance copies; repair always wins
	gcGrace    = 10 * time.Second
)

// watchLeadership runs on every leadership change, the moment raft reports it.
func (s *Server) watchLeadership(ctx context.Context, ch <-chan bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case leader := <-ch:
			if !leader {
				continue
			}
			// New leader: give every node a fresh grace period to heartbeat us,
			// instead of treating them all as dead until they do.
			s.mu.Lock()
			s.fsm.mu.RLock()
			for id := range s.fsm.st.Nodes {
				s.lastSeen[id] = time.Now()
			}
			s.fsm.mu.RUnlock()
			s.mu.Unlock()
			log.Printf("meta %s: became leader", s.cfg.ID)
		}
	}
}

func (s *Server) leaderLoops(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	gcTick := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		leader := s.raft.State() == raft.Leader
		if !leader {
			continue
		}
		s.reconcile(ctx)
		if gcTick++; gcTick%2 == 0 {
			s.gc(ctx)
		}
	}
}

type chunkView struct {
	sha     string
	want    int
	holders []string
}

// reconcile compares where each chunk is against where it should be and
// starts at most one copy or trim per chunk: repair first, then rebalance,
// then trimming extra copies.
func (s *Server) reconcile(ctx context.Context) {
	nodes := s.nodes()
	var alive []placement.Node
	addr := map[string]string{}
	isAlive := map[string]bool{}
	for _, n := range nodes {
		addr[n.Id] = n.Addr
		if n.Alive {
			alive = append(alive, placement.Node{ID: n.Id, Zone: n.Zone})
			isAlive[n.Id] = true
		}
	}

	s.fsm.mu.RLock()
	var chunks []chunkView
	for sha, ch := range s.fsm.st.Chunks {
		if ch.Refs > 0 {
			chunks = append(chunks, chunkView{sha, int(ch.Want), slices.Clone(ch.Holders)})
		}
	}
	s.fsm.mu.RUnlock()

	now := time.Now()
	degradedStart := now
	degraded := 0
	s.mu.Lock()
	defer s.mu.Unlock()
	repairs := 0
	for _, c := range chunks {
		var live, down []string
		for _, h := range c.holders {
			if isAlive[h] {
				live = append(live, h)
			} else {
				down = append(down, h)
			}
		}
		if len(live) == 0 {
			continue // lost: nothing to copy from
		}
		owners := ids(placement.Pick(c.sha, alive, c.want))
		if len(live) < c.want {
			degraded++
			for _, h := range down {
				// Count detection time in MTTR, but only for deaths in this episode.
				if seen, ok := s.lastSeen[h]; ok && seen.After(s.lastHealthy) && seen.Before(degradedStart) {
					degradedStart = seen
				}
			}
		}
		if s.inflight[c.sha] {
			continue
		}
		switch {
		case len(live) < c.want && repairs < maxRepairs:
			var targets []string
			for _, n := range placement.Order(c.sha, alive) {
				if !slices.Contains(c.holders, n.ID) {
					targets = append(targets, n.ID)
				}
			}
			if len(targets) == 0 {
				continue // not enough nodes to reach want
			}
			repairs++
			s.inflight[c.sha] = true
			go s.copyChunk(ctx, c.sha, live, targets[:min(3, len(targets))], addr, true)

		case len(live) >= c.want && s.moves < maxMoves:
			if missing := firstNotIn(owners, live); missing != "" {
				s.moves++
				s.inflight[c.sha] = true
				go s.copyChunk(ctx, c.sha, live, []string{missing}, addr, false)
			} else if extra := firstNotIn(live, owners); extra != "" && len(live) > c.want {
				s.inflight[c.sha] = true
				go s.trim(ctx, c.sha, extra, addr[extra])
			}
		}
	}

	if degraded == 0 {
		s.lastHealthy = now
	}
	switch {
	case degraded > 0 && s.degraded.IsZero():
		s.degraded = degradedStart
		log.Printf("meta: %d chunks under-replicated, repairing", degraded)
	case degraded == 0 && !s.degraded.IsZero():
		s.lastMTTR = now.Sub(s.degraded)
		s.degraded = time.Time{}
		log.Printf("meta: full redundancy restored, MTTR %s", s.lastMTTR.Round(time.Millisecond))
	}
}

func ids(ns []placement.Node) []string {
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = n.ID
	}
	return out
}

func firstNotIn(xs, set []string) string {
	for _, x := range xs {
		if !slices.Contains(set, x) {
			return x
		}
	}
	return ""
}

func (s *Server) nodeClient(addr string) (vaultv1.NodeServiceClient, error) {
	conn, err := s.pool.Get(addr)
	if err != nil {
		return nil, err
	}
	return vaultv1.NewNodeServiceClient(conn), nil
}

// copyChunk asks each source in turn to push the chunk to each target, so a
// partition between one pair doesn't block the repair.
func (s *Server) copyChunk(ctx context.Context, sha string, sources, targets []string, addr map[string]string, repair bool) {
	defer func() {
		s.mu.Lock()
		delete(s.inflight, sha)
		if !repair {
			s.moves--
		}
		s.mu.Unlock()
	}()
	for _, t := range targets {
		for _, src := range sources {
			c, err := s.nodeClient(addr[src])
			if err != nil {
				continue
			}
			cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			_, err = c.PushChunk(cctx, &vaultv1.PushChunkRequest{Sha256: sha, TargetId: t, TargetAddr: addr[t]})
			cancel()
			if err != nil {
				continue
			}
			if _, err := s.propose(&command{Op: "add_holder", SHA: sha, NodeID: t}); err != nil {
				return
			}
			s.mu.Lock()
			if repair {
				s.repairs++
			} else {
				s.rebalances++
			}
			s.mu.Unlock()
			return
		}
	}
	log.Printf("meta: could not copy %.12s from %v to %v", sha, sources, targets)
}

// trim removes an extra copy: metadata first so readers stop using it.
func (s *Server) trim(ctx context.Context, sha, node, addr string) {
	defer func() {
		s.mu.Lock()
		delete(s.inflight, sha)
		s.mu.Unlock()
	}()
	before := time.Now()
	if _, err := s.propose(&command{Op: "remove_holder", SHA: sha, NodeID: node}); err != nil {
		return
	}
	if c, err := s.nodeClient(addr); err == nil {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		c.DeleteChunk(cctx, &vaultv1.DeleteChunkRequest{Sha256: sha, IfWrittenBefore: before.UnixNano()})
		cancel()
	}
}

// gc tombstones unreferenced chunks, then deletes their files, retrying
// nodes that were unreachable until every holder confirms.
func (s *Server) gc(ctx context.Context) {
	cutoff := time.Now().Add(-gcGrace).UnixNano()
	s.fsm.mu.RLock()
	var dead []string
	for sha, ch := range s.fsm.st.Chunks {
		if ch.Refs == 0 && ch.ZeroSince < cutoff && len(dead) < 256 {
			dead = append(dead, sha)
		}
	}
	s.fsm.mu.RUnlock()
	for _, sha := range dead {
		if _, err := s.propose(&command{Op: "tombstone", SHA: sha}); err != nil {
			return
		}
	}

	addr := map[string]string{}
	for _, n := range s.nodes() {
		if n.Alive {
			addr[n.Id] = n.Addr
		}
	}
	s.fsm.mu.RLock()
	pending := map[string]Tombstone{}
	for sha, t := range s.fsm.st.Tombstones {
		if len(t.Pending) > 0 {
			pending[sha] = Tombstone{At: t.At, Pending: slices.Clone(t.Pending)}
		}
	}
	s.fsm.mu.RUnlock()
	for _, sha := range slices.Sorted(maps.Keys(pending)) {
		t := pending[sha]
		for _, n := range t.Pending {
			a, ok := addr[n]
			if !ok {
				continue // retry when it's back
			}
			c, err := s.nodeClient(a)
			if err != nil {
				continue
			}
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, err = c.DeleteChunk(cctx, &vaultv1.DeleteChunkRequest{Sha256: sha, IfWrittenBefore: t.At})
			cancel()
			if err == nil {
				s.propose(&command{Op: "deleted", SHA: sha, NodeID: n})
			}
		}
	}
}
