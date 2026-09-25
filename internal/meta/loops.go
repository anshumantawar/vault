package meta

import (
	"context"
	"log"
	"slices"
	"time"

	"github.com/hashicorp/raft"

	vaultv1 "vault/gen/vault/v1"
	"vault/internal/placement"
)

const (
	tick         = 500 * time.Millisecond
	maxRepairs   = 16   // concurrent repair copies
	maxMoves     = 4    // concurrent rebalance copies; repair always wins
	perTick      = 4096 // queued chunks evaluated per tick
	scanPerTick  = 2000 // chunks the safety-net scan walks per tick
	gcPerTick    = 256
	gcGrace      = 10 * time.Second
	retryBackoff = 2 * time.Second
)

// markDirty queues a chunk for the leader to look at. Called by the FSM after
// a change that may leave a chunk short of copies; followers ignore it.
func (s *Server) markDirty(sha string) {
	if !s.leader.Load() {
		return
	}
	s.mu.Lock()
	s.queue[sha] = time.Time{}
	s.mu.Unlock()
}

// enqueueHolder queues every chunk a node holds: O(chunks on that node).
func (s *Server) enqueueHolder(node string, at time.Time) {
	var shas []string
	s.fsm.view(func(t *tx) error {
		t.scan(bHolder, node+"\x00", func(k, _ []byte) bool {
			shas = append(shas, string(k[len(node)+1:]))
			return true
		})
		return nil
	})
	s.mu.Lock()
	for _, sha := range shas {
		s.queue[sha] = at
	}
	s.mu.Unlock()
}

// watchLeadership runs on every leadership change, the moment raft reports it.
func (s *Server) watchLeadership(ctx context.Context, ch <-chan bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case leader := <-ch:
			s.leader.Store(leader)
			if !leader {
				continue
			}
			// New leader: give every node a fresh grace period to heartbeat us,
			// instead of treating them all as dead until they do, and start the
			// bookkeeping over; the safety-net scan rebuilds it.
			ids := map[string]bool{}
			s.fsm.view(func(t *tx) error {
				return t.Bucket(bNodes).ForEach(func(k, _ []byte) error { ids[string(k)] = true; return nil })
			})
			s.mu.Lock()
			for id := range ids {
				s.lastSeen[id] = time.Now()
			}
			s.queue, s.under, s.lost, s.wasAlive, s.scanPos = map[string]time.Time{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, nil
			s.mu.Unlock()
			log.Printf("meta %s: became leader", s.cfg.ID)
		}
	}
}

func (s *Server) leaderLoops(ctx context.Context) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for n := 0; ; n++ {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if s.raft.State() != raft.Leader {
			continue
		}
		s.reconcile(ctx)
		if n%4 == 0 {
			s.gc(ctx)
		}
	}
}

type cluster struct {
	alive   []placement.Node
	isAlive map[string]bool
	addr    map[string]string
}

// reconcile is one incremental pass: note node transitions, advance the
// safety-net scan, then evaluate at most perTick queued chunks.
func (s *Server) reconcile(ctx context.Context) {
	cl := cluster{isAlive: map[string]bool{}, addr: map[string]string{}}
	for _, n := range s.nodes() {
		cl.addr[n.Id] = n.Addr
		if n.Alive {
			cl.alive = append(cl.alive, placement.Node{ID: n.Id, Zone: n.Zone})
			cl.isAlive[n.Id] = true
		}
	}
	now := time.Now()

	// A node that died or came back changes its chunks: queue just those.
	s.mu.Lock()
	var changed []string
	for id := range cl.addr {
		if was, seen := s.wasAlive[id]; !seen && !cl.isAlive[id] || seen && was != cl.isAlive[id] {
			changed = append(changed, id)
		}
	}
	s.wasAlive = cl.isAlive
	pos := s.scanPos
	s.mu.Unlock()
	for _, id := range changed {
		s.enqueueHolder(id, now)
	}

	// The safety net: walk the chunk table a page per tick, wrapping around.
	// It catches rebalancing onto new nodes and anything a hint missed.
	var page []string
	s.fsm.view(func(t *tx) error {
		c := t.Bucket(bChunks).Cursor()
		k, _ := c.Seek(append(slices.Clone(pos), 0))
		if pos == nil {
			k, _ = c.First()
		}
		for ; k != nil && len(page) < scanPerTick; k, _ = c.Next() {
			page = append(page, string(k))
		}
		return nil
	})

	s.mu.Lock()
	for _, sha := range page {
		if _, queued := s.queue[sha]; !queued {
			s.queue[sha] = now
		}
	}
	if len(page) < scanPerTick {
		s.scanPos = nil // wrap around
	} else {
		s.scanPos = []byte(page[len(page)-1])
	}
	var due []string
	for sha, at := range s.queue {
		if !at.After(now) && !s.inflight[sha] {
			due = append(due, sha)
			if len(due) == perTick {
				break
			}
		}
	}
	s.mu.Unlock()

	// Evaluate the due chunks against the store.
	views := map[string]*ChunkInfo{}
	s.fsm.view(func(t *tx) error {
		for _, sha := range due {
			views[sha] = t.chunk(sha)
		}
		return nil
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	repairs := 0
	for _, sha := range due {
		if s.evaluate(ctx, sha, views[sha], cl, &repairs) {
			delete(s.queue, sha)
		}
	}

	// MTTR: from the first failure of an episode until nothing is under-replicated.
	switch {
	case len(s.under) == 0:
		if !s.degraded.IsZero() {
			s.lastMTTR = now.Sub(s.degraded)
			s.degraded = time.Time{}
			log.Printf("meta: full redundancy restored, MTTR %s", s.lastMTTR.Round(time.Millisecond))
		}
		s.lastHealthy = now
	case s.degraded.IsZero():
		s.degraded = now
		for id, seen := range s.lastSeen { // count detection time for deaths in this episode
			if !cl.isAlive[id] && seen.After(s.lastHealthy) && seen.Before(s.degraded) {
				s.degraded = seen
			}
		}
		log.Printf("meta: %d chunks under-replicated, repairing", len(s.under))
	}
}

// evaluate decides one chunk's next step and starts it. It returns true when
// the chunk can leave the queue (healthy, lost, gone, or work started).
// Called with s.mu held.
func (s *Server) evaluate(ctx context.Context, sha string, ch *ChunkInfo, cl cluster, repairs *int) bool {
	if ch == nil || ch.Refs == 0 {
		delete(s.under, sha)
		delete(s.lost, sha)
		return true
	}
	want := int(ch.Want)
	var live []string
	for _, h := range ch.Holders {
		if cl.isAlive[h] {
			live = append(live, h)
		}
	}
	delete(s.under, sha)
	delete(s.lost, sha)
	switch {
	case len(live) == 0:
		s.lost[sha] = true
		return true // nothing to copy from; a returning holder re-queues it
	case len(live) < want:
		s.under[sha] = true
	}
	owners := ids(placement.Pick(sha, cl.alive, want))

	switch {
	case len(live) < want:
		if *repairs >= maxRepairs {
			return false
		}
		var targets []string
		for _, n := range placement.Order(sha, cl.alive) {
			if !slices.Contains(ch.Holders, n.ID) {
				targets = append(targets, n.ID)
			}
		}
		if len(targets) == 0 {
			return true // not enough nodes to reach want; a node join re-queues it
		}
		*repairs++
		s.inflight[sha] = true
		go s.copyChunk(ctx, sha, live, targets[:min(3, len(targets))], cl.addr, true)
	case firstNotIn(owners, live) != "":
		if s.moves >= maxMoves {
			return false
		}
		s.moves++
		s.inflight[sha] = true
		go s.copyChunk(ctx, sha, live, []string{firstNotIn(owners, live)}, cl.addr, false)
	case len(live) > want:
		extra := firstNotIn(live, owners)
		s.inflight[sha] = true
		go s.trim(ctx, sha, extra, cl.addr[extra])
	}
	return true
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

// done ends a copy or trim and re-queues the chunk to confirm the result.
func (s *Server) done(sha string, ok, move bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inflight, sha)
	if move {
		s.moves--
	}
	at := time.Now()
	if !ok {
		at = at.Add(retryBackoff)
	}
	if s.leader.Load() {
		s.queue[sha] = at
	}
}

// copyChunk asks each source in turn to push the chunk to each target, so a
// partition between one pair doesn't block the repair.
func (s *Server) copyChunk(ctx context.Context, sha string, sources, targets []string, addr map[string]string, repair bool) {
	ok := false
	defer func() { s.done(sha, ok, !repair) }()
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
			ok = true
			return
		}
	}
	log.Printf("meta: could not copy %.12s from %v to %v", sha, sources, targets)
}

// trim removes an extra copy: metadata first so readers stop using it.
func (s *Server) trim(ctx context.Context, sha, node, addr string) {
	ok := false
	defer func() { s.done(sha, ok, false) }()
	before := time.Now()
	if _, err := s.propose(&command{Op: "remove_holder", SHA: sha, NodeID: node}); err != nil {
		return
	}
	ok = true
	if c, err := s.nodeClient(addr); err == nil {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		c.DeleteChunk(cctx, &vaultv1.DeleteChunkRequest{Sha256: sha, IfWrittenBefore: before.UnixNano()})
		cancel()
	}
}

// gc tombstones unreferenced chunks, then deletes their files, retrying
// nodes that were unreachable until every holder confirms. It walks only the
// zero-reference and pending-delete indexes, never the whole chunk table.
func (s *Server) gc(ctx context.Context) {
	cutoff := time.Now().Add(-gcGrace).UnixNano()
	var dead []string
	type job struct {
		sha string
		t   Tombstone
	}
	var jobs []job
	s.fsm.view(func(t *tx) error {
		t.scan(bZero, "", func(k, _ []byte) bool {
			if ch := t.chunk(string(k)); ch != nil && ch.Refs == 0 && ch.ZeroSince < cutoff {
				dead = append(dead, string(k))
			}
			return len(dead) < gcPerTick
		})
		t.scan(bPending, "", func(k, _ []byte) bool {
			if x := t.tomb(string(k)); x != nil {
				jobs = append(jobs, job{string(k), *x})
			}
			return len(jobs) < gcPerTick
		})
		return nil
	})
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
	for _, j := range jobs {
		for _, n := range j.t.Pending {
			a, ok := addr[n]
			if !ok {
				continue // retry when it's back
			}
			c, err := s.nodeClient(a)
			if err != nil {
				continue
			}
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, err = c.DeleteChunk(cctx, &vaultv1.DeleteChunkRequest{Sha256: j.sha, IfWrittenBefore: j.t.At})
			cancel()
			if err == nil {
				s.propose(&command{Op: "deleted", SHA: j.sha, NodeID: n})
			}
		}
	}
}
