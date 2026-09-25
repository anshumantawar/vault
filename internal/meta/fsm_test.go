package meta

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/raft"
)

// store is an FSM on a temp file, fed Raft-shaped log entries.
type store struct {
	t     *testing.T
	f     *fsm
	index uint64
}

func newStore(t *testing.T) *store {
	f, err := openFSM(filepath.Join(t.TempDir(), "fsm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return &store{t: t, f: f}
}

func (s *store) do(c *command) result {
	s.t.Helper()
	b, _ := json.Marshal(c)
	s.index++
	return s.f.Apply(&raft.Log{Index: s.index, Type: raft.LogCommand, Data: b}).(result)
}

func (s *store) must(c *command) result {
	s.t.Helper()
	r := s.do(c)
	if r.err != nil {
		s.t.Fatalf("%s: %v", c.Op, r.err)
	}
	return r
}

func (s *store) chunk(sha string) (ch *ChunkInfo) {
	s.f.view(func(t *tx) error { ch = t.chunk(sha); return nil })
	return ch
}

func (s *store) counters() (objects, logical, chunks int64) {
	s.f.view(func(t *tx) error {
		objects, logical, chunks = t.counter(cObjects), t.counter(cLogical), t.counter(cChunks)
		return nil
	})
	return
}

func sha(c byte) string { return strings.Repeat(string(c), 64) }

func bucket(s *store) {
	s.must(&command{Op: "create_bucket", Name: "b", Bucket: &Bucket{Replicas: 3, WriteQuorum: 2}})
}

func commit(key string, written int64, shas ...string) *command {
	c := &command{Op: "commit_object", Name: "b", Key: key, Object: &Object{Size: int64(len(shas))}}
	for _, s := range shas {
		c.Chunks = append(c.Chunks, CommitChunk{SHA: s, Size: 1, Holders: []string{"n1"}, WrittenAt: written})
	}
	c.Object.Chunks = refs(c.Chunks)
	return c
}

// A chunk collected by GC must not be resurrected by a commit whose copy was
// written before the tombstone: that file may already be deleted.
func TestGCRaceRefusesStaleCommit(t *testing.T) {
	s := newStore(t)
	bucket(s)
	s.must(commit("k", 100, sha('a')))
	s.must(&command{Op: "delete_object", Name: "b", Key: "k", Now: 150})
	if s.chunk(sha('a')).Refs != 0 {
		t.Fatal("refcount should drop to 0")
	}
	if r := s.must(&command{Op: "tombstone", SHA: sha('a'), Now: 200}); len(r.pending) != 1 {
		t.Fatalf("tombstone should return holders to delete from, got %v", r.pending)
	}
	if r := s.must(commit("k2", 180, sha('a'))); len(r.retry) != 1 {
		t.Fatalf("commit written before the tombstone must be retried, got %v", r.retry)
	}
	var o *Object
	s.f.view(func(t *tx) error { o = t.object("b", "k2"); return nil })
	if o != nil {
		t.Fatal("a refused commit must not create the object")
	}
	if r := s.must(commit("k2", 250, sha('a'))); len(r.retry) != 0 {
		t.Fatalf("rewritten chunk should commit, got retry %v", r.retry)
	}
	if ch := s.chunk(sha('a')); ch == nil || ch.Refs != 1 {
		t.Fatal("recommitted chunk should be live with one ref")
	}
}

func TestTombstoneSkipsReferencedChunk(t *testing.T) {
	s := newStore(t)
	bucket(s)
	s.must(commit("k", 100, sha('a')))
	s.must(&command{Op: "delete_object", Name: "b", Key: "k"})
	s.must(commit("k2", 120, sha('a'))) // re-referenced before GC ran
	s.must(&command{Op: "tombstone", SHA: sha('a'), Now: 200})
	if s.chunk(sha('a')) == nil {
		t.Fatal("GC removed a chunk that is referenced again")
	}
}

func TestMultipartRefcountsAndETag(t *testing.T) {
	s := newStore(t)
	bucket(s)
	s.must(&command{Op: "create_upload", UploadID: "u", Name: "b", Key: "k"})
	part := func(n uint32, etag string, x string) *command {
		return &command{Op: "commit_part", UploadID: "u", PartNum: n, ETag: etag, Size: 1,
			Chunks: []CommitChunk{{SHA: x, Size: 1, Holders: []string{"n1"}, WrittenAt: 1}}}
	}
	s.must(part(1, "0cc175b9c0f1b6a831c399e269772661", sha('a')))
	s.must(part(2, "92eb5ffee6ae2fec3ad71c777531578f", sha('b')))
	s.must(part(3, "4a8a08f09d37b73795649038408b5f33", sha('c'))) // uploaded but not used
	r := s.must(&command{Op: "complete_upload", UploadID: "u", Parts: []completedPart{
		{1, `"0cc175b9c0f1b6a831c399e269772661"`}, {2, "92eb5ffee6ae2fec3ad71c777531578f"},
	}})
	if !strings.HasSuffix(r.object.ETag, "-2") || r.object.Size != 2 {
		t.Fatalf("bad completed object: %+v", r.object)
	}
	if s.chunk(sha('a')).Refs != 1 || s.chunk(sha('b')).Refs != 1 || s.chunk(sha('c')).Refs != 0 {
		t.Fatalf("refs a=%d b=%d c=%d, want 1 1 0", s.chunk(sha('a')).Refs, s.chunk(sha('b')).Refs, s.chunk(sha('c')).Refs)
	}
	if r := s.do(&command{Op: "complete_upload", UploadID: "u"}); r.err == nil {
		t.Fatal("completing twice should fail with NoSuchUpload")
	}
}

func TestListObjectsDelimiter(t *testing.T) {
	s := newStore(t)
	bucket(s)
	for _, k := range []string{"a.txt", "docs/1", "docs/2", "img/x/1", "z"} {
		s.must(commit(k, 1, sha('a')))
	}
	var keys, prefixes []string
	var trunc bool
	list := func(after string) {
		s.f.view(func(t *tx) error { keys, prefixes, trunc = t.listObjects("b", "", "/", after, 3); return nil })
	}
	list("")
	if strings.Join(keys, ",") != "a.txt" || strings.Join(prefixes, ",") != "docs/,img/" || !trunc {
		t.Fatalf("page 1: keys=%v prefixes=%v truncated=%v", keys, prefixes, trunc)
	}
	list("img/\U0010FFFF")
	if strings.Join(keys, ",") != "z" || len(prefixes) != 0 || trunc {
		t.Fatalf("page 2: keys=%v prefixes=%v truncated=%v", keys, prefixes, trunc)
	}
	s.f.view(func(t *tx) error { keys, prefixes, trunc = t.listObjects("b", "docs/", "/", "docs/1", 10); return nil })
	if strings.Join(keys, ",") != "docs/2" {
		t.Fatalf("prefix + start-after: %v", keys)
	}
}

// Users survive the Raft log round trip and the last admin can't be deleted.
func TestUsers(t *testing.T) {
	s := newStore(t)
	s.must(&command{Op: "create_user", User: &User{AccessKey: "VKADMIN01", Secret: "s", Name: "admin", Admin: true}})
	var u User
	var found bool
	s.f.view(func(t *tx) error { found = t.get(bUsers, "VKADMIN01", &u); return nil })
	if !found || !u.Admin {
		t.Fatal("user stored under the wrong key")
	}
	if r := s.do(&command{Op: "create_user", User: &User{AccessKey: "VKADMIN01", Secret: "x", Name: "dup"}}); r.err == nil {
		t.Error("duplicate access key accepted")
	}
	if r := s.do(&command{Op: "delete_user", Key: "VKADMIN01"}); r.err == nil {
		t.Error("deleted the last admin")
	}
}

// Counters and indexes stay in step with the records they summarize, and a
// replayed log entry (index already applied) changes nothing.
func TestCountersIndexesAndReplay(t *testing.T) {
	s := newStore(t)
	bucket(s)
	c := commit("k", 1, sha('a'), sha('b'))
	s.must(c)
	if o, l, ch := s.counters(); o != 1 || l != 2 || ch != 2 {
		t.Fatalf("counters objects=%d logical=%d chunks=%d, want 1 2 2", o, l, ch)
	}
	// replay the same entry at an old index: must be a no-op
	b, _ := json.Marshal(c)
	s.f.Apply(&raft.Log{Index: s.index, Type: raft.LogCommand, Data: b})
	if o, _, _ := s.counters(); o != 1 {
		t.Fatalf("replayed entry was applied twice: objects=%d", o)
	}
	s.must(&command{Op: "add_holder", SHA: sha('a'), NodeID: "n2"})
	s.must(&command{Op: "remove_holder", SHA: sha('a'), NodeID: "n1"})
	held := map[string]bool{}
	s.f.view(func(t *tx) error {
		t.scan(bHolder, "", func(k, _ []byte) bool { held[string(k)] = true; return true })
		return nil
	})
	if !held[holderKey("n2", sha('a'))] || held[holderKey("n1", sha('a'))] || !held[holderKey("n1", sha('b'))] {
		t.Fatalf("holder index out of step: %v", held)
	}
	s.must(&command{Op: "delete_object", Name: "b", Key: "k", Now: 5})
	zero := 0
	s.f.view(func(t *tx) error { t.scan(bZero, "", func(_, _ []byte) bool { zero++; return true }); return nil })
	if o, l, ch := s.counters(); o != 0 || l != 0 || ch != 0 || zero != 2 {
		t.Fatalf("after delete: objects=%d logical=%d chunks=%d zero=%d", o, l, ch, zero)
	}
}

type memSink struct {
	bytes.Buffer
}

func (m *memSink) ID() string    { return "mem" }
func (m *memSink) Cancel() error { return nil }
func (m *memSink) Close() error  { return nil }

// A snapshot is the store itself, and restores into another store intact.
func TestSnapshotRestore(t *testing.T) {
	a := newStore(t)
	bucket(a)
	a.must(commit("k", 1, sha('a')))
	snap, err := a.f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var sink memSink
	if err := snap.Persist(&sink); err != nil {
		t.Fatal(err)
	}
	snap.Release()
	b := newStore(t)
	if err := b.f.Restore(io.NopCloser(&sink)); err != nil {
		t.Fatal(err)
	}
	if o, _, ch := b.counters(); o != 1 || ch != 1 || b.chunk(sha('a')) == nil {
		t.Fatalf("restored store: objects=%d chunks=%d", o, ch)
	}
	// a legacy JSON snapshot converts once
	legacy := `{"buckets":{"b":{"replicas":3,"write_quorum":2}},"objects":{"b":{"x":{"size":7,"chunks":[{"sha":"` + sha('c') + `","size":7}]}}},"chunks":{"` + sha('c') + `":{"size":7,"want":3,"holders":["n1"],"refs":1}},"users":{}}`
	c := newStore(t)
	if err := c.f.Restore(io.NopCloser(strings.NewReader(legacy))); err != nil {
		t.Fatal(err)
	}
	if o, l, ch := c.counters(); o != 1 || l != 7 || ch != 1 {
		t.Fatalf("legacy restore: objects=%d logical=%d chunks=%d", o, l, ch)
	}
}
