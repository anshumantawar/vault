package meta

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hashicorp/raft"
)

func sha(c byte) string { return strings.Repeat(string(c), 64) }

func must(t *testing.T, st *state, c *command) result {
	t.Helper()
	r := st.apply(c)
	if r.err != nil {
		t.Fatalf("%s: %v", c.Op, r.err)
	}
	return r
}

func commit(key string, written int64, shas ...string) *command {
	c := &command{Op: "commit_object", Name: "b", Key: key, Object: &Object{}}
	for _, s := range shas {
		c.Chunks = append(c.Chunks, CommitChunk{SHA: s, Size: 1, Holders: []string{"n1"}, WrittenAt: written})
	}
	c.Object.Chunks = refs(c.Chunks)
	return c
}

// A chunk collected by GC must not be resurrected by a commit whose copy was
// written before the tombstone: that file may already be deleted.
func TestGCRaceRefusesStaleCommit(t *testing.T) {
	st := newState()
	must(t, st, &command{Op: "create_bucket", Name: "b", Bucket: &Bucket{Replicas: 3, WriteQuorum: 2}})
	must(t, st, commit("k", 100, sha('a')))
	must(t, st, &command{Op: "delete_object", Name: "b", Key: "k", Now: 150})
	if st.Chunks[sha('a')].Refs != 0 {
		t.Fatal("refcount should drop to 0")
	}
	if r := must(t, st, &command{Op: "tombstone", SHA: sha('a'), Now: 200}); len(r.pending) != 1 {
		t.Fatalf("tombstone should return holders to delete from, got %v", r.pending)
	}

	if r := must(t, st, commit("k2", 180, sha('a'))); len(r.retry) != 1 {
		t.Fatalf("commit written before the tombstone must be retried, got %v", r.retry)
	}
	if st.Objects["b"]["k2"] != nil {
		t.Fatal("a refused commit must not create the object")
	}
	if r := must(t, st, commit("k2", 250, sha('a'))); len(r.retry) != 0 {
		t.Fatalf("rewritten chunk should commit, got retry %v", r.retry)
	}
	if st.Chunks[sha('a')].Refs != 1 || st.Tombstones[sha('a')] != nil {
		t.Fatal("recommitted chunk should be live with one ref and no tombstone")
	}
}

func TestTombstoneSkipsReferencedChunk(t *testing.T) {
	st := newState()
	must(t, st, &command{Op: "create_bucket", Name: "b", Bucket: &Bucket{Replicas: 3, WriteQuorum: 2}})
	must(t, st, commit("k", 100, sha('a')))
	must(t, st, &command{Op: "delete_object", Name: "b", Key: "k"})
	must(t, st, commit("k2", 120, sha('a'))) // re-referenced before GC ran
	must(t, st, &command{Op: "tombstone", SHA: sha('a'), Now: 200})
	if st.Chunks[sha('a')] == nil {
		t.Fatal("GC removed a chunk that is referenced again")
	}
}

func TestMultipartRefcountsAndETag(t *testing.T) {
	st := newState()
	must(t, st, &command{Op: "create_bucket", Name: "b", Bucket: &Bucket{Replicas: 3, WriteQuorum: 2}})
	must(t, st, &command{Op: "create_upload", UploadID: "u", Name: "b", Key: "k"})
	part := func(n uint32, etag string, s string) *command {
		c := &command{Op: "commit_part", UploadID: "u", PartNum: n, ETag: etag, Size: 1,
			Chunks: []CommitChunk{{SHA: s, Size: 1, Holders: []string{"n1"}, WrittenAt: 1}}}
		return c
	}
	must(t, st, part(1, "0cc175b9c0f1b6a831c399e269772661", sha('a')))
	must(t, st, part(2, "92eb5ffee6ae2fec3ad71c777531578f", sha('b')))
	must(t, st, part(3, "4a8a08f09d37b73795649038408b5f33", sha('c'))) // uploaded but not used
	r := must(t, st, &command{Op: "complete_upload", UploadID: "u", Parts: []completedPart{
		{1, `"0cc175b9c0f1b6a831c399e269772661"`}, {2, "92eb5ffee6ae2fec3ad71c777531578f"},
	}})
	if !strings.HasSuffix(r.object.ETag, "-2") || r.object.Size != 2 {
		t.Fatalf("bad completed object: %+v", r.object)
	}
	if st.Chunks[sha('a')].Refs != 1 || st.Chunks[sha('b')].Refs != 1 || st.Chunks[sha('c')].Refs != 0 {
		t.Fatalf("refs a=%d b=%d c=%d, want 1 1 0", st.Chunks[sha('a')].Refs, st.Chunks[sha('b')].Refs, st.Chunks[sha('c')].Refs)
	}
	if st.Uploads["u"] != nil {
		t.Fatal("completed upload should be gone")
	}
	if r := st.apply(&command{Op: "complete_upload", UploadID: "u"}); r.err == nil {
		t.Fatal("completing twice should fail with NoSuchUpload")
	}
}

func TestListObjectsDelimiter(t *testing.T) {
	st := newState()
	st.Objects["b"] = map[string]*Object{}
	for _, k := range []string{"a.txt", "docs/1", "docs/2", "img/x/1", "z"} {
		st.Objects["b"][k] = &Object{}
	}
	keys, prefixes, trunc := st.listObjects("b", "", "/", "", 3)
	if strings.Join(keys, ",") != "a.txt" || strings.Join(prefixes, ",") != "docs/,img/" || !trunc {
		t.Fatalf("page 1: keys=%v prefixes=%v truncated=%v", keys, prefixes, trunc)
	}
	keys, prefixes, trunc = st.listObjects("b", "", "/", "img/\U0010FFFF", 3)
	if strings.Join(keys, ",") != "z" || len(prefixes) != 0 || trunc {
		t.Fatalf("page 2: keys=%v prefixes=%v truncated=%v", keys, prefixes, trunc)
	}
}

// Users survive the Raft log round trip (JSON) and the last admin can't be deleted.
func TestUsers(t *testing.T) {
	st := newState()
	f := &fsm{st: st}
	apply := func(c *command) result {
		b, _ := json.Marshal(c)
		return f.Apply(&raft.Log{Data: b}).(result)
	}
	if r := apply(&command{Op: "create_user", User: &User{AccessKey: "VKADMIN01", Secret: "s", Name: "admin", Admin: true}}); r.err != nil {
		t.Fatal(r.err)
	}
	if st.Users["VKADMIN01"] == nil {
		t.Fatalf("user stored under the wrong key: %v", st.Users)
	}
	if r := apply(&command{Op: "create_user", User: &User{AccessKey: "VKADMIN01", Secret: "x", Name: "dup"}}); r.err == nil {
		t.Error("duplicate access key accepted")
	}
	if r := apply(&command{Op: "delete_user", Key: "VKADMIN01"}); r.err == nil {
		t.Error("deleted the last admin")
	}
}
