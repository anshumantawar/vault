package meta

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The replicated metadata lives on disk in bbolt, one keyspace per kind of
// record plus the indexes the leader loops need, so work is proportional to
// what changed rather than to the size of the store:
//
//	sys      applied index and running counters
//	buckets  name → Bucket
//	objects  bucket \x00 key → Object          (sorted: a list page is one seek)
//	chunks   sha → ChunkInfo
//	holder   node \x00 sha → ∅                  (what a node holds: repair on node death)
//	zero     sha → ∅                            (unreferenced chunks: GC walks only these)
//	tombs    sha → Tombstone
//	pending  sha → ∅                            (tombstones with copies still to delete)
//	uploads  id → Upload,  parts  id \x00 part# → Part
//	nodes    id → NodeInfo,  users  access key → User
//
// Every mutation happens in fsm.ApplyBatch, one transaction per Raft batch,
// which also records the last applied index: replaying the log after a crash
// skips entries already applied, so the store is never double-counted.
// ponytail: user secrets are stored as-is (SigV4 needs them); encrypt the
// store and Raft log at rest before handling real customer keys.
var (
	bSys         = []byte("sys")
	bBuckets     = []byte("buckets")
	bObjects     = []byte("objects")
	bChunks      = []byte("chunks")
	bHolder      = []byte("holder")
	bZero        = []byte("zero")
	bTombs       = []byte("tombs")
	bPending     = []byte("pending")
	bUploads     = []byte("uploads")
	bParts       = []byte("parts")
	bNodes       = []byte("nodes")
	bUsers       = []byte("users")
	allKeyspaces = [][]byte{bSys, bBuckets, bObjects, bChunks, bHolder, bZero, bTombs, bPending, bUploads, bParts, bNodes, bUsers}
)

// Counters kept in sys, so status never has to count.
const (
	cApplied = "applied"
	cObjects = "objects"
	cLogical = "logical_bytes"
	cChunks  = "live_chunks"
)

type User struct {
	Secret    string `json:"secret"`
	Name      string `json:"name"`
	Admin     bool   `json:"admin,omitempty"`
	CreatedAt int64  `json:"created_at"`
	AccessKey string `json:"access_key"`
}

type Bucket struct {
	Replicas    uint32 `json:"replicas"`
	WriteQuorum uint32 `json:"write_quorum"`
	CreatedAt   int64  `json:"created_at"`
	Owner       string `json:"owner,omitempty"` // access key; empty = admins only
}

type ChunkRef struct {
	SHA  string `json:"sha"`
	Size int64  `json:"size"`
}

type Object struct {
	Size        int64             `json:"size"`
	ETag        string            `json:"etag"`
	ContentType string            `json:"content_type,omitempty"`
	UserMeta    map[string]string `json:"user_meta,omitempty"`
	ModifiedAt  int64             `json:"modified_at"`
	Chunks      []ChunkRef        `json:"chunks"`
}

type ChunkInfo struct {
	Size    int64    `json:"size"`
	Want    uint32   `json:"want"`
	Holders []string `json:"holders"`
	Refs    int      `json:"refs"`
	// When Refs dropped to 0 (leader clock); GC tombstones it later.
	ZeroSince int64 `json:"zero_since,omitempty"`
}

// Tombstone marks a chunk whose metadata was deleted at At. Files written
// before At may be deleted; a commit that wrote the chunk before At is refused.
// ponytail: tombstones are kept forever; prune after a max upload age if they pile up.
type Tombstone struct {
	At      int64    `json:"at"`
	Pending []string `json:"pending,omitempty"` // holders not yet confirmed deleted
}

type Part struct {
	ETag   string     `json:"etag"`
	Size   int64      `json:"size"`
	Chunks []ChunkRef `json:"chunks"`
}

type Upload struct {
	Bucket      string            `json:"bucket"`
	Key         string            `json:"key"`
	ContentType string            `json:"content_type,omitempty"`
	UserMeta    map[string]string `json:"user_meta,omitempty"`
	CreatedAt   int64             `json:"created_at"`
}

type NodeInfo struct {
	Addr string `json:"addr"`
	Zone string `json:"zone"`
}

// CommitChunk is a chunk as written by a gateway: who acked and when.
type CommitChunk struct {
	SHA       string   `json:"sha"`
	Size      int64    `json:"size"`
	Holders   []string `json:"holders"`
	WrittenAt int64    `json:"written_at"`
}

type command struct {
	Op  string `json:"op"`
	Now int64  `json:"now"` // leader clock at propose time, so Apply is deterministic

	Name     string            `json:"name,omitempty"` // bucket
	Key      string            `json:"key,omitempty"`
	Bucket   *Bucket           `json:"bucket,omitempty"`
	Object   *Object           `json:"object,omitempty"`
	Chunks   []CommitChunk     `json:"chunks,omitempty"`
	DstName  string            `json:"dst_name,omitempty"`
	DstKey   string            `json:"dst_key,omitempty"`
	Replace  bool              `json:"replace,omitempty"`
	CType    string            `json:"ctype,omitempty"`
	UserMeta map[string]string `json:"user_meta,omitempty"`
	UploadID string            `json:"upload_id,omitempty"`
	PartNum  uint32            `json:"part_num,omitempty"`
	ETag     string            `json:"etag,omitempty"`
	Size     int64             `json:"size,omitempty"`
	Parts    []completedPart   `json:"parts,omitempty"`
	SHA      string            `json:"sha,omitempty"`
	NodeID   string            `json:"node_id,omitempty"`
	Node     *NodeInfo         `json:"node,omitempty"`
	User     *User             `json:"user,omitempty"`
}

type completedPart struct {
	Num  uint32 `json:"num"`
	ETag string `json:"etag"`
}

type result struct {
	err     error
	retry   []string
	object  *Object
	pending []string
}

func s3err(c codes.Code, s3code string) error { return status.Error(c, s3code) }

// ---- the store ----

type fsm struct {
	path string
	mu   sync.RWMutex // guards db against a swap in Restore
	db   *bolt.DB
	// onDirty hears about chunks whose placement needs a look (leader hint only;
	// it never affects replicated state).
	onDirty func(sha string)
}

func openFSM(path string) (*fsm, error) {
	db, err := openBolt(path)
	if err != nil {
		return nil, err
	}
	return &fsm{path: path, db: db}, nil
}

func openBolt(path string) (*bolt.DB, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{NoFreelistSync: true})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(t *bolt.Tx) error {
		for _, b := range allKeyspaces {
			if _, err := t.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func (f *fsm) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.db.Close()
}

// view runs fn in a read-only transaction.
func (f *fsm) view(fn func(*tx) error) error {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.db.View(func(t *bolt.Tx) error { return fn(&tx{Tx: t}) })
}

// tx wraps a bolt transaction with typed record helpers. Records are small
// JSON documents; a storage error mid-apply panics, because Raft cannot
// continue with a half-applied entry (the transaction rolls back, and the
// entry is re-applied after restart).
type tx struct {
	*bolt.Tx
	dirty []string
}

func must(err error) {
	if err != nil {
		panic(fmt.Sprintf("meta store: %v", err))
	}
}

func (t *tx) get(b []byte, k string, v any) bool {
	raw := t.Bucket(b).Get([]byte(k))
	if raw == nil {
		return false
	}
	must(json.Unmarshal(raw, v))
	return true
}

func (t *tx) has(b []byte, k string) bool { return t.Bucket(b).Get([]byte(k)) != nil }

func (t *tx) put(b []byte, k string, v any) {
	raw, err := json.Marshal(v)
	must(err)
	must(t.Bucket(b).Put([]byte(k), raw))
}

func (t *tx) mark(b []byte, k string) { must(t.Bucket(b).Put([]byte(k), []byte{})) }
func (t *tx) del(b []byte, k string)  { must(t.Bucket(b).Delete([]byte(k))) }

func (t *tx) counter(name string) int64 {
	raw := t.Bucket(bSys).Get([]byte(name))
	if len(raw) != 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(raw))
}

func (t *tx) add(name string, d int64) {
	if d == 0 {
		return
	}
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], uint64(t.counter(name)+d))
	must(t.Bucket(bSys).Put([]byte(name), raw[:]))
}

// scan calls fn for each key with prefix, in order, until fn returns false.
func (t *tx) scan(b []byte, prefix string, fn func(k, v []byte) bool) {
	c := t.Bucket(b).Cursor()
	p := []byte(prefix)
	for k, v := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, v = c.Next() {
		if !fn(k, v) {
			return
		}
	}
}

func objKey(bucket, key string) string   { return bucket + "\x00" + key }
func partKey(id string, n uint32) string { return fmt.Sprintf("%s\x00%05d", id, n) }
func holderKey(node, sha string) string  { return node + "\x00" + sha }
func (t *tx) bucket(name string) *Bucket { var b Bucket; return ptrIf(t.get(bBuckets, name, &b), &b) }
func (t *tx) object(bucket, key string) *Object {
	var o Object
	return ptrIf(t.get(bObjects, objKey(bucket, key), &o), &o)
}
func (t *tx) chunk(sha string) *ChunkInfo { var c ChunkInfo; return ptrIf(t.get(bChunks, sha, &c), &c) }
func (t *tx) upload(id string) *Upload    { var u Upload; return ptrIf(t.get(bUploads, id, &u), &u) }
func (t *tx) tomb(sha string) *Tombstone  { var x Tombstone; return ptrIf(t.get(bTombs, sha, &x), &x) }

func ptrIf[T any](ok bool, v *T) *T {
	if ok {
		return v
	}
	return nil
}

// setHolders stores ch with holders, keeping the per-node index in step.
func (t *tx) setHolders(sha string, ch *ChunkInfo, holders []string) {
	for _, h := range ch.Holders {
		if !slices.Contains(holders, h) {
			t.del(bHolder, holderKey(h, sha))
		}
	}
	for _, h := range holders {
		if !slices.Contains(ch.Holders, h) {
			t.mark(bHolder, holderKey(h, sha))
		}
	}
	ch.Holders = holders
	t.put(bChunks, sha, ch)
}

// ---- raft.FSM / raft.BatchingFSM ----

func (f *fsm) Apply(l *raft.Log) any { return f.ApplyBatch([]*raft.Log{l})[0] }

// ApplyBatch applies a whole Raft batch in one transaction (one fsync).
func (f *fsm) ApplyBatch(logs []*raft.Log) []any {
	out := make([]any, len(logs))
	var dirty []string
	f.mu.RLock()
	err := f.db.Update(func(bt *bolt.Tx) error {
		t := &tx{Tx: bt}
		applied := uint64(t.counter(cApplied))
		for i, l := range logs {
			if l.Index <= applied {
				out[i] = result{} // already in the store: a replay after restart
				continue
			}
			if l.Type == raft.LogCommand {
				var c command
				if err := json.Unmarshal(l.Data, &c); err != nil {
					out[i] = result{err: fmt.Errorf("bad command: %w", err)}
				} else {
					out[i] = t.apply(&c)
				}
			}
			applied = l.Index
		}
		var raw [8]byte
		binary.BigEndian.PutUint64(raw[:], applied)
		dirty = t.dirty
		return bt.Bucket(bSys).Put([]byte(cApplied), raw[:])
	})
	f.mu.RUnlock()
	must(err)
	if f.onDirty != nil {
		for _, sha := range dirty {
			f.onDirty(sha)
		}
	}
	return out
}

func (t *tx) apply(c *command) result {
	switch c.Op {
	case "create_bucket":
		if t.has(bBuckets, c.Name) {
			return result{err: s3err(codes.AlreadyExists, "BucketAlreadyOwnedByYou")}
		}
		b := *c.Bucket
		b.CreatedAt = c.Now
		t.put(bBuckets, c.Name, &b)

	case "delete_bucket":
		if !t.has(bBuckets, c.Name) {
			return result{err: s3err(codes.NotFound, "NoSuchBucket")}
		}
		empty := true
		t.scan(bObjects, c.Name+"\x00", func(_, _ []byte) bool { empty = false; return false })
		if !empty {
			return result{err: s3err(codes.FailedPrecondition, "BucketNotEmpty")}
		}
		// ponytail: scans all open uploads; index uploads by bucket if thousands stay open.
		var drop []string
		t.Bucket(bUploads).ForEach(func(k, v []byte) error {
			var u Upload
			must(json.Unmarshal(v, &u))
			if u.Bucket == c.Name {
				drop = append(drop, string(k))
			}
			return nil
		})
		for _, id := range drop {
			t.dropUpload(id, c.Now)
		}
		t.del(bBuckets, c.Name)

	case "commit_object":
		b := t.bucket(c.Name)
		if b == nil {
			return result{err: s3err(codes.NotFound, "NoSuchBucket")}
		}
		if retry := t.needRetry(c.Chunks); len(retry) > 0 {
			return result{retry: retry}
		}
		t.addChunks(c.Chunks, b.Replicas)
		o := *c.Object
		o.ModifiedAt = c.Now
		t.putObject(c.Name, c.Key, &o, c.Now)
		return result{object: &o}

	case "delete_object":
		if !t.has(bBuckets, c.Name) {
			return result{err: s3err(codes.NotFound, "NoSuchBucket")}
		}
		if old := t.object(c.Name, c.Key); old != nil {
			t.decref(old.Chunks, c.Now)
			t.add(cObjects, -1)
			t.add(cLogical, -old.Size)
			t.del(bObjects, objKey(c.Name, c.Key))
		}

	case "copy_object":
		if !t.has(bBuckets, c.Name) {
			return result{err: s3err(codes.NotFound, "NoSuchBucket")}
		}
		src := t.object(c.Name, c.Key)
		if src == nil {
			return result{err: s3err(codes.NotFound, "NoSuchKey")}
		}
		db := t.bucket(c.DstName)
		if db == nil {
			return result{err: s3err(codes.NotFound, "NoSuchBucket")}
		}
		o := *src
		o.ModifiedAt = c.Now
		if c.Replace {
			o.ContentType, o.UserMeta = c.CType, c.UserMeta
		}
		t.incref(o.Chunks, db.Replicas)
		t.putObject(c.DstName, c.DstKey, &o, c.Now)
		return result{object: &o}

	case "create_upload":
		if !t.has(bBuckets, c.Name) {
			return result{err: s3err(codes.NotFound, "NoSuchBucket")}
		}
		t.put(bUploads, c.UploadID, &Upload{Bucket: c.Name, Key: c.Key, ContentType: c.CType, UserMeta: c.UserMeta, CreatedAt: c.Now})

	case "commit_part":
		u := t.upload(c.UploadID)
		if u == nil {
			return result{err: s3err(codes.NotFound, "NoSuchUpload")}
		}
		if retry := t.needRetry(c.Chunks); len(retry) > 0 {
			return result{retry: retry}
		}
		want := uint32(3)
		if b := t.bucket(u.Bucket); b != nil {
			want = b.Replicas
		}
		t.addChunks(c.Chunks, want)
		var old Part
		if t.get(bParts, partKey(c.UploadID, c.PartNum), &old) {
			t.decref(old.Chunks, c.Now)
		}
		t.put(bParts, partKey(c.UploadID, c.PartNum), &Part{ETag: c.ETag, Size: c.Size, Chunks: refs(c.Chunks)})

	case "complete_upload":
		u := t.upload(c.UploadID)
		if u == nil {
			return result{err: s3err(codes.NotFound, "NoSuchUpload")}
		}
		b := t.bucket(u.Bucket)
		if b == nil {
			return result{err: s3err(codes.NotFound, "NoSuchBucket")}
		}
		if len(c.Parts) == 0 {
			return result{err: s3err(codes.InvalidArgument, "MalformedXML")}
		}
		o := &Object{ContentType: u.ContentType, UserMeta: u.UserMeta, ModifiedAt: c.Now}
		md5s := md5.New()
		for i, cp := range c.Parts {
			if i > 0 && cp.Num <= c.Parts[i-1].Num {
				return result{err: s3err(codes.InvalidArgument, "InvalidPartOrder")}
			}
			var p Part
			if !t.get(bParts, partKey(c.UploadID, cp.Num), &p) || strings.Trim(cp.ETag, `"`) != p.ETag {
				return result{err: s3err(codes.InvalidArgument, "InvalidPart")}
			}
			raw, _ := hex.DecodeString(p.ETag)
			md5s.Write(raw)
			o.Size += p.Size
			o.Chunks = append(o.Chunks, p.Chunks...)
		}
		o.ETag = fmt.Sprintf("%x-%d", md5s.Sum(nil), len(c.Parts))
		t.incref(o.Chunks, b.Replicas)
		t.dropUpload(c.UploadID, c.Now) // releases every part's refs, used or not
		t.putObject(u.Bucket, u.Key, o, c.Now)
		return result{object: o}

	case "abort_upload":
		if !t.has(bUploads, c.UploadID) {
			return result{err: s3err(codes.NotFound, "NoSuchUpload")}
		}
		t.dropUpload(c.UploadID, c.Now)

	case "create_user":
		if t.has(bUsers, c.User.AccessKey) {
			return result{err: s3err(codes.AlreadyExists, "UserAlreadyExists")}
		}
		u := *c.User
		u.CreatedAt = c.Now
		t.put(bUsers, u.AccessKey, &u)

	case "delete_user":
		var u User
		if !t.get(bUsers, c.Key, &u) {
			return result{err: s3err(codes.NotFound, "NoSuchUser")}
		}
		if u.Admin {
			admins := 0
			t.Bucket(bUsers).ForEach(func(_, v []byte) error {
				var x User
				must(json.Unmarshal(v, &x))
				if x.Admin {
					admins++
				}
				return nil
			})
			if admins == 1 {
				return result{err: s3err(codes.FailedPrecondition, "LastAdmin")}
			}
		}
		t.del(bUsers, c.Key)

	case "upsert_node":
		t.put(bNodes, c.NodeID, c.Node)

	case "add_holder":
		if ch := t.chunk(c.SHA); ch != nil && !slices.Contains(ch.Holders, c.NodeID) {
			t.setHolders(c.SHA, ch, append(slices.Clone(ch.Holders), c.NodeID))
		}

	case "remove_holder":
		if ch := t.chunk(c.SHA); ch != nil && slices.Contains(ch.Holders, c.NodeID) {
			t.setHolders(c.SHA, ch, slices.DeleteFunc(slices.Clone(ch.Holders), func(h string) bool { return h == c.NodeID }))
			t.dirty = append(t.dirty, c.SHA)
		}

	case "tombstone":
		ch := t.chunk(c.SHA)
		if ch == nil || ch.Refs > 0 {
			return result{} // re-referenced since GC looked: keep it
		}
		for _, h := range ch.Holders {
			t.del(bHolder, holderKey(h, c.SHA))
		}
		t.del(bChunks, c.SHA)
		t.del(bZero, c.SHA)
		t.put(bTombs, c.SHA, &Tombstone{At: c.Now, Pending: slices.Clone(ch.Holders)})
		if len(ch.Holders) > 0 {
			t.mark(bPending, c.SHA)
		}
		return result{pending: ch.Holders}

	case "deleted":
		if x := t.tomb(c.SHA); x != nil {
			x.Pending = slices.DeleteFunc(x.Pending, func(h string) bool { return h == c.NodeID })
			t.put(bTombs, c.SHA, x)
			if len(x.Pending) == 0 {
				t.del(bPending, c.SHA)
			}
		}

	default:
		return result{err: fmt.Errorf("unknown op %q", c.Op)}
	}
	return result{}
}

// needRetry returns chunks that GC tombstoned after the writer wrote them:
// their files may be gone, so the writer must write them again.
func (t *tx) needRetry(chunks []CommitChunk) []string {
	var retry []string
	for _, c := range chunks {
		if t.has(bChunks, c.SHA) {
			continue
		}
		if x := t.tomb(c.SHA); x != nil && c.WrittenAt <= x.At {
			retry = append(retry, c.SHA)
		}
	}
	return retry
}

func (t *tx) addChunks(chunks []CommitChunk, want uint32) {
	for _, c := range chunks {
		ch := t.chunk(c.SHA)
		if ch == nil {
			ch = &ChunkInfo{Size: c.Size}
			t.del(bTombs, c.SHA)
			t.del(bPending, c.SHA)
		}
		holders := slices.Clone(ch.Holders)
		for _, h := range c.Holders {
			if !slices.Contains(holders, h) {
				holders = append(holders, h)
			}
		}
		t.setHolders(c.SHA, ch, holders)
	}
	t.incref(refs(chunks), want)
}

func (t *tx) incref(chunks []ChunkRef, want uint32) {
	for _, c := range chunks {
		ch := t.chunk(c.SHA)
		if ch == nil {
			continue // callers only pass chunks already in the table
		}
		if ch.Refs == 0 {
			t.add(cChunks, 1)
			t.del(bZero, c.SHA)
		}
		ch.Refs++
		ch.ZeroSince = 0
		// ponytail: want only grows; recompute from referencing buckets if that wastes space.
		if want > ch.Want {
			ch.Want = want
		}
		if len(ch.Holders) < int(ch.Want) {
			t.dirty = append(t.dirty, c.SHA) // written with fewer copies than wanted
		}
		t.put(bChunks, c.SHA, ch)
	}
}

func (t *tx) decref(chunks []ChunkRef, now int64) {
	for _, c := range chunks {
		ch := t.chunk(c.SHA)
		if ch == nil || ch.Refs == 0 {
			continue
		}
		ch.Refs--
		if ch.Refs == 0 {
			ch.ZeroSince = now
			t.add(cChunks, -1)
			t.mark(bZero, c.SHA)
		}
		t.put(bChunks, c.SHA, ch)
	}
}

func (t *tx) putObject(bucket, key string, o *Object, now int64) {
	if old := t.object(bucket, key); old != nil {
		t.decref(old.Chunks, now)
		t.add(cObjects, -1)
		t.add(cLogical, -old.Size)
	}
	t.put(bObjects, objKey(bucket, key), o)
	t.add(cObjects, 1)
	t.add(cLogical, o.Size)
}

func (t *tx) dropUpload(id string, now int64) {
	var keys [][]byte
	t.scan(bParts, id+"\x00", func(k, v []byte) bool {
		var p Part
		must(json.Unmarshal(v, &p))
		t.decref(p.Chunks, now)
		keys = append(keys, slices.Clone(k))
		return true
	})
	for _, k := range keys {
		must(t.Bucket(bParts).Delete(k))
	}
	t.del(bUploads, id)
}

func refs(cs []CommitChunk) []ChunkRef {
	out := make([]ChunkRef, len(cs))
	for i, c := range cs {
		out[i] = ChunkRef{SHA: c.SHA, Size: c.Size}
	}
	return out
}

// listObjects implements ListObjectsV2 over the sorted key space: one seek,
// then a walk of exactly one page (a common prefix is skipped with a seek).
func (t *tx) listObjects(bucket, prefix, delim, after string, max int) (keys []string, prefixes []string, truncated bool) {
	base := bucket + "\x00"
	c := t.Bucket(bObjects).Cursor()
	start := []byte(base + prefix)
	if after != "" && base+after >= string(start) {
		start = append([]byte(base+after), 0) // strictly after
	}
	for k, _ := c.Seek(start); k != nil && bytes.HasPrefix(k, []byte(base+prefix)); {
		key := string(k[len(base):])
		if delim != "" {
			if i := strings.Index(key[len(prefix):], delim); i >= 0 {
				cp := key[:len(prefix)+i+len(delim)]
				if len(keys)+len(prefixes) == max {
					return keys, prefixes, true
				}
				if cp > after {
					prefixes = append(prefixes, cp)
				}
				k, _ = c.Seek(append([]byte(base+cp), 0xff)) // jump past the whole group
				continue
			}
		}
		if len(keys)+len(prefixes) == max {
			return keys, prefixes, true
		}
		keys = append(keys, key)
		k, _ = c.Next()
	}
	return keys, prefixes, false
}

// ---- raft snapshots: stream the store itself ----

func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	t, err := f.db.Begin(false) // a consistent MVCC view; writers carry on
	if err != nil {
		return nil, err
	}
	return &snapshot{t}, nil
}

type snapshot struct{ t *bolt.Tx }

func (s *snapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := s.t.WriteTo(sink); err != nil {
		sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s *snapshot) Release() { s.t.Rollback() }

// Restore replaces the store with a snapshot from the leader. Snapshots are
// bbolt files; a JSON snapshot from before the on-disk store is converted once.
func (f *fsm) Restore(r io.ReadCloser) error {
	defer r.Close()
	tmp := f.path + ".restore"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	head := make([]byte, 1)
	n, _ := io.ReadFull(r, head)
	if n == 1 && head[0] == '{' {
		out.Close()
		os.Remove(tmp)
		return f.restoreLegacy(io.MultiReader(bytes.NewReader(head), r))
	}
	if _, err := io.Copy(out, io.MultiReader(bytes.NewReader(head[:n]), r)); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	out.Close()
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.db.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, f.path); err != nil {
		return err
	}
	f.db, err = openBolt(f.path)
	return err
}

// legacyState is the pre-bbolt JSON snapshot format, kept only to migrate it.
type legacyState struct {
	Buckets    map[string]*Bucket            `json:"buckets"`
	Objects    map[string]map[string]*Object `json:"objects"`
	Chunks     map[string]*ChunkInfo         `json:"chunks"`
	Tombstones map[string]*Tombstone         `json:"tombstones"`
	Uploads    map[string]*struct {
		Upload
		Parts map[uint32]*Part `json:"parts"`
	} `json:"uploads"`
	Nodes map[string]*NodeInfo `json:"nodes"`
	Users map[string]*User     `json:"users"`
}

func (f *fsm) restoreLegacy(r io.Reader) error {
	var st legacyState
	if err := json.NewDecoder(r).Decode(&st); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.db.Update(func(bt *bolt.Tx) error {
		for _, b := range allKeyspaces { // start clean, counters included; Raft replays what follows
			if err := bt.DeleteBucket(b); err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
				return err
			}
			if _, err := bt.CreateBucket(b); err != nil {
				return err
			}
		}
		t := &tx{Tx: bt}
		for k, v := range st.Buckets {
			t.put(bBuckets, k, v)
		}
		for sha, ch := range st.Chunks {
			holders := ch.Holders
			ch.Holders = nil
			t.setHolders(sha, ch, holders)
			if ch.Refs > 0 {
				t.add(cChunks, 1)
			} else {
				t.mark(bZero, sha)
			}
		}
		for b, objs := range st.Objects {
			for k, o := range objs {
				t.put(bObjects, objKey(b, k), o)
				t.add(cObjects, 1)
				t.add(cLogical, o.Size)
			}
		}
		for sha, x := range st.Tombstones {
			t.put(bTombs, sha, x)
			if len(x.Pending) > 0 {
				t.mark(bPending, sha)
			}
		}
		for id, u := range st.Uploads {
			t.put(bUploads, id, &u.Upload)
			for n, p := range u.Parts {
				t.put(bParts, partKey(id, n), p)
			}
		}
		for k, v := range st.Nodes {
			t.put(bNodes, k, v)
		}
		for k, v := range st.Users {
			t.put(bUsers, k, v)
		}
		return nil
	})
}
