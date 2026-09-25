package meta

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/hashicorp/raft"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Everything the cluster must agree on. Mutated only by fsm.Apply, so every
// meta member holds the same state for the same log index.
// ponytail: whole state in memory + JSON snapshots; move to an on-disk
// B-tree when metadata outgrows RAM.
type state struct {
	Buckets    map[string]*Bucket            `json:"buckets"`
	Objects    map[string]map[string]*Object `json:"objects"` // bucket → key → object
	Chunks     map[string]*ChunkInfo         `json:"chunks"`
	Tombstones map[string]*Tombstone         `json:"tombstones"`
	Uploads    map[string]*Upload            `json:"uploads"`
	Nodes      map[string]*NodeInfo          `json:"nodes"`
	// ponytail: secrets are stored as-is (SigV4 needs them); encrypt Raft
	// snapshots and logs at rest before handling real customer keys.
	Users map[string]*User `json:"users"` // access key → user
}

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
	Parts       map[uint32]*Part  `json:"parts"`
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

type fsm struct {
	mu sync.RWMutex
	st *state
}

func newState() *state {
	return &state{
		Buckets: map[string]*Bucket{}, Objects: map[string]map[string]*Object{},
		Chunks: map[string]*ChunkInfo{}, Tombstones: map[string]*Tombstone{},
		Uploads: map[string]*Upload{}, Nodes: map[string]*NodeInfo{}, Users: map[string]*User{},
	}
}

func s3err(c codes.Code, s3code string) error { return status.Error(c, s3code) }

func (f *fsm) Apply(l *raft.Log) any {
	var c command
	if err := json.Unmarshal(l.Data, &c); err != nil {
		return result{err: fmt.Errorf("bad command: %w", err)}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st.apply(&c)
}

func (st *state) apply(c *command) result {
	switch c.Op {
	case "create_bucket":
		if _, ok := st.Buckets[c.Name]; ok {
			return result{err: s3err(codes.AlreadyExists, "BucketAlreadyOwnedByYou")}
		}
		b := *c.Bucket
		b.CreatedAt = c.Now
		st.Buckets[c.Name] = &b
		st.Objects[c.Name] = map[string]*Object{}

	case "delete_bucket":
		if _, ok := st.Buckets[c.Name]; !ok {
			return result{err: s3err(codes.NotFound, "NoSuchBucket")}
		}
		if len(st.Objects[c.Name]) > 0 {
			return result{err: s3err(codes.FailedPrecondition, "BucketNotEmpty")}
		}
		for id, u := range st.Uploads {
			if u.Bucket == c.Name {
				st.dropUpload(id, c.Now)
			}
		}
		delete(st.Buckets, c.Name)
		delete(st.Objects, c.Name)

	case "commit_object":
		b, ok := st.Buckets[c.Name]
		if !ok {
			return result{err: s3err(codes.NotFound, "NoSuchBucket")}
		}
		if retry := st.needRetry(c.Chunks); len(retry) > 0 {
			return result{retry: retry}
		}
		st.addChunks(c.Chunks, b.Replicas)
		o := *c.Object
		o.ModifiedAt = c.Now
		st.putObject(c.Name, c.Key, &o, c.Now)
		return result{object: &o}

	case "delete_object":
		if _, ok := st.Buckets[c.Name]; !ok {
			return result{err: s3err(codes.NotFound, "NoSuchBucket")}
		}
		if old := st.Objects[c.Name][c.Key]; old != nil {
			st.decref(old.Chunks, c.Now)
			delete(st.Objects[c.Name], c.Key)
		}

	case "copy_object":
		src := st.Objects[c.Name][c.Key]
		if _, ok := st.Buckets[c.Name]; !ok {
			return result{err: s3err(codes.NotFound, "NoSuchBucket")}
		}
		if src == nil {
			return result{err: s3err(codes.NotFound, "NoSuchKey")}
		}
		db, ok := st.Buckets[c.DstName]
		if !ok {
			return result{err: s3err(codes.NotFound, "NoSuchBucket")}
		}
		o := *src
		o.Chunks = slices.Clone(src.Chunks)
		o.ModifiedAt = c.Now
		if c.Replace {
			o.ContentType, o.UserMeta = c.CType, c.UserMeta
		}
		st.incref(o.Chunks, db.Replicas)
		st.putObject(c.DstName, c.DstKey, &o, c.Now)
		return result{object: &o}

	case "create_upload":
		if _, ok := st.Buckets[c.Name]; !ok {
			return result{err: s3err(codes.NotFound, "NoSuchBucket")}
		}
		st.Uploads[c.UploadID] = &Upload{
			Bucket: c.Name, Key: c.Key, ContentType: c.CType, UserMeta: c.UserMeta,
			CreatedAt: c.Now, Parts: map[uint32]*Part{},
		}

	case "commit_part":
		u := st.Uploads[c.UploadID]
		if u == nil {
			return result{err: s3err(codes.NotFound, "NoSuchUpload")}
		}
		if retry := st.needRetry(c.Chunks); len(retry) > 0 {
			return result{retry: retry}
		}
		st.addChunks(c.Chunks, st.Buckets[u.Bucket].Replicas)
		if old := u.Parts[c.PartNum]; old != nil {
			st.decref(old.Chunks, c.Now)
		}
		u.Parts[c.PartNum] = &Part{ETag: c.ETag, Size: c.Size, Chunks: refs(c.Chunks)}

	case "complete_upload":
		u := st.Uploads[c.UploadID]
		if u == nil {
			return result{err: s3err(codes.NotFound, "NoSuchUpload")}
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
			p := u.Parts[cp.Num]
			if p == nil || strings.Trim(cp.ETag, `"`) != p.ETag {
				return result{err: s3err(codes.InvalidArgument, "InvalidPart")}
			}
			raw, _ := hex.DecodeString(p.ETag)
			md5s.Write(raw)
			o.Size += p.Size
			o.Chunks = append(o.Chunks, p.Chunks...)
		}
		o.ETag = fmt.Sprintf("%x-%d", md5s.Sum(nil), len(c.Parts))
		st.incref(o.Chunks, st.Buckets[u.Bucket].Replicas)
		st.dropUpload(c.UploadID, c.Now) // releases every part's refs, used or not
		st.putObject(u.Bucket, u.Key, o, c.Now)
		return result{object: o}

	case "abort_upload":
		if st.Uploads[c.UploadID] == nil {
			return result{err: s3err(codes.NotFound, "NoSuchUpload")}
		}
		st.dropUpload(c.UploadID, c.Now)

	case "create_user":
		if _, ok := st.Users[c.User.AccessKey]; ok {
			return result{err: s3err(codes.AlreadyExists, "UserAlreadyExists")}
		}
		u := *c.User
		u.CreatedAt = c.Now
		st.Users[u.AccessKey] = &u

	case "delete_user":
		u := st.Users[c.Key]
		if u == nil {
			return result{err: s3err(codes.NotFound, "NoSuchUser")}
		}
		if u.Admin {
			admins := 0
			for _, x := range st.Users {
				if x.Admin {
					admins++
				}
			}
			if admins == 1 {
				return result{err: s3err(codes.FailedPrecondition, "LastAdmin")}
			}
		}
		delete(st.Users, c.Key)

	case "upsert_node":
		st.Nodes[c.NodeID] = c.Node

	case "add_holder":
		if ch := st.Chunks[c.SHA]; ch != nil && !slices.Contains(ch.Holders, c.NodeID) {
			ch.Holders = append(ch.Holders, c.NodeID)
		}

	case "remove_holder":
		if ch := st.Chunks[c.SHA]; ch != nil {
			ch.Holders = slices.DeleteFunc(ch.Holders, func(h string) bool { return h == c.NodeID })
		}

	case "tombstone":
		ch := st.Chunks[c.SHA]
		if ch == nil || ch.Refs > 0 {
			return result{} // re-referenced since GC looked: keep it
		}
		delete(st.Chunks, c.SHA)
		st.Tombstones[c.SHA] = &Tombstone{At: c.Now, Pending: slices.Clone(ch.Holders)}
		return result{pending: ch.Holders}

	case "deleted":
		if t := st.Tombstones[c.SHA]; t != nil {
			t.Pending = slices.DeleteFunc(t.Pending, func(h string) bool { return h == c.NodeID })
		}

	default:
		return result{err: fmt.Errorf("unknown op %q", c.Op)}
	}
	return result{}
}

// needRetry returns chunks that GC tombstoned after the writer wrote them:
// their files may be gone, so the writer must write them again.
func (st *state) needRetry(chunks []CommitChunk) []string {
	var retry []string
	for _, c := range chunks {
		if _, live := st.Chunks[c.SHA]; live {
			continue
		}
		if t := st.Tombstones[c.SHA]; t != nil && c.WrittenAt <= t.At {
			retry = append(retry, c.SHA)
		}
	}
	return retry
}

func (st *state) addChunks(chunks []CommitChunk, want uint32) {
	for _, c := range chunks {
		ch := st.Chunks[c.SHA]
		if ch == nil {
			ch = &ChunkInfo{Size: c.Size}
			st.Chunks[c.SHA] = ch
			delete(st.Tombstones, c.SHA)
		}
		for _, h := range c.Holders {
			if !slices.Contains(ch.Holders, h) {
				ch.Holders = append(ch.Holders, h)
			}
		}
	}
	st.incref(refs(chunks), want)
}

func (st *state) incref(chunks []ChunkRef, want uint32) {
	for _, c := range chunks {
		ch := st.Chunks[c.SHA]
		if ch == nil {
			continue // callers only pass chunks already in the table
		}
		ch.Refs++
		ch.ZeroSince = 0
		// ponytail: want only grows; recompute from referencing buckets if that wastes space.
		ch.Want = max(ch.Want, want)
	}
}

func (st *state) decref(chunks []ChunkRef, now int64) {
	for _, c := range chunks {
		if ch := st.Chunks[c.SHA]; ch != nil {
			ch.Refs--
			if ch.Refs <= 0 {
				ch.Refs = 0
				ch.ZeroSince = now
			}
		}
	}
}

func (st *state) putObject(bucket, key string, o *Object, now int64) {
	if old := st.Objects[bucket][key]; old != nil {
		st.decref(old.Chunks, now)
	}
	st.Objects[bucket][key] = o
}

func (st *state) dropUpload(id string, now int64) {
	for _, p := range st.Uploads[id].Parts {
		st.decref(p.Chunks, now)
	}
	delete(st.Uploads, id)
}

func refs(cs []CommitChunk) []ChunkRef {
	out := make([]ChunkRef, len(cs))
	for i, c := range cs {
		out[i] = ChunkRef{SHA: c.SHA, Size: c.Size}
	}
	return out
}

// listObjects implements ListObjectsV2 semantics over the sorted key space.
// ponytail: sorts the bucket's keys per call, O(n log n); use a B-tree past ~1M keys.
func (st *state) listObjects(bucket, prefix, delim, after string, max int) (keys []string, prefixes []string, truncated bool) {
	all := make([]string, 0, len(st.Objects[bucket]))
	for k := range st.Objects[bucket] {
		if strings.HasPrefix(k, prefix) && k > after {
			all = append(all, k)
		}
	}
	sort.Strings(all)
	seen := map[string]bool{}
	for _, k := range all {
		if delim != "" {
			if i := strings.Index(k[len(prefix):], delim); i >= 0 {
				cp := k[:len(prefix)+i+len(delim)]
				if seen[cp] || cp <= after {
					continue
				}
				if len(keys)+len(prefixes) == max {
					return keys, prefixes, true
				}
				seen[cp] = true
				prefixes = append(prefixes, cp)
				continue
			}
		}
		if len(keys)+len(prefixes) == max {
			return keys, prefixes, true
		}
		keys = append(keys, k)
	}
	return keys, prefixes, false
}

// ---- raft snapshots ----

func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	b, err := json.Marshal(f.st)
	return snapshot(b), err
}

func (f *fsm) Restore(r io.ReadCloser) error {
	defer r.Close()
	st := newState()
	if err := json.NewDecoder(r).Decode(st); err != nil {
		return err
	}
	if st.Users == nil {
		st.Users = map[string]*User{}
	}
	f.mu.Lock()
	f.st = st
	f.mu.Unlock()
	return nil
}

type snapshot []byte

func (s snapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := sink.Write(s); err != nil {
		sink.Cancel()
		return err
	}
	return sink.Close()
}

func (snapshot) Release() {}
