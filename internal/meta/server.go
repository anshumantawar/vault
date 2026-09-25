// Package meta is the Raft-replicated metadata service: buckets, object
// manifests, chunk locations and multipart uploads. The leader also runs
// the failure detector, repair, rebalance and GC loops.
package meta

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	vaultv1 "vault/gen/vault/v1"
	"vault/internal/pki"
	"vault/internal/wire"
)

type Config struct {
	ID       string
	GRPCAddr string
	RaftAddr string
	Dir      string
	// Peers maps every member's id to its raft address, including this one.
	Peers map[string]string
	TLS   *wire.TLS // this member's certificate; its id must equal ID
}

// rules: every metadata RPC is for gateways, except what nodes report.
var rules = func() wire.Rules {
	r := wire.Rules{}
	for _, m := range vaultv1.MetaService_ServiceDesc.Methods {
		r["/"+vaultv1.MetaService_ServiceDesc.ServiceName+"/"+m.MethodName] = []string{pki.RoleGateway}
	}
	r[vaultv1.MetaService_Heartbeat_FullMethodName] = []string{pki.RoleNode}
	r[vaultv1.MetaService_ReportCorrupt_FullMethodName] = []string{pki.RoleNode, pki.RoleGateway}
	return r
}()

// onlyMeta rejects TLS peers that are not metadata members (Raft traffic).
func onlyMeta(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 || pki.IdentityOf(cs.PeerCertificates[0]).Role != pki.RoleMeta {
		return errors.New("raft peer is not a metadata member")
	}
	return nil
}

// tlsStream is Raft's transport over mutual TLS, members only.
type tlsStream struct {
	net.Listener
	advertise net.Addr
	client    *tls.Config
}

func (s *tlsStream) Dial(addr raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", string(addr), s.client)
}

func (s *tlsStream) Addr() net.Addr { return s.advertise }

type Server struct {
	vaultv1.UnimplementedMetaServiceServer
	cfg  Config
	raft *raft.Raft
	fsm  *fsm
	pool *wire.Pool

	// Leader-only, in-memory: rebuilt from heartbeats after every election.
	mu          sync.Mutex
	lastSeen    map[string]time.Time
	stats       map[string]*vaultv1.Node
	inflight    map[string]bool
	moves       int
	repairs     int64
	rebalances  int64
	degraded    time.Time
	lastHealthy time.Time
	lastMTTR    time.Duration

	// Incremental reconciliation (leader only): chunks to look at, and what the
	// last look found, so no loop walks every chunk every tick.
	leader   atomic.Bool
	queue    map[string]time.Time // sha → not before
	under    map[string]bool      // under-replicated, as last evaluated
	lost     map[string]bool      // no live copy, as last evaluated
	wasAlive map[string]bool
	scanPos  []byte // paced full-scan cursor (safety net + rebalancing)
}

// Run serves the meta member until ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	if cfg.TLS == nil || cfg.TLS.Self.ID != cfg.ID || cfg.TLS.Self.Role != pki.RoleMeta {
		return fmt.Errorf("meta %s needs its own meta certificate", cfg.ID)
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return err
	}
	fsmPath := filepath.Join(cfg.Dir, "fsm.db")
	_, statErr := os.Stat(fsmPath)
	storeExisted := statErr == nil
	f, err := openFSM(fsmPath)
	if err != nil {
		return err
	}
	defer f.Close()
	s := &Server{
		cfg: cfg, fsm: f, pool: wire.NewPool(cfg.TLS),
		lastSeen: map[string]time.Time{}, stats: map[string]*vaultv1.Node{}, inflight: map[string]bool{},
		queue: map[string]time.Time{}, under: map[string]bool{}, lost: map[string]bool{}, wasAlive: map[string]bool{},
	}
	f.onDirty = s.markDirty
	defer s.pool.Close()

	rc := raft.DefaultConfig()
	rc.LocalID = raft.ServerID(cfg.ID)
	// Fast failover for a LAN demo: a new leader in about a second.
	rc.HeartbeatTimeout = 500 * time.Millisecond
	rc.ElectionTimeout = 500 * time.Millisecond
	rc.LeaderLeaseTimeout = 250 * time.Millisecond
	rc.CommitTimeout = 20 * time.Millisecond
	rc.LogLevel = "WARN"
	rc.BatchApplyCh = true // group concurrent proposals into one log append
	// The store on disk already is the state: replaying the log tail after a
	// restart is enough, so don't overwrite it with the last snapshot. A brand
	// new store (first start, or migrating from the in-memory FSM) does restore.
	rc.NoSnapshotRestoreOnStart = storeExisted
	leaderCh := make(chan bool, 8)
	rc.NotifyCh = leaderCh

	store, err := raftboltdb.New(raftboltdb.Options{Path: filepath.Join(cfg.Dir, "raft.db")})
	if err != nil {
		return err
	}
	defer store.Close()
	snaps, err := raft.NewFileSnapshotStore(cfg.Dir, 2, os.Stderr)
	if err != nil {
		return err
	}
	addr, err := net.ResolveTCPAddr("tcp", cfg.RaftAddr)
	if err != nil {
		return err
	}
	srvTLS, cliTLS := cfg.TLS.Server.Clone(), cfg.TLS.Client.Clone()
	srvTLS.VerifyConnection, cliTLS.VerifyConnection = onlyMeta, onlyMeta
	raftLis, err := tls.Listen("tcp", cfg.RaftAddr, srvTLS)
	if err != nil {
		return err
	}
	trans := raft.NewNetworkTransport(&tlsStream{Listener: raftLis, advertise: addr, client: cliTLS}, 3, 5*time.Second, os.Stderr)
	defer trans.Close()
	r, err := raft.NewRaft(rc, s.fsm, store, store, snaps, trans)
	if err != nil {
		return err
	}
	s.raft = r
	if has, _ := raft.HasExistingState(store, store, snaps); !has {
		var servers []raft.Server
		for id, a := range cfg.Peers {
			servers = append(servers, raft.Server{ID: raft.ServerID(id), Address: raft.ServerAddress(a)})
		}
		// Every member bootstraps with the identical config; raft tolerates that.
		if err := r.BootstrapCluster(raft.Configuration{Servers: servers}).Error(); err != nil && !errors.Is(err, raft.ErrCantBootstrap) {
			return err
		}
	}

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		r.Shutdown()
		return err
	}
	gs := grpc.NewServer(append([]grpc.ServerOption{cfg.TLS.ServerCreds()}, rules.Interceptors()...)...)
	vaultv1.RegisterMetaServiceServer(gs, s)

	go s.watchLeadership(ctx, leaderCh)
	go s.leaderLoops(ctx)
	go func() {
		<-ctx.Done()
		gs.Stop()
	}()
	log.Printf("meta %s serving gRPC %s, raft %s", cfg.ID, cfg.GRPCAddr, cfg.RaftAddr)
	err = gs.Serve(lis)
	r.Shutdown().Error()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

var errNotLeader = status.Error(codes.FailedPrecondition, "not the raft leader")

func (s *Server) leaderOnly() error {
	if s.raft.State() != raft.Leader {
		return errNotLeader
	}
	return nil
}

// read runs fn on the state after confirming this member is still leader,
// so a deposed leader never serves stale metadata.
func (s *Server) read(fn func(*tx) error) error {
	if err := s.raft.VerifyLeader().Error(); err != nil {
		return errNotLeader
	}
	return s.fsm.view(fn)
}

func (s *Server) propose(c *command) (result, error) {
	c.Now = time.Now().UnixNano()
	b, err := json.Marshal(c)
	if err != nil {
		return result{}, err
	}
	f := s.raft.Apply(b, 5*time.Second)
	if err := f.Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) || errors.Is(err, raft.ErrLeadershipLost) {
			return result{}, errNotLeader
		}
		return result{}, status.Error(codes.Unavailable, err.Error())
	}
	res := f.Response().(result)
	return res, res.err
}

// ---- nodes ----

func (s *Server) Heartbeat(ctx context.Context, req *vaultv1.HeartbeatRequest) (*vaultv1.HeartbeatResponse, error) {
	if err := s.leaderOnly(); err != nil {
		return nil, err
	}
	n := req.GetNode()
	if n.GetId() == "" || n.GetAddr() == "" {
		return nil, status.Error(codes.InvalidArgument, "node id and addr required")
	}
	if c, _ := wire.Caller(ctx); c.ID != n.GetId() {
		return nil, status.Errorf(codes.PermissionDenied, "node %q may not heartbeat as %q", c.ID, n.GetId())
	}
	var known *NodeInfo
	s.fsm.view(func(t *tx) error {
		var ni NodeInfo
		known = ptrIf(t.get(bNodes, n.GetId(), &ni), &ni)
		return nil
	})
	if known == nil || known.Addr != n.GetAddr() || known.Zone != n.GetZone() {
		if _, err := s.propose(&command{Op: "upsert_node", NodeID: n.GetId(), Node: &NodeInfo{Addr: n.GetAddr(), Zone: n.GetZone()}}); err != nil {
			return nil, err
		}
		log.Printf("meta: node %s joined at %s (zone %s)", n.GetId(), n.GetAddr(), n.GetZone())
	}
	s.mu.Lock()
	s.lastSeen[n.GetId()] = time.Now()
	s.stats[n.GetId()] = n
	s.mu.Unlock()
	return &vaultv1.HeartbeatResponse{}, nil
}

func (s *Server) ReportCorrupt(ctx context.Context, req *vaultv1.ReportCorruptRequest) (*vaultv1.ReportCorruptResponse, error) {
	if err := s.leaderOnly(); err != nil {
		return nil, err
	}
	if c, _ := wire.Caller(ctx); c.Role == pki.RoleNode && c.ID != req.GetNodeId() {
		return nil, status.Errorf(codes.PermissionDenied, "node %q may only report its own copies", c.ID)
	}
	_, err := s.propose(&command{Op: "remove_holder", SHA: req.GetSha256(), NodeID: req.GetNodeId()})
	if err == nil {
		log.Printf("meta: dropped bad copy of %.12s on %s; repair will replace it", req.GetSha256(), req.GetNodeId())
	}
	return &vaultv1.ReportCorruptResponse{}, err
}

const deadAfter = 3 * time.Second

func (s *Server) nodes() []*vaultv1.Node {
	infos := map[string]*NodeInfo{}
	s.fsm.view(func(t *tx) error {
		return t.Bucket(bNodes).ForEach(func(k, v []byte) error {
			var ni NodeInfo
			must(json.Unmarshal(v, &ni))
			infos[string(k)] = &ni
			return nil
		})
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*vaultv1.Node
	for id, info := range infos {
		n := &vaultv1.Node{Id: id, Addr: info.Addr, Zone: info.Zone}
		if st := s.stats[id]; st != nil {
			n.UsedBytes, n.ChunkCount = st.UsedBytes, st.ChunkCount
			n.PartitionedFrom, n.SlowMs = st.PartitionedFrom, st.SlowMs
		}
		n.Alive = time.Since(s.lastSeen[id]) < deadAfter
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Id < out[j].Id })
	return out
}

func (s *Server) ListNodes(context.Context, *vaultv1.ListNodesRequest) (*vaultv1.ListNodesResponse, error) {
	if err := s.leaderOnly(); err != nil {
		return nil, err
	}
	return &vaultv1.ListNodesResponse{Nodes: s.nodes()}, nil
}

// ---- buckets ----

func (s *Server) CreateBucket(_ context.Context, req *vaultv1.CreateBucketRequest) (*vaultv1.CreateBucketResponse, error) {
	b := req.GetBucket()
	if b.GetReplicas() == 0 || b.GetWriteQuorum() == 0 || b.GetWriteQuorum() > b.GetReplicas() {
		return nil, status.Error(codes.InvalidArgument, "InvalidArgument")
	}
	_, err := s.propose(&command{Op: "create_bucket", Name: b.GetName(), Bucket: &Bucket{Replicas: b.GetReplicas(), WriteQuorum: b.GetWriteQuorum(), Owner: b.GetOwner()}})
	return &vaultv1.CreateBucketResponse{}, err
}

func (s *Server) DeleteBucket(_ context.Context, req *vaultv1.DeleteBucketRequest) (*vaultv1.DeleteBucketResponse, error) {
	_, err := s.propose(&command{Op: "delete_bucket", Name: req.GetName()})
	return &vaultv1.DeleteBucketResponse{}, err
}

func bucketPB(name string, b *Bucket) *vaultv1.Bucket {
	return &vaultv1.Bucket{Name: name, Replicas: b.Replicas, WriteQuorum: b.WriteQuorum, CreatedAt: b.CreatedAt, Owner: b.Owner}
}

func (s *Server) GetBucket(_ context.Context, req *vaultv1.GetBucketRequest) (*vaultv1.GetBucketResponse, error) {
	var out *vaultv1.Bucket
	err := s.read(func(t *tx) error {
		b := t.bucket(req.GetName())
		if b == nil {
			return s3err(codes.NotFound, "NoSuchBucket")
		}
		out = bucketPB(req.GetName(), b)
		return nil
	})
	return &vaultv1.GetBucketResponse{Bucket: out}, err
}

func (s *Server) ListBuckets(context.Context, *vaultv1.ListBucketsRequest) (*vaultv1.ListBucketsResponse, error) {
	resp := &vaultv1.ListBucketsResponse{}
	err := s.read(func(t *tx) error {
		return t.Bucket(bBuckets).ForEach(func(k, v []byte) error {
			var b Bucket
			must(json.Unmarshal(v, &b))
			resp.Buckets = append(resp.Buckets, bucketPB(string(k), &b))
			return nil
		})
	})
	return resp, err
}

// ---- objects ----

func commitChunks(pb []*vaultv1.Chunk) ([]CommitChunk, error) {
	out := make([]CommitChunk, len(pb))
	for i, c := range pb {
		if len(c.GetSha256()) != 64 || len(c.GetHolders()) == 0 {
			return nil, status.Error(codes.InvalidArgument, "chunk needs sha256 and holders")
		}
		out[i] = CommitChunk{SHA: c.GetSha256(), Size: c.GetSize(), Holders: c.GetHolders(), WrittenAt: c.GetWrittenAt()}
	}
	return out, nil
}

func (s *Server) CommitObject(_ context.Context, req *vaultv1.CommitObjectRequest) (*vaultv1.CommitObjectResponse, error) {
	o := req.GetObject()
	chunks, err := commitChunks(o.GetChunks())
	if err != nil {
		return nil, err
	}
	res, err := s.propose(&command{
		Op: "commit_object", Name: o.GetBucket(), Key: o.GetKey(), Chunks: chunks,
		Object: &Object{Size: o.GetSize(), ETag: o.GetEtag(), ContentType: o.GetContentType(), UserMeta: o.GetUserMeta(), Chunks: refs(chunks)},
	})
	return &vaultv1.CommitObjectResponse{RetrySha256: res.retry}, err
}

// objectPB converts an object, attaching current holders to each chunk.
func objectPB(t *tx, bucket, key string, o *Object, withChunks bool) *vaultv1.Object {
	pb := &vaultv1.Object{
		Bucket: bucket, Key: key, Size: o.Size, Etag: o.ETag, ContentType: o.ContentType,
		UserMeta: o.UserMeta, ModifiedAt: o.ModifiedAt,
	}
	if withChunks {
		for _, c := range o.Chunks {
			ch := &vaultv1.Chunk{Sha256: c.SHA, Size: c.Size}
			if info := t.chunk(c.SHA); info != nil {
				ch.Holders = slices.Clone(info.Holders)
			}
			pb.Chunks = append(pb.Chunks, ch)
		}
	}
	return pb
}

func (s *Server) GetObject(_ context.Context, req *vaultv1.GetObjectRequest) (*vaultv1.GetObjectResponse, error) {
	var out *vaultv1.Object
	err := s.read(func(t *tx) error {
		if !t.has(bBuckets, req.GetBucket()) {
			return s3err(codes.NotFound, "NoSuchBucket")
		}
		o := t.object(req.GetBucket(), req.GetKey())
		if o == nil {
			return s3err(codes.NotFound, "NoSuchKey")
		}
		out = objectPB(t, req.GetBucket(), req.GetKey(), o, true)
		return nil
	})
	return &vaultv1.GetObjectResponse{Object: out}, err
}

func (s *Server) DeleteObject(_ context.Context, req *vaultv1.DeleteObjectRequest) (*vaultv1.DeleteObjectResponse, error) {
	_, err := s.propose(&command{Op: "delete_object", Name: req.GetBucket(), Key: req.GetKey()})
	return &vaultv1.DeleteObjectResponse{}, err
}

func (s *Server) CopyObject(_ context.Context, req *vaultv1.CopyObjectRequest) (*vaultv1.CopyObjectResponse, error) {
	res, err := s.propose(&command{
		Op: "copy_object", Name: req.GetSrcBucket(), Key: req.GetSrcKey(), DstName: req.GetDstBucket(), DstKey: req.GetDstKey(),
		Replace: req.GetReplaceMeta(), CType: req.GetContentType(), UserMeta: req.GetUserMeta(),
	})
	if err != nil {
		return nil, err
	}
	return &vaultv1.CopyObjectResponse{Object: objectPB(nil, req.GetDstBucket(), req.GetDstKey(), res.object, false)}, nil
}

func (s *Server) ListObjects(_ context.Context, req *vaultv1.ListObjectsRequest) (*vaultv1.ListObjectsResponse, error) {
	max := int(req.GetMaxKeys())
	if max <= 0 || max > 1000 {
		max = 1000
	}
	resp := &vaultv1.ListObjectsResponse{}
	err := s.read(func(t *tx) error {
		if !t.has(bBuckets, req.GetBucket()) {
			return s3err(codes.NotFound, "NoSuchBucket")
		}
		keys, prefixes, truncated := t.listObjects(req.GetBucket(), req.GetPrefix(), req.GetDelimiter(), req.GetStartAfter(), max)
		for _, k := range keys {
			resp.Objects = append(resp.Objects, objectPB(t, req.GetBucket(), k, t.object(req.GetBucket(), k), false))
		}
		resp.CommonPrefixes = prefixes
		resp.Truncated = truncated
		if truncated {
			last := ""
			if len(keys) > 0 {
				last = keys[len(keys)-1]
			}
			if len(prefixes) > 0 && prefixes[len(prefixes)-1] > last {
				// Skip past everything under the last prefix.
				last = prefixes[len(prefixes)-1] + "\U0010FFFF"
			}
			resp.NextStartAfter = last
		}
		return nil
	})
	return resp, err
}

// ---- multipart ----

func (s *Server) CreateUpload(_ context.Context, req *vaultv1.CreateUploadRequest) (*vaultv1.CreateUploadResponse, error) {
	id := make([]byte, 16)
	rand.Read(id)
	uid := hex.EncodeToString(id)
	_, err := s.propose(&command{Op: "create_upload", UploadID: uid, Name: req.GetBucket(), Key: req.GetKey(), CType: req.GetContentType(), UserMeta: req.GetUserMeta()})
	return &vaultv1.CreateUploadResponse{UploadId: uid}, err
}

func (s *Server) CommitPart(_ context.Context, req *vaultv1.CommitPartRequest) (*vaultv1.CommitPartResponse, error) {
	chunks, err := commitChunks(req.GetChunks())
	if err != nil {
		return nil, err
	}
	res, err := s.propose(&command{Op: "commit_part", UploadID: req.GetUploadId(), PartNum: req.GetPartNumber(), ETag: strings.Trim(req.GetEtag(), `"`), Size: req.GetSize(), Chunks: chunks})
	return &vaultv1.CommitPartResponse{RetrySha256: res.retry}, err
}

func (s *Server) CompleteUpload(_ context.Context, req *vaultv1.CompleteUploadRequest) (*vaultv1.CompleteUploadResponse, error) {
	var parts []completedPart
	for _, p := range req.GetParts() {
		parts = append(parts, completedPart{Num: p.GetPartNumber(), ETag: p.GetEtag()})
	}
	var bucket, key string
	s.fsm.view(func(t *tx) error {
		if u := t.upload(req.GetUploadId()); u != nil {
			bucket, key = u.Bucket, u.Key
		}
		return nil
	})
	res, err := s.propose(&command{Op: "complete_upload", UploadID: req.GetUploadId(), Parts: parts})
	if err != nil {
		return nil, err
	}
	return &vaultv1.CompleteUploadResponse{Object: objectPB(nil, bucket, key, res.object, false)}, nil
}

func (s *Server) AbortUpload(_ context.Context, req *vaultv1.AbortUploadRequest) (*vaultv1.AbortUploadResponse, error) {
	_, err := s.propose(&command{Op: "abort_upload", UploadID: req.GetUploadId()})
	return &vaultv1.AbortUploadResponse{}, err
}

// ---- status ----

func (s *Server) ClusterStatus(_ context.Context, req *vaultv1.ClusterStatusRequest) (*vaultv1.ClusterStatusResponse, error) {
	if err := s.leaderOnly(); err != nil {
		return nil, err
	}
	nodes := s.nodes()
	resp := &vaultv1.ClusterStatusResponse{Nodes: nodes}
	for _, n := range nodes {
		if n.Alive {
			resp.RawBytes += n.UsedBytes
		}
	}
	max := int(req.GetMaxChunks())
	// Totals are running counters; the heatmap reads only its first page.
	s.fsm.view(func(t *tx) error {
		resp.Objects, resp.LogicalBytes, resp.TotalChunks = t.counter(cObjects), t.counter(cLogical), t.counter(cChunks)
		c := t.Bucket(bChunks).Cursor()
		for k, v := c.First(); k != nil && len(resp.Chunks) < max; k, v = c.Next() {
			var ch ChunkInfo
			must(json.Unmarshal(v, &ch))
			if ch.Refs > 0 {
				resp.Chunks = append(resp.Chunks, &vaultv1.ChunkStatus{Sha256: string(k), Want: ch.Want, Holders: ch.Holders})
			}
		}
		return nil
	})
	s.mu.Lock()
	// Kept current by the reconcile loop as it evaluates chunks.
	resp.UnderReplicated, resp.Lost = int64(len(s.under)), int64(len(s.lost))
	resp.Repairs, resp.Rebalances, resp.LastMttrMs = s.repairs, s.rebalances, s.lastMTTR.Milliseconds()
	if !s.degraded.IsZero() {
		resp.DegradedSince = s.degraded.UnixNano()
	}
	s.mu.Unlock()
	return resp, nil
}

func (s *Server) RaftStatus(context.Context, *vaultv1.RaftStatusRequest) (*vaultv1.RaftStatusResponse, error) {
	_, leaderID := s.raft.LeaderWithID()
	var term uint64
	fmt.Sscan(s.raft.Stats()["term"], &term)
	return &vaultv1.RaftStatusResponse{
		Id: s.cfg.ID, State: s.raft.State().String(), LeaderId: string(leaderID),
		Term: term, LastIndex: s.raft.LastIndex(),
	}, nil
}

func (s *Server) StepDown(context.Context, *vaultv1.StepDownRequest) (*vaultv1.StepDownResponse, error) {
	if err := s.leaderOnly(); err != nil {
		return nil, err
	}
	if err := s.raft.LeadershipTransfer().Error(); err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return &vaultv1.StepDownResponse{}, nil
}

// ---- users ----

func (s *Server) CreateUser(_ context.Context, req *vaultv1.CreateUserRequest) (*vaultv1.CreateUserResponse, error) {
	u := req.GetUser()
	if len(u.GetAccessKey()) < 8 || len(u.GetSecretKey()) < 16 || u.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "InvalidArgument")
	}
	_, err := s.propose(&command{Op: "create_user", User: &User{AccessKey: u.GetAccessKey(), Secret: u.GetSecretKey(), Name: u.GetName(), Admin: u.GetAdmin()}})
	return &vaultv1.CreateUserResponse{}, err
}

func (s *Server) DeleteUser(_ context.Context, req *vaultv1.DeleteUserRequest) (*vaultv1.DeleteUserResponse, error) {
	_, err := s.propose(&command{Op: "delete_user", Key: req.GetAccessKey()})
	return &vaultv1.DeleteUserResponse{}, err
}

func (s *Server) ListUsers(context.Context, *vaultv1.ListUsersRequest) (*vaultv1.ListUsersResponse, error) {
	resp := &vaultv1.ListUsersResponse{}
	err := s.read(func(t *tx) error {
		return t.Bucket(bUsers).ForEach(func(k, v []byte) error {
			var u User
			must(json.Unmarshal(v, &u))
			resp.Users = append(resp.Users, &vaultv1.User{AccessKey: string(k), SecretKey: u.Secret, Name: u.Name, Admin: u.Admin, CreatedAt: u.CreatedAt})
			return nil
		})
	})
	return resp, err
}
