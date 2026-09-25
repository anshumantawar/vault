package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vaultv1 "vault/gen/vault/v1"
	"vault/internal/meta"
	"vault/internal/node"
	"vault/internal/wire"
)

const testAK, testSK = "testkey", "testsecret"

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

type cluster struct {
	t        *testing.T
	s3       string
	metaGRPC []string
	metaStop map[string]context.CancelFunc
	nodeStop map[string]context.CancelFunc
	nodeDirs map[string]string
	metaCli  *meta.Client
	pool     *wire.Pool
}

func startCluster(t *testing.T) *cluster {
	root := t.TempDir()
	c := &cluster{t: t, metaStop: map[string]context.CancelFunc{}, nodeStop: map[string]context.CancelFunc{}, nodeDirs: map[string]string{}, pool: wire.NewPool()}
	t.Cleanup(c.pool.Close)

	peers := map[string]string{}
	grpcAddr := map[string]string{}
	for _, id := range []string{"m1", "m2", "m3"} {
		peers[id] = freeAddr(t)
		grpcAddr[id] = freeAddr(t)
		c.metaGRPC = append(c.metaGRPC, grpcAddr[id])
	}
	for _, id := range []string{"m1", "m2", "m3"} {
		ctx, cancel := context.WithCancel(context.Background())
		c.metaStop[id] = cancel
		cfg := meta.Config{ID: id, GRPCAddr: grpcAddr[id], RaftAddr: peers[id], Dir: filepath.Join(root, id), Peers: peers}
		go func() {
			if err := meta.Run(ctx, cfg); err != nil {
				t.Errorf("meta %s: %v", id, err)
			}
		}()
	}
	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("n%d", i)
		ctx, cancel := context.WithCancel(context.Background())
		c.nodeStop[id] = cancel
		c.nodeDirs[id] = filepath.Join(root, id)
		cfg := node.Config{ID: id, Addr: freeAddr(t), Zone: fmt.Sprintf("z%d", (i-1)%3+1), Dir: c.nodeDirs[id], MetaAddrs: c.metaGRPC, ScrubBytesPerSec: 1 << 30}
		go func() {
			if err := node.Run(ctx, cfg); err != nil {
				t.Errorf("node %s: %v", id, err)
			}
		}()
	}
	c.s3 = freeAddr(t)
	gctx, gcancel := context.WithCancel(context.Background())
	go Run(gctx, Config{S3Addr: c.s3, MetaAddrs: c.metaGRPC, AccessKey: testAK, SecretKey: testSK})

	t.Cleanup(func() {
		gcancel()
		for _, stop := range c.nodeStop {
			stop()
		}
		for _, stop := range c.metaStop {
			stop()
		}
		time.Sleep(200 * time.Millisecond)
	})

	c.metaCli = meta.NewClient(c.metaGRPC, c.pool, "test")
	c.waitFor(t, "5 live nodes", func(st *vaultv1.ClusterStatusResponse) bool {
		alive := 0
		for _, n := range st.GetNodes() {
			if n.GetAlive() {
				alive++
			}
		}
		return alive == 5
	})
	time.Sleep(1500 * time.Millisecond) // let the gateway's node cache catch up
	return c
}

func (c *cluster) status() (*vaultv1.ClusterStatusResponse, error) {
	var st *vaultv1.ClusterStatusResponse
	err := c.metaCli.Call(context.Background(), func(ctx context.Context, mc vaultv1.MetaServiceClient) (err error) {
		st, err = mc.ClusterStatus(ctx, &vaultv1.ClusterStatusRequest{MaxChunks: 1000})
		return err
	})
	return st, err
}

func (c *cluster) waitFor(t *testing.T, what string, ok func(*vaultv1.ClusterStatusResponse) bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := c.status(); err == nil && ok(st) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func fullyRedundant(st *vaultv1.ClusterStatusResponse) bool {
	return st.GetTotalChunks() > 0 && st.GetUnderReplicated() == 0 && st.GetLost() == 0 && st.GetDegradedSince() == 0
}

func (c *cluster) do(method, path string, body []byte, hdr map[string]string) (*http.Response, []byte) {
	c.t.Helper()
	req, err := http.NewRequest(method, "http://"+c.s3+path, bytes.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	sum := sha256.Sum256(body)
	signRequest(req, testAK, testSK, "us-east-1", time.Now(), hex.EncodeToString(sum[:]))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (c *cluster) mustDo(want int, method, path string, body []byte, hdr map[string]string) []byte {
	c.t.Helper()
	resp, b := c.do(method, path, body, hdr)
	if resp.StatusCode != want {
		c.t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, b)
	}
	return b
}

func (c *cluster) mustGet(path string, want []byte) {
	c.t.Helper()
	got := c.mustDo(200, "GET", path, nil, nil)
	if !bytes.Equal(got, want) {
		c.t.Fatalf("GET %s: got %d bytes that differ from the %d written", path, len(got), len(want))
	}
}

func random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func TestCluster(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a 9-process cluster")
	}
	c := startCluster(t)
	c.mustDo(200, "PUT", "/photos", nil, nil)
	big := random(20 << 20)
	c.mustDo(200, "PUT", "/photos/big.bin", big, nil)
	c.mustGet("/photos/big.bin", big)
	c.waitFor(t, "initial full redundancy", fullyRedundant)

	t.Run("range read", func(t *testing.T) {
		resp, b := c.do("GET", "/photos/big.bin", nil, map[string]string{"Range": "bytes=4194300-4194310"})
		if resp.StatusCode != 206 || !bytes.Equal(b, big[4194300:4194311]) {
			t.Fatalf("range across a chunk boundary: status %d, %d bytes", resp.StatusCode, len(b))
		}
	})

	t.Run("node crash", func(t *testing.T) {
		c.nodeStop["n2"]()
		c.mustGet("/photos/big.bin", big)
		c.waitFor(t, "n2 declared dead", func(st *vaultv1.ClusterStatusResponse) bool {
			for _, n := range st.GetNodes() {
				if n.GetId() == "n2" {
					return !n.GetAlive()
				}
			}
			return false
		})
		c.waitFor(t, "repair after node crash", fullyRedundant)
	})

	t.Run("corruption", func(t *testing.T) {
		var victim string
		filepath.WalkDir(filepath.Join(c.nodeDirs["n1"], "chunks"), func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && victim == "" {
				victim = p
			}
			return nil
		})
		if victim == "" {
			t.Skip("n1 holds no chunks")
		}
		b, _ := os.ReadFile(victim)
		b[len(b)/2] ^= 0xff
		os.WriteFile(victim, b, 0o644)

		c.mustGet("/photos/big.bin", big) // never serves the bad copy
		sha := filepath.Base(victim)
		c.waitFor(t, "bad copy replaced", func(st *vaultv1.ClusterStatusResponse) bool {
			if !fullyRedundant(st) {
				return false
			}
			// Repair may legitimately put a fresh copy back on n1; it must verify.
			if b, err := os.ReadFile(victim); err == nil {
				sum := sha256.Sum256(b)
				return hex.EncodeToString(sum[:]) == sha
			}
			return true
		})
		if _, err := os.Stat(filepath.Join(c.nodeDirs["n1"], "corrupt", filepath.Base(victim))); err != nil {
			t.Errorf("corrupt chunk was not quarantined: %v", err)
		}
	})

	t.Run("meta leader crash", func(t *testing.T) {
		leader := ""
		for _, a := range c.metaGRPC {
			conn, _ := c.pool.Get(a)
			rs, err := vaultv1.NewMetaServiceClient(conn).RaftStatus(context.Background(), &vaultv1.RaftStatusRequest{})
			if err == nil && rs.GetState() == "Leader" {
				leader = rs.GetId()
			}
		}
		if leader == "" {
			t.Fatal("no leader")
		}
		c.metaStop[leader]()
		small := random(1000)
		c.mustDo(200, "PUT", "/photos/after-failover.bin", small, nil)
		c.mustGet("/photos/after-failover.bin", small)
		c.mustGet("/photos/big.bin", big)
	})

	t.Run("multipart", func(t *testing.T) {
		b := c.mustDo(200, "POST", "/photos/mp.bin?uploads", nil, nil)
		var init struct{ UploadId string }
		xml.Unmarshal(b, &init)
		p1, p2 := random(5<<20), random(1<<20)
		var etags []string
		for i, p := range [][]byte{p1, p2} {
			resp, body := c.do("PUT", fmt.Sprintf("/photos/mp.bin?partNumber=%d&uploadId=%s", i+1, init.UploadId), p, nil)
			if resp.StatusCode != 200 {
				t.Fatalf("part %d: %d %s", i+1, resp.StatusCode, body)
			}
			etags = append(etags, resp.Header.Get("ETag"))
		}
		done := fmt.Sprintf("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part><Part><PartNumber>2</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>", etags[0], etags[1])
		b = c.mustDo(200, "POST", "/photos/mp.bin?uploadId="+init.UploadId, []byte(done), nil)
		if !strings.Contains(string(b), `-2&#34;</ETag>`) && !strings.Contains(string(b), `-2"</ETag>`) {
			t.Errorf("multipart ETag should end in -2: %s", b)
		}
		c.mustGet("/photos/mp.bin", append(p1, p2...))
	})

	t.Run("errors", func(t *testing.T) {
		if resp, _ := c.do("GET", "/photos/nope", nil, nil); resp.StatusCode != 404 {
			t.Errorf("missing key: %d", resp.StatusCode)
		}
		if resp, _ := c.do("DELETE", "/photos", nil, nil); resp.StatusCode != 409 {
			t.Errorf("non-empty bucket delete: %d", resp.StatusCode)
		}
		req, _ := http.NewRequest("GET", "http://"+c.s3+"/photos/big.bin", nil)
		signRequest(req, testAK, "wrong-secret", "us-east-1", time.Now(), emptySHA256)
		if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 403 {
			t.Errorf("bad signature was not rejected")
		}
	})
}
