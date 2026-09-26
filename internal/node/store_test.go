package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func shaOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func newStore(t *testing.T) *store {
	t.Helper()
	s, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStorePutRead(t *testing.T) {
	s := newStore(t)
	data := []byte("hello vault")
	sha := shaOf(data)
	if _, err := s.put(sha, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	got, err := s.read(sha, nil)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read = %q, %v; want %q", got, err, data)
	}
	// Re-putting the same chunk must not double-count it.
	if _, err := s.put(sha, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if s.count.Load() != 1 || s.used.Load() != int64(len(data)) {
		t.Errorf("count=%d used=%d, want 1 and %d", s.count.Load(), s.used.Load(), len(data))
	}
}

func TestStorePutRejectsWrongHash(t *testing.T) {
	s := newStore(t)
	sha := shaOf([]byte("expected"))
	if _, err := s.put(sha, bytes.NewReader([]byte("something else"))); !errors.Is(err, errCorrupt) {
		t.Fatalf("put with mismatched content: %v, want errCorrupt", err)
	}
	if _, err := os.Stat(s.path(sha)); !errors.Is(err, fs.ErrNotExist) {
		t.Error("mismatched chunk was stored")
	}
	if tmps, _ := os.ReadDir(filepath.Join(s.dir, "tmp")); len(tmps) != 0 {
		t.Errorf("temp files left behind: %d", len(tmps))
	}
}

func TestStoreQuarantinesCorruptChunks(t *testing.T) {
	for _, tc := range []struct {
		name  string
		check func(s *store, sha string) error
	}{
		{"read", func(s *store, sha string) error { _, err := s.read(sha, nil); return err }},
		{"verify", func(s *store, sha string) error { _, err := s.verify(sha); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			data := bytes.Repeat([]byte("x"), 1024)
			sha := shaOf(data)
			if _, err := s.put(sha, bytes.NewReader(data)); err != nil {
				t.Fatal(err)
			}
			if err := s.corrupt(sha); err != nil {
				t.Fatal(err)
			}
			if err := tc.check(s, sha); !errors.Is(err, errCorrupt) {
				t.Fatalf("%s of corrupt chunk: %v, want errCorrupt", tc.name, err)
			}
			if _, err := os.Stat(filepath.Join(s.dir, "corrupt", sha)); err != nil {
				t.Errorf("corrupt chunk not quarantined: %v", err)
			}
			if _, err := s.read(sha, nil); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("quarantined chunk still readable: %v", err)
			}
			if s.count.Load() != 0 || s.used.Load() != 0 {
				t.Errorf("counters not released: count=%d used=%d", s.count.Load(), s.used.Load())
			}
		})
	}
}

func TestStoreDeleteIfWrittenBefore(t *testing.T) {
	s := newStore(t)
	data := []byte("chunk")
	sha := shaOf(data)
	written, err := s.put(sha, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	// A GC decision older than the write must not delete the fresh copy.
	if err := s.delete(sha, written.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.path(sha)); err != nil {
		t.Fatalf("chunk rewritten after the cutoff was deleted: %v", err)
	}
	if err := s.delete(sha, written.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.path(sha)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("chunk older than the cutoff survived delete")
	}
	if err := s.delete(sha, time.Time{}); err != nil {
		t.Errorf("deleting a missing chunk: %v, want nil", err)
	}
}

func TestOpenStoreRecountsAndCleansTemp(t *testing.T) {
	s := newStore(t)
	for _, d := range [][]byte{[]byte("a"), []byte("bb")} {
		if _, err := s.put(shaOf(d), bytes.NewReader(d)); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(s.dir, "tmp", "crashed-write"), []byte("partial"), 0o644)

	s2, err := openStore(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.count.Load() != 2 || s2.used.Load() != 3 {
		t.Errorf("reopened count=%d used=%d, want 2 and 3", s2.count.Load(), s2.used.Load())
	}
	if tmps, _ := os.ReadDir(filepath.Join(s.dir, "tmp")); len(tmps) != 0 {
		t.Errorf("leftover temp files not removed: %d", len(tmps))
	}
}

func TestValidSHA(t *testing.T) {
	for sha, want := range map[string]bool{
		shaOf(nil):                            true,
		"abc":                                 false,
		"../../../../etc/passwd":              false,
		string(bytes.Repeat([]byte("z"), 64)): false,
	} {
		if validSHA(sha) != want {
			t.Errorf("validSHA(%q) = %v, want %v", sha, !want, want)
		}
	}
}
