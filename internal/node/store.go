package node

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

var errCorrupt = errors.New("chunk content does not match its sha256")

// store keeps chunks as files named by their SHA-256 under dir/chunks/ab/cd/.
type store struct {
	dir   string
	used  atomic.Int64
	count atomic.Int64
}

func openStore(dir string) (*store, error) {
	s := &store{dir: dir}
	for _, d := range []string{"chunks", "tmp", "corrupt"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return nil, err
		}
	}
	// Leftover temp files are writes that crashed before rename.
	tmps, _ := os.ReadDir(filepath.Join(dir, "tmp"))
	for _, t := range tmps {
		os.Remove(filepath.Join(dir, "tmp", t.Name()))
	}
	err := s.walk(func(_ string, info fs.FileInfo) {
		s.used.Add(info.Size())
		s.count.Add(1)
	})
	return s, err
}

func validSHA(sha string) bool {
	if len(sha) != 64 {
		return false
	}
	_, err := hex.DecodeString(sha)
	return err == nil
}

func (s *store) path(sha string) string {
	return filepath.Join(s.dir, "chunks", sha[:2], sha[2:4], sha)
}

// put writes r to the chunk file for sha, verifying the hash, and returns the
// file's mtime. Re-putting an existing chunk just refreshes its mtime.
func (s *store) put(sha string, r io.Reader) (time.Time, error) {
	tmp, err := os.CreateTemp(filepath.Join(s.dir, "tmp"), sha+"-*")
	if err != nil {
		return time.Time{}, err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	defer tmp.Close()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, maxChunk+1))
	if err != nil {
		return time.Time{}, err
	}
	if n > maxChunk {
		return time.Time{}, fmt.Errorf("chunk larger than %d bytes", maxChunk)
	}
	if hex.EncodeToString(h.Sum(nil)) != sha {
		return time.Time{}, errCorrupt
	}

	// Always replace: the verified copy also heals a silently corrupted file.
	final := s.path(sha)
	_, statErr := os.Stat(final)
	existed := statErr == nil
	if err := tmp.Sync(); err != nil {
		return time.Time{}, err
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o755); err != nil {
		return time.Time{}, err
	}
	if err := os.Rename(tmp.Name(), final); err != nil {
		return time.Time{}, err
	}
	if d, err := os.Open(filepath.Dir(final)); err == nil {
		d.Sync()
		d.Close()
	}
	if !existed {
		s.used.Add(n)
		s.count.Add(1)
	}
	info, err := os.Stat(final)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// get reads and verifies a chunk. A corrupt chunk is quarantined and
// errCorrupt returned, so it's never served twice.
// ponytail: whole chunk in memory (≤16 MB) so nothing unverified is ever sent.
func (s *store) get(sha string) ([]byte, error) {
	b, err := os.ReadFile(s.path(sha))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != sha {
		s.quarantine(sha)
		return nil, errCorrupt
	}
	return b, nil
}

func (s *store) quarantine(sha string) {
	p := s.path(sha)
	info, err := os.Stat(p)
	if err != nil {
		return
	}
	if os.Rename(p, filepath.Join(s.dir, "corrupt", sha)) == nil {
		s.used.Add(-info.Size())
		s.count.Add(-1)
	}
}

// delete removes a chunk unless it was (re)written at or after ifBefore.
func (s *store) delete(sha string, ifBefore time.Time) error {
	p := s.path(sha)
	info, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !ifBefore.IsZero() && !info.ModTime().Before(ifBefore) {
		return nil
	}
	if err := os.Remove(p); err != nil {
		return err
	}
	s.used.Add(-info.Size())
	s.count.Add(-1)
	return nil
}

// corrupt flips one byte of a chunk file on disk (fault injection).
func (s *store) corrupt(sha string) error {
	f, err := os.OpenFile(s.path(sha), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return fmt.Errorf("cannot corrupt empty chunk")
	}
	b := []byte{0}
	off := info.Size() / 2
	if _, err := f.ReadAt(b, off); err != nil {
		return err
	}
	b[0] ^= 0xff
	_, err = f.WriteAt(b, off)
	return err
}

func (s *store) walk(fn func(sha string, info fs.FileInfo)) error {
	return filepath.WalkDir(filepath.Join(s.dir, "chunks"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !validSHA(d.Name()) {
			return nil
		}
		if info, err := d.Info(); err == nil {
			fn(d.Name(), info)
		}
		return nil
	})
}

func matches(sha string, b []byte) bool {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]) == sha
}
