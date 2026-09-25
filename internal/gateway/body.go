package gateway

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// s3Error is an error that maps straight to an S3 error code.
type s3Error struct{ code, msg string }

func (e *s3Error) Error() string { return e.code + ": " + e.msg }

func errS3(code, format string, a ...any) error { return &s3Error{code, fmt.Sprintf(format, a...)} }

var crc64nvme = crc64.MakeTable(0x9a6c9329ac4bc9b5)

// newChecksum returns the hash for an x-amz-checksum-* header name.
func newChecksum(header string) hash.Hash {
	switch strings.ToLower(header) {
	case "x-amz-checksum-crc32":
		return crc32.NewIEEE()
	case "x-amz-checksum-crc32c":
		return crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case "x-amz-checksum-crc64nvme":
		return crc64.New(crc64nvme)
	case "x-amz-checksum-sha1":
		return sha1.New()
	case "x-amz-checksum-sha256":
		return sha256.New()
	}
	return nil
}

type check struct {
	h    hash.Hash
	want func() []byte // read lazily: trailer values arrive at the end
	code string
}

// verifyReader feeds every byte to its checks and fails at EOF if any
// digest differs, so a bad upload never reaches CommitObject.
type verifyReader struct {
	r      io.Reader
	checks []check
}

func (v *verifyReader) Read(p []byte) (int, error) {
	n, err := v.r.Read(p)
	for _, c := range v.checks {
		c.h.Write(p[:n])
	}
	if err == io.EOF {
		for _, c := range v.checks {
			want := c.want()
			if want == nil {
				continue
			}
			if !bytes.Equal(c.h.Sum(nil), want) {
				return n, errS3(c.code, "body does not match the declared digest")
			}
		}
	}
	return n, err
}

// requestBody returns r's payload, decoded from aws-chunked if needed and
// verified against every digest the client declared.
func requestBody(r *http.Request, sig *sigCtx) (io.Reader, error) {
	var body io.Reader = r.Body
	var checks []check
	payload := r.Header.Get("X-Amz-Content-Sha256")

	switch payload {
	case "UNSIGNED-PAYLOAD", "":
	case "STREAMING-UNSIGNED-PAYLOAD-TRAILER", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER":
		dec := &chunkedReader{
			br:      bufio.NewReaderSize(r.Body, 64<<10),
			signed:  strings.HasPrefix(payload, "STREAMING-AWS4"),
			trailer: strings.HasSuffix(payload, "TRAILER"),
			sig:     sig,
			prev:    sig.seed,
			values:  map[string]string{},
		}
		if dl := r.Header.Get("X-Amz-Decoded-Content-Length"); dl != "" {
			n, err := strconv.ParseInt(dl, 10, 64)
			if err != nil {
				return nil, errS3("InvalidArgument", "bad x-amz-decoded-content-length")
			}
			dec.want = n
		} else {
			dec.want = -1
		}
		body = dec
		if name := r.Header.Get("X-Amz-Trailer"); name != "" {
			h := newChecksum(name)
			if h == nil {
				return nil, errS3("InvalidArgument", "unsupported trailer %s", name)
			}
			checks = append(checks, check{h: h, code: "BadDigest", want: func() []byte {
				return b64(dec.values[strings.ToLower(name)])
			}})
		}
	default:
		want, err := hex.DecodeString(payload)
		if err != nil || len(want) != sha256.Size {
			return nil, errS3("InvalidArgument", "bad x-amz-content-sha256")
		}
		checks = append(checks, check{h: sha256.New(), code: "XAmzContentSHA256Mismatch", want: func() []byte { return want }})
	}

	if m := r.Header.Get("Content-Md5"); m != "" {
		want := b64(m)
		if len(want) != md5.Size {
			return nil, errS3("InvalidDigest", "bad Content-MD5")
		}
		checks = append(checks, check{h: md5.New(), code: "BadDigest", want: func() []byte { return want }})
	}
	for name, vs := range r.Header {
		if h := newChecksum(name); h != nil && len(vs) > 0 {
			want := b64(vs[0])
			checks = append(checks, check{h: h, code: "BadDigest", want: func() []byte { return want }})
		}
	}
	if len(checks) == 0 {
		return body, nil
	}
	return &verifyReader{r: body, checks: checks}, nil
}

func b64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return []byte{} // non-nil: forces a mismatch
	}
	return b
}

// chunkedReader decodes an aws-chunked body:
//
//	hex-size[;chunk-signature=sig]\r\n data \r\n ... 0[;chunk-signature=sig]\r\n [trailers\r\n] \r\n
type chunkedReader struct {
	br      *bufio.Reader
	signed  bool
	trailer bool
	sig     *sigCtx
	prev    string
	values  map[string]string // trailer headers, lower-cased
	want    int64             // decoded length, -1 if unknown
	got     int64
	cur     []byte
	done    bool
}

const maxAWSChunk = 16 << 20

func (c *chunkedReader) Read(p []byte) (int, error) {
	for len(c.cur) == 0 {
		if c.done {
			return 0, io.EOF
		}
		if err := c.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.cur)
	c.cur = c.cur[n:]
	return n, nil
}

func (c *chunkedReader) line() (string, error) {
	l, err := c.br.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "", errS3("IncompleteBody", "aws-chunked body ended early")
		}
		return "", errS3("InvalidRequest", "bad aws-chunked framing")
	}
	return strings.TrimRight(string(l), "\r\n"), nil
}

func (c *chunkedReader) next() error {
	hdr, err := c.line()
	if err != nil {
		return err
	}
	sizeHex, ext, _ := strings.Cut(hdr, ";")
	size, err := strconv.ParseInt(sizeHex, 16, 64)
	if err != nil || size < 0 || size > maxAWSChunk {
		return errS3("InvalidRequest", "bad aws-chunked chunk size")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(c.br, data); err != nil {
		return errS3("IncompleteBody", "aws-chunked chunk truncated")
	}
	if c.signed {
		sig := strings.TrimPrefix(ext, "chunk-signature=")
		want := c.sig.chunkSignature(c.prev, data)
		if sig != want {
			return errS3("SignatureDoesNotMatch", "chunk signature mismatch")
		}
		c.prev = want
	}
	if size > 0 {
		if l, err := c.line(); err != nil || l != "" {
			return errS3("InvalidRequest", "bad aws-chunked framing")
		}
		c.got += size
		c.cur = data
		return nil
	}

	// Final chunk: optional trailers, then an empty line.
	var raw strings.Builder
	for {
		l, err := c.line()
		if err == nil && l == "" {
			break
		}
		if err != nil {
			if c.trailer || raw.Len() > 0 {
				return err
			}
			break // some clients omit the final CRLF when there are no trailers
		}
		k, v, _ := strings.Cut(l, ":")
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "x-amz-trailer-signature" {
			if c.signed && strings.TrimSpace(v) != c.sig.trailerSignature(c.prev, []byte(raw.String())) {
				return errS3("SignatureDoesNotMatch", "trailer signature mismatch")
			}
			continue
		}
		raw.WriteString(k + ":" + strings.TrimSpace(v) + "\n")
		c.values[k] = strings.TrimSpace(v)
	}
	if c.want >= 0 && c.got != c.want {
		return errS3("IncompleteBody", "decoded %d bytes, expected %d", c.got, c.want)
	}
	c.done = true
	return nil
}
