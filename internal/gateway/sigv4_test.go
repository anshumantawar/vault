package gateway

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Examples from the AWS "Signature Version 4 for Amazon S3" documentation.
const (
	exAccess = "AKIAIOSFODNN7EXAMPLE"
	exSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	exDate   = "20130524T000000Z"
)

var exNow = time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

func keys(ak, sk string) func(string) (string, bool) {
	return func(k string) (string, bool) { return sk, k == ak }
}

func auth(signed, sig string) string {
	return "AWS4-HMAC-SHA256 Credential=" + exAccess + "/20130524/us-east-1/s3/aws4_request,SignedHeaders=" + signed + ",Signature=" + sig
}

func TestSigV4AWSExamples(t *testing.T) {
	get := httptest.NewRequest("GET", "http://examplebucket.s3.amazonaws.com/test.txt", nil)
	get.Header.Set("Range", "bytes=0-9")
	get.Header.Set("X-Amz-Content-Sha256", emptySHA256)
	get.Header.Set("X-Amz-Date", exDate)
	get.Header.Set("Authorization", auth("host;range;x-amz-content-sha256;x-amz-date", "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"))

	put := httptest.NewRequest("PUT", "http://examplebucket.s3.amazonaws.com/test$file.text", strings.NewReader("Welcome to Amazon S3."))
	put.Header.Set("Date", "Fri, 24 May 2013 00:00:00 GMT")
	put.Header.Set("X-Amz-Date", exDate)
	put.Header.Set("X-Amz-Storage-Class", "REDUCED_REDUNDANCY")
	put.Header.Set("X-Amz-Content-Sha256", "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072")
	put.Header.Set("Authorization", auth("date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class", "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"))

	for name, r := range map[string]*http.Request{"GET object": get, "PUT object": put} {
		if _, code := verifySigV4(r, keys(exAccess, exSecret), exNow); code != "" {
			t.Errorf("%s: %s", name, code)
		}
	}

	get.Header.Set("Range", "bytes=0-10")
	if _, code := verifySigV4(get, keys(exAccess, exSecret), exNow); code != "SignatureDoesNotMatch" {
		t.Errorf("tampered header: got %q", code)
	}
	if _, code := verifySigV4(put, keys(exAccess, exSecret), exNow.Add(time.Hour)); code != "RequestTimeTooSkewed" {
		t.Errorf("skewed clock: got %q", code)
	}
}

// AWS's STREAMING-AWS4-HMAC-SHA256-PAYLOAD example: 64 KiB + 1 KiB of 'a'.
func TestAWSChunkedSignedExample(t *testing.T) {
	sigs := []string{
		"ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
		"0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
		"b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
	}
	var body bytes.Buffer
	for i, n := range []int{65536, 1024, 0} {
		fmt.Fprintf(&body, "%x;chunk-signature=%s\r\n%s\r\n", n, sigs[i], strings.Repeat("a", n))
	}
	r := httptest.NewRequest("PUT", "http://s3.amazonaws.com/examplebucket/chunkObject.txt", &body)
	for k, v := range map[string]string{
		"X-Amz-Date": exDate, "X-Amz-Storage-Class": "REDUCED_REDUNDANCY",
		"X-Amz-Content-Sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "Content-Encoding": "aws-chunked",
		"Content-Length": "66824", "X-Amz-Decoded-Content-Length": "66560",
	} {
		r.Header.Set(k, v)
	}
	r.Header.Set("Authorization", auth("content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class",
		"4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"))

	sig, code := verifySigV4(r, keys(exAccess, exSecret), exNow)
	if code != "" {
		t.Fatalf("seed signature: %s", code)
	}
	br, err := requestBody(r, sig)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 66560 || strings.Trim(string(got), "a") != "" {
		t.Fatalf("decoded %d bytes", len(got))
	}
}

func TestUnsignedTrailerChecksum(t *testing.T) {
	// crc32("hello") = 0x3610a686 → base64 "NhCmhg=="
	mk := func(crc string) *http.Request {
		body := "5\r\nhello\r\n0\r\nx-amz-checksum-crc32:" + crc + "\r\n\r\n"
		r := httptest.NewRequest("PUT", "http://localhost/b/k", strings.NewReader(body))
		r.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc32")
		r.Header.Set("X-Amz-Decoded-Content-Length", "5")
		signRequest(r, "ak", "sk", "us-east-1", time.Now(), "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
		return r
	}
	for crc, wantErr := range map[string]bool{"NhCmhg==": false, "AAAAAA==": true} {
		r := mk(crc)
		sig, code := verifySigV4(r, keys("ak", "sk"), time.Now())
		if code != "" {
			t.Fatal(code)
		}
		br, err := requestBody(r, sig)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(br)
		if (err != nil) != wantErr || (!wantErr && string(got) != "hello") {
			t.Errorf("crc %s: got %q, err %v", crc, got, err)
		}
	}
}

func TestParseRange(t *testing.T) {
	for _, c := range []struct {
		h          string
		start, end int64
		partial    bool
		err        bool
	}{
		{"", 0, 99, false, false},
		{"bytes=0-9", 0, 9, true, false},
		{"bytes=90-", 90, 99, true, false},
		{"bytes=-10", 90, 99, true, false},
		{"bytes=95-200", 95, 99, true, false},
		{"bytes=100-", 0, 0, false, true},
	} {
		s, e, p, err := parseRange(c.h, 100)
		if s != c.start || e != c.end || p != c.partial || (err != nil) != c.err {
			t.Errorf("%q: got %d-%d partial=%v err=%v", c.h, s, e, p, err)
		}
	}
}
