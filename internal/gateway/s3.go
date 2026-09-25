package gateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	vaultv1 "vault/gen/vault/v1"
)

const s3NS = "http://s3.amazonaws.com/doc/2006-03-01/"

var errStatus = map[string]int{
	"AccessDenied": 403, "InvalidAccessKeyId": 403, "SignatureDoesNotMatch": 403, "RequestTimeTooSkewed": 403,
	"NoSuchBucket": 404, "NoSuchKey": 404, "NoSuchUpload": 404,
	"BucketAlreadyOwnedByYou": 409, "BucketNotEmpty": 409,
	"InvalidRange": 416, "MethodNotAllowed": 405, "NotImplemented": 501,
	"InternalError": 500, "ServiceUnavailable": 503, "SlowDown": 503,
}

// metaCodes are the S3 error codes the meta service returns as status messages.
var metaCodes = map[string]bool{
	"NoSuchBucket": true, "NoSuchKey": true, "NoSuchUpload": true, "BucketAlreadyOwnedByYou": true,
	"BucketNotEmpty": true, "InvalidPart": true, "InvalidPartOrder": true, "MalformedXML": true, "InvalidArgument": true,
}

type errorXML struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource"`
	RequestID string   `xml:"RequestId"`
}

// writeErr maps any error (S3, gRPC or other) to an S3 error response.
func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	code, msg := "InternalError", err.Error()
	var se *s3Error
	if errors.As(err, &se) {
		code, msg = se.code, se.msg
	} else if st, ok := status.FromError(err); ok {
		switch {
		case metaCodes[st.Message()]:
			code, msg = st.Message(), st.Message()
		case st.Code() == codes.Unavailable, st.Code() == codes.FailedPrecondition, st.Code() == codes.DeadlineExceeded:
			code, msg = "ServiceUnavailable", st.Message()
		}
	}
	httpStatus, ok := errStatus[code]
	if !ok {
		httpStatus = 400
	}
	if httpStatus >= 500 {
		log.Printf("gateway: %s %s: %v", r.Method, r.URL.Path, err)
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(httpStatus)
	if r.Method != http.MethodHead {
		writeXMLBody(w, errorXML{Code: code, Message: msg, Resource: r.URL.Path, RequestID: w.Header().Get("X-Amz-Request-Id")})
	}
}

func writeXMLBody(w io.Writer, v any) {
	io.WriteString(w, xml.Header)
	xml.NewEncoder(w).Encode(v)
}

func writeXML(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/xml")
	writeXMLBody(w, v)
}

func (g *Gateway) serveS3(w http.ResponseWriter, r *http.Request) {
	id := make([]byte, 8)
	rand.Read(id)
	w.Header().Set("X-Amz-Request-Id", strings.ToUpper(hex.EncodeToString(id)))
	w.Header().Set("Server", "Vault")

	sig, code := verifySigV4(r, g.cfg.AccessKey, g.cfg.SecretKey, time.Now())
	if code != "" {
		writeErr(w, r, errS3(code, "request signature rejected"))
		return
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	q := r.URL.Query()
	ctx := r.Context()

	var err error
	switch {
	case bucket == "":
		if r.Method != http.MethodGet {
			err = errS3("MethodNotAllowed", "")
			break
		}
		err = g.listBuckets(ctx, w)
	case key == "":
		err = g.bucketOp(ctx, w, r, bucket, q, sig)
	default:
		err = g.objectOp(ctx, w, r, bucket, key, q, sig)
	}
	if err != nil {
		writeErr(w, r, err)
	}
}

// Sub-resources we don't implement; answering NotImplemented beats
// silently treating ?acl as a plain GET.
var unsupported = []string{"acl", "tagging", "versioning", "policy", "lifecycle", "cors", "encryption", "versions", "retention", "legal-hold", "object-lock", "website", "logging", "notification", "replication", "accelerate", "requestPayment", "analytics", "metrics", "inventory", "intelligent-tiering", "ownershipControls", "publicAccessBlock", "attributes", "restore", "select", "torrent"}

func checkUnsupported(q url.Values) error {
	for _, s := range unsupported {
		if q.Has(s) {
			return errS3("NotImplemented", "?%s is not supported by Vault", s)
		}
	}
	return nil
}

// ---- buckets ----

var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

type bucketXML struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

type listBucketsXML struct {
	XMLName xml.Name    `xml:"ListAllMyBucketsResult"`
	NS      string      `xml:"xmlns,attr"`
	OwnerID string      `xml:"Owner>ID"`
	Owner   string      `xml:"Owner>DisplayName"`
	Buckets []bucketXML `xml:"Buckets>Bucket"`
}

func isoTime(nanos int64) string { return time.Unix(0, nanos).UTC().Format("2006-01-02T15:04:05.000Z") }

func (g *Gateway) listBuckets(ctx context.Context, w http.ResponseWriter) error {
	var resp *vaultv1.ListBucketsResponse
	err := g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) (err error) {
		resp, err = c.ListBuckets(ctx, &vaultv1.ListBucketsRequest{})
		return err
	})
	if err != nil {
		return err
	}
	out := listBucketsXML{NS: s3NS, OwnerID: "vault", Owner: "vault"}
	for _, b := range resp.GetBuckets() {
		out.Buckets = append(out.Buckets, bucketXML{b.GetName(), isoTime(b.GetCreatedAt())})
	}
	writeXML(w, out)
	return nil
}

// parsePolicy reads x-vault-replicas: "N" or "N/W". Default 3/2.
func parsePolicy(h string) (uint32, uint32, error) {
	if h == "" {
		return 3, 2, nil
	}
	ns, ws, hasW := strings.Cut(h, "/")
	n, err := strconv.ParseUint(ns, 10, 32)
	if err != nil || n < 1 || n > 7 {
		return 0, 0, errS3("InvalidArgument", "x-vault-replicas must be N or N/W with 1 ≤ W ≤ N ≤ 7")
	}
	wq := n/2 + 1
	if hasW {
		if wq, err = strconv.ParseUint(ws, 10, 32); err != nil || wq < 1 || wq > n {
			return 0, 0, errS3("InvalidArgument", "x-vault-replicas must be N or N/W with 1 ≤ W ≤ N ≤ 7")
		}
	}
	return uint32(n), uint32(wq), nil
}

func (g *Gateway) createBucket(ctx context.Context, name string, replicas, quorum uint32) error {
	if !bucketName.MatchString(name) || strings.Contains(name, "..") {
		return errS3("InvalidBucketName", "bucket names are 3-63 chars of a-z 0-9 . -")
	}
	return g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) error {
		_, err := c.CreateBucket(ctx, &vaultv1.CreateBucketRequest{Bucket: &vaultv1.Bucket{Name: name, Replicas: replicas, WriteQuorum: quorum}})
		return err
	})
}

func (g *Gateway) deleteBucket(ctx context.Context, name string) error {
	return g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) error {
		_, err := c.DeleteBucket(ctx, &vaultv1.DeleteBucketRequest{Name: name})
		return err
	})
}

func (g *Gateway) bucketOp(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, q url.Values, sig *sigCtx) error {
	if err := checkUnsupported(q); err != nil {
		return err
	}
	switch r.Method {
	case http.MethodPut:
		n, wq, err := parsePolicy(r.Header.Get("X-Vault-Replicas"))
		if err != nil {
			return err
		}
		if err := g.createBucket(ctx, bucket, n, wq); err != nil {
			return err
		}
		w.Header().Set("Location", "/"+bucket)
		return nil
	case http.MethodDelete:
		if err := g.deleteBucket(ctx, bucket); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	case http.MethodHead:
		_, err := g.getBucket(ctx, bucket)
		return err
	case http.MethodPost:
		if q.Has("delete") {
			return g.deleteObjects(ctx, w, r, bucket, sig)
		}
	case http.MethodGet:
		switch {
		case q.Has("location"):
			if _, err := g.getBucket(ctx, bucket); err != nil {
				return err
			}
			writeXML(w, struct {
				XMLName xml.Name `xml:"LocationConstraint"`
				NS      string   `xml:"xmlns,attr"`
			}{NS: s3NS})
			return nil
		case q.Has("uploads"):
			return errS3("NotImplemented", "ListMultipartUploads is not supported")
		default:
			return g.listObjects(ctx, w, bucket, q)
		}
	}
	return errS3("MethodNotAllowed", "")
}

type contentsXML struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

type prefixXML struct {
	Prefix string `xml:"Prefix"`
}

type listObjectsXML struct {
	XMLName               xml.Name      `xml:"ListBucketResult"`
	NS                    string        `xml:"xmlns,attr"`
	Name                  string        `xml:"Name"`
	Prefix                string        `xml:"Prefix"`
	Delimiter             string        `xml:"Delimiter,omitempty"`
	MaxKeys               int           `xml:"MaxKeys"`
	EncodingType          string        `xml:"EncodingType,omitempty"`
	IsTruncated           bool          `xml:"IsTruncated"`
	KeyCount              *int          `xml:"KeyCount,omitempty"`
	ContinuationToken     string        `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string        `xml:"NextContinuationToken,omitempty"`
	StartAfter            string        `xml:"StartAfter,omitempty"`
	Marker                *string       `xml:"Marker,omitempty"`
	NextMarker            string        `xml:"NextMarker,omitempty"`
	Contents              []contentsXML `xml:"Contents"`
	CommonPrefixes        []prefixXML   `xml:"CommonPrefixes"`
}

func (g *Gateway) listObjects(ctx context.Context, w http.ResponseWriter, bucket string, q url.Values) error {
	v2 := q.Get("list-type") == "2"
	maxKeys := 1000
	if s := q.Get("max-keys"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return errS3("InvalidArgument", "bad max-keys")
		}
		maxKeys = min(n, 1000)
	}
	enc := func(s string) string { return s }
	if q.Get("encoding-type") == "url" {
		enc = url.QueryEscape
	}

	after := q.Get("marker")
	if v2 {
		after = q.Get("start-after")
		if tok := q.Get("continuation-token"); tok != "" {
			b, err := base64.RawURLEncoding.DecodeString(tok)
			if err != nil {
				return errS3("InvalidArgument", "bad continuation-token")
			}
			after = string(b)
		}
	}
	out := listObjectsXML{
		NS: s3NS, Name: bucket, Prefix: enc(q.Get("prefix")), Delimiter: enc(q.Get("delimiter")),
		MaxKeys: maxKeys, EncodingType: q.Get("encoding-type"),
	}
	resp := &vaultv1.ListObjectsResponse{}
	if maxKeys > 0 {
		err := g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) (err error) {
			resp, err = c.ListObjects(ctx, &vaultv1.ListObjectsRequest{
				Bucket: bucket, Prefix: q.Get("prefix"), Delimiter: q.Get("delimiter"), StartAfter: after, MaxKeys: uint32(maxKeys),
			})
			return err
		})
		if err != nil {
			return err
		}
	} else if _, err := g.getBucket(ctx, bucket); err != nil {
		return err
	}
	for _, o := range resp.GetObjects() {
		out.Contents = append(out.Contents, contentsXML{enc(o.GetKey()), isoTime(o.GetModifiedAt()), `"` + o.GetEtag() + `"`, o.GetSize(), "STANDARD"})
	}
	for _, p := range resp.GetCommonPrefixes() {
		out.CommonPrefixes = append(out.CommonPrefixes, prefixXML{enc(p)})
	}
	out.IsTruncated = resp.GetTruncated()
	if v2 {
		n := len(out.Contents) + len(out.CommonPrefixes)
		out.KeyCount = &n
		out.ContinuationToken = q.Get("continuation-token")
		out.StartAfter = enc(q.Get("start-after"))
		if out.IsTruncated {
			out.NextContinuationToken = base64.RawURLEncoding.EncodeToString([]byte(resp.GetNextStartAfter()))
		}
	} else {
		m := enc(q.Get("marker"))
		out.Marker = &m
		if out.IsTruncated {
			out.NextMarker = enc(resp.GetNextStartAfter())
		}
	}
	writeXML(w, out)
	return nil
}

type deleteReq struct {
	Quiet   bool `xml:"Quiet"`
	Objects []struct {
		Key string `xml:"Key"`
	} `xml:"Object"`
}

type deleteErrXML struct {
	Key     string `xml:"Key"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

type deleteResultXML struct {
	XMLName xml.Name       `xml:"DeleteResult"`
	NS      string         `xml:"xmlns,attr"`
	Deleted []prefixKey    `xml:"Deleted"`
	Errors  []deleteErrXML `xml:"Error"`
}

type prefixKey struct {
	Key string `xml:"Key"`
}

func (g *Gateway) deleteObjects(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, sig *sigCtx) error {
	body, err := requestBody(r, sig)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(body, 2<<20))
	if err != nil {
		return err
	}
	var req deleteReq
	if err := xml.Unmarshal(raw, &req); err != nil || len(req.Objects) > 1000 {
		return errS3("MalformedXML", "bad Delete request")
	}
	out := deleteResultXML{NS: s3NS}
	for _, o := range req.Objects {
		if err := g.deleteObject(ctx, bucket, o.Key); err != nil {
			out.Errors = append(out.Errors, deleteErrXML{o.Key, "InternalError", err.Error()})
		} else if !req.Quiet {
			out.Deleted = append(out.Deleted, prefixKey{o.Key})
		}
	}
	writeXML(w, out)
	return nil
}

func (g *Gateway) deleteObject(ctx context.Context, bucket, key string) error {
	return g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) error {
		_, err := c.DeleteObject(ctx, &vaultv1.DeleteObjectRequest{Bucket: bucket, Key: key})
		return err
	})
}

// ---- objects ----

func userMeta(h http.Header) map[string]string {
	m := map[string]string{}
	for k, vs := range h {
		if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-amz-meta-") && len(vs) > 0 {
			m[strings.TrimPrefix(lk, "x-amz-meta-")] = vs[0]
		}
	}
	return m
}

func (g *Gateway) objectOp(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, key string, q url.Values, sig *sigCtx) error {
	if len(key) > 1024 {
		return errS3("KeyTooLongError", "keys are at most 1024 bytes")
	}
	if err := checkUnsupported(q); err != nil {
		return err
	}
	uploadID := q.Get("uploadId")
	switch r.Method {
	case http.MethodPut:
		if uploadID != "" {
			return g.uploadPart(ctx, w, r, bucket, q, sig)
		}
		if r.Header.Get("X-Amz-Copy-Source") != "" {
			return g.copyObject(ctx, w, r, bucket, key)
		}
		body, err := requestBody(r, sig)
		if err != nil {
			return err
		}
		ct := r.Header.Get("Content-Type")
		if ct == "" {
			ct = "binary/octet-stream"
		}
		o, err := g.putObject(ctx, bucket, key, ct, userMeta(r.Header), body)
		if err != nil {
			return err
		}
		w.Header().Set("ETag", `"`+o.GetEtag()+`"`)
		return nil
	case http.MethodGet, http.MethodHead:
		return g.getObjectHTTP(ctx, w, r, bucket, key)
	case http.MethodDelete:
		if uploadID != "" {
			if err := g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) error {
				_, err := c.AbortUpload(ctx, &vaultv1.AbortUploadRequest{UploadId: uploadID})
				return err
			}); err != nil {
				return err
			}
		} else if err := g.deleteObject(ctx, bucket, key); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	case http.MethodPost:
		if q.Has("uploads") {
			return g.createUpload(ctx, w, r, bucket, key)
		}
		if uploadID != "" {
			return g.completeUpload(ctx, w, r, bucket, key, uploadID, sig)
		}
	}
	return errS3("MethodNotAllowed", "")
}

// parseRange handles a single "bytes=a-b", "bytes=a-" or "bytes=-n".
func parseRange(h string, size int64) (start, end int64, ok bool, err error) {
	if h == "" {
		return 0, size - 1, false, nil
	}
	spec, found := strings.CutPrefix(h, "bytes=")
	if !found || strings.Contains(spec, ",") {
		return 0, size - 1, false, nil // unsupported forms: serve the whole object, as S3 does
	}
	a, b, _ := strings.Cut(spec, "-")
	switch {
	case a == "":
		n, perr := strconv.ParseInt(b, 10, 64)
		if perr != nil || n <= 0 {
			return 0, 0, false, errS3("InvalidRange", "bad range")
		}
		start, end = max(size-n, 0), size-1
	default:
		s, perr := strconv.ParseInt(a, 10, 64)
		if perr != nil {
			return 0, 0, false, errS3("InvalidRange", "bad range")
		}
		start, end = s, size-1
		if b != "" {
			e, perr := strconv.ParseInt(b, 10, 64)
			if perr != nil || e < s {
				return 0, 0, false, errS3("InvalidRange", "bad range")
			}
			end = min(e, size-1)
		}
	}
	if start >= size {
		return 0, 0, false, errS3("InvalidRange", "range starts past the end of the object")
	}
	return start, end, true, nil
}

func (g *Gateway) getObjectHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, key string) error {
	o, err := g.getObject(ctx, bucket, key)
	if err != nil {
		return err
	}
	start, end, partial, err := parseRange(r.Header.Get("Range"), o.GetSize())
	if err != nil {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", o.GetSize()))
		return err
	}
	hd := w.Header()
	hd.Set("ETag", `"`+o.GetEtag()+`"`)
	hd.Set("Last-Modified", time.Unix(0, o.GetModifiedAt()).UTC().Format(http.TimeFormat))
	hd.Set("Content-Type", o.GetContentType())
	hd.Set("Accept-Ranges", "bytes")
	for k, v := range o.GetUserMeta() {
		hd.Set("X-Amz-Meta-"+k, v)
	}
	n := max(end-start+1, 0)
	hd.Set("Content-Length", strconv.FormatInt(n, 10))
	if partial {
		hd.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, o.GetSize()))
		w.WriteHeader(http.StatusPartialContent)
	}
	if r.Method == http.MethodHead || n == 0 {
		return nil
	}
	if err := g.readRange(ctx, o, start, end, w); err != nil {
		// Headers are already sent: abort the connection so the client sees a truncated body.
		log.Printf("gateway: GET %s/%s failed mid-stream: %v", bucket, key, err)
		panic(http.ErrAbortHandler)
	}
	return nil
}

func (g *Gateway) copyObject(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, key string) error {
	sb, sk, err := parseCopySource(r.Header.Get("X-Amz-Copy-Source"))
	if err != nil {
		return err
	}
	replace := strings.EqualFold(r.Header.Get("X-Amz-Metadata-Directive"), "REPLACE")
	var o *vaultv1.Object
	err = g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) error {
		resp, err := c.CopyObject(ctx, &vaultv1.CopyObjectRequest{
			SrcBucket: sb, SrcKey: sk, DstBucket: bucket, DstKey: key,
			ReplaceMeta: replace, ContentType: r.Header.Get("Content-Type"), UserMeta: userMeta(r.Header),
		})
		o = resp.GetObject()
		return err
	})
	if err != nil {
		return err
	}
	writeXML(w, copyResultXML{XMLName: xml.Name{Local: "CopyObjectResult"}, ETag: `"` + o.GetEtag() + `"`, LastModified: isoTime(o.GetModifiedAt())})
	return nil
}

type copyResultXML struct {
	XMLName      xml.Name
	ETag         string `xml:"ETag"`
	LastModified string `xml:"LastModified"`
}

func parseCopySource(h string) (string, string, error) {
	h, _, _ = strings.Cut(h, "?versionId=")
	src, err := url.PathUnescape(strings.TrimPrefix(h, "/"))
	if err != nil {
		return "", "", errS3("InvalidArgument", "bad x-amz-copy-source")
	}
	b, k, ok := strings.Cut(src, "/")
	if !ok || b == "" || k == "" {
		return "", "", errS3("InvalidArgument", "bad x-amz-copy-source")
	}
	return b, k, nil
}

// ---- multipart ----

func (g *Gateway) createUpload(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, key string) error {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		ct = "binary/octet-stream"
	}
	var id string
	err := g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) error {
		resp, err := c.CreateUpload(ctx, &vaultv1.CreateUploadRequest{Bucket: bucket, Key: key, ContentType: ct, UserMeta: userMeta(r.Header)})
		id = resp.GetUploadId()
		return err
	})
	if err != nil {
		return err
	}
	writeXML(w, struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		NS       string   `xml:"xmlns,attr"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		UploadID string   `xml:"UploadId"`
	}{NS: s3NS, Bucket: bucket, Key: key, UploadID: id})
	return nil
}

func (g *Gateway) uploadPart(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string, q url.Values, sig *sigCtx) error {
	num, err := strconv.ParseUint(q.Get("partNumber"), 10, 32)
	if err != nil || num < 1 || num > 10000 {
		return errS3("InvalidArgument", "partNumber must be 1-10000")
	}
	b, err := g.getBucket(ctx, bucket)
	if err != nil {
		return err
	}

	var body io.Reader
	copySrc := r.Header.Get("X-Amz-Copy-Source")
	if copySrc != "" {
		// UploadPartCopy: stream the source range through the normal write path.
		// Identical 4 MB-aligned content dedups to the same chunks.
		sb, sk, err := parseCopySource(copySrc)
		if err != nil {
			return err
		}
		src, err := g.getObject(ctx, sb, sk)
		if err != nil {
			return err
		}
		start, end, _, err := parseRange(r.Header.Get("X-Amz-Copy-Source-Range"), src.GetSize())
		if err != nil {
			return err
		}
		pr, pw := io.Pipe()
		go func() { pw.CloseWithError(g.readRange(ctx, src, start, end, pw)) }()
		defer pr.Close()
		body = pr
	} else if body, err = requestBody(r, sig); err != nil {
		return err
	}

	wr, err := g.writeObject(ctx, b, body)
	if err != nil {
		return err
	}
	err = g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) error {
		resp, err := c.CommitPart(ctx, &vaultv1.CommitPartRequest{UploadId: q.Get("uploadId"), PartNumber: uint32(num), Etag: wr.md5, Size: wr.size, Chunks: wr.chunks})
		if err == nil && len(resp.GetRetrySha256()) > 0 {
			return errS3("SlowDown", "chunk collected during upload, please retry")
		}
		return err
	})
	if err != nil {
		return err
	}
	if copySrc != "" {
		writeXML(w, copyResultXML{XMLName: xml.Name{Local: "CopyPartResult"}, ETag: `"` + wr.md5 + `"`, LastModified: isoTime(time.Now().UnixNano())})
		return nil
	}
	w.Header().Set("ETag", `"`+wr.md5+`"`)
	return nil
}

type completeReq struct {
	Parts []struct {
		PartNumber uint32 `xml:"PartNumber"`
		ETag       string `xml:"ETag"`
	} `xml:"Part"`
}

func (g *Gateway) completeUpload(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, sig *sigCtx) error {
	body, err := requestBody(r, sig)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(body, 2<<20))
	if err != nil {
		return err
	}
	var req completeReq
	if err := xml.Unmarshal(raw, &req); err != nil {
		return errS3("MalformedXML", "bad CompleteMultipartUpload request")
	}
	var parts []*vaultv1.CompletedPart
	for _, p := range req.Parts {
		parts = append(parts, &vaultv1.CompletedPart{PartNumber: p.PartNumber, Etag: p.ETag})
	}
	var o *vaultv1.Object
	err = g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) error {
		resp, err := c.CompleteUpload(ctx, &vaultv1.CompleteUploadRequest{UploadId: uploadID, Parts: parts})
		o = resp.GetObject()
		return err
	})
	if err != nil {
		return err
	}
	writeXML(w, struct {
		XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
		NS       string   `xml:"xmlns,attr"`
		Location string   `xml:"Location"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		ETag     string   `xml:"ETag"`
	}{NS: s3NS, Location: "/" + bucket + "/" + key, Bucket: bucket, Key: key, ETag: `"` + o.GetEtag() + `"`})
	return nil
}
