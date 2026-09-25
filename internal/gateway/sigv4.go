package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	sigAlgo       = "AWS4-HMAC-SHA256"
	amzDateFormat = "20060102T150405Z"
	emptySHA256   = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	maxSkew       = 15 * time.Minute
)

// sigCtx is what a verified request carries forward: the pieces needed to
// check aws-chunked chunk signatures.
type sigCtx struct {
	seed  string
	key   []byte
	scope string
	date  string
}

// verifySigV4 checks the Authorization header of r against the secret for
// accessKey. It returns the S3 error code on failure.
// ponytail: header auth only; presigned URLs (query auth) not supported.
func verifySigV4(r *http.Request, accessKey, secretKey string, now time.Time) (*sigCtx, string) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, "AccessDenied"
	}
	if !strings.HasPrefix(auth, sigAlgo+" ") {
		return nil, "AuthorizationHeaderMalformed"
	}
	fields := map[string]string{}
	for _, kv := range strings.Split(strings.TrimPrefix(auth, sigAlgo+" "), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			return nil, "AuthorizationHeaderMalformed"
		}
		fields[k] = v
	}
	cred := strings.Split(fields["Credential"], "/")
	signed := fields["SignedHeaders"]
	if len(cred) != 5 || cred[4] != "aws4_request" || signed == "" || fields["Signature"] == "" {
		return nil, "AuthorizationHeaderMalformed"
	}
	if cred[0] != accessKey {
		return nil, "InvalidAccessKeyId"
	}

	amzDate := r.Header.Get("X-Amz-Date")
	t, err := time.Parse(amzDateFormat, amzDate)
	if err != nil {
		return nil, "AccessDenied"
	}
	if d := now.Sub(t); d > maxSkew || d < -maxSkew {
		return nil, "RequestTimeTooSkewed"
	}
	if cred[1] != amzDate[:8] {
		return nil, "SignatureDoesNotMatch"
	}

	payload := r.Header.Get("X-Amz-Content-Sha256")
	if payload == "" {
		payload = emptySHA256
	}
	creq := canonicalRequest(r, strings.Split(signed, ";"), payload)
	scope := strings.Join(cred[1:], "/")
	key := signingKey(secretKey, cred[1], cred[2], cred[3])
	want := hmacHex(key, stringToSign(amzDate, scope, creq))
	if !hmac.Equal([]byte(want), []byte(fields["Signature"])) {
		return nil, "SignatureDoesNotMatch"
	}
	return &sigCtx{seed: want, key: key, scope: scope, date: amzDate}, ""
}

func canonicalRequest(r *http.Request, signed []string, payload string) string {
	var hdrs strings.Builder
	for _, h := range signed {
		var v string
		switch h {
		case "host":
			v = r.Host
		case "content-length":
			v = r.Header.Get("Content-Length")
			if v == "" {
				v = strconv.FormatInt(r.ContentLength, 10)
			}
		default:
			v = strings.Join(r.Header.Values(h), ",")
		}
		hdrs.WriteString(h + ":" + strings.Join(strings.Fields(v), " ") + "\n")
	}
	return strings.Join([]string{
		r.Method,
		awsEscape(r.URL.Path, false),
		canonicalQuery(r.URL.RawQuery),
		hdrs.String(),
		strings.Join(signed, ";"),
		payload,
	}, "\n")
}

func canonicalQuery(raw string) string {
	q, _ := url.ParseQuery(raw)
	var pairs []string
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, awsEscape(k, true)+"="+awsEscape(v, true))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

func stringToSign(amzDate, scope, creq string) string {
	h := sha256.Sum256([]byte(creq))
	return sigAlgo + "\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(h[:])
}

func signingKey(secret, date, region, service string) []byte {
	k := hmacSum([]byte("AWS4"+secret), date)
	k = hmacSum(k, region)
	k = hmacSum(k, service)
	return hmacSum(k, "aws4_request")
}

func hmacSum(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func hmacHex(key []byte, data string) string { return hex.EncodeToString(hmacSum(key, data)) }

// awsEscape is SigV4's URI encoding: everything except A-Z a-z 0-9 - _ . ~
// is %XX-encoded; '/' is kept unless encodeSlash.
func awsEscape(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9',
			c == '-', c == '_', c == '.', c == '~', c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

// chunkSignature is the signature of one aws-chunked chunk given the previous one.
func (s *sigCtx) chunkSignature(prev string, data []byte) string {
	h := sha256.Sum256(data)
	return hmacHex(s.key, "AWS4-HMAC-SHA256-PAYLOAD\n"+s.date+"\n"+s.scope+"\n"+prev+"\n"+emptySHA256+"\n"+hex.EncodeToString(h[:]))
}

func (s *sigCtx) trailerSignature(prev string, trailer []byte) string {
	h := sha256.Sum256(trailer)
	return hmacHex(s.key, "AWS4-HMAC-SHA256-TRAILER\n"+s.date+"\n"+s.scope+"\n"+prev+"\n"+hex.EncodeToString(h[:]))
}

// signRequest signs r in place (used by tests and the e2e client).
func signRequest(r *http.Request, accessKey, secretKey, region string, now time.Time, payload string) {
	amzDate := now.UTC().Format(amzDateFormat)
	r.Header.Set("X-Amz-Date", amzDate)
	r.Header.Set("X-Amz-Content-Sha256", payload)
	if r.Host == "" {
		r.Host = r.URL.Host
	}
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	for h := range r.Header {
		lh := strings.ToLower(h)
		if strings.HasPrefix(lh, "x-amz-meta-") || lh == "content-type" || lh == "x-amz-copy-source" || lh == "x-vault-replicas" {
			signed = append(signed, lh)
		}
	}
	sort.Strings(signed)
	scope := amzDate[:8] + "/" + region + "/s3/aws4_request"
	creq := canonicalRequest(r, signed, payload)
	sig := hmacHex(signingKey(secretKey, amzDate[:8], region, "s3"), stringToSign(amzDate, scope, creq))
	r.Header.Set("Authorization", sigAlgo+" Credential="+accessKey+"/"+scope+", SignedHeaders="+strings.Join(signed, ";")+", Signature="+sig)
}
