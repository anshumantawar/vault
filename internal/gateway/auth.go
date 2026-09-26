package gateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	vaultv1 "vault/gen/vault/v1"
)

// ---- users: the tenant table lives in the Raft metadata; gateways cache it ----

type users struct {
	byKey     atomic.Pointer[map[string]*vaultv1.User]
	mu        sync.Mutex
	lastFetch time.Time
}

func (g *Gateway) refreshUsers(ctx context.Context) error {
	var resp *vaultv1.ListUsersResponse
	err := g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) (err error) {
		resp, err = c.ListUsers(ctx, &vaultv1.ListUsersRequest{})
		return err
	})
	if err != nil {
		return err
	}
	m := map[string]*vaultv1.User{}
	for _, u := range resp.GetUsers() {
		m[u.GetAccessKey()] = u
	}
	g.users.byKey.Store(&m)
	return nil
}

// user looks up an access key. A miss triggers at most one refresh per
// second, so a user created on another gateway works right away.
func (g *Gateway) user(ctx context.Context, accessKey string) *vaultv1.User {
	if m := g.users.byKey.Load(); m != nil {
		if u := (*m)[accessKey]; u != nil {
			return u
		}
	}
	g.users.mu.Lock()
	stale := time.Since(g.users.lastFetch) > time.Second
	if stale {
		g.users.lastFetch = time.Now()
	}
	g.users.mu.Unlock()
	if stale && g.refreshUsers(ctx) == nil {
		if m := g.users.byKey.Load(); m != nil {
			return (*m)[accessKey]
		}
	}
	return nil
}

// usersLoop creates the bootstrap admin if the cluster has no such user yet,
// then keeps the cache fresh so deleted users lose access within seconds.
func (g *Gateway) usersLoop(ctx context.Context) {
	for ctx.Err() == nil {
		err := g.meta.Call(ctx, func(ctx context.Context, c vaultv1.MetaServiceClient) error {
			_, err := c.CreateUser(ctx, &vaultv1.CreateUserRequest{User: &vaultv1.User{
				AccessKey: g.cfg.AccessKey, SecretKey: g.cfg.SecretKey, Name: "admin", Admin: true,
			}})
			return err
		})
		if err == nil || status.Code(err) == codes.AlreadyExists {
			break
		}
		time.Sleep(time.Second)
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		if err := g.refreshUsers(ctx); err != nil && ctx.Err() == nil {
			log.Printf("gateway: refreshing users: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// secretFor adapts the cache for SigV4 verification.
func (g *Gateway) secretFor(ctx context.Context) func(string) (string, bool) {
	return func(ak string) (string, bool) {
		if u := g.user(ctx, ak); u != nil {
			return u.GetSecretKey(), true
		}
		return "", false
	}
}

// canUse reports whether u may use bucket b: its owner, or any admin.
// Buckets from before tenancy have no owner and are admin-only.
func canUse(u *vaultv1.User, b *vaultv1.Bucket) bool {
	return u.GetAdmin() || (b.GetOwner() != "" && b.GetOwner() == u.GetAccessKey())
}

// authorize fetches bucket and checks u may use it.
func (g *Gateway) authorize(ctx context.Context, u *vaultv1.User, bucket string) (*vaultv1.Bucket, error) {
	b, err := g.getBucket(ctx, bucket)
	if err != nil {
		return nil, err
	}
	if !canUse(u, b) {
		return nil, errS3("AccessDenied", "bucket %s belongs to another user", bucket)
	}
	return b, nil
}

func newKey(prefix string, n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return prefix + string(b)
}

func newSecret() string {
	b := make([]byte, 30)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---- UI sessions: HMAC-signed cookies, keyed per gateway process ----
// ponytail: the signing key is random per gateway, so a restart logs everyone
// out and sessions don't move between gateways; share a key if UIs are load-balanced.

type ctxKey struct{}

func sessionUser(ctx context.Context) *vaultv1.User {
	u, _ := ctx.Value(ctxKey{}).(*vaultv1.User)
	return u
}

// asAdmin wraps a UI route: there is no sign-in, every visitor acts as the bootstrap admin.
// ponytail: the UI is fully open; bind it to localhost (the default) or put auth in front before exposing it.
func (g *Gateway) asAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := g.user(r.Context(), g.cfg.AccessKey)
		if u == nil {
			http.Error(w, "cluster starting, retry in a moment", http.StatusServiceUnavailable)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	}
}
