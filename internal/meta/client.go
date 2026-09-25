package meta

import (
	"context"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	vaultv1 "vault/gen/vault/v1"
	"vault/internal/wire"
)

// Client calls the meta group, finding the leader by trying each member.
type Client struct {
	addrs  []string
	pool   *wire.Pool
	leader atomic.Int32
}

// NewClient calls the meta group over pool; the pool's certificate is the caller's identity.
func NewClient(addrs []string, pool *wire.Pool) *Client {
	return &Client{addrs: addrs, pool: pool}
}

// Call runs fn against the leader, retrying other members for up to ~6s
// (long enough to ride out an election).
func (c *Client) Call(ctx context.Context, fn func(context.Context, vaultv1.MetaServiceClient) error) error {
	var err error
	deadline := time.Now().Add(6 * time.Second)
	for attempt := 0; ; attempt++ {
		i := (int(c.leader.Load()) + attempt) % len(c.addrs)
		err = c.try(ctx, c.addrs[i], fn)
		if err == nil {
			c.leader.Store(int32(i))
			return nil
		}
		switch status.Code(err) {
		case codes.FailedPrecondition, codes.Unavailable, codes.DeadlineExceeded:
		default:
			return err
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return err
		}
		if (attempt+1)%len(c.addrs) == 0 {
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func (c *Client) try(ctx context.Context, addr string, fn func(context.Context, vaultv1.MetaServiceClient) error) error {
	conn, err := c.pool.Get(addr)
	if err != nil {
		return status.Error(codes.Unavailable, err.Error())
	}
	actx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err = fn(actx, vaultv1.NewMetaServiceClient(conn))
	if status.Code(err) == codes.DeadlineExceeded && ctx.Err() == nil {
		return status.Error(codes.Unavailable, err.Error())
	}
	return err
}

// Addrs returns the meta members' gRPC addresses.
func (c *Client) Addrs() []string { return c.addrs }
