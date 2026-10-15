// Package session persists short-lived challenge sessions in Redis.
//
// Each challenge issued by the server carries a cryptographically random
// session ID. The server stores { issued_at, recipe } in Redis under
// the key `bd:sess:<id>` with a 90-second TTL, giving the browser a
// small window to run the VM and submit its result. The record is
// deleted on the first verification attempt, so every challenge is
// single-use.
//
// The persisted recipe (TokenRecipe) is what allows the verify
// endpoint to recompute the per-session token: each session uses a
// fresh permutation of the 17 sensor segments before hashing, so the
// concatenation order is no longer a global constant.
package session

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/redis/go-redis/v9"
)

// NumTokenSegments is the number of logical sensor segments the VM
// concatenates before hashing. The segment-to-register mapping is
// stable and shared between the JS template and the server-side
// recompute helper:
//
//	0  userAgent           9  sessionID
//	1  screenW + screenH  10  webdriver flag
//	2  timezone           11  automation globals signature
//	3  canvasFingerprint  12  plugins length
//	4  webglVendor        13  navigator.languages
//	5  mouseX + mouseY    14  notification permission coherence
//	6  timingFingerprint  15  timezone offset minutes
//	7  platform           16  device pixel ratio
//	8  colorDepth
const NumTokenSegments = 17

// TokenRecipe describes how the VM assembles the token hash input for
// a given session. Permutation is a permutation of the segment indices
// 0..NumTokenSegments-1 which dictates the concatenation order at the
// VM's hash_stage. The recipe is generated server-side, embedded in
// the polymorphic bytecode shipped to the browser, and persisted in
// Redis so the server can recompute the expected token.
type TokenRecipe struct {
	Permutation [NumTokenSegments]byte `json:"perm"`
}

// NewTokenRecipe returns a uniform random permutation of the segment
// indices 0..NumTokenSegments-1 using crypto/rand (Fisher–Yates,
// Durstenfeld in-place variant).
//
// At each step i (n-1 down to 1), j is drawn uniformly from [0, i] and
// elements at positions i and j are swapped. The bound argument to
// rand.Int is allocated once and mutated in place to avoid an
// allocation per iteration.
func NewTokenRecipe() (TokenRecipe, error) {
	var r TokenRecipe
	for i := 0; i < NumTokenSegments; i++ {
		r.Permutation[i] = byte(i)
	}
	bound := new(big.Int)
	for i := NumTokenSegments - 1; i > 0; i-- {
		bound.SetInt64(int64(i + 1))
		n, err := rand.Int(rand.Reader, bound)
		if err != nil {
			return TokenRecipe{}, fmt.Errorf("token recipe rand: %w", err)
		}
		j := int(n.Int64())
		r.Permutation[i], r.Permutation[j] = r.Permutation[j], r.Permutation[i]
	}
	return r, nil
}

// IsValid checks the permutation contains exactly the indices
// 0..NumTokenSegments-1 once each. Returns false on a zero-value or
// otherwise malformed recipe (e.g. legacy Redis entries from a release
// before recipes were stored).
func (r TokenRecipe) IsValid() bool {
	var seen [NumTokenSegments]bool
	for _, idx := range r.Permutation {
		if int(idx) >= NumTokenSegments || seen[idx] {
			return false
		}
		seen[idx] = true
	}
	return true
}

// sessionTTL is how long a challenge remains valid after issuance.
// 90 seconds leaves comfortable headroom above the ~600ms browser delay
// while still rejecting stale submissions (replay/cached bots).
const sessionTTL = 90 * time.Second

// SessionData is the payload stored in Redis.
// Additional fields (e.g. issuer IP, UA hash) can be added without
// breaking wire compatibility because we marshal with encoding/json.
type SessionData struct {
	IssuedAt    int64       `json:"issued_at"` // unix milliseconds
	TokenRecipe TokenRecipe `json:"recipe"`    // per-session token assembly order
}

// Store is the session persistence layer.
type Store struct {
	client *redis.Client
	ttl    time.Duration
}

// NewRedisClient returns a configured Redis client. It does not ping;
// connection errors surface on first use.
func NewRedisClient(addr string) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr: addr,
		DB:   0,
	})
}

// NewStore wraps a Redis client with session-specific helpers.
func NewStore(client *redis.Client) *Store {
	return &Store{client: client, ttl: sessionTTL}
}

// Ping verifies connectivity. Called once at startup so we fail fast if
// Redis is unreachable (rather than letting the first request 500).
func (s *Store) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

// key returns the fully-qualified Redis key for a session ID.
// The `bd:sess:` prefix lets operators inspect all live challenges via
// `redis-cli KEYS "bd:sess:*"`.
func key(sessionID string) string {
	return fmt.Sprintf("bd:sess:%s", sessionID)
}

// Save writes the session under its TTL. Overwrites any existing key.
func (s *Store) Save(ctx context.Context, sessionID string, sd SessionData) error {
	data, err := json.Marshal(sd)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}
	if err := s.client.Set(ctx, key(sessionID), data, s.ttl).Err(); err != nil {
		return fmt.Errorf("redis set: %w", err)
	}
	return nil
}

// Get returns the session or nil if the key is absent / expired.
// A nil, nil return means "not found" and should be treated as rejection.
func (s *Store) Get(ctx context.Context, sessionID string) (*SessionData, error) {
	val, err := s.client.Get(ctx, key(sessionID)).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("redis get: %w", err)
	}
	var sd SessionData
	if err := json.Unmarshal([]byte(val), &sd); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}
	return &sd, nil
}

// Delete removes the session. Called on the first verification attempt
// to make the challenge single-use.
func (s *Store) Delete(ctx context.Context, sessionID string) error {
	return s.client.Del(ctx, key(sessionID)).Err()
}
