// Package store keeps login attempts and sessions in memory.
//
// Only the SHA-256 hash of each token is kept, so a memory dump does not
// contain a usable token. A restart signs every user out; this is accepted
// for a single-instance proxy.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/catalystcommunity/grafana-linkkeys-login/internal/access"
)

// ErrFull means the store has no space for a new login attempt.
var ErrFull = errors.New("store: too many pending logins")

const tokenBytes = 32

// Attempt is a started login that waits for its callback.
type Attempt struct {
	Pending   []byte
	Next      string
	ExpiresAt time.Time
}

// Session is a signed-in browser.
type Session struct {
	Identity  access.Identity
	Role      string
	ExpiresAt time.Time
}

// Store holds attempts and sessions. It is safe for concurrent use.
type Store struct {
	mu          sync.Mutex
	attempts    map[[32]byte]Attempt
	sessions    map[[32]byte]Session
	maxAttempts int
	now         func() time.Time
}

// New returns an empty Store. maxAttempts limits pending logins, because an
// unauthenticated client can start a login.
func New(maxAttempts int, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		attempts:    make(map[[32]byte]Attempt),
		sessions:    make(map[[32]byte]Session),
		maxAttempts: maxAttempts,
		now:         now,
	}
}

func newToken() (string, [32]byte, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", [32]byte{}, err
	}
	token := hex.EncodeToString(buf)
	return token, sha256.Sum256([]byte(token)), nil
}

// AddAttempt saves a login attempt and returns its token.
func (s *Store) AddAttempt(pending []byte, next string, ttl time.Duration) (string, error) {
	token, key, err := newToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.attempts) >= s.maxAttempts {
		s.sweepLocked()
		if len(s.attempts) >= s.maxAttempts {
			return "", ErrFull
		}
	}
	s.attempts[key] = Attempt{Pending: pending, Next: next, ExpiresAt: s.now().Add(ttl)}
	return token, nil
}

// TakeAttempt removes and returns the attempt for token. A token works one
// time only, also when the attempt has expired.
func (s *Store) TakeAttempt(token string) (Attempt, bool) {
	if token == "" {
		return Attempt{}, false
	}
	key := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.attempts[key]
	if !ok {
		return Attempt{}, false
	}
	delete(s.attempts, key)
	if !s.now().Before(a.ExpiresAt) {
		return Attempt{}, false
	}
	return a, true
}

// AddSession saves a session and returns its token.
func (s *Store) AddSession(id access.Identity, role string, ttl time.Duration) (string, error) {
	token, key, err := newToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[key] = Session{Identity: id, Role: role, ExpiresAt: s.now().Add(ttl)}
	return token, nil
}

// Session returns the active session for token.
func (s *Store) Session(token string) (Session, bool) {
	if token == "" {
		return Session{}, false
	}
	key := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[key]
	if !ok {
		return Session{}, false
	}
	if !s.now().Before(sess.ExpiresAt) {
		delete(s.sessions, key)
		return Session{}, false
	}
	return sess, true
}

// RevokeSession removes the session for token, if there is one.
func (s *Store) RevokeSession(token string) {
	if token == "" {
		return
	}
	key := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, key)
}

// Sweep removes expired attempts and sessions.
func (s *Store) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
}

func (s *Store) sweepLocked() {
	now := s.now()
	for k, a := range s.attempts {
		if !now.Before(a.ExpiresAt) {
			delete(s.attempts, k)
		}
	}
	for k, sess := range s.sessions {
		if !now.Before(sess.ExpiresAt) {
			delete(s.sessions, k)
		}
	}
}
