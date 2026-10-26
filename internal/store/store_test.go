package store

import (
	"errors"
	"testing"
	"time"

	"github.com/catalystcommunity/grafana-linkkeys-login/internal/access"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestAttemptIsSingleUse(t *testing.T) {
	s := New(10, nil)
	token, err := s.AddAttempt([]byte("p"), "/next", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := s.TakeAttempt(token)
	if !ok || string(a.Pending) != "p" || a.Next != "/next" {
		t.Fatalf("first take = %+v, %v", a, ok)
	}
	if _, ok := s.TakeAttempt(token); ok {
		t.Fatal("second take succeeded")
	}
}

func TestExpiredAttemptIsRefusedAndRemoved(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	s := New(10, c.now)
	token, _ := s.AddAttempt([]byte("p"), "/", time.Minute)
	c.t = c.t.Add(time.Minute)
	if _, ok := s.TakeAttempt(token); ok {
		t.Fatal("expired attempt accepted")
	}
	if len(s.attempts) != 0 {
		t.Fatal("expired attempt kept")
	}
}

func TestUnknownTokens(t *testing.T) {
	s := New(10, nil)
	if _, ok := s.TakeAttempt(""); ok {
		t.Fatal("empty attempt token accepted")
	}
	if _, ok := s.TakeAttempt("nope"); ok {
		t.Fatal("unknown attempt token accepted")
	}
	if _, ok := s.Session(""); ok {
		t.Fatal("empty session token accepted")
	}
	if _, ok := s.Session("nope"); ok {
		t.Fatal("unknown session token accepted")
	}
}

func TestAttemptLimit(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	s := New(2, c.now)
	for i := 0; i < 2; i++ {
		if _, err := s.AddAttempt(nil, "/", time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AddAttempt(nil, "/", time.Minute); !errors.Is(err, ErrFull) {
		t.Fatalf("err = %v, want ErrFull", err)
	}
	// Expired attempts free space.
	c.t = c.t.Add(2 * time.Minute)
	if _, err := s.AddAttempt(nil, "/", time.Minute); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	s := New(10, c.now)
	id := access.Identity{UserID: "u", Domain: "example.com"}
	token, err := s.AddSession(id, "Viewer", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s.Session(token)
	if !ok || got.Identity != id || got.Role != "Viewer" {
		t.Fatalf("session = %+v, %v", got, ok)
	}
	c.t = c.t.Add(time.Hour)
	if _, ok := s.Session(token); ok {
		t.Fatal("expired session accepted")
	}

	token, _ = s.AddSession(id, "Viewer", time.Hour)
	s.RevokeSession(token)
	if _, ok := s.Session(token); ok {
		t.Fatal("revoked session accepted")
	}
}

func TestTokensAreStoredHashed(t *testing.T) {
	s := New(10, nil)
	token, _ := s.AddSession(access.Identity{UserID: "u", Domain: "d"}, "Viewer", time.Hour)
	for k := range s.sessions {
		if string(k[:]) == token {
			t.Fatal("raw token used as key")
		}
	}
	if len(token) != 64 {
		t.Fatalf("token length = %d, want 64 hex chars", len(token))
	}
}

func TestSweep(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	s := New(10, c.now)
	s.AddAttempt(nil, "/", time.Minute)
	s.AddSession(access.Identity{}, "Viewer", time.Minute)
	c.t = c.t.Add(time.Minute)
	s.Sweep()
	if len(s.attempts) != 0 || len(s.sessions) != 0 {
		t.Fatalf("sweep left %d attempts, %d sessions", len(s.attempts), len(s.sessions))
	}
}
