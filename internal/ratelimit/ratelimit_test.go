package ratelimit

import (
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestBurstThenRefill(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	l := New(3, 10*time.Second, 100, c.now)
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("request %d refused inside the burst", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("request allowed after the burst")
	}
	if !l.Allow("b") {
		t.Fatal("other key affected by key a")
	}
	c.t = c.t.Add(10 * time.Second)
	if !l.Allow("a") {
		t.Fatal("token did not come back after one interval")
	}
	if l.Allow("a") {
		t.Fatal("more than one token came back")
	}
}

func TestMaxKeysAndSweep(t *testing.T) {
	c := &clock{t: time.Unix(1000, 0)}
	l := New(1, time.Second, 2, c.now)
	l.Allow("a")
	l.Allow("b")
	if l.Allow("c") {
		t.Fatal("new key allowed when the limiter is full")
	}
	c.t = c.t.Add(2 * time.Second)
	l.Sweep()
	if !l.Allow("c") {
		t.Fatal("new key refused after sweep")
	}
}
