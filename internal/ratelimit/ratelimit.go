// Package ratelimit limits how often a client can start a login.
//
// Each key (a client address, or a fixed key for the global limit) has a
// token bucket. A login start uses one token. Tokens come back at a fixed
// rate, up to the burst size.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is a set of token buckets. It is safe for concurrent use.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
	maxKeys int
	now     func() time.Time
}

// New returns a Limiter that allows burst requests at once and then one
// request per interval for each key. maxKeys limits memory; when it is
// reached, a new key is refused until Sweep removes full buckets.
func New(burst int, interval time.Duration, maxKeys int, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		buckets: make(map[string]*bucket),
		rate:    1 / interval.Seconds(),
		burst:   float64(burst),
		maxKeys: maxKeys,
		now:     now,
	}
}

// Allow uses one token of key. It returns false when the bucket is empty.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			return false
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Sweep removes buckets that are full again. Such a bucket has the same
// effect as no bucket.
func (l *Limiter) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}
