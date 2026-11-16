package cache

import (
	"context"
	"crypto/sha256"
	"strconv"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func key(s string) Key { return sha256.Sum256([]byte(s)) }

func TestTTL(t *testing.T) {
	clk := newClock()
	c := New(time.Minute, 10, clk.Now)
	c.Add(key("a"))
	if !c.Has(key("a")) {
		t.Fatal("expected hit")
	}
	if c.Has(key("b")) {
		t.Fatal("unexpected hit for unknown key")
	}
	clk.Advance(59 * time.Second)
	if !c.Has(key("a")) {
		t.Fatal("expected hit before expiry")
	}
	clk.Advance(time.Second)
	if c.Has(key("a")) {
		t.Fatal("expected miss at expiry")
	}
	if c.Len() != 0 {
		t.Fatalf("expired entry not removed on lookup, len=%d", c.Len())
	}
}

func TestHitDoesNotExtendLifetime(t *testing.T) {
	clk := newClock()
	c := New(time.Minute, 10, clk.Now)
	c.Add(key("a"))
	clk.Advance(40 * time.Second)
	c.Has(key("a"))
	clk.Advance(21 * time.Second)
	if c.Has(key("a")) {
		t.Fatal("a hit must not refresh the TTL")
	}
}

func TestAddRefreshesExpiry(t *testing.T) {
	clk := newClock()
	c := New(time.Minute, 10, clk.Now)
	c.Add(key("a"))
	clk.Advance(50 * time.Second)
	c.Add(key("a"))
	clk.Advance(50 * time.Second)
	if !c.Has(key("a")) {
		t.Fatal("re-adding should refresh expiry")
	}
	if c.Len() != 1 {
		t.Fatalf("len = %d, want 1", c.Len())
	}
}

func TestLRUBound(t *testing.T) {
	c := New(time.Hour, 3, newClock().Now)
	for _, k := range []string{"a", "b", "c"} {
		c.Add(key(k))
	}
	c.Has(key("a")) // a becomes most recent; b is now least recent
	c.Add(key("d"))
	if c.Len() != 3 {
		t.Fatalf("len = %d, want 3", c.Len())
	}
	if c.Has(key("b")) {
		t.Fatal("b should have been evicted")
	}
	for _, k := range []string{"a", "c", "d"} {
		if !c.Has(key(k)) {
			t.Fatalf("%s should remain", k)
		}
	}
}

func TestDisabled(t *testing.T) {
	for name, c := range map[string]*Cache{
		"ttl zero": New(0, 10, nil),
		"max zero": New(time.Minute, 0, nil),
	} {
		t.Run(name, func(t *testing.T) {
			if c.Enabled() {
				t.Fatal("should be disabled")
			}
			c.Add(key("a"))
			if c.Has(key("a")) || c.Len() != 0 {
				t.Fatal("disabled cache must not store")
			}
		})
	}
}

func TestSweep(t *testing.T) {
	clk := newClock()
	c := New(time.Minute, 100, clk.Now)
	c.Add(key("old1"))
	c.Add(key("old2"))
	clk.Advance(45 * time.Second)
	c.Add(key("new"))
	c.Has(key("old1")) // reorder so expired entries are not all at the back
	clk.Advance(20 * time.Second)
	c.Sweep()
	if c.Len() != 1 || !c.Has(key("new")) {
		t.Fatalf("sweep left len=%d", c.Len())
	}
}

func TestRun(t *testing.T) {
	clk := newClock()
	c := New(time.Millisecond, 10, clk.Now)
	c.Add(key("a"))
	clk.Advance(time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx, 5*time.Millisecond); close(done) }()

	deadline := time.Now().Add(2 * time.Second)
	for c.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if c.Len() != 0 {
		t.Fatal("janitor did not sweep")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
}

func TestConcurrent(t *testing.T) {
	clk := newClock()
	c := New(time.Minute, 50, clk.Now)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 500 {
				k := key(strconv.Itoa((g*31 + i) % 200))
				c.Add(k)
				c.Has(k)
				if i%100 == 0 {
					clk.Advance(time.Second)
					c.Sweep()
				}
				_ = c.Len()
			}
		}()
	}
	wg.Wait()
	if c.Len() > 50 {
		t.Fatalf("bound exceeded: %d", c.Len())
	}
}
