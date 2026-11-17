package ratelimit

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
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

func newLimiter(clk *fakeClock, limit, maxKeys int) *Limiter {
	return New(Config{Limit: limit, Window: 10 * time.Minute, BanTime: 15 * time.Minute, MaxKeys: maxKeys, Now: clk.Now})
}

func TestBanAfterLimit(t *testing.T) {
	clk := newClock()
	var bans []string
	l := New(Config{Limit: 3, Window: time.Minute, BanTime: time.Hour, Now: clk.Now, OnBan: func(k string) { bans = append(bans, k) }})

	for i := 1; i <= 2; i++ {
		if l.Fail("ip:1") || l.Banned("ip:1") {
			t.Fatalf("banned after %d failures", i)
		}
	}
	if !l.Fail("ip:1") {
		t.Fatal("third failure should ban")
	}
	if !l.Banned("ip:1") {
		t.Fatal("Banned should be true")
	}
	if l.Banned("ip:2") {
		t.Fatal("other keys unaffected")
	}
	if len(bans) != 1 || bans[0] != "ip:1" {
		t.Fatalf("OnBan calls = %v", bans)
	}
	// Failing again while banned is not a new ban.
	l.Fail("ip:1")
	if len(bans) != 1 {
		t.Fatalf("OnBan fired again: %v", bans)
	}
}

func TestBanExpiryAndHistoryCleared(t *testing.T) {
	clk := newClock()
	l := New(Config{Limit: 2, Window: time.Minute, BanTime: 10 * time.Minute, Now: clk.Now})
	l.Fail("k")
	l.Fail("k")
	clk.Advance(10*time.Minute - time.Second)
	if !l.Banned("k") {
		t.Fatal("still banned just before expiry")
	}
	clk.Advance(time.Second)
	if l.Banned("k") {
		t.Fatal("ban should have expired")
	}
	if l.Len() != 0 {
		t.Fatalf("expired ban not dropped, len=%d", l.Len())
	}
	// History was cleared at ban time: one failure must not re-ban.
	if l.Fail("k") {
		t.Fatal("history should start fresh after a ban")
	}
}

func TestFailAfterExpiredBanStartsFresh(t *testing.T) {
	clk := newClock()
	l := New(Config{Limit: 2, Window: time.Minute, BanTime: time.Minute, Now: clk.Now})
	l.Fail("k")
	l.Fail("k")
	clk.Advance(2 * time.Minute) // expired, never queried via Banned
	if l.Fail("k") {
		t.Fatal("first failure after expired ban must not ban")
	}
	if !l.Fail("k") {
		t.Fatal("second should ban again")
	}
}

func TestWindowSliding(t *testing.T) {
	clk := newClock()
	l := New(Config{Limit: 3, Window: time.Minute, BanTime: time.Hour, Now: clk.Now})
	l.Fail("k") // t=0
	clk.Advance(40 * time.Second)
	l.Fail("k") // t=40
	clk.Advance(40 * time.Second)
	// t=80: the first failure is out of the window, so this is only the 2nd.
	if l.Fail("k") {
		t.Fatal("old failure should have slid out of the window")
	}
	clk.Advance(5 * time.Second)
	if !l.Fail("k") { // 40, 80, 85
		t.Fatal("three failures within the window should ban")
	}
}

func TestDisabled(t *testing.T) {
	l := New(Config{Limit: 0, Window: time.Minute, BanTime: time.Hour})
	if l.Enabled() {
		t.Fatal("limit 0 disables")
	}
	for range 100 {
		if l.Fail("k") {
			t.Fatal("disabled limiter banned")
		}
	}
	if l.Banned("k") || l.Len() != 0 {
		t.Fatal("disabled limiter kept state")
	}
}

func TestMaxKeysEvictsOldestHistory(t *testing.T) {
	clk := newClock()
	l := newLimiter(clk, 5, 3)
	l.Fail("a")
	l.Fail("b")
	l.Fail("c")
	l.Fail("a") // a is now the most recently touched; b is oldest
	l.Fail("d") // evicts b
	if l.Len() != 3 {
		t.Fatalf("len = %d, want 3", l.Len())
	}
	if _, ok := l.entries["b"]; ok {
		t.Fatal("b should have been evicted")
	}
	for _, k := range []string{"a", "c", "d"} {
		if _, ok := l.entries[k]; !ok {
			t.Fatalf("%s missing", k)
		}
	}
}

func TestBansNeverEvicted(t *testing.T) {
	clk := newClock()
	l := newLimiter(clk, 1, 2) // every failure bans
	l.Fail("x")
	l.Fail("y")
	if l.Len() != 2 {
		t.Fatalf("len = %d", l.Len())
	}
	// All slots are bans: the new failure is dropped, existing bans stay.
	if l.Fail("z") {
		t.Fatal("untracked key cannot be banned when full of bans")
	}
	if !l.Banned("x") || !l.Banned("y") || l.Banned("z") || l.Len() != 2 {
		t.Fatal("bans must survive and bound must hold")
	}
}

func TestBansDoNotBlockHistoryEviction(t *testing.T) {
	clk := newClock()
	l := newLimiter(clk, 2, 2)
	l.Fail("banme")
	l.Fail("banme") // banned
	l.Fail("h1")
	l.Fail("h2") // must evict h1, not the ban
	if !l.Banned("banme") {
		t.Fatal("ban evicted")
	}
	if _, ok := l.entries["h1"]; ok {
		t.Fatal("h1 should have been evicted")
	}
}

func TestCountBannedAndPrune(t *testing.T) {
	clk := newClock()
	l := New(Config{Limit: 1, Window: time.Minute, BanTime: time.Minute, Now: clk.Now})
	l.Fail("ip:1")
	l.Fail("ip:2")
	l.Fail("user:a")
	if got := l.CountBanned("ip:"); got != 2 {
		t.Fatalf("ip bans = %d", got)
	}
	if got := l.CountBanned("user:"); got != 1 {
		t.Fatalf("user bans = %d", got)
	}
	if got := l.CountBanned(""); got != 3 {
		t.Fatalf("all bans = %d", got)
	}
	clk.Advance(2 * time.Minute)
	if got := l.CountBanned(""); got != 0 {
		t.Fatalf("expired bans counted: %d", got)
	}
	l.Prune()
	if l.Len() != 0 {
		t.Fatalf("prune left %d entries", l.Len())
	}
}

func TestPruneDropsStaleHistoriesKeepsFresh(t *testing.T) {
	clk := newClock()
	l := New(Config{Limit: 5, Window: time.Minute, BanTime: time.Hour, Now: clk.Now})
	l.Fail("stale")
	clk.Advance(90 * time.Second)
	l.Fail("fresh")
	l.Prune()
	if _, ok := l.entries["stale"]; ok {
		t.Fatal("stale history should be pruned")
	}
	if _, ok := l.entries["fresh"]; !ok {
		t.Fatal("fresh history should be kept")
	}
	if l.history.Len() != 1 {
		t.Fatalf("history list out of sync: %d", l.history.Len())
	}
}

func TestRun(t *testing.T) {
	clk := newClock()
	l := New(Config{Limit: 5, Window: time.Millisecond, BanTime: time.Hour, Now: clk.Now})
	l.Fail("k")
	clk.Advance(time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.Run(ctx, 5*time.Millisecond); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for l.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if l.Len() != 0 {
		t.Fatal("janitor did not prune")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestDefaultMaxKeysAndClock(t *testing.T) {
	l := New(Config{Limit: 1, Window: time.Minute, BanTime: time.Minute})
	if l.cfg.MaxKeys != defaultMaxKeys {
		t.Fatalf("MaxKeys = %d", l.cfg.MaxKeys)
	}
	l.Fail("k")
	if !l.Banned("k") {
		t.Fatal("real clock ban failed")
	}
}

func TestConcurrent(t *testing.T) {
	clk := newClock()
	var bans atomic.Int64
	l := New(Config{Limit: 3, Window: time.Minute, BanTime: time.Minute, MaxKeys: 100, Now: clk.Now,
		OnBan: func(string) { bans.Add(1) }})
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 500 {
				k := "k" + strconv.Itoa((g*7+i)%300)
				l.Fail(k)
				l.Banned(k)
				if i%50 == 0 {
					clk.Advance(time.Second)
					l.Prune()
					l.CountBanned("k")
				}
			}
		}()
	}
	wg.Wait()
	if l.Len() > 100 {
		t.Fatalf("bound exceeded: %d", l.Len())
	}
	if bans.Load() == 0 {
		t.Fatal("expected some bans")
	}
}

func TestReserveRefusals(t *testing.T) {
	clk := newClock()
	l := newLimiter(clk, 3, 100)

	r1, st := l.Reserve("a", "b")
	if st != Allowed {
		t.Fatal(st)
	}
	r2, _ := l.Reserve("a")
	r3, _ := l.Reserve("a")
	// failures(0) + pending(3) >= limit(3): throttled, though not banned.
	if r, st := l.Reserve("a"); st != Throttled || r != nil {
		t.Fatalf("status = %v", st)
	}
	if l.Banned("a") {
		t.Fatal("throttled is not banned")
	}
	// A key with budget left is unaffected, and a refusal reserves nothing.
	if _, st := l.Reserve("b", "a"); st != Throttled {
		t.Fatalf("status = %v", st)
	}
	if r, st := l.Reserve("b"); st != Allowed {
		t.Fatalf("b should have budget, got %v", st)
	} else {
		r.Release()
	}

	// Releasing frees budget; failing consumes it and finally bans.
	r1.Release()
	r1.Release() // idempotent
	if r, st := l.Reserve("a"); st != Allowed {
		t.Fatalf("status = %v after release", st)
	} else {
		r.Release()
	}
	r2.Fail()
	if r3.Fail() || l.Banned("a") {
		t.Fatal("two failures must not ban at limit 3")
	}
	rr, _ := l.Reserve("a")
	if !rr.Fail() {
		t.Fatal("third failure should report a new ban")
	}
	if _, st := l.Reserve("a"); st != Banned {
		t.Fatalf("status = %v", st)
	}
	if _, st := l.Reserve("zzz", "a"); st != Banned {
		t.Fatalf("a ban on any key refuses the reservation, got %v", st)
	}
}

func TestParallelGuessesBounded(t *testing.T) {
	clk := newClock()
	l := newLimiter(clk, 3, 100)
	var allowed atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, st := l.Reserve("ip:1", "user:x")
			if st != Allowed {
				return
			}
			allowed.Add(1)
			time.Sleep(5 * time.Millisecond) // the "Entra call"
			r.Fail()
		}()
	}
	close(start)
	wg.Wait()
	if got := allowed.Load(); got > 3 {
		t.Fatalf("%d attempts got through with limit 3", got)
	}
	if !l.Banned("ip:1") || !l.Banned("user:x") {
		t.Fatal("both keys should be banned")
	}
}

func TestPendingEntriesNotEvictedOrPruned(t *testing.T) {
	clk := newClock()
	l := newLimiter(clk, 5, 2)
	r, _ := l.Reserve("p")
	l.Fail("q")
	// Table full (p pending, q history). A new key evicts q, never p.
	if _, st := l.Reserve("n"); st != Allowed {
		t.Fatalf("status = %v", st)
	}
	if _, ok := l.entries["p"]; !ok {
		t.Fatal("pending entry evicted")
	}
	if _, ok := l.entries["q"]; ok {
		t.Fatal("q should have been evicted")
	}
	// Nothing evictable now (p and n pending): fail closed.
	if _, st := l.Reserve("m"); st != Full {
		t.Fatalf("status = %v, want Full", st)
	}
	clk.Advance(time.Hour)
	l.Prune()
	if _, ok := l.entries["p"]; !ok {
		t.Fatal("prune dropped pending entry")
	}
	r.Release()
	if _, ok := l.entries["p"]; ok {
		t.Fatal("released empty entry should be dropped")
	}
}

func TestReserveDoesNotEvictOwnKeys(t *testing.T) {
	clk := newClock()
	l := newLimiter(clk, 5, 2)
	l.Fail("a") // history: a
	if r, st := l.Reserve("a", "b"); st != Allowed {
		t.Fatalf("status = %v", st)
	} else {
		r.Fail()
	}
	if len(l.entries["a"].fails) != 2 {
		t.Fatal("a's history must survive its own reservation")
	}
	if _, st := l.Reserve("a", "b", "c"); st != Full {
		t.Fatalf("three keys cannot fit in two slots, got %v", st)
	}
}

func TestBanExpiryWithPendingAttempt(t *testing.T) {
	clk := newClock()
	l := New(Config{Limit: 2, Window: time.Minute, BanTime: time.Minute, Now: clk.Now})
	pending, _ := l.Reserve("k") // stays in flight
	other, _ := l.Reserve("k")
	other.Fail()
	if _, st := l.Reserve("k"); st != Throttled { // 1 failure + 1 pending = limit
		t.Fatalf("status = %v", st)
	}
	if l.Banned("k") {
		t.Fatal("not banned yet")
	}
	pending.Fail() // second failure: ban
	if !l.Banned("k") {
		t.Fatal("expected ban")
	}
	clk.Advance(2 * time.Minute)
	if l.Banned("k") {
		t.Fatal("ban should have expired")
	}
	if r, st := l.Reserve("k"); st != Allowed {
		t.Fatalf("status = %v", st)
	} else {
		r.Release()
	}
}

func TestExpiredBanKeptWhileAttemptPending(t *testing.T) {
	clk := newClock()
	l := New(Config{Limit: 1, Window: time.Minute, BanTime: time.Minute, Now: clk.Now})
	slow, _ := l.Reserve("k", "u")
	// Another path bans "u" while the attempt is pending.
	l.mu.Lock()
	l.recordFailForTest("u", clk.Now())
	l.mu.Unlock()
	clk.Advance(2 * time.Minute)
	l.Prune()
	if _, ok := l.entries["u"]; !ok {
		t.Fatal("entry with pending attempt must survive expiry")
	}
	slow.Release()
	if l.Len() != 0 {
		t.Fatalf("len = %d after release", l.Len())
	}
	slow.Fail() // settled once already; must be a no-op
	var nilRes *Reservation
	nilRes.Release()
}

func (l *Limiter) recordFailForTest(key string, now time.Time) {
	l.recordFail(l.entries[key], now)
}

func TestDisabledReserve(t *testing.T) {
	l := New(Config{})
	r, st := l.Reserve("a")
	if st != Allowed || r == nil {
		t.Fatal("disabled limiter must allow")
	}
	if r.Fail() {
		t.Fatal("no bans when disabled")
	}
	r.Release()
	if l.Len() != 0 {
		t.Fatal("state kept")
	}
}

func TestKeyLimits(t *testing.T) {
	clk := newClock()
	l := New(Config{
		Window: time.Minute, BanTime: time.Hour, Now: clk.Now,
		KeyLimit: func(k string) int {
			switch k[:2] {
			case "ip":
				return 0
			case "us":
				return 2
			}
			return 4
		},
	})
	if !l.Enabled() {
		t.Fatal("KeyLimit enables the limiter")
	}
	// ip keys are untracked: no budget, no state, no ban, any number of times.
	for range 50 {
		r, st := l.Reserve("ip:1")
		if st != Allowed {
			t.Fatal(st)
		}
		r.Fail()
	}
	if l.Banned("ip:1") || l.Len() != 0 {
		t.Fatal("untracked key left state")
	}
	// A mixed reservation only tracks the keys with a limit.
	r, _ := l.Reserve("ip:1", "user:a")
	if l.Len() != 1 {
		t.Fatalf("len = %d", l.Len())
	}
	r.Fail()
	l.Fail("user:a")
	if !l.Banned("user:a") || l.Banned("ip:1") {
		t.Fatal("user:a (limit 2) should be banned, ip:1 never")
	}
	// Each key uses its own limit for budget checks.
	r1, _ := l.Reserve("other:x")
	r2, _ := l.Reserve("other:x")
	r3, _ := l.Reserve("other:x")
	r4, st := l.Reserve("other:x")
	if st != Allowed {
		t.Fatalf("4th reservation within limit 4: %v", st)
	}
	if _, st := l.Reserve("other:x"); st != Throttled {
		t.Fatalf("5th: %v", st)
	}
	for _, r := range []*Reservation{r1, r2, r3, r4} {
		r.Release()
	}
}
