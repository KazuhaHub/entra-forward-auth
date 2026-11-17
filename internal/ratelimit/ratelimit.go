// Package ratelimit implements a sliding-window failure counter with a ban
// list. Memory use is bounded.
//
// Callers do not check-then-count. They Reserve an attempt, which atomically
// refuses banned or exhausted keys and otherwise counts the attempt as
// pending, and later settle it with Reservation.Fail or Reservation.Release.
// Pending attempts count against the budget, so any number of concurrent
// guesses cannot exceed Limit before the ban lands.
package ratelimit

import (
	"container/list"
	"context"
	"strings"
	"sync"
	"time"
)

// Config configures a Limiter.
type Config struct {
	// Limit is the number of failures within Window that triggers a ban.
	// Zero (or less) disables limiting, unless KeyLimit says otherwise.
	Limit int
	// KeyLimit, if set, gives the limit for each key and replaces Limit; a
	// result of zero (or less) means that key is not tracked at all: no
	// counting, no budget, no ban.
	KeyLimit func(key string) int
	// Window is how long a failure counts.
	Window time.Duration
	// BanTime is how long a ban lasts.
	BanTime time.Duration
	// MaxKeys bounds the number of tracked keys (failure histories plus
	// bans). Zero means 100000.
	MaxKeys int
	// OnBan, if set, is called (without internal locks held) each time a key
	// becomes banned.
	OnBan func(key string)
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

const defaultMaxKeys = 100_000

// Status is the result of Reserve.
type Status int

const (
	// Allowed means the attempt may proceed.
	Allowed Status = iota
	// Banned means at least one key is banned.
	Banned
	// Throttled means no key is banned yet, but failures plus attempts still
	// in flight already use up the budget of at least one key.
	Throttled
	// Full means the key table is full of active bans and cannot track the
	// request; callers should fail closed.
	Full
)

type entry struct {
	key         string
	fails       []time.Time
	pending     int // attempts reserved but not yet settled
	bannedUntil time.Time
	elem        *list.Element // position in Limiter.history; nil while banned
}

// Limiter tracks failures per key. It is safe for concurrent use.
type Limiter struct {
	cfg Config
	now func() time.Time

	mu      sync.Mutex
	entries map[string]*entry
	history *list.List // keys that are not banned, front = most recently touched
}

// New returns a Limiter for cfg.
func New(cfg Config) *Limiter {
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = defaultMaxKeys
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		cfg:     cfg,
		now:     now,
		entries: make(map[string]*entry),
		history: list.New(),
	}
}

// Enabled reports whether the limiter does anything.
func (l *Limiter) Enabled() bool { return l.cfg.Limit > 0 || l.cfg.KeyLimit != nil }

// limitOf returns the failure limit for key; zero means untracked.
func (l *Limiter) limitOf(key string) int {
	if l.cfg.KeyLimit != nil {
		return l.cfg.KeyLimit(key)
	}
	return l.cfg.Limit
}

// Reservation is one counted attempt across one or more keys. Settle it
// exactly once with Fail or Release; further calls are ignored.
type Reservation struct {
	l    *Limiter
	keys []string
	done bool
}

// Reserve atomically checks keys and, if none is banned and every key still
// has budget (failures in the window plus pending attempts below that key's
// limit; keys whose limit is zero are ignored),
// registers a pending attempt on all of them. On any refusal nothing is
// registered and the returned Reservation is nil. With the limiter disabled
// the reservation is a no-op.
//
// When MaxKeys is reached, the least recently touched failure histories
// without pending attempts are evicted to make room. Bans are never evicted
// early; if no room can be made, Reserve returns Full.
func (l *Limiter) Reserve(keys ...string) (*Reservation, Status) {
	if !l.Enabled() {
		return &Reservation{}, Allowed
	}
	now := l.now()
	cutoff := now.Add(-l.cfg.Window)

	tracked := make([]string, 0, len(keys))
	for _, k := range keys {
		if l.limitOf(k) > 0 {
			tracked = append(tracked, k)
		}
	}
	keys = tracked

	l.mu.Lock()
	defer l.mu.Unlock()

	newKeys := 0
	for _, k := range keys {
		e, banned := l.lookup(k, now)
		if banned {
			return nil, Banned
		}
		if e == nil {
			newKeys++
			continue
		}
		e.trim(cutoff)
		if len(e.fails)+e.pending >= l.limitOf(k) {
			return nil, Throttled
		}
	}
	for _, k := range keys {
		if e := l.entries[k]; e != nil && e.elem != nil {
			l.history.MoveToFront(e.elem)
		}
	}
	for len(l.entries)+newKeys > l.cfg.MaxKeys {
		if !l.evictOne(keys) {
			return nil, Full
		}
	}
	for _, k := range keys {
		e := l.entries[k]
		if e == nil {
			e = &entry{key: k}
			e.elem = l.history.PushFront(k)
			l.entries[k] = e
		}
		e.pending++
	}
	return &Reservation{l: l, keys: keys}, Allowed
}

// Fail settles the attempt as a failure: the pending count becomes a recorded
// failure on every key, and a key reaching Limit is banned. It reports
// whether any key was newly banned.
func (r *Reservation) Fail() bool { return r.settle(true) }

// Release settles the attempt without counting a failure (accepted or
// unavailable outcomes).
func (r *Reservation) Release() { r.settle(false) }

func (r *Reservation) settle(fail bool) bool {
	if r == nil || r.l == nil || r.done {
		return false
	}
	r.done = true
	l := r.l
	now := l.now()

	var banned []string
	l.mu.Lock()
	for _, k := range r.keys {
		e := l.entries[k]
		if e == nil {
			continue
		}
		e.pending--
		if fail && l.recordFail(e, now) {
			banned = append(banned, k)
		}
		// Do not leave empty, unreferenced entries behind.
		if e.pending == 0 && e.bannedUntil.IsZero() && len(e.fails) == 0 {
			l.drop(e)
		}
	}
	l.mu.Unlock()

	if l.cfg.OnBan != nil {
		for _, k := range banned {
			l.cfg.OnBan(k)
		}
	}
	return len(banned) > 0
}

// Fail records one failure for key without a prior reservation and reports
// whether it started a ban. It exists for callers that count after the fact;
// Reserve is preferred wherever attempts can run concurrently.
func (l *Limiter) Fail(key string) bool {
	r, st := l.Reserve(key)
	if st != Allowed {
		return false
	}
	return r.Fail()
}

// Banned reports whether key is currently banned.
func (l *Limiter) Banned(key string) bool {
	if l.limitOf(key) <= 0 {
		return false
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	_, banned := l.lookup(key, now)
	return banned
}

// recordFail appends a failure (the caller already decremented pending) and
// starts a ban when Limit is reached. Failures on an actively banned key are
// ignored. The caller holds l.mu.
func (l *Limiter) recordFail(e *entry, now time.Time) bool {
	if !e.bannedUntil.IsZero() {
		if now.Before(e.bannedUntil) {
			return false
		}
		l.expireBan(e)
	}
	e.trim(now.Add(-l.cfg.Window))
	e.fails = append(e.fails, now)
	if len(e.fails) < l.limitOf(e.key) {
		return false
	}
	e.fails = nil
	e.bannedUntil = now.Add(l.cfg.BanTime)
	if e.elem != nil {
		l.history.Remove(e.elem)
		e.elem = nil
	}
	return true
}

// lookup returns the entry for key and whether it is actively banned,
// retiring an expired ban on the way. The caller holds l.mu.
func (l *Limiter) lookup(key string, now time.Time) (e *entry, banned bool) {
	e = l.entries[key]
	if e == nil || e.bannedUntil.IsZero() {
		return e, false
	}
	if now.Before(e.bannedUntil) {
		return e, true
	}
	l.expireBan(e)
	return l.entries[key], false
}

// expireBan clears an expired ban; the entry is dropped unless attempts are
// still pending on it. The caller holds l.mu.
func (l *Limiter) expireBan(e *entry) {
	e.bannedUntil = time.Time{}
	e.fails = nil
	if e.pending == 0 {
		l.drop(e)
	} else if e.elem == nil {
		e.elem = l.history.PushFront(e.key)
	}
}

// evictOne removes the least recently touched history entry that has no
// pending attempts and is not one of keep. It reports whether it removed one.
// The caller holds l.mu.
func (l *Limiter) evictOne(keep []string) bool {
	for el := l.history.Back(); el != nil; el = el.Prev() {
		k := el.Value.(string)
		e := l.entries[k]
		if e.pending > 0 || contains(keep, k) {
			continue
		}
		l.drop(e)
		return true
	}
	return false
}

func contains(keys []string, s string) bool {
	for _, x := range keys {
		if x == s {
			return true
		}
	}
	return false
}

// trim drops failures that fell out of the window.
func (e *entry) trim(cutoff time.Time) {
	kept := e.fails[:0]
	for _, ts := range e.fails {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	e.fails = kept
}

// CountBanned returns the number of currently banned keys that start with
// prefix (use "" for all).
func (l *Limiter) CountBanned(prefix string) int {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for k, e := range l.entries {
		if !e.bannedUntil.IsZero() && now.Before(e.bannedUntil) && strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}

// Len returns the number of tracked keys.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// Prune removes expired bans and failure histories that have aged out of the
// window. Entries with pending attempts are kept.
func (l *Limiter) Prune() {
	now := l.now()
	cutoff := now.Add(-l.cfg.Window)
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		if !e.bannedUntil.IsZero() {
			if !now.Before(e.bannedUntil) {
				l.expireBan(e)
			}
			continue
		}
		if e.pending > 0 {
			continue
		}
		if len(e.fails) == 0 || !e.fails[len(e.fails)-1].After(cutoff) {
			l.drop(e)
		}
	}
}

// Run prunes every interval until ctx is cancelled.
func (l *Limiter) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.Prune()
		}
	}
}

// drop removes e. The caller holds l.mu.
func (l *Limiter) drop(e *entry) {
	if e.elem != nil {
		l.history.Remove(e.elem)
		e.elem = nil
	}
	delete(l.entries, e.key)
}
