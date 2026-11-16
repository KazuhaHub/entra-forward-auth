// Package cache implements a bounded set of fixed-size keys with a
// time-to-live and least-recently-used eviction.
//
// It stores only the keys (hashes of successful credentials) and their expiry;
// nothing else about an entry is retained.
package cache

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// Key is a cache key, typically a SHA-256 digest.
type Key [32]byte

type entry struct {
	key     Key
	expires time.Time
}

// Cache is a TTL + LRU set. The zero value is not usable; call New. All
// methods are safe for concurrent use.
type Cache struct {
	ttl time.Duration
	max int
	now func() time.Time

	mu    sync.Mutex
	order *list.List // front = most recently used
	items map[Key]*list.Element
}

// New returns a Cache whose entries live for ttl and which holds at most
// maxEntries entries. A ttl or maxEntries of zero (or less) disables the cache: Add does nothing
// and Has always reports false. A nil clock means time.Now.
func New(ttl time.Duration, maxEntries int, now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	return &Cache{
		ttl:   ttl,
		max:   maxEntries,
		now:   now,
		order: list.New(),
		items: make(map[Key]*list.Element),
	}
}

// Enabled reports whether the cache stores anything.
func (c *Cache) Enabled() bool { return c.ttl > 0 && c.max > 0 }

// Has reports whether key is present and unexpired. A hit marks the entry as
// recently used but does not extend its lifetime.
func (c *Cache) Has(key Key) bool {
	if !c.Enabled() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return false
	}
	if !c.now().Before(el.Value.(*entry).expires) {
		c.remove(el)
		return false
	}
	c.order.MoveToFront(el)
	return true
}

// Add inserts key, or refreshes its expiry, evicting the least recently used
// entries if the bound is exceeded.
func (c *Cache) Add(key Key) {
	if !c.Enabled() {
		return
	}
	expires := c.now().Add(c.ttl)
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		el.Value.(*entry).expires = expires
		c.order.MoveToFront(el)
		return
	}
	c.items[key] = c.order.PushFront(&entry{key: key, expires: expires})
	for len(c.items) > c.max {
		c.remove(c.order.Back())
	}
}

// Len returns the number of stored entries, including expired entries that
// have not been swept yet.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// Sweep removes all expired entries.
func (c *Cache) Sweep() {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for el := c.order.Back(); el != nil; {
		prev := el.Prev()
		if !now.Before(el.Value.(*entry).expires) {
			c.remove(el)
		}
		el = prev
	}
}

// Run sweeps expired entries every interval until ctx is cancelled.
func (c *Cache) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Sweep()
		}
	}
}

func (c *Cache) remove(el *list.Element) {
	delete(c.items, el.Value.(*entry).key)
	c.order.Remove(el)
}
