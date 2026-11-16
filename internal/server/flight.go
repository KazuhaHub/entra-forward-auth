package server

import (
	"context"
	"errors"
	"sync"

	"github.com/KazuhaHub/entra-forward-auth/internal/cache"
	"github.com/KazuhaHub/entra-forward-auth/internal/entra"
	"github.com/KazuhaHub/entra-forward-auth/internal/ratelimit"
)

// errOverloaded is returned when too many flights are already in progress.
var errOverloaded = errors.New("too many attempts in flight")

// attemptResult is the outcome of one shared attempt. When refused is not
// ratelimit.Allowed, Entra was not called.
type attemptResult struct {
	res     entra.Result
	err     error
	refused ratelimit.Status
}

// flightGroup collapses concurrent attempts with the same key into one
// execution (a minimal singleflight; the project avoids extra dependencies)
// and bounds the number of executions in progress.
type flightGroup struct {
	max int // maximum flights in progress; 0 = unbounded

	mu    sync.Mutex
	calls map[cache.Key]*flight
}

type flight struct {
	done chan struct{}
	res  attemptResult
}

// do runs fn once per key among overlapping callers. Callers that arrive
// while a flight is running only wait for its result, or give up when their
// own context ends; the flight itself is never tied to any caller: fn
// receives a context detached from the starter's cancellation and does all
// recording (failure counts, cache, metrics) itself, so it takes effect even
// if every caller has gone away.
//
// If max flights are already running and key is new, do returns
// errOverloaded immediately, without starting a goroutine.
func (g *flightGroup) do(ctx context.Context, key cache.Key, fn func(ctx context.Context) attemptResult) (attemptResult, error) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = make(map[cache.Key]*flight)
	}
	if f, ok := g.calls[key]; ok {
		g.mu.Unlock()
		return f.wait(ctx)
	}
	if g.max > 0 && len(g.calls) >= g.max {
		g.mu.Unlock()
		return attemptResult{}, errOverloaded
	}
	f := &flight{done: make(chan struct{})}
	g.calls[key] = f
	g.mu.Unlock()

	detached := context.WithoutCancel(ctx)
	go func() {
		f.res = fn(detached)
		g.mu.Lock()
		delete(g.calls, key)
		g.mu.Unlock()
		close(f.done)
	}()
	return f.wait(ctx)
}

func (f *flight) wait(ctx context.Context) (attemptResult, error) {
	select {
	case <-f.done:
		return f.res, nil
	case <-ctx.Done():
		return attemptResult{}, ctx.Err()
	}
}
