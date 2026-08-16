package limiter

import (
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// maxEntries bounds the limiter map so a flood of distinct keys cannot grow it
// without limit between cleanup runs.
const maxEntries = 100_000

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64 // unix nanoseconds
}

type IPRateLimiter struct {
	limiters  map[string]*limiterEntry
	mu        sync.RWMutex
	rateLimit int
}

func NewIPRateLimiter(rateLimit int) *IPRateLimiter {
	if rateLimit < 1 {
		// Defensive: rate.Every(time.Minute/0) panics with a divide-by-zero.
		rateLimit = 1
	}
	return &IPRateLimiter{
		limiters:  make(map[string]*limiterEntry),
		rateLimit: rateLimit,
	}
}

func (i *IPRateLimiter) GetLimiter(key string) *rate.Limiter {
	now := time.Now().UnixNano()

	// Fast path: existing entry needs only a read lock.
	i.mu.RLock()
	entry, exists := i.limiters[key]
	i.mu.RUnlock()
	if exists {
		entry.lastSeen.Store(now)
		return entry.limiter
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	// Double-check after upgrading to the write lock.
	if entry, exists = i.limiters[key]; exists {
		entry.lastSeen.Store(now)
		return entry.limiter
	}
	// Bound memory before growing the map further.
	if len(i.limiters) >= maxEntries {
		i.evictStaleLocked(now - int64(time.Minute))
	}
	entry = &limiterEntry{
		limiter: rate.NewLimiter(rate.Every(time.Minute/time.Duration(i.rateLimit)), i.rateLimit),
	}
	entry.lastSeen.Store(now)
	i.limiters[key] = entry
	return entry.limiter
}

func (i *IPRateLimiter) Cleanup() {
	threshold := time.Now().Add(-5 * time.Minute).UnixNano()
	i.mu.Lock()
	defer i.mu.Unlock()
	i.evictStaleLocked(threshold)
}

// evictStaleLocked removes entries not seen since thresholdNanos.
// The caller must hold i.mu for writing.
func (i *IPRateLimiter) evictStaleLocked(thresholdNanos int64) {
	for key, entry := range i.limiters {
		if entry.lastSeen.Load() < thresholdNanos {
			delete(i.limiters, key)
		}
	}
}
