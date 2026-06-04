package limiter

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type IPRateLimiter struct {
	limiters map[string]*limiterEntry
	mu       sync.RWMutex
	rateLimit int
}

func NewIPRateLimiter(rateLimit int) *IPRateLimiter {
	return &IPRateLimiter{
		limiters:  make(map[string]*limiterEntry),
		rateLimit: rateLimit,
	}
}

func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	entry, exists := i.limiters[ip]
	if !exists {
		// Rate limit: requests per minute with burst
		limiter := rate.NewLimiter(rate.Every(time.Minute/time.Duration(i.rateLimit)), i.rateLimit)
		entry = &limiterEntry{
			limiter:  limiter,
			lastSeen: time.Now(),
		}
		i.limiters[ip] = entry
	} else {
		entry.lastSeen = time.Now()
	}
	return entry.limiter
}

func (i *IPRateLimiter) Cleanup() {
	i.mu.Lock()
	defer i.mu.Unlock()

	threshold := time.Now().Add(-5 * time.Minute)
	for ip, entry := range i.limiters {
		if entry.lastSeen.Before(threshold) {
			delete(i.limiters, ip)
		}
	}
}
