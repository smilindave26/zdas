package zdas

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipRateLimiter tracks per-IP token buckets for rate limiting the /authorize
// endpoint. Stale entries are cleaned up periodically.
type ipRateLimiter struct {
	rate  rate.Limit
	burst int

	mu      sync.Mutex
	clients map[string]*rateLimitEntry
}

type rateLimitEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPRateLimiter(perSecond float64, burst int) *ipRateLimiter {
	rl := &ipRateLimiter{
		rate:    rate.Limit(perSecond),
		burst:   burst,
		clients: make(map[string]*rateLimitEntry),
	}
	go rl.cleanupLoop()
	return rl
}

// allow checks whether the given IP is within its rate limit.
func (rl *ipRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	entry, ok := rl.clients[ip]
	if !ok {
		entry = &rateLimitEntry{
			limiter: rate.NewLimiter(rl.rate, rl.burst),
		}
		rl.clients[ip] = entry
	}
	entry.lastSeen = time.Now()
	rl.mu.Unlock()
	return entry.limiter.Allow()
}

// cleanupLoop removes entries that haven't been seen in 5 minutes.
func (rl *ipRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-5 * time.Minute)
		for ip, entry := range rl.clients {
			if entry.lastSeen.Before(cutoff) {
				delete(rl.clients, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// extractIP returns the client IP from the request, stripping the port.
// Uses X-Forwarded-For if present (common behind reverse proxies),
// falling back to RemoteAddr.
func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For may contain multiple IPs; use the first (client).
		if i := len(xff); i > 0 {
			for j := 0; j < len(xff); j++ {
				if xff[j] == ',' {
					return xff[:j]
				}
			}
			return xff
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
