package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/glinet/reflector/internal/config"
	"github.com/glinet/reflector/internal/limiter"
	"github.com/glinet/reflector/internal/logger"
	"github.com/glinet/reflector/internal/scanner"
	"github.com/glinet/reflector/internal/util"
)

// Version is reported by the /health endpoint.
const Version = "2.0.0"

type Handlers struct {
	cfg         config.Config
	rateLimiter *limiter.IPRateLimiter
	log         *logger.Logger
	sc          *scanner.Scanner
	trusted     []*net.IPNet
	startTime   time.Time

	// Basic metrics
	checksCount atomic.Int64
}

func NewHandlers(cfg config.Config, rl *limiter.IPRateLimiter, l *logger.Logger) *Handlers {
	return &Handlers{
		cfg:         cfg,
		rateLimiter: rl,
		log:         l,
		sc:          scanner.NewScanner(cfg.Timeout),
		trusted:     util.ParseTrustedProxies(cfg.TrustedProxies),
		startTime:   time.Now(),
	}
}

func (h *Handlers) parsePorts(portsParam string) ([]int, error) {
	if portsParam == "" {
		// Apply the allowlist to the defaults too, so restricting AllowedPorts is
		// not silently bypassed when the client omits the ports parameter.
		var def []int
		for _, p := range []int{80, 443} {
			if h.cfg.AllowedPorts[p] {
				def = append(def, p)
			}
		}
		return def, nil
	}

	seen := make(map[int]struct{})
	var ports []int
	for _, p := range strings.Split(portsParam, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", p)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port out of range: %d", port)
		}
		if !h.cfg.AllowedPorts[port] {
			return nil, fmt.Errorf("port not allowed: %d", port)
		}
		if _, dup := seen[port]; dup {
			continue // ignore duplicates: they only multiply scan work
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
		if len(ports) > 5 {
			return nil, fmt.Errorf("too many ports (max 5)")
		}
	}

	return ports, nil
}

func (h *Handlers) HandleCheck(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP := util.GetClientIP(r, h.trusted)

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if !h.rateLimiter.GetLimiter(util.RateLimitKey(clientIP)).Allow() {
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(CheckResponse{
			Success:   false,
			ClientIP:  clientIP,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Error:     "rate_limit_exceeded",
			Message:   "Too many requests. Please try again later.",
		})
		h.log.LogAccess(logger.AccessLogEntry{
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
			IP:         clientIP,
			Method:     r.Method,
			Path:       r.URL.Path,
			DurationMs: time.Since(start).Milliseconds(),
			Status:     http.StatusTooManyRequests,
			Error:      "rate_limit_exceeded",
		})
		return
	}

	ip := util.CleanIP(net.ParseIP(clientIP))
	if ip == nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(CheckResponse{
			Success:   false,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Error:     "invalid_ip",
			Message:   "Could not determine client IP",
		})
		return
	}

	if util.IsPrivateIP(ip) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(CheckResponse{
			Success:   false,
			ClientIP:  clientIP,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Error:     "private_ip",
			Message:   "Cannot test private/internal IP addresses",
		})
		h.log.LogAccess(logger.AccessLogEntry{
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
			IP:         clientIP,
			Method:     r.Method,
			Path:       r.URL.Path,
			DurationMs: time.Since(start).Milliseconds(),
			Status:     http.StatusForbidden,
			Error:      "private_ip",
		})
		return
	}

	query := r.URL.Query()
	ports, err := h.parsePorts(query.Get("ports"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(CheckResponse{
			Success:   false,
			ClientIP:  clientIP,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Error:     "invalid_ports",
			Message:   err.Error(),
		})
		return
	}

	challengePort := 80
	if cp := query.Get("challenge_port"); cp != "" {
		if p, err := strconv.Atoi(cp); err == nil && p > 0 && p < 65536 {
			challengePort = p
		}
	}

	req := scanner.ScanRequest{
		Host:          clientIP,
		Ports:         ports,
		Challenge:     query.Get("challenge"),
		ChallengePath: query.Get("challenge_path"),
		ChallengePort: challengePort,
		TLSAnalyze:    query.Get("tls_analyze") != "false",
		WantBanner:    query.Get("banner") == "true",
	}

	// Wait up to MaxTimeout for all concurrent checks
	maxTimeout := h.cfg.Timeout + 2*time.Second
	ctx, cancel := context.WithTimeout(r.Context(), maxTimeout)
	defer cancel()

	results := h.sc.ScanAllConcurrent(ctx, req)

	resultsBool := make(map[string]bool)
	for k, v := range results {
		resultsBool[k] = v.Reachable
	}

	h.checksCount.Add(1)

	response := CheckResponse{
		Success:   true,
		ClientIP:  clientIP,
		IPVersion: util.GetIPVersion(ip),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Results:   results,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	h.log.LogAccess(logger.AccessLogEntry{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		IP:         clientIP,
		Method:     r.Method,
		Path:       r.URL.Path,
		Ports:      ports,
		Results:    resultsBool,
		DurationMs: time.Since(start).Milliseconds(),
		Status:     http.StatusOK,
	})
}

func (h *Handlers) HandleSimple(w http.ResponseWriter, r *http.Request) {
	clientIP := util.GetClientIP(r, h.trusted)

	if !h.rateLimiter.GetLimiter(util.RateLimitKey(clientIP)).Allow() {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, "error")
		return
	}

	ip := util.CleanIP(net.ParseIP(clientIP))
	if ip == nil || util.IsPrivateIP(ip) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "error")
		return
	}

	port := 80
	if pStr := r.URL.Query().Get("port"); pStr != "" {
		p, err := strconv.Atoi(pStr)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "error")
			return
		}
		port = p
	}

	if !h.cfg.AllowedPorts[port] {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "error")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.Timeout)
	defer cancel()

	reachable, _, _ := h.sc.CheckPort(ctx, clientIP, port)
	if reachable {
		fmt.Fprint(w, "yes")
	} else {
		fmt.Fprint(w, "no")
	}
}

func (h *Handlers) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := HealthResponse{
		Status:        "healthy",
		UptimeSeconds: int64(time.Since(h.startTime).Seconds()),
		Version:       Version,
		ChecksTotal:   h.checksCount.Load(),
		Goroutines:    runtime.NumGoroutine(),
	}

	json.NewEncoder(w).Encode(response)
}
