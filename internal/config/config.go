package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port            string
	AllowedPorts    map[int]bool
	Timeout         time.Duration
	RateLimitPerMin int
	TrustedProxies  []string
	LogDir          string
}

func LoadConfig() Config {
	cfg := Config{
		Port: "8080",
		AllowedPorts: map[int]bool{
			22:   true,
			80:   true,
			443:  true,
			8080: true,
			8443: true,
		},
		Timeout:         5 * time.Second,
		RateLimitPerMin: 10,
		TrustedProxies: []string{
			// Private networks
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fd00::/8", "::1/128",
			// Cloudflare IPv4
			"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
			"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
			"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
			"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
			// Cloudflare IPv6
			"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
			"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
		},
		LogDir:          "/logs",
	}

	if port := os.Getenv("REFLECTOR_PORT"); port != "" {
		cfg.Port = port
	}
	if logDir := os.Getenv("REFLECTOR_LOG_DIR"); logDir != "" {
		cfg.LogDir = logDir
	}
	if timeout := os.Getenv("REFLECTOR_TIMEOUT"); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			cfg.Timeout = d
		}
	}
	if rateLimit := os.Getenv("REFLECTOR_RATE_LIMIT_PER_MIN"); rateLimit != "" {
		if r, err := strconv.Atoi(rateLimit); err == nil {
			cfg.RateLimitPerMin = r
		}
	}
	if allowedPorts := os.Getenv("REFLECTOR_ALLOWED_PORTS"); allowedPorts != "" {
		cfg.AllowedPorts = make(map[int]bool)
		for _, p := range strings.Split(allowedPorts, ",") {
			if port, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				cfg.AllowedPorts[port] = true
			}
		}
	}
	if trustedProxies := os.Getenv("REFLECTOR_TRUSTED_PROXIES"); trustedProxies != "" {
		cfg.TrustedProxies = make([]string, 0)
		for _, p := range strings.Split(trustedProxies, ",") {
			cfg.TrustedProxies = append(cfg.TrustedProxies, strings.TrimSpace(p))
		}
	}

	return cfg
}
