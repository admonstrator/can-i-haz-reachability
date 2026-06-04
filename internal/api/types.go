package api

import (
	"github.com/glinet/reflector/internal/scanner"
)

type CheckResponse struct {
	Success   bool                          `json:"success"`
	ClientIP  string                        `json:"client_ip"`
	IPVersion int                           `json:"ip_version,omitempty"`
	Timestamp string                        `json:"timestamp"`
	Results   map[string]scanner.PortResult `json:"results,omitempty"`
	Error     string                        `json:"error,omitempty"`
	Message   string                        `json:"message,omitempty"`
}

type HealthResponse struct {
	Status         string `json:"status"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
	Version        string `json:"version"`
	ChecksLastHour int64  `json:"checks_last_hour"`
	Goroutines     int    `json:"goroutines"`
}
