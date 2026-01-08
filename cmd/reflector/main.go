package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Configuration
type Config struct {
	Port            string
	AllowedPorts    map[int]bool
	Timeout         time.Duration
	RateLimitPerMin int
	TrustedProxies  []string
	LogDir          string
}

var config = Config{
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
	TrustedProxies:  []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
	LogDir:          "/logs",
}

// Response types
type CheckResponse struct {
	Success   bool                  `json:"success"`
	ClientIP  string                `json:"client_ip"`
	IPVersion int                   `json:"ip_version,omitempty"`
	Timestamp string                `json:"timestamp"`
	Results   map[string]PortResult `json:"results,omitempty"`
	Error     string                `json:"error,omitempty"`
	Message   string                `json:"message,omitempty"`
}

type PortResult struct {
	Reachable bool          `json:"reachable"`
	LatencyMs int64         `json:"latency_ms,omitempty"`
	Error     string        `json:"error,omitempty"`
	TLS       *TLSInfo      `json:"tls,omitempty"`
	Challenge *ChallengeRes `json:"challenge,omitempty"`
	Banner    string        `json:"banner,omitempty"`
}

type TLSInfo struct {
	Version     string   `json:"version"`
	CipherSuite string   `json:"cipher_suite"`
	Certificate CertInfo `json:"certificate"`
	ChainLength int      `json:"chain_length"`
	Warnings    []string `json:"warnings,omitempty"`
}

type CertInfo struct {
	Subject         string   `json:"subject"`
	Issuer          string   `json:"issuer"`
	SelfSigned      bool     `json:"self_signed"`
	NotBefore       string   `json:"not_before"`
	NotAfter        string   `json:"not_after"`
	DaysUntilExpiry int      `json:"days_until_expiry"`
	DNSNames        []string `json:"dns_names,omitempty"`
	Serial          string   `json:"serial"`
}

type ChallengeRes struct {
	Verified bool   `json:"verified"`
	Token    string `json:"token,omitempty"`
	Error    string `json:"error,omitempty"`
	Expected string `json:"expected,omitempty"`
	Received string `json:"received,omitempty"`
}

type HealthResponse struct {
	Status         string `json:"status"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
	Version        string `json:"version"`
	ChecksLastHour int64  `json:"checks_last_hour"`
	Goroutines     int    `json:"goroutines"`
}

// Rate Limiter
type IPRateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
}

func NewIPRateLimiter() *IPRateLimiter {
	return &IPRateLimiter{
		limiters: make(map[string]*rate.Limiter),
	}
}

func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter, exists := i.limiters[ip]
	if !exists {
		// Rate limit: requests per minute with burst
		limiter = rate.NewLimiter(rate.Every(time.Minute/time.Duration(config.RateLimitPerMin)), config.RateLimitPerMin)
		i.limiters[ip] = limiter
	}
	return limiter
}

// Cleanup old limiters periodically
func (i *IPRateLimiter) Cleanup() {
	i.mu.Lock()
	defer i.mu.Unlock()
	// Simple cleanup: remove all (they will be recreated on next request)
	i.limiters = make(map[string]*rate.Limiter)
}

// Logger
type Logger struct {
	accessLog io.WriteCloser
	errorLog  io.WriteCloser
	mu        sync.Mutex
}

type AccessLogEntry struct {
	Timestamp  string         `json:"ts"`
	IP         string         `json:"ip"`
	Method     string         `json:"method"`
	Path       string         `json:"path"`
	Ports      []int          `json:"ports,omitempty"`
	Results    map[string]bool `json:"results,omitempty"`
	DurationMs int64          `json:"duration_ms"`
	Status     int            `json:"status"`
	Error      string         `json:"error,omitempty"`
}

func NewLogger(logDir string) (*Logger, error) {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, err
	}

	// Configure log rotation with lumberjack
	accessLog := &lumberjack.Logger{
		Filename:   logDir + "/access.log",
		MaxSize:    100, // megabytes
		MaxBackups: 7,   // keep 7 old log files
		MaxAge:     30,  // days
		Compress:   true,
	}

	errorLog := &lumberjack.Logger{
		Filename:   logDir + "/error.log",
		MaxSize:    100, // megabytes
		MaxBackups: 7,   // keep 7 old log files
		MaxAge:     30,  // days
		Compress:   true,
	}

	return &Logger{
		accessLog: accessLog,
		errorLog:  errorLog,
	}, nil
}

func (l *Logger) LogAccess(entry AccessLogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Anonymize IP before logging
	entry.IP = anonymizeIP(entry.IP)
	json.NewEncoder(l.accessLog).Encode(entry)
}

func (l *Logger) LogError(level, msg string, fields map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	entry := map[string]interface{}{
		"ts":    time.Now().UTC().Format(time.RFC3339),
		"level": level,
		"msg":   msg,
	}
	for k, v := range fields {
		entry[k] = v
	}
	json.NewEncoder(l.errorLog).Encode(entry)
}

func (l *Logger) Close() {
	l.accessLog.Close()
	l.errorLog.Close()
}

// Global variables
var (
	rateLimiter *IPRateLimiter
	logger      *Logger
	startTime   time.Time
	checkCount  int64
	checkMu     sync.Mutex
)

// Private IP check
var privateBlocks []*net.IPNet

func init() {
	privateCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range privateCIDRs {
		_, block, _ := net.ParseCIDR(cidr)
		privateBlocks = append(privateBlocks, block)
	}
}

func isPrivateIP(ip net.IP) bool {
	for _, block := range privateBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// Get client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if net.ParseIP(xri) != nil {
			return xri
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Get IP version
func getIPVersion(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	}
	return 6
}

// Anonymize IP address for logging
func anonymizeIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}

	if ip.To4() != nil {
		// IPv4: Set last octet to 0
		parts := strings.Split(ipStr, ".")
		if len(parts) == 4 {
			parts[3] = "0"
			return strings.Join(parts, ".")
		}
		return ipStr
	} else {
		// IPv6: Keep only the first 48 bits (3 groups of 16 bits)
		// This is similar to /48 prefix
		ip16 := ip.To16()
		if ip16 != nil {
			// Zero out the last 80 bits (10 bytes)
			for i := 6; i < 16; i++ {
				ip16[i] = 0
			}
			return ip16.String()
		}
		return ipStr
	}
}

// Parse ports from query parameter
func parsePorts(portsParam string) ([]int, error) {
	if portsParam == "" {
		return []int{80, 443}, nil // Default ports
	}

	var ports []int
	for _, p := range strings.Split(portsParam, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", p)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port out of range: %d", port)
		}
		if !config.AllowedPorts[port] {
			return nil, fmt.Errorf("port not allowed: %d", port)
		}
		ports = append(ports, port)
	}

	if len(ports) > 5 {
		return nil, fmt.Errorf("too many ports (max 5)")
	}

	return ports, nil
}

// Format host:port correctly for IPv6 addresses
func formatHostPort(host string, port int) string {
	// If host contains colons (IPv6), wrap it in brackets
	if strings.Contains(host, ":") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// TCP port check
func checkPort(ctx context.Context, host string, port int) (bool, int64, error) {
	start := time.Now()
	
	dialer := &net.Dialer{
		Timeout: config.Timeout,
	}
	
	conn, err := dialer.DialContext(ctx, "tcp", formatHostPort(host, port))
	if err != nil {
		return false, 0, err
	}
	defer conn.Close()
	
	latency := time.Since(start).Milliseconds()
	return true, latency, nil
}

// TLS analysis
func analyzeTLS(host string, port int) (*TLSInfo, error) {
	dialer := &net.Dialer{Timeout: config.Timeout}
	
	conn, err := tls.DialWithDialer(dialer, "tcp",
		formatHostPort(host, port),
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates received")
	}
	
	cert := state.PeerCertificates[0]

	info := &TLSInfo{
		Version:     tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ChainLength: len(state.PeerCertificates),
		Certificate: CertInfo{
			Subject:         cert.Subject.CommonName,
			Issuer:          cert.Issuer.CommonName,
			SelfSigned:      cert.Subject.String() == cert.Issuer.String(),
			NotBefore:       cert.NotBefore.Format(time.RFC3339),
			NotAfter:        cert.NotAfter.Format(time.RFC3339),
			DaysUntilExpiry: int(time.Until(cert.NotAfter).Hours() / 24),
			DNSNames:        cert.DNSNames,
			Serial:          cert.SerialNumber.Text(16),
		},
	}

	// Generate warnings
	info.Warnings = generateTLSWarnings(state.Version, cert)

	return info, nil
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

func generateTLSWarnings(version uint16, cert *x509.Certificate) []string {
	var warnings []string

	// Check TLS version
	if version == tls.VersionTLS10 || version == tls.VersionTLS11 {
		warnings = append(warnings, "weak_tls_version")
	}

	// Check if self-signed
	if cert.Subject.String() == cert.Issuer.String() {
		warnings = append(warnings, "self_signed_certificate")
	}

	// Check certificate expiration
	now := time.Now()
	if cert.NotAfter.Before(now) {
		warnings = append(warnings, "certificate_expired")
	} else if cert.NotAfter.Before(now.AddDate(0, 0, 30)) {
		warnings = append(warnings, "certificate_expires_soon")
	}

	if cert.NotBefore.After(now) {
		warnings = append(warnings, "certificate_not_yet_valid")
	}

	// Check for missing SANs
	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
		warnings = append(warnings, "missing_san")
	}

	return warnings
}

// Challenge verification
func verifyChallenge(host string, port int, token, path string) *ChallengeRes {
	if path == "" {
		path = fmt.Sprintf("/.well-known/reflector/%s", token)
	}

	url := fmt.Sprintf("http://%s:%d%s", host, port, path)
	
	client := &http.Client{
		Timeout: config.Timeout,
	}
	
	resp, err := client.Get(url)
	if err != nil {
		return &ChallengeRes{
			Verified: false,
			Error:    "http_error",
			Expected: token,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &ChallengeRes{
			Verified: false,
			Error:    fmt.Sprintf("http_status_%d", resp.StatusCode),
			Expected: token,
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return &ChallengeRes{
			Verified: false,
			Error:    "read_error",
			Expected: token,
		}
	}

	received := strings.TrimSpace(string(body))
	if received == token {
		return &ChallengeRes{
			Verified: true,
			Token:    token,
		}
	}

	return &ChallengeRes{
		Verified: false,
		Error:    "token_mismatch",
		Expected: token,
		Received: received,
	}
}

// Banner grabbing
func grabBanner(host string, port int) string {
	conn, err := net.DialTimeout("tcp", formatHostPort(host, port), 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Send a simple HTTP request for web ports
	if port == 80 || port == 8080 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	
	if n > 0 {
		return sanitizeBanner(string(buf[:n]))
	}
	return ""
}

// sanitizeBanner removes non-printable characters and limits banner length
func sanitizeBanner(banner string) string {
	// Check if it's an SSH banner (starts with "SSH-")
	if strings.HasPrefix(banner, "SSH-") {
		// For SSH, just take the first line and remove binary data after it
		lines := strings.Split(banner, "\n")
		if len(lines) > 0 {
			// Clean the first line - keep only printable ASCII
			firstLine := lines[0]
			var cleaned strings.Builder
			for _, r := range firstLine {
				if r >= 32 && r <= 126 {
					cleaned.WriteRune(r)
				}
			}
			result := strings.TrimSpace(cleaned.String())
			if len(result) > 100 {
				result = result[:100]
			}
			return result
		}
	}
	
	// For non-SSH banners, filter out non-printable characters
	var sanitized strings.Builder
	for _, r := range banner {
		if (r >= 32 && r <= 126) || r == '\t' || r == '\n' || r == '\r' {
			sanitized.WriteRune(r)
		}
	}
	
	result := sanitized.String()
	
	// Trim whitespace and limit length
	result = strings.TrimSpace(result)
	if len(result) > 200 {
		result = result[:200] + "..."
	}
	
	return result
}

// HTTP Handlers
func handleCheck(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	clientIP := getClientIP(r)
	
	// CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Rate limiting
	if !rateLimiter.GetLimiter(clientIP).Allow() {
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(CheckResponse{
			Success:   false,
			ClientIP:  clientIP,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Error:     "rate_limit_exceeded",
			Message:   "Too many requests. Please try again later.",
		})
		logger.LogAccess(AccessLogEntry{
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

	// Parse and validate client IP
	ip := net.ParseIP(clientIP)
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

	// Check for private IP
	if isPrivateIP(ip) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(CheckResponse{
			Success:   false,
			ClientIP:  clientIP,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Error:     "private_ip",
			Message:   "Cannot test private/internal IP addresses",
		})
		logger.LogAccess(AccessLogEntry{
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

	// Parse query parameters
	query := r.URL.Query()
	ports, err := parsePorts(query.Get("ports"))
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

	challenge := query.Get("challenge")
	challengePath := query.Get("challenge_path")
	challengePortStr := query.Get("challenge_port")
	tlsAnalyze := query.Get("tls_analyze") != "false"
	wantBanner := query.Get("banner") == "true"

	challengePort := 80
	if challengePortStr != "" {
		if p, err := strconv.Atoi(challengePortStr); err == nil && p > 0 && p < 65536 {
			challengePort = p
		}
	}

	// Perform checks
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	results := make(map[string]PortResult)
	resultsBool := make(map[string]bool)

	for _, port := range ports {
		portStr := strconv.Itoa(port)
		reachable, latency, err := checkPort(ctx, clientIP, port)
		
		result := PortResult{
			Reachable: reachable,
			LatencyMs: latency,
		}

		if err != nil {
			result.Error = "connection_failed"
		}

		// TLS analysis for port 443
		if reachable && port == 443 && tlsAnalyze {
			if tlsInfo, err := analyzeTLS(clientIP, port); err == nil {
				result.TLS = tlsInfo
			}
		}

		// Challenge verification
		if reachable && challenge != "" && port == challengePort {
			result.Challenge = verifyChallenge(clientIP, port, challenge, challengePath)
		}

		// Banner grabbing
		// Auto-grab for known service ports (SSH, FTP, SMTP, etc.) or if explicitly requested
		shouldGrabBanner := wantBanner || port == 22 || port == 21 || port == 25
		if reachable && shouldGrabBanner {
			if banner := grabBanner(clientIP, port); banner != "" {
				result.Banner = banner
			}
		}

		results[portStr] = result
		resultsBool[portStr] = reachable
	}

	// Increment check counter
	checkMu.Lock()
	checkCount++
	checkMu.Unlock()

	// Send response
	response := CheckResponse{
		Success:   true,
		ClientIP:  clientIP,
		IPVersion: getIPVersion(ip),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Results:   results,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	// Log access
	logger.LogAccess(AccessLogEntry{
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

func handleSimple(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)

	// Rate limiting
	if !rateLimiter.GetLimiter(clientIP).Allow() {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, "error")
		return
	}

	ip := net.ParseIP(clientIP)
	if ip == nil || isPrivateIP(ip) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "error")
		return
	}

	portStr := r.URL.Query().Get("port")
	port := 80
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	if !config.AllowedPorts[port] {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "error")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), config.Timeout)
	defer cancel()

	reachable, _, _ := checkPort(ctx, clientIP, port)
	
	if reachable {
		fmt.Fprint(w, "yes")
	} else {
		fmt.Fprint(w, "no")
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	checkMu.Lock()
	count := checkCount
	checkMu.Unlock()

	response := HealthResponse{
		Status:         "healthy",
		UptimeSeconds:  int64(time.Since(startTime).Seconds()),
		Version:        "1.0.0",
		ChecksLastHour: count, // Simplified - would need proper hourly tracking
		Goroutines:     0,     // Could use runtime.NumGoroutine()
	}

	json.NewEncoder(w).Encode(response)
}

func main() {
	// Load configuration from environment
	if port := os.Getenv("REFLECTOR_PORT"); port != "" {
		config.Port = port
	}
	if logDir := os.Getenv("REFLECTOR_LOG_DIR"); logDir != "" {
		config.LogDir = logDir
	}
	if timeout := os.Getenv("REFLECTOR_TIMEOUT"); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			config.Timeout = d
		}
	}
	if rateLimit := os.Getenv("REFLECTOR_RATE_LIMIT_PER_MIN"); rateLimit != "" {
		if r, err := strconv.Atoi(rateLimit); err == nil {
			config.RateLimitPerMin = r
		}
	}
	if allowedPorts := os.Getenv("REFLECTOR_ALLOWED_PORTS"); allowedPorts != "" {
		config.AllowedPorts = make(map[int]bool)
		for _, p := range strings.Split(allowedPorts, ",") {
			if port, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				config.AllowedPorts[port] = true
			}
		}
	}

	// Initialize logger
	var err error
	logger, err = NewLogger(config.LogDir)
	if err != nil {
		log.Printf("Warning: Could not initialize file logger: %v", err)
		// Create a dummy logger that writes to stdout
		logger = &Logger{
			accessLog: os.Stdout,
			errorLog:  os.Stderr,
		}
	}
	defer logger.Close()

	// Initialize rate limiter
	rateLimiter = NewIPRateLimiter()
	startTime = time.Now()

	// Cleanup rate limiter periodically
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		for range ticker.C {
			rateLimiter.Cleanup()
		}
	}()

	// Setup HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/check", handleCheck)
	mux.HandleFunc("/simple", handleSimple)
	mux.HandleFunc("/health", handleHealth)

	// Create server
	server := &http.Server{
		Addr:         ":" + config.Port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down gracefully...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		server.Shutdown(ctx)
	}()

	// Start server
	log.Printf("Reflector server starting on port %s", config.Port)
	log.Printf("Allowed ports: %v", config.AllowedPorts)
	log.Printf("Rate limit: %d requests/min per IP", config.RateLimitPerMin)

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}

	log.Println("Server stopped")
}
