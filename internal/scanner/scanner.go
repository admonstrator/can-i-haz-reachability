package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

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

type Scanner struct {
	Timeout time.Duration
	// challengeClient is reused across challenge verifications. It never follows
	// redirects (a redirect could point the request at an internal host and turn
	// the challenge into an SSRF primitive) and does not keep connections to the
	// many one-off foreign hosts it contacts.
	challengeClient *http.Client
}

func NewScanner(timeout time.Duration) *Scanner {
	return &Scanner{
		Timeout: timeout,
		challengeClient: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				DisableKeepAlives:      true,
				MaxResponseHeaderBytes: 8 << 10,
			},
		},
	}
}

func formatHostPort(host string, port int) string {
	if strings.Contains(host, ":") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func (s *Scanner) CheckPort(ctx context.Context, host string, port int) (bool, int64, error) {
	start := time.Now()

	dialer := &net.Dialer{}

	conn, err := dialer.DialContext(ctx, "tcp", formatHostPort(host, port))
	if err != nil {
		return false, 0, err
	}
	defer conn.Close()

	latency := time.Since(start).Milliseconds()
	return true, latency, nil
}

func (s *Scanner) AnalyzeTLS(ctx context.Context, host string, port int) (*TLSInfo, error) {
	// Use a context-aware dialer so the TCP connect AND the TLS handshake are both
	// bounded by ctx. tls.DialWithDialer only honours the dialer's Timeout/Deadline,
	// which were unset here, letting a silent peer block the goroutine indefinitely.
	// MinVersion TLS 1.0 lets us actually handshake with (and then flag) legacy
	// servers instead of failing the connection outright.
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", formatHostPort(host, port))
	if err != nil {
		return nil, err
	}
	conn := rawConn.(*tls.Conn)
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

	info.Warnings = generateTLSWarnings(state.Version, cert)
	return info, nil
}

func (s *Scanner) VerifyChallenge(ctx context.Context, host string, port int, token, path string) *ChallengeRes {
	if path == "" {
		path = "/.well-known/reflector/" + url.PathEscape(token)
	}

	// Harden against SSRF: challenge_path is attacker-controlled. It must be an
	// absolute path only. Reject anything that could move the request off the
	// verified client host — a leading "@" (which pushes host:port into the URL
	// userinfo and lets the caller pick the host), or query/fragment/backslashes.
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "@?#\\") {
		return &ChallengeRes{Verified: false, Error: "invalid_challenge_path", Expected: token}
	}

	// Build the URL from a struct so the host can never be overridden by the path.
	u := url.URL{Scheme: "http", Host: formatHostPort(host, port), Path: path}

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return &ChallengeRes{Verified: false, Error: "request_creation_failed", Expected: token}
	}

	resp, err := s.challengeClient.Do(req)
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

func (s *Scanner) GrabBanner(ctx context.Context, host string, port int) string {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", formatHostPort(host, port))
	if err != nil {
		return ""
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(2 * time.Second))
	}

	if port == 80 || port == 8080 {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	}

	buf := make([]byte, 256)
	n, _ := conn.Read(buf)

	if n > 0 {
		return sanitizeBanner(string(buf[:n]))
	}
	return ""
}

// ... internal helpers ...

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
	if version == tls.VersionTLS10 || version == tls.VersionTLS11 {
		warnings = append(warnings, "weak_tls_version")
	}
	if cert.Subject.String() == cert.Issuer.String() {
		warnings = append(warnings, "self_signed_certificate")
	}
	now := time.Now()
	if cert.NotAfter.Before(now) {
		warnings = append(warnings, "certificate_expired")
	} else if cert.NotAfter.Before(now.AddDate(0, 0, 30)) {
		warnings = append(warnings, "certificate_expires_soon")
	}
	if cert.NotBefore.After(now) {
		warnings = append(warnings, "certificate_not_yet_valid")
	}
	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
		warnings = append(warnings, "missing_san")
	}
	return warnings
}

func sanitizeBanner(banner string) string {
	if strings.HasPrefix(banner, "SSH-") {
		lines := strings.Split(banner, "\n")
		if len(lines) > 0 {
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

	var sanitized strings.Builder
	for _, r := range banner {
		if (r >= 32 && r <= 126) || r == '\t' || r == '\n' || r == '\r' {
			sanitized.WriteRune(r)
		}
	}

	result := strings.TrimSpace(sanitized.String())
	if len(result) > 200 {
		result = result[:200] + "..."
	}

	return result
}

type ScanRequest struct {
	Host          string
	Ports         []int
	Challenge     string
	ChallengePath string
	ChallengePort int
	TLSAnalyze    bool
	WantBanner    bool
}

func (s *Scanner) ScanAllConcurrent(ctx context.Context, req ScanRequest) map[string]PortResult {
	results := make(map[string]PortResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, port := range req.Ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			// Give each port its own timeout context based on scanner configuration
			portCtx, cancel := context.WithTimeout(ctx, s.Timeout)
			defer cancel()

			reachable, latency, err := s.CheckPort(portCtx, req.Host, p)

			result := PortResult{
				Reachable: reachable,
				LatencyMs: latency,
			}

			if err != nil {
				result.Error = "connection_failed"
			}

			if reachable && p == 443 && req.TLSAnalyze {
				if tlsInfo, err := s.AnalyzeTLS(portCtx, req.Host, p); err == nil {
					result.TLS = tlsInfo
				}
			}

			if reachable && req.Challenge != "" && p == req.ChallengePort {
				result.Challenge = s.VerifyChallenge(portCtx, req.Host, p, req.Challenge, req.ChallengePath)
			}

			shouldGrabBanner := req.WantBanner || p == 22 || p == 21 || p == 25
			if reachable && shouldGrabBanner {
				if banner := s.GrabBanner(portCtx, req.Host, p); banner != "" {
					result.Banner = banner
				}
			}

			mu.Lock()
			results[fmt.Sprintf("%d", p)] = result
			mu.Unlock()
		}(port)
	}

	wg.Wait()
	return results
}
