package util

import (
	"net"
	"net/http"
	"strings"
)

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

func IsPrivateIP(ip net.IP) bool {
	for _, block := range privateBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// GetIPVersion returns 4 or 6. We ensure mapped IPv4 are treated as IPv4.
func GetIPVersion(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	}
	return 6
}

// CleanIP converts an IPv4-mapped IPv6 address to a pure IPv4 address.
func CleanIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

func AnonymizeIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}

	ip = CleanIP(ip)

	if ip.To4() != nil {
		// IPv4: Set last octet to 0
		parts := strings.Split(ip.String(), ".")
		if len(parts) == 4 {
			parts[3] = "0"
			return strings.Join(parts, ".")
		}
		return ip.String()
	} else {
		// IPv6: Keep only the first 48 bits
		ip16 := ip.To16()
		if ip16 != nil {
			for i := 6; i < 16; i++ {
				ip16[i] = 0
			}
			return ip16.String()
		}
		return ipStr
	}
}

// isTrustedProxy checks if the given IP is within the trusted proxy list
func isTrustedProxy(ip net.IP, trustedProxies []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, block := range trustedProxies {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseTrustedProxies parses a list of CIDR strings into a slice of IPNet
func ParseTrustedProxies(proxies []string) []*net.IPNet {
	var trusted []*net.IPNet
	for _, cidr := range proxies {
		// If it's a single IP, add /32 or /128
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		_, block, err := net.ParseCIDR(cidr)
		if err == nil {
			trusted = append(trusted, block)
		}
	}
	return trusted
}

// GetClientIP securely retrieves the client IP from the request, respecting trusted proxies
func GetClientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	remoteIPStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIPStr = r.RemoteAddr
	}

	remoteIP := CleanIP(net.ParseIP(remoteIPStr))

	// If remote IP is not a trusted proxy, return it directly
	if !isTrustedProxy(remoteIP, trustedProxies) {
		if remoteIP != nil {
			return remoteIP.String()
		}
		return remoteIPStr
	}

	// Remote is trusted, parse headers
	var potentialIPs []string

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		for _, ip := range ips {
			potentialIPs = append(potentialIPs, strings.TrimSpace(ip))
		}
	}

	// Parse from right to left
	// [client, proxy1, proxy2] <- remoteAddr (proxy3)
	// We trust remoteAddr, so we check proxy2. If we trust proxy2, we check proxy1.
	for i := len(potentialIPs) - 1; i >= 0; i-- {
		ipStr := potentialIPs[i]
		ip := CleanIP(net.ParseIP(ipStr))
		
		if ip == nil {
			continue // Invalid IP in header
		}

		if !isTrustedProxy(ip, trustedProxies) {
			return ip.String() // Found the first untrusted IP
		}
	}

	// If all IPs in X-Forwarded-For are trusted, or no header, check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := CleanIP(net.ParseIP(xri))
		if ip != nil && !isTrustedProxy(ip, trustedProxies) {
			return ip.String()
		}
	}

	// Fallback to the furthest known proxy
	if len(potentialIPs) > 0 {
		firstIP := CleanIP(net.ParseIP(potentialIPs[0]))
		if firstIP != nil {
			return firstIP.String()
		}
	}

	if remoteIP != nil {
		return remoteIP.String()
	}
	return remoteIPStr
}
