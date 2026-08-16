package util

import (
	"net"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	cases := map[string]bool{
		"10.0.0.1":        true,
		"192.168.1.5":     true,
		"172.16.0.1":      true,
		"127.0.0.1":       true,
		"169.254.1.1":     true,
		"100.64.0.1":      true, // CGNAT (RFC 6598)
		"100.127.255.254": true, // CGNAT upper bound
		"0.0.0.0":         true,
		"224.0.0.1":       true, // multicast
		"240.0.0.1":       true, // reserved
		"::1":             true,
		"fe80::1":         true,
		"fc00::1":         true,
		"ff02::1":         true, // multicast
		"8.8.8.8":         false,
		"1.1.1.1":         false,
		"100.63.255.255":  false, // just below CGNAT range
		"100.128.0.0":     false, // just above CGNAT range
		"2606:4700::1111": false,
	}
	for in, want := range cases {
		ip := net.ParseIP(in)
		if ip == nil {
			t.Fatalf("could not parse %q", in)
		}
		if got := IsPrivateIP(ip); got != want {
			t.Errorf("IsPrivateIP(%s) = %v, want %v", in, got, want)
		}
	}
}

func TestAnonymizeIP(t *testing.T) {
	cases := map[string]string{
		"203.0.113.45":         "203.0.113.0",
		"8.8.8.8":              "8.8.8.0",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1::",
		"not-an-ip":            "not-an-ip",
	}
	for in, want := range cases {
		if got := AnonymizeIP(in); got != want {
			t.Errorf("AnonymizeIP(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestAnonymizeIPDoesNotMutateInput(t *testing.T) {
	ip := net.ParseIP("2001:db8:1:2:3:4:5:6")
	before := ip.String()
	_ = AnonymizeIP(ip.String())
	if ip.String() != before {
		t.Errorf("AnonymizeIP mutated a shared IP: before %s, after %s", before, ip.String())
	}
}

func TestRateLimitKey(t *testing.T) {
	// IPv4: full address is the key.
	if got := RateLimitKey("203.0.113.9"); got != "203.0.113.9" {
		t.Errorf("RateLimitKey(v4) = %s, want 203.0.113.9", got)
	}
	// IPv6: two addresses in the same /64 collapse to the same key.
	a := RateLimitKey("2001:db8:abcd:1::1")
	b := RateLimitKey("2001:db8:abcd:1:ffff:ffff:ffff:ffff")
	if a != b {
		t.Errorf("same /64 produced different keys: %s vs %s", a, b)
	}
	// Different /64 must differ.
	c := RateLimitKey("2001:db8:abcd:2::1")
	if a == c {
		t.Errorf("different /64 produced same key: %s", a)
	}
	if a != "2001:db8:abcd:1::/64" {
		t.Errorf("RateLimitKey(v6) = %s, want 2001:db8:abcd:1::/64", a)
	}
}
