package scanner

import (
	"context"
	"testing"
	"time"
)

// TestVerifyChallengeRejectsMaliciousPath ensures the SSRF hardening rejects
// paths that could redirect the request to another host BEFORE any network call.
func TestVerifyChallengeRejectsMaliciousPath(t *testing.T) {
	s := NewScanner(time.Second)
	ctx := context.Background()

	malicious := []string{
		"@169.254.169.254/latest/meta-data/", // userinfo host override -> cloud metadata
		"@127.0.0.1:8080/health",             // loopback
		"@evil.example.com/x",
		"/path?next=@x", // query
		"/path#@x",      // fragment
		"\\@x",          // backslash / not absolute
		"relative/path", // not absolute
	}
	for _, p := range malicious {
		res := s.VerifyChallenge(ctx, "203.0.113.7", 80, "tok", p)
		if res.Verified || res.Error != "invalid_challenge_path" {
			t.Errorf("VerifyChallenge(path=%q) = %+v, want invalid_challenge_path", p, res)
		}
	}
}

func TestFormatHostPort(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7": "203.0.113.7:443",
		"2001:db8::1": "[2001:db8::1]:443",
	}
	for host, want := range cases {
		if got := formatHostPort(host, 443); got != want {
			t.Errorf("formatHostPort(%s) = %s, want %s", host, got, want)
		}
	}
}

func TestSanitizeBannerStripsControlChars(t *testing.T) {
	in := "SSH-2.0-OpenSSH_9.6\x00\x01 evil"
	got := sanitizeBanner(in)
	for _, r := range got {
		if r < 32 && r != '\t' {
			t.Errorf("sanitizeBanner left a control char %q in %q", r, got)
		}
	}
}
