package api

import (
	"testing"

	"github.com/glinet/reflector/internal/config"
)

func newTestHandlers(allowed ...int) *Handlers {
	m := make(map[int]bool)
	for _, p := range allowed {
		m[p] = true
	}
	return &Handlers{cfg: config.Config{AllowedPorts: m}}
}

func TestParsePortsDefaultsRespectAllowlist(t *testing.T) {
	// 80 allowed, 443 not: the empty default must not scan 443.
	h := newTestHandlers(80)
	ports, err := h.parsePorts("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != 80 {
		t.Errorf("default ports = %v, want [80]", ports)
	}
}

func TestParsePortsDeduplicates(t *testing.T) {
	h := newTestHandlers(443)
	ports, err := h.parsePorts("443,443,443,443,443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != 443 {
		t.Errorf("ports = %v, want [443] (duplicates collapsed)", ports)
	}
}

func TestParsePortsRejections(t *testing.T) {
	h := newTestHandlers(80, 443, 8080, 8443, 22, 8081)
	for _, in := range []string{
		"abc",                      // not a number
		"70000",                    // out of range
		"25",                       // not allowed
		"80,443,8080,8443,22,8081", // more than 5 distinct
	} {
		if _, err := h.parsePorts(in); err == nil {
			t.Errorf("parsePorts(%q) = nil error, want error", in)
		}
	}
}

func TestParsePortsHappyPath(t *testing.T) {
	h := newTestHandlers(80, 443)
	ports, err := h.parsePorts("80,443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 2 {
		t.Errorf("ports = %v, want two ports", ports)
	}
}
