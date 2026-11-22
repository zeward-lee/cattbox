package outbound

// Live OIX Snell test. The endpoint comes from env vars; never commit real
// relays. With the required vars unset the test skips, so the repository only
// ever carries the RFC 5737 placeholder below.
//
//	MIHOMO_TEST_OIX_SERVER     relay host (placeholder default 192.0.2.1)
//	MIHOMO_TEST_OIX_PORT       relay port (default 14888)
//	MIHOMO_TEST_OIX_SNI        ECH front name (default example.invalid)
//	MIHOMO_TEST_OIX_PSK        snell psk, required
//	MIHOMO_TEST_OIX_ECH_CONFIG pinned ECH config list in base64, optional;
//	                           generated for the SNI when unset

import (
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
)

const (
	// RFC 5737 TEST-NET-1: a placeholder, never a routable relay.
	defaultOIXLiveServer = "192.0.2.1"
	defaultOIXLivePort   = "14888"
	defaultOIXLiveSNI    = "example.invalid"
)

func oixLiveEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func TestLiveOIXSnell(t *testing.T) {
	server := oixLiveEnv("MIHOMO_TEST_OIX_SERVER", defaultOIXLiveServer)
	if server == defaultOIXLiveServer {
		t.Skip("MIHOMO_TEST_OIX_SERVER is unset; the placeholder endpoint is not dialed")
	}
	psk := os.Getenv("MIHOMO_TEST_OIX_PSK")
	if psk == "" {
		t.Skip("MIHOMO_TEST_OIX_PSK is unset")
	}
	port, err := strconv.Atoi(oixLiveEnv("MIHOMO_TEST_OIX_PORT", defaultOIXLivePort))
	if err != nil {
		t.Fatalf("MIHOMO_TEST_OIX_PORT is not a number: %v", err)
	}
	sni := oixLiveEnv("MIHOMO_TEST_OIX_SNI", defaultOIXLiveSNI)
	echConfig := oixLiveEnv("MIHOMO_TEST_OIX_ECH_CONFIG", "")
	if echConfig == "" {
		echConfig, _, err = ech.GenECHConfig(sni)
		if err != nil {
			t.Fatalf("generate ECH config for %q: %v", sni, err)
		}
	}
	proxy, err := NewSnell(SnellOption{
		Name: "oix-live", Server: server, Port: port,
		Psk: psk, Version: 4, UDP: true,
		Identity: true, IdentityConfigured: true,
		ObfsOpts: map[string]any{
			"mode": "oix-ech-tls", "alpn": "snell-ech/1", "identity-version": 2,
			"legacy-fallback": false, "preconnect": 0, "sni": sni,
			"ech-config":       echConfig,
			"skip-cert-verify": false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "example.com", DstPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = conn.Write([]byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 64)
	n, err := conn.Read(response)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("OIX Snell returned no application data")
	}
}
