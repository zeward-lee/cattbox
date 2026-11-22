package outbound

// The OIX enhancement of the snell client (psk suffix #oix, optional ech-tls
// front) is fork-only. Its helpers live here so the upstream snell.go keeps
// only the call sites, which keeps that file close to its upstream shape.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/component/ech/echparser"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/snell"
	"github.com/metacubex/mihomo/transport/vmess"
)

// snellECHTLSOption is the obfs-opts table of the OIX ech-tls mode. It is
// decoded separately from simpleObfsOption because the keys describe a TLS
// front, not a simple-obfs header.
type snellECHTLSOption struct {
	Mode              string `obfs:"mode,omitempty"`
	ALPN              string `obfs:"alpn,omitempty"`
	Protocol          string `obfs:"protocol,omitempty"`
	IdentityVersion   int    `obfs:"identity-version,omitempty"`
	LegacyFallback    bool   `obfs:"legacy-fallback,omitempty"`
	Preconnect        int    `obfs:"preconnect,omitempty"`
	Host              string `obfs:"host,omitempty"`
	SNI               string `obfs:"sni,omitempty"`
	Path              string `obfs:"path,omitempty"`
	ECHConfig         string `obfs:"ech-config,omitempty"`
	ECHConfigFile     string `obfs:"ech-config-file,omitempty"`
	CAFile            string `obfs:"ca-file,omitempty"`
	Insecure          bool   `obfs:"insecure,omitempty"`
	Fingerprint       string `obfs:"fingerprint,omitempty"`
	ClientFingerprint string `obfs:"client-fingerprint,omitempty"`
	Certificate       string `obfs:"certificate,omitempty"`
	PrivateKey        string `obfs:"private-key,omitempty"`
	SkipCertVerify    bool   `obfs:"skip-cert-verify,omitempty"`
	NameCertVerify    string `obfs:"name-cert-verify,omitempty"`
}

const defaultSnellClientFingerprint = "chrome"

const (
	snellECHTLSALPN         = "snell-ech/1"
	snellECHTLSPreviousALPN = "oix-snell/1"
	snellECHTLSLegacyALPN   = "h2"

	// snellOIXSuffix marks a node whose psk travels with the OIX identity header.
	snellOIXSuffix = "#oix"
)

// splitSnellOIXPSK strips the #oix suffix. The marker is case sensitive: the
// vendor app compares the exact literal, and a psk may legitimately contain '#'
// inside a key.
func splitSnellOIXPSK(psk string) (string, bool) {
	if !strings.HasSuffix(psk, snellOIXSuffix) {
		return psk, false
	}
	return strings.TrimSuffix(psk, snellOIXSuffix), true
}

func isSnellECHTLSMode(mode string) bool {
	return mode == "ech-tls"
}

// resolveSnellECHTLSALPN reconciles the alpn and protocol keys of the ech-tls
// obfs block. The previous protocol name is accepted as an alias so a node does
// not need editing when the front moves to the new name.
func resolveSnellECHTLSALPN(alpn, protocol string) (string, error) {
	if protocol == snellECHTLSPreviousALPN {
		protocol = snellECHTLSALPN
	}
	if alpn != "" && protocol != "" && alpn != protocol {
		return "", errors.New("ech-tls alpn and legacy protocol values conflict")
	}
	if alpn == "" {
		alpn = protocol
	}
	if alpn == "" {
		alpn = snellECHTLSALPN
	}
	if alpn != snellECHTLSALPN {
		return "", fmt.Errorf("unsupported ech-tls ALPN: %s", alpn)
	}
	return alpn, nil
}

func snellECHTLSHost(obfsOption *snellECHTLSOption, server string) string {
	if obfsOption.SNI != "" {
		return obfsOption.SNI
	}
	if obfsOption.Host != "" {
		return obfsOption.Host
	}
	return server
}

func resolveSnellClientFingerprint(obfsOption *snellECHTLSOption, option SnellOption) string {
	if obfsOption.ClientFingerprint != "" {
		return obfsOption.ClientFingerprint
	}
	if option.ClientFingerprint != "" {
		return option.ClientFingerprint
	}
	return defaultSnellClientFingerprint
}

// snellECHTLSConfig turns the ech-config / ech-config-file key into the ECH
// client config. The list is pinned, so a hostile DNS answer cannot swap it.
func snellECHTLSConfig(obfsOption *snellECHTLSOption) (*ech.Config, error) {
	if obfsOption.ECHConfig != "" && obfsOption.ECHConfigFile != "" {
		return nil, fmt.Errorf("ech-config and ech-config-file are mutually exclusive")
	}
	if obfsOption.ECHConfig == "" && obfsOption.ECHConfigFile == "" {
		return nil, fmt.Errorf("ech-tls requires ech-config or ech-config-file")
	}

	var list []byte
	var err error
	if obfsOption.ECHConfig != "" {
		list, err = base64.StdEncoding.DecodeString(strings.TrimSpace(obfsOption.ECHConfig))
		if err != nil {
			return nil, fmt.Errorf("base64 decode ech-config failed: %w", err)
		}
	} else {
		path := C.Path.Resolve(obfsOption.ECHConfigFile)
		if !C.Path.IsSafePath(path) {
			return nil, C.Path.ErrNotSafePath(path)
		}
		list, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read ech-config-file failed: %w", err)
		}
	}
	if configs, parseErr := echparser.ParseECHConfigList(list); parseErr != nil {
		return nil, fmt.Errorf("parse ech config list failed: %w", parseErr)
	} else if len(configs) == 0 {
		return nil, fmt.Errorf("ech config list is empty")
	}

	return &ech.Config{
		GetEncryptedClientHelloConfigList: func(context.Context, string) ([]byte, error) {
			return list, nil
		},
	}, nil
}

// requiresSnellV4Identity reports whether the obfs layer already binds the
// session to the psk, which forces the v4 identity transport on.
//
// Only the OIX ech-tls front does: it is the enhancement path and its server
// expects the identity header. A plain shadow-tls front is an upstream feature
// and keeps the native handshake, so a stock snell server behind shadow-tls
// still works.
func requiresSnellV4Identity(obfsMode string) bool {
	return isSnellECHTLSMode(obfsMode)
}

// snellStreamConn wraps c with the OIX identity header when the node asks for
// it, and falls back to a plain snell stream otherwise.
func (s *Snell) snellStreamConn(c net.Conn) (*snell.Snell, error) {
	if s.version == snell.Version6 {
		return snell.StreamConnV6(c, s.psk, s.v6Mode), nil
	}
	if !s.identity || s.version != snell.Version4 {
		return snell.StreamConn(c, s.psk, s.version), nil
	}
	if !isSnellECHTLSMode(s.obfsOption.Mode) {
		return snell.StreamConnWithIdentity(c, s.psk, s.version), nil
	}
	state := tlsC.GetTLSConnectionState(c)
	if !state.ECHAccepted {
		return nil, errors.New("snell ech-tls handshake did not accept ECH")
	}
	if state.NegotiatedProtocol == snellECHTLSLegacyALPN && !s.echTLSLegacyFallback {
		return nil, errors.New("snell ech-tls legacy ALPN was not enabled")
	}
	if state.NegotiatedProtocol != snellECHTLSALPN && state.NegotiatedProtocol != snellECHTLSLegacyALPN {
		return nil, fmt.Errorf("snell ech-tls negotiated ALPN %q", state.NegotiatedProtocol)
	}
	if state.NegotiatedProtocol == snellECHTLSALPN && s.echTLSIdentityVersion == 2 {
		exporter, err := state.ExportKeyingMaterial(
			snell.IdentityExporterLabel,
			[]byte{},
			snell.IdentityExporterLength,
		)
		if err != nil {
			return nil, fmt.Errorf("snell ech-tls exporter: %w", err)
		}
		return snell.StreamConnWithExporterIdentity(c, s.psk, s.version, exporter), nil
	}
	return snell.StreamConnWithIdentity(c, s.psk, s.version), nil
}

// dialSnellTransport dials the server and applies the TLS front of the OIX
// ech-tls mode. The simple-obfs / shadow-tls / restls / jls layers stay in
// streamConnContext, where they run on top of this conn.
func (s *Snell) dialSnellTransport(ctx context.Context) (net.Conn, error) {
	c, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}
	if s.echTLS == nil {
		return c, nil
	}
	tlsConn, err := vmess.StreamTLSConn(ctx, c, s.echTLS)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("%s ech-tls connect error: %w", s.addr, err)
	}
	return tlsConn, nil
}
