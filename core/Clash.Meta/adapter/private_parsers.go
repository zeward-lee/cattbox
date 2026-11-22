package adapter

import (
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
)

// privateProxyFactory parses one vendor-private proxy type. Keeping the vendor
// cases in this registry means a new protocol is a factory plus a map entry
// here instead of another case in the upstream ParseProxy switch. The result is
// the raw async adapter (C.Proxy is the later wrapper around it).
type privateProxyFactory func(name string, mapping map[string]any, basicOption *outbound.BasicOption) (outbound.ProxyAdapter, error)

var privateProxyFactories = map[string]privateProxyFactory{
	"fastup":       newFastupProxy,
	"x365":         newX365Proxy,
	"shanlian":     newShanlianProxy,
	"miu":          newMiuProxy,
	"oppa":         newOppaProxy,
	"ninja":        newNinjaProxy,
	"xhttp":        newXHttpProxy,
	"sntp-eclipse": newSNTPEclipseProxy,
}

// newPrivateProxyDecoder matches the decoder ParseProxy builds for the core
// types (same tag name, weakly typed input and key replacer).
func newPrivateProxyDecoder() *structure.Decoder {
	return structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
}

// newFastupProxy implements `type: fastup`, the vendor's own name for the
// trojan wire: the #fastup password derivation plus a forced h2mux session.
// The marker may be omitted because the type implies it; the plain `trojan`
// case keeps accepting the old `password: ...#fastup` spelling. The mux can be
// opted out per node (see fastupMuxOptedOut), the password derivation stays
// either way because it belongs to the wire, not mux.
func newFastupProxy(_ string, mapping map[string]any, basicOption *outbound.BasicOption) (outbound.ProxyAdapter, error) {
	trojanOption := &outbound.TrojanOption{BasicOption: *basicOption}
	err := newPrivateProxyDecoder().Decode(mapping, trojanOption)
	if err != nil {
		return nil, err
	}
	trojanOption.Password = outbound.EnsureFastupPasswordMarker(trojanOption.Password)
	fastupAdapter, err := outbound.NewTrojan(*trojanOption)
	if err != nil {
		return nil, err
	}
	fastupAdapter.SetAdapterType(C.Fastup)
	if fastupMuxOptedOut(mapping) {
		return fastupAdapter, nil
	}
	proxy, err := outbound.NewSingMux(outbound.SingMuxOption{
		Enabled:  true,
		Protocol: "h2mux",
	}, fastupAdapter)
	if err != nil {
		return nil, err
	}
	return proxy, nil
}

// applyFastupTrojanHook supplies the Fastup behaviour for a bare
// `type: trojan` node whose password carries the #fastup marker: report the
// vendor identity instead of Trojan (the UI maps it to FastUP), and force the
// vendor's h2mux session unless the node opts out. The bool reports that the
// returned proxy is already muxed so the caller's `smux:` block must not wrap
// it a second time.
func applyFastupTrojanHook(trojanAdapter *outbound.Trojan, password string, mapping map[string]any) (outbound.ProxyAdapter, bool, error) {
	if !outbound.IsFastupTrojanPassword(password) {
		return trojanAdapter, false, nil
	}
	trojanAdapter.SetAdapterType(C.Fastup)
	if fastupMuxOptedOut(mapping) {
		return trojanAdapter, false, nil
	}
	proxy, err := outbound.NewSingMux(outbound.SingMuxOption{
		Enabled:  true,
		Protocol: "h2mux",
	}, trojanAdapter)
	if err != nil {
		return nil, false, err
	}
	return proxy, true, nil
}

func newX365Proxy(_ string, mapping map[string]any, basicOption *outbound.BasicOption) (outbound.ProxyAdapter, error) {
	x365Option := &outbound.X365Option{BasicOption: *basicOption}
	err := newPrivateProxyDecoder().Decode(mapping, x365Option)
	if err != nil {
		return nil, err
	}
	return outbound.NewX365(*x365Option)
}

// newShanlianProxy implements `type: shanlian`, the vendor's own name for the
// anytls wire with the Shanlian direct-authentication password. The "#sl"
// marker may be omitted because the type implies it; the plain `anytls` case
// keeps accepting the old `password: ...#SL` spelling. The type also selects
// the vendor bare-32-hex credential scheme, so a shanlian node published with a
// 32 hex password keeps working after the credential derivation became an
// explicit opt-in. A bare `type: anytls` node is only switched when it carries
// `password-mode: raw16` itself.
func newShanlianProxy(_ string, mapping map[string]any, basicOption *outbound.BasicOption) (outbound.ProxyAdapter, error) {
	anytlsOption := &outbound.AnyTLSOption{BasicOption: *basicOption}
	err := newPrivateProxyDecoder().Decode(mapping, anytlsOption)
	if err != nil {
		return nil, err
	}
	anytlsOption.ApplyShanlianTypeDefaults()
	shanlianAdapter, err := outbound.NewAnyTLS(*anytlsOption)
	if err != nil {
		return nil, err
	}
	shanlianAdapter.SetAdapterType(C.Shanlian)
	return shanlianAdapter, nil
}

func newMiuProxy(_ string, mapping map[string]any, basicOption *outbound.BasicOption) (outbound.ProxyAdapter, error) {
	miuOption := &outbound.MiuOption{BasicOption: *basicOption}
	err := newPrivateProxyDecoder().Decode(mapping, miuOption)
	if err != nil {
		return nil, err
	}
	return outbound.NewMiu(*miuOption)
}

func newOppaProxy(_ string, mapping map[string]any, basicOption *outbound.BasicOption) (outbound.ProxyAdapter, error) {
	oppaOption := &outbound.OppaOption{BasicOption: *basicOption}
	err := newPrivateProxyDecoder().Decode(mapping, oppaOption)
	if err != nil {
		return nil, err
	}
	return outbound.NewOppa(*oppaOption)
}

func newNinjaProxy(_ string, mapping map[string]any, basicOption *outbound.BasicOption) (outbound.ProxyAdapter, error) {
	ninjaOption := &outbound.NinjaOption{BasicOption: *basicOption}
	err := newPrivateProxyDecoder().Decode(mapping, ninjaOption)
	if err != nil {
		return nil, err
	}
	return outbound.NewNinja(*ninjaOption)
}

func newXHttpProxy(_ string, mapping map[string]any, basicOption *outbound.BasicOption) (outbound.ProxyAdapter, error) {
	xhttpOption := &outbound.XHttpOption{BasicOption: *basicOption}
	err := newPrivateProxyDecoder().Decode(mapping, xhttpOption)
	if err != nil {
		return nil, err
	}
	return outbound.NewXHttp(*xhttpOption)
}

// newSNTPEclipseProxy implements `type: sntp-eclipse`, the vendor's own
// SNTP-framed transport (X25519 + XChaCha20-Poly1305 over TCP). The kernel
// reports the identity as SNTP; the config type is the only accepted name.
func newSNTPEclipseProxy(_ string, mapping map[string]any, basicOption *outbound.BasicOption) (outbound.ProxyAdapter, error) {
	sntpEclipseOption := &outbound.SNTPEclipseOption{BasicOption: *basicOption}
	err := newPrivateProxyDecoder().Decode(mapping, sntpEclipseOption)
	if err != nil {
		return nil, err
	}
	return outbound.NewSNTPEclipse(*sntpEclipseOption)
}
