package adapter

import (
	"fmt"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	shadowsockscipher "github.com/metacubex/sing-shadowsocks2/cipher"
)

// defaultBlackstoneCipher is the cipher the vendor client assumes for a
// blackstone-over-SS node that carries no cipher ("os" in its API).
const defaultBlackstoneCipher = "aes-128-ctr"

func ParseProxy(mapping map[string]any, options ...ProxyOption) (C.Proxy, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	proxyType, existType := mapping["type"].(string)
	if !existType {
		return nil, fmt.Errorf("missing type")
	}

	opt := applyProxyOptions(options...)
	basicOption := outbound.BasicOption{
		DialerForAPI: opt.DialerForAPI,
		TunnelForAPI: opt.TunnelForAPI,
		ProviderName: opt.ProviderName,
	}

	var (
		proxy outbound.ProxyAdapter
		err   error
		// forcedFastupMux records that the Fastup variant already wrapped the
		// trojan proxy in sing-mux, so a user `smux:` block must not wrap it a
		// second time.
		forcedFastupMux bool
		// dynamicXhttp keeps the adapter of a dynamic xhttp node so it can be
		// wrapped for URL testing after the generic wrapping below.
		dynamicXhttp *outbound.XHttp
	)
	switch proxyType {
	case "ss":
		// A #BLACKSTONE password is the vendor's blackstone-over-SS variant: the
		// cipher registry in the sing-shadowsocks2 fork strips the marker and
		// changes the handshake. Nodes pasted from a vendor subscription often
		// omit the cipher (the API calls it "os"); the vendor client defaults it
		// to aes-128-ctr, so do the same before the decoder rejects the node for
		// a missing required field.
		if password, ok := mapping["password"].(string); ok {
			if clean, blackstone := shadowsockscipher.ParseBlackstonePassword(password); blackstone {
				if clean == "" {
					err = fmt.Errorf("blackstone ss node has an empty password")
					break
				}
				if cipher, _ := mapping["cipher"].(string); cipher == "" {
					mapping["cipher"] = defaultBlackstoneCipher
				}
				if cipher, _ := mapping["cipher"].(string); !outbound.SupportsBlackstoneCipher(cipher) {
					// The classic AEAD family has no blackstone wire; the marker
					// would end up in the key and the server would drop the node
					// with no local error.
					err = fmt.Errorf("blackstone ss node requires a 2022-blake3-* or stream cipher, got %q", cipher)
					break
				}
				log.Debugln("[SS](%v) blackstone-over-ss node", mapping["name"])
			}
		}
		ssOption := &outbound.ShadowSocksOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, ssOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowSocks(*ssOption)
	case "ssr":
		ssrOption := &outbound.ShadowSocksROption{BasicOption: basicOption}
		err = decoder.Decode(mapping, ssrOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowSocksR(*ssrOption)
	case "socks5":
		socksOption := &outbound.Socks5Option{BasicOption: basicOption}
		err = decoder.Decode(mapping, socksOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSocks5(*socksOption)
	case "http":
		httpOption := &outbound.HttpOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, httpOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewHttp(*httpOption)
	case "vmess":
		vmessOption := &outbound.VmessOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, vmessOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewVmess(*vmessOption)
	case "vless":
		vlessOption := &outbound.VlessOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, vlessOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewVless(*vlessOption)
	case "snell":
		snellOption := &outbound.SnellOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, snellOption)
		if err != nil {
			break
		}
		// A bool cannot tell "identity: false" from an absent key; the OIX modes
		// reject an explicit disable, so the presence of the key is recorded.
		_, snellOption.IdentityConfigured = mapping["identity"]
		proxy, err = outbound.NewSnell(*snellOption)
	case "trojan":
		trojanOption := &outbound.TrojanOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, trojanOption)
		if err != nil {
			break
		}
		var trojanAdapter *outbound.Trojan
		trojanAdapter, err = outbound.NewTrojan(*trojanOption)
		if err != nil {
			break
		}
		// A bare `type: trojan` whose password carries the #fastup marker is the
		// old spelling of the Fastup variant: the hook reports the vendor
		// identity and forces the vendor's h2mux session unless the node opts
		// out (see fastupMuxOptedOut).
		proxy, forcedFastupMux, err = applyFastupTrojanHook(trojanAdapter, trojanOption.Password, mapping)
		if err != nil {
			break
		}
	case "hysteria":
		hyOption := &outbound.HysteriaOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, hyOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewHysteria(*hyOption)
	case "hysteria2":
		hyOption := &outbound.Hysteria2Option{BasicOption: basicOption}
		err = decoder.Decode(mapping, hyOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewHysteria2(*hyOption)
	case "wireguard":
		wgOption := &outbound.WireGuardOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, wgOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewWireGuard(*wgOption)
	case "tuic":
		tuicOption := &outbound.TuicOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, tuicOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTuic(*tuicOption)
	case "shadowquic":
		shadowQuicOption := &outbound.ShadowQuicOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, shadowQuicOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewShadowQuic(*shadowQuicOption)
	case "gost-relay":
		relayOption := &outbound.GostRelayOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, relayOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewGostRelay(*relayOption)
	case "direct":
		directOption := &outbound.DirectOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, directOption)
		if err != nil {
			break
		}
		proxy = outbound.NewDirectWithOption(*directOption)
	case "dns":
		dnsOptions := &outbound.DnsOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, dnsOptions)
		if err != nil {
			break
		}
		proxy = outbound.NewDnsWithOption(*dnsOptions)
	case "reject":
		rejectOption := &outbound.RejectOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, rejectOption)
		if err != nil {
			break
		}
		proxy = outbound.NewRejectWithOption(*rejectOption)
	case "rematch":
		rematchOption := &outbound.RematchOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, rematchOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewRematch(*rematchOption)
	case "ssh":
		sshOption := &outbound.SshOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, sshOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSsh(*sshOption)
	case "mieru":
		mieruOption := &outbound.MieruOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, mieruOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewMieru(*mieruOption)
	case "anytls":
		anytlsOption := &outbound.AnyTLSOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, anytlsOption)
		if err != nil {
			break
		}
		var anytlsAdapter *outbound.AnyTLS
		anytlsAdapter, err = outbound.NewAnyTLS(*anytlsOption)
		if err != nil {
			break
		}
		// A bare `type: anytls` whose password carries the Shanlian marker
		// (#sl over the 64 hex key) is the old spelling of the Shanlian
		// variant, so report the vendor identity: the UI maps it to 闪连.
		if outbound.IsShanlianPassword(anytlsOption.Password) {
			anytlsAdapter.SetAdapterType(C.Shanlian)
		}
		proxy = anytlsAdapter
	case "sudoku":
		sudokuOption := &outbound.SudokuOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, sudokuOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewSudoku(*sudokuOption)
	case "masque":
		masqueOption := &outbound.MasqueOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, masqueOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewMasque(*masqueOption)
	case "trusttunnel":
		trustTunnelOption := &outbound.TrustTunnelOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, trustTunnelOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTrustTunnel(*trustTunnelOption)
	case "openvpn":
		openVPNOption := &outbound.OpenVPNOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, openVPNOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewOpenVPN(*openVPNOption)
	case "tailscale":
		tailscaleOption := &outbound.TailscaleOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, tailscaleOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewTailscale(*tailscaleOption)
	case "zerotier":
		zeroTierOption := &outbound.ZeroTierOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, zeroTierOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewZeroTier(*zeroTierOption)
	case "easytier":
		easyTierOption := &outbound.EasyTierOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, easyTierOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewEasyTier(*easyTierOption)
	default:
		// Vendor-private types live in private_parsers.go so adding one does
		// not touch this upstream switch.
		factory, private := privateProxyFactories[proxyType]
		if !private {
			return nil, fmt.Errorf("unsupport proxy type: %s", proxyType)
		}
		name, _ := mapping["name"].(string)
		privateProxy, factoryErr := factory(name, mapping, &basicOption)
		if factoryErr != nil {
			return nil, factoryErr
		}
		proxy = privateProxy
		// Fastup is the only private factory that wraps its adapter in the
		// vendor's h2mux session; record it so the `smux:` block below does not
		// wrap the node a second time.
		if _, fastupMuxed := proxy.(*outbound.SingMux); fastupMuxed {
			forcedFastupMux = true
		}
		// A dynamic xhttp node resolves its real server at first use, so keep
		// its adapter for the URL-test wrapper below.
		if xhttpAdapter, isXHttp := proxy.(*outbound.XHttp); isXHttp && xhttpAdapter.IsDynamic() {
			dynamicXhttp = xhttpAdapter
		}
	}

	if err != nil {
		return nil, err
	}

	if muxMapping, muxExist := mapping["smux"].(map[string]any); muxExist && !forcedFastupMux {
		muxOption := &outbound.SingMuxOption{}
		err = decoder.Decode(muxMapping, muxOption)
		if err != nil {
			return nil, err
		}
		if muxOption.Enabled {
			proxy, err = outbound.NewSingMux(*muxOption, proxy)
			if err != nil {
				return nil, err
			}
		}
	}

	proxy = outbound.NewAutoCloseProxyAdapter(proxy)
	built := NewProxy(proxy)
	// A dynamic xhttp node resolves its real server at first use, so its URL
	// test pings the configured address instead of spending an API round trip.
	if dynamicXhttp != nil {
		return outbound.NewXHttpProxyWrapper(built, dynamicXhttp), nil
	}
	return built, nil
}

// fastupMuxOptedOut reports whether a Fastup node explicitly asks for the
// plain trojan wire instead of the vendor's forced h2mux session. The canonical
// mihomo spelling is a disabled per-proxy `smux` block; `mux: false` is accepted
// as a Fastup-only shorthand because the variant otherwise hard-wires mux and
// there is no other way to turn it off. A bare `smux: false` is honoured too:
// the API serialises ProxyInfo.SMUX as a bool under that key, so a node that was
// round-tripped through the UI keeps the opt-out. Telegram/MTProto is the known
// victim of that mux on some servers, hence the escape hatch.
func fastupMuxOptedOut(mapping map[string]any) bool {
	if mux, ok := mapping["mux"].(bool); ok && !mux {
		return true
	}
	switch smuxValue := mapping["smux"].(type) {
	case bool:
		return !smuxValue
	case map[string]any:
		enabled, ok := smuxValue["enabled"].(bool)
		return ok && !enabled
	}
	return false
}

type proxyOption struct {
	DialerForAPI C.Dialer
	TunnelForAPI C.Tunnel
	ProviderName string
}

func applyProxyOptions(options ...ProxyOption) proxyOption {
	opt := proxyOption{}
	for _, o := range options {
		o(&opt)
	}
	return opt
}

type ProxyOption func(opt *proxyOption)

func WithDialerForAPI(dialer C.Dialer) ProxyOption {
	return func(opt *proxyOption) {
		opt.DialerForAPI = dialer
	}
}

func WithTunnelForAPI(tunnel C.Tunnel) ProxyOption {
	return func(opt *proxyOption) {
		opt.TunnelForAPI = tunnel
	}
}

func WithProviderName(name string) ProxyOption {
	return func(opt *proxyOption) {
		opt.ProviderName = name
	}
}
