package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/jls"
	"github.com/metacubex/mihomo/transport/restls"
	"github.com/metacubex/mihomo/transport/shadowtls"
	obfs "github.com/metacubex/mihomo/transport/simple-obfs"
	"github.com/metacubex/mihomo/transport/snell"
	"github.com/metacubex/mihomo/transport/vmess"
)

type Snell struct {
	*Base
	option          *SnellOption
	psk             []byte
	userKey         []byte
	pool            *snell.Pool
	obfsOption      *simpleObfsOption
	shadowTLSOption *shadowtls.ShadowTLSOption
	restlsConfig    *restls.Config
	jlsConfig       *jls.ClientConfig
	version         int
	v6Mode          snell.V6Mode
	reuse           bool

	// OIX enhancement (psk suffix #oix, optionally with an ECH TLS front).
	oix                   bool
	identity              bool
	echTLS                *vmess.TLSConfig
	echTLSIdentityVersion int
	echTLSLegacyFallback  bool
}

type SnellOption struct {
	BasicOption
	Name              string         `proxy:"name"`
	Server            string         `proxy:"server"`
	Port              int            `proxy:"port"`
	Psk               string         `proxy:"psk"`
	UserKey           string         `proxy:"userkey,omitempty"`
	UDP               bool           `proxy:"udp,omitempty"`
	Version           int            `proxy:"version,omitempty"`
	Reuse             bool           `proxy:"reuse,omitempty"`
	Mode              string         `proxy:"mode,omitempty"` // v6 only: default / unshaped / unsafe-raw
	ObfsOpts          map[string]any `proxy:"obfs-opts,omitempty"`
	ClientFingerprint string         `proxy:"client-fingerprint,omitempty"`

	// Identity enables the OIX v1 identity header on a v4 node. It is turned on
	// automatically by ech-tls and shadow-tls, and cannot be turned off there;
	// IdentityConfigured records whether the operator set the key at all, so
	// "identity: false" is distinguishable from an absent key.
	Identity           bool `proxy:"identity,omitempty"`
	IdentityConfigured bool `proxy:"-"`

	// Flat OIX dialect emitted by NekoBox compatible exporters.
	OIXECH             bool   `proxy:"oix_ech,omitempty"`
	OIXIdentityVersion int    `proxy:"oix_identity_version,omitempty"`
	OIXALPN            string `proxy:"oix_alpn,omitempty"`
	OIXLegacyFallback  bool   `proxy:"oix_legacy_fallback,omitempty"`
	OIXPreconnect      int    `proxy:"oix_preconnect,omitempty"`
	OIXSNI             string `proxy:"oix_sni,omitempty"`
	OIXConfig          string `proxy:"oix_config,omitempty"`
}

func (s *Snell) streamConnContext(ctx context.Context, c net.Conn) (*snell.Snell, error) {
	var err error
	switch s.obfsOption.Mode {
	case "tls":
		c = obfs.NewTLSObfs(c, s.obfsOption.Host)
	case "http":
		_, port, _ := net.SplitHostPort(s.addr)
		c = obfs.NewHTTPObfs(c, s.obfsOption.Host, port)
	case shadowtls.Mode:
		c, err = shadowtls.NewShadowTLS(ctx, c, s.shadowTLSOption)
		if err != nil {
			return nil, err
		}
	case restls.Mode:
		c, err = restls.NewRestls(ctx, c, s.restlsConfig)
		if err != nil {
			return nil, err
		}
	case jls.Mode:
		c, err = jls.NewClient(ctx, c, s.jlsConfig)
		if err != nil {
			return nil, err
		}
	}
	return s.snellStreamConn(c)
}

// StreamConnContext implements C.ProxyAdapter
func (s *Snell) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	c, err := s.streamConnContext(ctx, c)
	if err != nil {
		return nil, err
	}
	err = s.writeHeaderContext(ctx, c, metadata)
	return c, err
}

func (s *Snell) writeHeaderContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, c)
		defer done(&err)
	}

	if metadata.NetWork == C.UDP {
		err = snell.WriteUDPHeader(c, s.version, s.userKey)
		if err == nil && s.version >= snell.Version4 {
			if sc, ok := c.(*snell.Snell); ok {
				err = sc.ReadReply()
			}
		}
		return
	}
	err = snell.WriteHeader(c, metadata.String(), metadata.DstPort, s.version, s.reuse, s.userKey)
	return
}

// DialContext implements C.ProxyAdapter
func (s *Snell) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if s.reuse {
		c, err := s.pool.Get()
		if err != nil {
			return nil, err
		}

		if err = s.writeHeaderContext(ctx, c, metadata); err != nil {
			_ = c.Close()
			return nil, err
		}
		if pc, ok := c.(*snell.PoolConn); ok {
			pc.MarkReusable()
		}
		return NewConn(c, s), err
	}

	c, err := s.dialSnellTransport(ctx)
	if err != nil {
		return nil, err
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = s.StreamConnContext(ctx, c, metadata)
	return NewConn(c, s), err
}

// ListenPacketContext implements C.ProxyAdapter
func (s *Snell) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = s.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	c, err := s.dialSnellTransport(ctx)
	if err != nil {
		return nil, err
	}

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = s.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, err
	}

	pc := snell.PacketConn(c)
	return NewPacketConn(pc, s), nil
}

// SupportUOT implements C.ProxyAdapter
func (s *Snell) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (s *Snell) ProxyInfo() C.ProxyInfo {
	info := s.Base.ProxyInfo()
	info.DialerProxy = s.option.DialerProxy
	return info
}

func NewSnell(option SnellOption) (*Snell, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	cleanPSK, oix := splitSnellOIXPSK(option.Psk)
	if oix && cleanPSK == "" {
		return nil, fmt.Errorf("snell %s oix psk is empty", addr)
	}
	option.Psk = cleanPSK
	psk := []byte(cleanPSK)

	decoder := structure.NewDecoder(structure.Option{TagName: "obfs", WeaklyTypedInput: true})
	obfsOption := &simpleObfsOption{Host: "bing.com"}
	if err := decoder.Decode(option.ObfsOpts, obfsOption); err != nil {
		return nil, fmt.Errorf("snell %s initialize obfs error: %w", addr, err)
	}
	// The ech-tls mode is a TLS front, not a simple-obfs header, so its keys are
	// decoded into their own table.
	echOpt := &snellECHTLSOption{}
	if obfsOption.Mode == "ech-tls" || obfsOption.Mode == "oix-ech-tls" {
		if err := decoder.Decode(option.ObfsOpts, echOpt); err != nil {
			return nil, fmt.Errorf("snell %s initialize ech-tls error: %w", addr, err)
		}
		if obfsOption.Mode == "oix-ech-tls" {
			// The NekoBox compatible exporter names the mode after the node.
			obfsOption.Mode = "ech-tls"
			oix = true
		}
	}
	// Normalize the flat OIX dialect on top of whatever the obfs block said.
	if option.OIXECH {
		oix = true
		if obfsOption.Mode == "" {
			obfsOption.Mode = "ech-tls"
			if err := decoder.Decode(option.ObfsOpts, echOpt); err != nil {
				return nil, fmt.Errorf("snell %s initialize ech-tls error: %w", addr, err)
			}
		}
	}
	if option.OIXIdentityVersion != 0 {
		echOpt.IdentityVersion = option.OIXIdentityVersion
	}
	if option.OIXALPN != "" {
		echOpt.ALPN = option.OIXALPN
	}
	if option.OIXLegacyFallback {
		echOpt.LegacyFallback = true
	}
	if option.OIXPreconnect != 0 {
		echOpt.Preconnect = option.OIXPreconnect
	}
	if option.OIXSNI != "" {
		echOpt.SNI = option.OIXSNI
	}
	if option.OIXConfig != "" {
		echOpt.ECHConfig = option.OIXConfig
	}

	var shadowTLSOpt *shadowtls.ShadowTLSOption
	var restlsConfig *restls.Config
	var jlsConfig *jls.ClientConfig
	switch obfsOption.Mode {
	case "tls", "http", "ech-tls", "":
		break
	case shadowtls.Mode:
		opt := &shadowTLSOption{
			Version: 2,
		}
		if err := decoder.Decode(option.ObfsOpts, opt); err != nil {
			return nil, fmt.Errorf("snell %s initialize shadow-tls-plugin error: %w", addr, err)
		}

		shadowTLSOpt = &shadowtls.ShadowTLSOption{
			Password:          opt.Password,
			Host:              opt.Host,
			Fingerprint:       opt.Fingerprint,
			Certificate:       opt.Certificate,
			PrivateKey:        opt.PrivateKey,
			ClientFingerprint: option.ClientFingerprint,
			SkipCertVerify:    opt.SkipCertVerify,
			NameCertVerify:    opt.NameCertVerify,
			Version:           opt.Version,
		}

		if opt.ALPN != nil { // structure's Decode will ensure value not nil when input has value even it was set an empty array
			shadowTLSOpt.ALPN = opt.ALPN
		} else {
			shadowTLSOpt.ALPN = shadowtls.DefaultALPN
		}
	case restls.Mode:
		opt := &restlsOption{}
		if err := decoder.Decode(option.ObfsOpts, opt); err != nil {
			return nil, fmt.Errorf("snell %s initialize restls-plugin error: %w", addr, err)
		}

		var err error
		restlsConfig, err = restls.NewRestlsConfig(opt.Host, opt.Password, opt.VersionHint, opt.RestlsScript, option.ClientFingerprint)
		if err != nil {
			return nil, fmt.Errorf("snell %s initialize restls-plugin error: %w", addr, err)
		}
		restlsConfig.InsecureSkipVerify = opt.SkipCertVerify
		if opt.Fingerprint != "" {
			if err = restls.SetFingerprint(restlsConfig, opt.Fingerprint, opt.NameCertVerify); err != nil {
				return nil, fmt.Errorf("snell %s initialize restls-plugin error: %w", addr, err)
			}
		} else if opt.NameCertVerify != "" {
			restls.SetNameCertVerify(restlsConfig, opt.NameCertVerify)
		}
		restlsConfig.ForceTLS12 = opt.ForceTLS12
	case jls.Mode:
		opt := &jlsOption{}
		if err := decoder.Decode(option.ObfsOpts, opt); err != nil {
			return nil, fmt.Errorf("snell %s initialize jls-plugin error: %w", addr, err)
		}

		var err error
		jlsConfig, err = jls.NewClientConfig(opt.Host, opt.Username, opt.Password, opt.ALPN)
		if err != nil {
			return nil, fmt.Errorf("snell %s initialize jls-plugin error: %w", addr, err)
		}
		jlsConfig.ClientFingerprint = option.ClientFingerprint
	default:
		return nil, fmt.Errorf("snell %s obfs mode error: %s", addr, obfsOption.Mode)
	}

	if isSnellECHTLSMode(obfsOption.Mode) {
		if !oix {
			return nil, fmt.Errorf("snell %s ech-tls requires psk suffix %s", addr, snellOIXSuffix)
		}
		alpn, err := resolveSnellECHTLSALPN(echOpt.ALPN, echOpt.Protocol)
		if err != nil {
			return nil, fmt.Errorf("snell %s %w", addr, err)
		}
		echOpt.ALPN = alpn
		if echOpt.IdentityVersion == 0 {
			echOpt.IdentityVersion = 2
		}
		if echOpt.IdentityVersion != 1 && echOpt.IdentityVersion != 2 {
			return nil, fmt.Errorf("snell %s unsupported identity version: %d", addr, echOpt.IdentityVersion)
		}
		if echOpt.Preconnect < 0 || echOpt.Preconnect > 4 {
			return nil, fmt.Errorf("snell %s preconnect must be between 0 and 4", addr)
		}
		echOpt.Host = snellECHTLSHost(echOpt, option.Server)
		echOpt.SkipCertVerify = echOpt.SkipCertVerify || echOpt.Insecure
		if echOpt.SkipCertVerify {
			return nil, fmt.Errorf("snell %s %s requires certificate verification", addr, snellECHTLSALPN)
		}
		if echOpt.CAFile != "" {
			return nil, fmt.Errorf("snell %s ca-file is not supported for ech-tls", addr)
		}
	}

	identity := option.Identity
	if requiresSnellV4Identity(obfsOption.Mode) {
		if option.IdentityConfigured && !option.Identity {
			return nil, fmt.Errorf("snell %s identity cannot be disabled with ech-tls", addr)
		}
		identity = true
	}

	// backward compatible
	if option.Version == 0 {
		if requiresSnellV4Identity(obfsOption.Mode) {
			option.Version = snell.Version4
		} else {
			option.Version = snell.DefaultSnellVersion
		}
	}
	if option.Version == snell.Version5 {
		// Snell v5 servers are backward-compatible with v4 clients.
		option.Version = snell.Version4
	}
	userKey := []byte(option.UserKey)
	if len(userKey) > snell.MaxClientIDLength {
		return nil, fmt.Errorf("snell %s userkey must be at most 255 bytes", addr)
	}
	if len(userKey) > 0 && option.Version != snell.Version6 {
		return nil, fmt.Errorf("snell %s userkey is only supported on version 6", addr)
	}
	// An OIX v4 node keeps its session reusable by default: the identity header
	// makes a warm session cheap, and the vendor client prewarms one per node.
	reuse := option.Version == snell.Version2 ||
		((option.Version == snell.Version4 || option.Version == snell.Version6) && (option.Reuse || oix))
	var v6Mode snell.V6Mode
	switch option.Version {
	case snell.Version1, snell.Version2:
		if option.UDP {
			return nil, fmt.Errorf("snell version %d not support UDP", option.Version)
		}
	case snell.Version3, snell.Version4:
	case snell.Version6:
		if err := snell.ValidateV6PSK(psk); err != nil {
			return nil, fmt.Errorf("snell %s %w", addr, err)
		}
		switch obfsOption.Mode {
		case "tls", "http":
			// v6 replaced the simple-obfs layer with PSK-derived traffic shaping
			return nil, fmt.Errorf("snell %s version 6 does not support obfs mode %s", addr, obfsOption.Mode)
		}
		var err error
		v6Mode, err = snell.ParseV6Mode(option.Mode)
		if err != nil {
			return nil, fmt.Errorf("snell %s %w", addr, err)
		}
	default:
		return nil, fmt.Errorf("snell version error: %d", option.Version)
	}
	if option.Mode != "" && option.Version != snell.Version6 {
		return nil, fmt.Errorf("snell %s mode is only supported on version 6", addr)
	}
	if identity && option.Version != snell.Version4 {
		// The identity header is a v4 record layer feature; a v1-v3 server would
		// read the magic as a request header.
		return nil, fmt.Errorf("snell %s identity requires version 4", addr)
	}
	if isSnellECHTLSMode(obfsOption.Mode) && option.Version != snell.Version4 {
		return nil, fmt.Errorf("snell %s ech-tls requires version 4", addr)
	}

	s := &Snell{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Snell,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:                &option,
		psk:                   psk,
		userKey:               userKey,
		obfsOption:            obfsOption,
		shadowTLSOption:       shadowTLSOpt,
		restlsConfig:          restlsConfig,
		jlsConfig:             jlsConfig,
		version:               option.Version,
		v6Mode:                v6Mode,
		reuse:                 reuse,
		oix:                   oix,
		identity:              identity,
		echTLSIdentityVersion: echOpt.IdentityVersion,
		echTLSLegacyFallback:  echOpt.LegacyFallback,
	}
	s.dialer = option.NewDialer(s.DialOptions())
	// OIX is the vendor's own name for the snell wire with the identity header:
	// the psk marker (#oix), the oix-ech-tls alias and the flat oix_* keys all
	// select it, and `oix` above is exactly that decision. Publish the vendor
	// identity so the API and the UI show OIX instead of Snell; a plain snell
	// node keeps Snell.
	if oix {
		s.SetAdapterType(C.OIX)
	}

	if isSnellECHTLSMode(obfsOption.Mode) {
		echConfig, err := snellECHTLSConfig(echOpt)
		if err != nil {
			return nil, err
		}
		nextProtos := []string{echOpt.ALPN}
		if echOpt.LegacyFallback {
			nextProtos = append(nextProtos, snellECHTLSLegacyALPN)
		}
		s.echTLS = &vmess.TLSConfig{
			Host:              echOpt.Host,
			SkipCertVerify:    echOpt.SkipCertVerify,
			NameCertVerify:    echOpt.NameCertVerify,
			ClientFingerprint: resolveSnellClientFingerprint(echOpt, option),
			FingerPrint:       echOpt.Fingerprint,
			Certificate:       echOpt.Certificate,
			PrivateKey:        echOpt.PrivateKey,
			NextProtos:        nextProtos,
			ECH:               echConfig,
		}
	}

	if s.reuse {
		s.pool = snell.NewPool(func(ctx context.Context) (*snell.Snell, error) {
			c, err := s.dialSnellTransport(ctx)
			if err != nil {
				return nil, err
			}

			sc, err := s.streamConnContext(ctx, c)
			if err != nil {
				_ = c.Close()
				return nil, err
			}
			// The identity transport keeps a v4 session reusable. A plain upstream
			// Snell server closes it after pong, so only identity sessions are
			// warmed up.
			if s.version == snell.Version4 && s.identity {
				if err = sc.Warmup(); err != nil {
					_ = sc.Close()
					return nil, err
				}
			}
			return sc, nil
		})
	}
	return s, nil
}
