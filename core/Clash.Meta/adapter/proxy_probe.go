package adapter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/convert"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/mmdb"
	"github.com/metacubex/mihomo/component/smart"
	"github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/http"
)

var (
	banStatus = map[int]bool{
		http.StatusForbidden:          true, // 403
		http.StatusMethodNotAllowed:   true, // 405
		http.StatusMisdirectedRequest: true, // 421
		http.StatusNotImplemented:     true, // 501
		http.StatusServiceUnavailable: true, // 503
		520:                           true, // Cloudflare 520
		599:                           true, // timeout
	}
)

func (p *Proxy) StatusTest(ctx context.Context, rawURL string) (status uint16, ok bool, err error) {
	resp, transport, err := p.statusRequest(ctx, rawURL, nil, nil)
	if transport != nil {
		defer transport.CloseIdleConnections()
	}

	var statusCode int
	if err != nil {
		if netErr, okNet := err.(net.Error); okNet && netErr.Timeout() {
			statusCode = 599
		} else if err == context.Canceled || err == context.DeadlineExceeded {
			statusCode = 599
		} else {
			return 1, false, err
		}
	} else {
		statusCode = resp.StatusCode
		ok = !banStatus[statusCode]
		if !ok {
			if statusCode == http.StatusForbidden {
				if resp.Header.Get("Server") == "cloudflare" {
					ok = true
				}
			}
			if statusCode == 520 {
				if resp.Header.Get("Server") != "cloudflare" {
					ok = true
				}
			}
		}
		_ = resp.Body.Close()
	}

	return uint16(statusCode), ok, nil
}

// StatusProbe fetches rawURL through the proxy for the smart group's answer checks and,
// unlike StatusTest, leaves cross-host redirects unfollowed for the caller to classify.
func (p *Proxy) StatusProbe(ctx context.Context, rawURL string) (*smart.ProbeResult, error) {
	header := http.Header{}
	header.Set("Accept-Encoding", "identity")

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		// only an identical host[:port] keeps following; another host would test another site
		if !sameHostPort(req.URL, via[0].URL) {
			return http.ErrUseLastResponse
		}
		return nil
	}

	resp, transport, err := p.statusRequest(ctx, rawURL, header, checkRedirect)
	if transport != nil {
		defer transport.CloseIdleConnections()
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	return &smart.ProbeResult{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       readBodySnippet(resp.Body, smart.ProbeBodyLimit, smart.ProbeBodyWait),
	}, nil
}

// readBodySnippet never drains a streaming body; the caller closing it releases the read.
func readBodySnippet(body io.Reader, limit int, wait time.Duration) []byte {
	snippet := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(io.LimitReader(body, int64(limit)))
		snippet <- data
	}()
	select {
	case data := <-snippet:
		return data
	case <-time.After(wait):
		return nil
	}
}

// ExitProbe asks the trace endpoints through this node where its traffic lands, trying
// the fallbacks until one answers; the address serves the ASN lookup and is never returned.
func (p *Proxy) ExitProbe(ctx context.Context, wantASN bool) (*smart.ExitProbeResult, error) {
	var lastErr error
	for _, rawURL := range smart.ExitTraceURLs {
		if ctx.Err() != nil {
			break
		}
		result, err := p.exitProbe(ctx, rawURL, wantASN, false)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", rawURL, err)
			continue
		}
		return result, nil
	}
	if lastErr == nil {
		lastErr = ctx.Err()
	}
	return nil, lastErr
}

func (p *Proxy) TargetExitProbe(ctx context.Context, host string, wantASN bool) (*smart.ExitProbeResult, error) {
	if host == "" {
		return nil, errors.New("empty target host")
	}
	return p.exitProbe(ctx, "https://"+host+"/cdn-cgi/trace", wantASN, true)
}

func (p *Proxy) exitProbe(ctx context.Context, rawURL string, wantASN bool, followOffHost bool) (*smart.ExitProbeResult, error) {
	header := http.Header{}
	header.Set("Accept-Encoding", "identity")

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if sameHostPort(req.URL, via[len(via)-1].URL) {
			return nil
		}
		if followOffHost && len(via) == 1 {
			return nil
		}
		return http.ErrUseLastResponse
	}

	resp, transport, err := p.statusRequest(ctx, rawURL, header, checkRedirect)
	if transport != nil {
		defer transport.CloseIdleConnections()
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &smart.TraceUnanswerableError{Reason: fmt.Sprintf("exit trace answered %d", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, smart.ExitProbeBodyLimit))
	if err != nil {
		return nil, err
	}
	region, ip := smart.ParseExitAnswer(body)
	if region == "" {
		return nil, &smart.TraceUnanswerableError{Reason: "exit trace has no region"}
	}
	result := &smart.ExitProbeResult{Region: region}
	if ip.IsValid() {
		result.Key = smart.ExitKey(ip)
	}
	if wantASN && ip.IsValid() {
		// ASNInstance stops the process without a loadable database, so Verify guards it
		if path := C.Path.ASN(); path != "" && mmdb.Verify(path) {
			asn, _ := mmdb.ASNInstance().LookupASN(ip.AsSlice())
			result.ASN = asn
		}
	}
	return result, nil
}

// sameHostPort ignores an explicit default port, so a redirect that only spells out :443
// keeps being followed.
func sameHostPort(a, b *url.URL) bool {
	normalize := func(u *url.URL) string {
		port := u.Port()
		if port == "" || (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
			return u.Hostname()
		}
		return net.JoinHostPort(u.Hostname(), port)
	}
	return strings.EqualFold(normalize(a), normalize(b))
}

// statusRequest sends a GET through the proxy with a browser preset; the transport it
// returns (nil when the request could not be built) holds connections the caller must close.
// extraHeader overrides preset headers; checkRedirect runs after the 3-redirect limit.
func (p *Proxy) statusRequest(ctx context.Context, rawURL string, extraHeader http.Header, checkRedirect func(req *http.Request, via []*http.Request) error) (*http.Response, *http.Transport, error) {
	if _, err := urlToMetadata(rawURL); err != nil {
		return nil, nil, err
	}

	tlsConfig, err := ca.GetTLSConfig(ca.Option{})
	if err != nil {
		return nil, nil, err
	}

	preset := convert.RandBrowserPreset()
	fingerprint, ok2 := tls.GetFingerprint(preset.FingerprintName)
	if !ok2 {
		return nil, nil, fmt.Errorf("failed to get TLS fingerprint: %s", preset.FingerprintName)
	}

	// Resolve the target per hop instead of pinning the one from rawURL: redirects
	// may point at another host, and every hop has to be dialed through the proxy.
	dialProxy := func(dialCtx context.Context, targetAddr string) (net.Conn, error) {
		var metadata C.Metadata
		if err := metadata.SetRemoteAddress(targetAddr); err != nil {
			return nil, err
		}
		return p.DialContext(dialCtx, &metadata)
	}

	// force ForceAttemptHTTP2 to false and use BuildWebsocketHandshakeState to custom http1.1 type for clear status code detection
	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     false,
		// DialContext is required even though the probe URL is https: on a redirect to
		// a plain-http URL the Transport uses this hook, and when it is nil it silently
		// falls back to its package-level zeroDialer, which resolves through
		// net.DefaultResolver and trips the guard installed in main().
		DialContext: func(dialCtx context.Context, network, targetAddr string) (net.Conn, error) {
			return dialProxy(dialCtx, targetAddr)
		},
		DialTLSContext: func(dialCtx context.Context, network, targetAddr string) (net.Conn, error) {
			serverName, _, splitErr := net.SplitHostPort(targetAddr)
			if splitErr != nil {
				return nil, splitErr
			}
			rawConn, err := dialProxy(dialCtx, targetAddr)
			if err != nil {
				return nil, err
			}
			uCfg := tls.UConfig(tlsConfig)
			uCfg.ServerName = serverName
			uConn := tls.UClient(rawConn, uCfg, fingerprint)
			if err := tls.BuildWebsocketHandshakeState(uConn); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			if err := uConn.HandshakeContext(dialCtx); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			return uConn, nil
		},
	}

	client := http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			if checkRedirect != nil {
				return checkRedirect(req, via)
			}
			return nil
		},
	}

	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, transport, err
	}
	req = req.WithContext(ctx)
	req.Header = preset.Headers.Clone()
	for key, values := range extraHeader {
		req.Header[key] = values
	}

	resp, err := client.Do(req)
	return resp, transport, err
}
