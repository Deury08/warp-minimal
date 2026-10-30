package warp

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ProxyHandler creates an HTTP handler that forwards requests through WARP exits.
// It handles both CONNECT (HTTPS tunneling) and regular HTTP proxy requests.
func ProxyHandler(pool *Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if r.Method == http.MethodConnect {
			handleConnect(w, r, pool)
			return
		}

		exit, err := pool.Acquire(ctx)
		if err != nil {
			http.Error(w, fmt.Sprintf("WARP unavailable: %v", err), http.StatusServiceUnavailable)
			return
		}
		defer pool.Release(exit)

		if err := proxyRequest(ctx, w, r, exit); err != nil {
			log.Printf("WARP proxy error: %v", err)
			pool.Fail(exit, err.Error())
			http.Error(w, fmt.Sprintf("WARP proxy error: %v", err), http.StatusBadGateway)
		}
	}
}

// handleConnect establishes a TCP tunnel through a WARP exit for HTTPS traffic.
func handleConnect(w http.ResponseWriter, r *http.Request, pool *Pool) {
	ctx := r.Context()

	exit, err := pool.Acquire(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("WARP unavailable: %v", err), http.StatusServiceUnavailable)
		return
	}
	defer pool.Release(exit)

	target := r.Host
	if target == "" {
		target = r.URL.Host
	}
	if !strings.Contains(target, ":") {
		target = target + ":443"
	}

	conn, err := exit.DialContext(ctx, "tcp", target)
	if err != nil {
		http.Error(w, fmt.Sprintf("WARP dial failed: %v", err), http.StatusBadGateway)
		pool.Fail(exit, err.Error())
		return
	}

	// Signal successful tunnel establishment.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		conn.Close()
		pool.Fail(exit, "hijacking not supported")
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("hijacking failed: %v", err), http.StatusInternalServerError)
		conn.Close()
		pool.Fail(exit, err.Error())
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		conn.Close()
		pool.Fail(exit, err.Error())
		return
	}

	// Relay bidirectionally until both sides close.
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(conn, clientConn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, conn)
		errCh <- err
	}()
	<-errCh

	clientConn.Close()
	conn.Close()
	pool.Fail(exit, "tunnel closed")
}

// proxyRequest forwards a single HTTP request through a WARP exit.
func proxyRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, exit *Exit) error {
	host := r.URL.Host
	if !strings.Contains(host, ":") {
		if r.URL.Scheme == "https" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}

	conn, err := exit.DialContext(ctx, "tcp", host)
	if err != nil {
		return fmt.Errorf("dial %s: %w", host, err)
	}
	defer conn.Close()

	if r.URL.Scheme == "https" || r.TLS != nil {
		return proxyHTTPS(ctx, conn, r, w)
	}
	return proxyHTTP(conn, r, w)
}

// bunClientHelloSpec returns the uTLS ClientHelloSpec mimicking Bun (JA4 t13d1713h1).
func bunClientHelloSpec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CompressionMethods: []uint8{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: ""}, // filled below per connection
			&utls.UtlsExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: 1},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&utls.SessionTicketExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
			}},
		},
	}
}

// proxyHTTPS performs HTTPS proxy through the WARP exit using uTLS.
func proxyHTTPS(ctx context.Context, conn net.Conn, r *http.Request, w http.ResponseWriter) error {
	tlsConn := utls.UClient(conn, &utls.Config{
		ServerName:         r.URL.Hostname(),
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: true,
	}, utls.HelloCustom)

	spec := bunClientHelloSpec()
	// Fill in SNI per-request.
	for i, ext := range spec.Extensions {
		if sniExt, ok := ext.(*utls.SNIExtension); ok {
			sniExt.ServerName = r.URL.Hostname()
			spec.Extensions[i] = sniExt
			break
		}
	}

	if err := tlsConn.ApplyPreset(spec); err != nil {
		return fmt.Errorf("apply uTLS preset: %w", err)
	}

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("uTLS handshake: %w", err)
	}

	// Forward the original request over the uTLS connection.
	req := cloneRequest(r)
	if err := req.Write(tlsConn); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	// Read the upstream response and relay it to the client.
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		return fmt.Errorf("relay response body: %w", err)
	}
	return nil
}

// proxyHTTP forwards a plain HTTP request through the WARP exit.
func proxyHTTP(conn net.Conn, r *http.Request, w http.ResponseWriter) error {
	req := cloneRequest(r)
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		return fmt.Errorf("relay response body: %w", err)
	}
	return nil
}

// cloneRequest copies the incoming request, stripping hop-by-hop headers.
func cloneRequest(r *http.Request) *http.Request {
	req := &http.Request{
		Method:        r.Method,
		URL:           r.URL,
		Proto:         r.Proto,
		ProtoMajor:    r.ProtoMajor,
		ProtoMinor:    r.ProtoMinor,
		Header:        make(http.Header),
		Body:          r.Body,
		Host:          r.Host,
		ContentLength: r.ContentLength,
		RemoteAddr:    r.RemoteAddr,
		RequestURI:    r.RequestURI,
		TLS:           r.TLS,
	}

	for k, vv := range r.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	return req
}

var hopByHop = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

func isHopByHop(k string) bool {
	if hopByHop[k] {
		return true
	}
	return strings.HasPrefix(k, "Proxy-") || strings.HasPrefix(k, "Te")
}

// copyHeaders copies all headers from src to dst, omitting hop-by-hop headers.
func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

var _ = time.Second
