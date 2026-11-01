package warp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ProxyHandler crea un HTTP handler que reenvía requests a través de exits
// WireGuard del pool. Maneja tanto CONNECT (tunelado HTTPS) como requests HTTP
// normales de proxy.
func ProxyHandler(pool *wgPool) http.HandlerFunc {
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

// handleConnect establece un túnel TCP a través de un exit WireGuard para tráfico HTTPS.
func handleConnect(w http.ResponseWriter, r *http.Request, pool *wgPool) {
	ctx := r.Context()

	exit, err := pool.Acquire(ctx)
	if err != nil {
		log.Printf("CONNECT (no host): acquire failed: %v", err)
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
		log.Printf("CONNECT %s: dial failed on exit %s: %v", target, exit.ID(), err)
		http.Error(w, fmt.Sprintf("WARP dial failed: %v", err), http.StatusBadGateway)
		pool.Fail(exit, err.Error())
		return
	}

	// Señal de establecimiento exitoso del túnel.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("CONNECT %s: hijacking not supported", target)
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		conn.Close()
		pool.Fail(exit, "hijacking not supported")
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("CONNECT %s: hijack failed: %v", target, err)
		http.Error(w, fmt.Sprintf("hijacking failed: %v", err), http.StatusInternalServerError)
		conn.Close()
		pool.Fail(exit, err.Error())
		return
	}

	// El read deadline del http.Server (ReadTimeout) permanece en la conexión
	// hijacked: tras 30s mata cada stream long-lived (SSE) con un reset
	// silencioso. Lo limpio — el relay gestiona su propia vida.
	_ = clientConn.SetReadDeadline(time.Time{})
	_ = clientConn.SetWriteDeadline(time.Time{})

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		conn.Close()
		pool.Fail(exit, err.Error())
		return
	}

	// Relay con separación explícita de lectura/escritura para que abortos
	// del cliente (normal para streams SSE: el cliente corta a mitad del
	// body) nunca envenenen el exit.
	stopRelay := func() func() {
		var once sync.Once
		closedFLG := make(chan struct{})
		go func() {
			<-closedFLG
			_ = clientConn.Close()
			_ = conn.Close()
		}()
		return func() { once.Do(func() { close(closedFLG) }) }
	}()
	defer stopRelay()

	t2cErrCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 8192)
		for {
			n, rerr := conn.Read(buf) // fallo de lectura upstream = problema de túnel
			if rerr != nil {
				t2cErrCh <- rerr
				return
			}
			if n > 0 {
				if _, werr := clientConn.Write(buf[:n]); werr != nil {
					// lado del cliente murió: abortar el relay localmente, mantener el exit
					stopRelay()
					t2cErrCh <- nil
					return
				}
			}
		}
	}()
	// Cliente -> túnel: cualquier fallo de lectura aquí es un problema LOCAL del cliente.
	io.Copy(conn, clientConn)
	stopRelay()
	// Darle al pump upstream un respiro para que note los sockets cerrados.
	select {
	case upErr := <-t2cErrCh:
		if upErr != nil && upErr != io.EOF && !errors.Is(upErr, net.ErrClosed) {
			pool.Fail(exit, "tunnel read error: "+upErr.Error())
		}
	case <-time.After(3 * time.Second):
	}
	clientConn.Close()
	conn.Close()
}

// proxyRequest reenvía un único request HTTP a través de un exit WireGuard.
func proxyRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, exit *exitWG) error {
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

// bunClientHelloSpec devuelve el ClientHelloSpec de uTLS mimificando Bun (JA4 t13d1713h1).
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
			&utls.SNIExtension{ServerName: ""}, // se llena por conexión
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

// proxyHTTPS realiza proxy HTTPS a través del exit WireGuard usando uTLS.
func proxyHTTPS(ctx context.Context, conn net.Conn, r *http.Request, w http.ResponseWriter) error {
	tlsConn := utls.UClient(conn, &utls.Config{
		ServerName:         r.URL.Hostname(),
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: true,
	}, utls.HelloCustom)

	spec := bunClientHelloSpec()
	// Llenar SNI por request.
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

	// Reenviar el request original sobre la conexión uTLS.
	req := cloneRequest(r)
	if err := req.Write(tlsConn); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	// Leer la respuesta upstream y reenviarla al cliente.
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

// proxyHTTP reenvía un request HTTP plano a través del exit WireGuard.
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

// cloneRequest copia el request entrante, eliminando headers hop-by-hop.
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

// copyHeaders copia todos los headers de src a dst, omitiendo headers hop-by-hop.
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
