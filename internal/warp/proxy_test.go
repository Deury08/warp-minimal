package warp

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubEgress is an EgressDialer with a fixed id and an injected dial, so this
// test never touches a real tunnel.
type stubEgress struct {
	id     string
	served int
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (s stubEgress) ID() string { return s.id }

func (s stubEgress) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.dial(ctx, network, addr)
}

// noteServed makes this stub a servedNoter, so the test can prove the proxy
// counts each tunnel it establishes on the exit that dialed it.
func (s *stubEgress) noteServed() { s.served++ }

// stubEgressPool hands out one exit that is never released for real.
type stubEgressPool struct{ exit EgressDialer }

func (s stubEgressPool) Acquire(ctx context.Context) (EgressDialer, error) { return s.exit, nil }
func (s stubEgressPool) Release(exit EgressDialer)                        {}

type stubFailer struct{}

func (stubFailer) Fail(exit EgressDialer, reason string) {}

// TestConnectReplyCarriesEgressID pins the attribution contract the relay
// depends on: TLS hides the upstream status from the proxy, so the CONNECT reply
// itself has to name the exit that dialed, with its full id.
func TestConnectReplyCarriesEgressID(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstream.Close()
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	const wantID = "warp-18e5257c545b2e64"
	exit := &stubEgress{
		id: wantID,
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, upstream.Addr().String())
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleConnect(w, r, stubEgressPool{exit: exit}, stubFailer{})
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Warp-Exit"); got != wantID {
		t.Fatalf("X-Warp-Exit = %q, want %q (without the full id the relay cannot attribute a failure)", got, wantID)
	}
	if exit.served != 1 {
		t.Fatalf("served = %d after one CONNECT, want 1 (the snapshot diff needs this count)", exit.served)
	}
}

// preferStubPool is a pool that supports the optional preference capability.
type preferStubPool struct {
	stubEgressPool
	preferCalls []string
}

func (p *preferStubPool) AcquirePrefer(ctx context.Context, id string) (EgressDialer, error) {
	p.preferCalls = append(p.preferCalls, id)
	return p.exit, nil
}

// closeAcceptingUpstream accepts connections until the test ends.
func closeAcceptingUpstream(t *testing.T) net.Listener {
	t.Helper()
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	t.Cleanup(func() { upstream.Close() })
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return upstream
}

// connectThrough sends a CONNECT carrying Proxy-Authorization and returns the
// reply, so a test can prove which channel actually reaches the proxy.
func connectThrough(t *testing.T, target, proxyAuth string) *http.Response {
	t.Helper()
	upstream := closeAcceptingUpstream(t)
	exit := &stubEgress{
		id: "warp-fallback",
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, upstream.Addr().String())
		},
	}
	pool := &preferStubPool{stubEgressPool: stubEgressPool{exit: exit}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleConnect(w, r, pool, stubFailer{})
	}))
	t.Cleanup(srv.Close)

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	request := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if proxyAuth != "" {
		request += "Proxy-Authorization: " + proxyAuth + "\r\n"
	}
	request += "\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })

	if len(pool.preferCalls) != 1 {
		t.Fatalf("AcquirePrefer calls = %v, want exactly one (the credential must reach the proxy)", pool.preferCalls)
	}
	if want := "warp-missing"; pool.preferCalls[0] != want {
		t.Fatalf("AcquirePrefer(%q), want the id from Proxy-Authorization (%q)", pool.preferCalls[0], want)
	}
	return resp
}

// TestConnectPreferenceNeverReturns407 pins the silent-fallback contract: an
// unknown id must be served by the normal path, never rejected. A 407 here would
// make Bun retry and surface a proxy error instead of a fallback.
func TestConnectPreferenceNeverReturns407(t *testing.T) {
	resp := connectThrough(t, "example.com:443", basicAuth("warp-missing", ""))

	if resp.StatusCode == http.StatusProxyAuthRequired {
		t.Fatal("CONNECT replied 407: the password is never validated and an unknown id must fall back")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 via fallback", resp.StatusCode)
	}
}

// TestConnectWithoutCredentialSkipsPreference proves the header is genuinely
// the channel: no credential means no preference call at all.
func TestConnectWithoutCredentialSkipsPreference(t *testing.T) {
	upstream := closeAcceptingUpstream(t)
	exit := &stubEgress{
		id: "warp-plain",
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, upstream.Addr().String())
		},
	}
	pool := &preferStubPool{stubEgressPool: stubEgressPool{exit: exit}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleConnect(w, r, pool, stubFailer{})
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	defer resp.Body.Close()

	if len(pool.preferCalls) != 0 {
		t.Fatalf("AcquirePrefer calls = %v, want none without Proxy-Authorization", pool.preferCalls)
	}
}

// TestProxyHTTPResponseCarriesExitID covers the plain-HTTP path: the origin's
// own X-Warp-Exit must lose against the exit that actually dialed.
func TestProxyHTTPResponseCarriesExitID(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Warp-Exit", "warp-origin-lie")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	const wantID = "warp-aaaa1111"
	exit := &stubEgress{id: wantID, dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(network, upstream.Listener.Addr().String())
	}}

	conn, err := net.Dial("tcp", upstream.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial upstream: %v", err)
	}
	defer conn.Close()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	if err := proxyHTTP(conn, req, rec, exit); err != nil {
		t.Fatalf("proxyHTTP: %v", err)
	}

	res := rec.Result()
	defer res.Body.Close()
	if got := res.Header.Get("X-Warp-Exit"); got != wantID {
		t.Fatalf("X-Warp-Exit = %q, want %q (the dialer's id, not the origin's claim)", got, wantID)
	}
}

// TestConnectPreferenceWithValidIDUsesThatExit covers the hit case end to end.
func TestConnectPreferenceWithValidIDUsesThatExit(t *testing.T) {
	upstream := closeAcceptingUpstream(t)
	const wantID = "warp-preferred"
	exit := &stubEgress{id: wantID, dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(network, upstream.Addr().String())
	}}
	pool := &preferStubPool{stubEgressPool: stubEgressPool{exit: exit}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleConnect(w, r, pool, stubFailer{})
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(wantID+":"))
	request := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: " + header + "\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("X-Warp-Exit"); got != wantID {
		t.Fatalf("X-Warp-Exit = %q, want %q", got, wantID)
	}
	if len(pool.preferCalls) != 1 || pool.preferCalls[0] != wantID {
		t.Fatalf("AcquirePrefer calls = %v, want [%s]", pool.preferCalls, wantID)
	}
}
