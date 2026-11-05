package warp

import (
	"bufio"
	"context"
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
	id   string
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (s stubEgress) ID() string { return s.id }

func (s stubEgress) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.dial(ctx, network, addr)
}

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
	exit := stubEgress{
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
}
