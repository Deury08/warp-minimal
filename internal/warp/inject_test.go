package warp

import (
	"encoding/hex"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	parse "gvisor.dev/gvisor/pkg/tcpip/header/parse"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// TestInjectSynAck builds a stack like production and injects a synthetic
// SYN-ACK (104.16.133.229:443 -> 172.16.0.2:25089), checking which gVisor
// counter counts the drop. Mirrors the masque inbound bridge.
func TestInjectSynAck(t *testing.T) {
	ch := channel.New(64, 1280, "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := s.CreateNIC(1, ch); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice([]byte{172, 16, 0, 2}), PrefixLen: 32},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %v", err)
	}

	raw, _ := hex.DecodeString("45000028000000004006e0c8681085e5ac10000201bb620100000001000000011412ffffee0c0000")

	validBefore := s.Stats().IP.ValidPacketsReceived.Value()
	malBefore := s.Stats().IP.MalformedPacketsReceived.Value()

	var pl buffer.Buffer
	pl.Append(buffer.NewViewWithData(append([]byte(nil), raw...)))
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:            pl,
		ReserveHeaderBytes: header.IPv6MinimumSize,
	})
	pkt.RXChecksumValidated = true
	ch.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()

	// Diagnose: run parse.IPv4 on a fresh copy.
	var pl3 buffer.Buffer
	pl3.Append(buffer.NewViewWithData(append([]byte(nil), raw...)))
	pkt3 := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:            pl3,
		ReserveHeaderBytes: header.IPv6MinimumSize,
	})
	ok3 := parse.IPv4(pkt3)
	t.Logf("diag parse.IPv4 ok=%v nwLen=%d dataLen=%d", ok3, len(pkt3.NetworkHeader().Slice()), pkt3.Data().Size())
	pkt3.DecRef()

	validAfter := s.Stats().IP.ValidPacketsReceived.Value()
	malAfter := s.Stats().IP.MalformedPacketsReceived.Value()

	ts := s.Stats().TCP
	t.Logf("tcp: valid=%d invalid=%d resets=%d failedOpens=%d listenSynDrop=%d",
		ts.ValidSegmentsReceived.Value(), ts.InvalidSegmentsReceived.Value(),
		ts.ResetsReceived.Value(), ts.FailedConnectionAttempts.Value(), ts.ListenOverflowSynDrop.Value())
	t.Logf("valid: %d -> %d; malformed: %d -> %d", validBefore, validAfter, malBefore, malAfter)
	if malAfter != malBefore {
		t.Errorf("inbound SYN-ACK marked malformed (ReserveHeaderBytes path broken)")
	}
	if validAfter == validBefore {
		t.Errorf("inbound SYN-ACK did not register as valid")
	}
}
