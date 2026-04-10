package mobile

import (
	"errors"
	"net"
	"testing"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

type recordingPacketConn struct {
	payload []byte
	addr    net.Addr
}

func (c *recordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}

func (c *recordingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.payload = append([]byte(nil), p...)
	c.addr = addr
	return len(p), nil
}

func (c *recordingPacketConn) Close() error { return nil }

func (c *recordingPacketConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (c *recordingPacketConn) SetDeadline(time.Time) error { return nil }

func (c *recordingPacketConn) SetReadDeadline(time.Time) error { return nil }

func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestDNSPacketConnSendUsesConservativeEDNSPayload(t *testing.T) {
	domain, err := dns.ParseName("t.example.com")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}

	transport := &recordingPacketConn{}
	conn := &dnsPacketConn{domain: domain}
	targetAddr := &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}

	if err := conn.send(transport, []byte("abc"), targetAddr); err != nil {
		t.Fatalf("send: %v", err)
	}

	if len(transport.payload) == 0 {
		t.Fatal("expected a DNS packet to be written")
	}

	msg, err := dns.MessageFromWireFormat(transport.payload)
	if err != nil {
		t.Fatalf("MessageFromWireFormat: %v", err)
	}

	if len(msg.Additional) != 1 {
		t.Fatalf("expected 1 additional record, got %d", len(msg.Additional))
	}

	opt := msg.Additional[0]
	if opt.Type != dns.RRTypeOPT {
		t.Fatalf("expected OPT RR, got type %d", opt.Type)
	}
	if opt.Class != advertisedEDNSPayloadSize {
		t.Fatalf("expected OPT class %d, got %d", advertisedEDNSPayloadSize, opt.Class)
	}
}
