package mobile

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	defaultRetryAfter = 10 * time.Second
	dialTimeout       = 30 * time.Second
)

type HTTPPacketConn struct {
	client *http.Client
	url    string

	notBefore     time.Time
	notBeforeLock sync.RWMutex

	*turbotunnel.QueuePacketConn
}

func NewHTTPPacketConn(urlString string, numSenders int) (*HTTPPacketConn, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil

	c := &HTTPPacketConn{
		client: &http.Client{
			Transport: transport,
			Timeout:   time.Minute,
		},
		url:             urlString,
		QueuePacketConn: turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, 0),
	}

	for i := 0; i < numSenders; i++ {
		go c.sendLoop()
	}

	return c, nil
}

func (c *HTTPPacketConn) send(p []byte) error {
	req, err := http.NewRequest("POST", c.url, bytes.NewReader(p))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("User-Agent", "")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		if resp.Header.Get("Content-Type") != "application/dns-message" {
			return fmt.Errorf("unknown HTTP response Content-Type %q", resp.Header.Get("Content-Type"))
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64000))
		if err == nil {
			c.QueuePacketConn.QueueIncoming(body, turbotunnel.DummyAddr{})
		}
	default:
		now := time.Now()
		retryAfter := now.Add(defaultRetryAfter)
		if value := resp.Header.Get("Retry-After"); value != "" {
			if parsed, err := parseRetryAfter(value, now); err == nil {
				retryAfter = parsed
			}
		}
		c.notBeforeLock.Lock()
		if retryAfter.After(c.notBefore) {
			c.notBefore = retryAfter
		}
		c.notBeforeLock.Unlock()
	}

	return nil
}

func (c *HTTPPacketConn) sendLoop() {
	for p := range c.QueuePacketConn.OutgoingQueue(turbotunnel.DummyAddr{}) {
		c.notBeforeLock.RLock()
		notBefore := c.notBefore
		c.notBeforeLock.RUnlock()
		if wait := notBefore.Sub(time.Now()); wait > 0 {
			continue
		}
		_ = c.send(p)
	}
}

func parseRetryAfter(value string, now time.Time) (time.Time, error) {
	if t, err := http.ParseTime(value); err == nil {
		return t, nil
	}
	i, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return time.Time{}, err
	}
	return now.Add(time.Duration(i) * time.Second), nil
}

type TLSPacketConn struct {
	*turbotunnel.QueuePacketConn
}

func NewTLSPacketConn(addr string) (*TLSPacketConn, error) {
	dial := func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		defer cancel()
		return (&tls.Dialer{}).DialContext(ctx, "tcp", addr)
	}

	conn, err := dial()
	if err != nil {
		return nil, err
	}

	c := &TLSPacketConn{
		QueuePacketConn: turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, 0),
	}

	go func() {
		defer c.Close()
		for {
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				_ = c.recvLoop(conn)
				wg.Done()
			}()
			go func() {
				_ = c.sendLoopTLS(conn)
				wg.Done()
			}()
			wg.Wait()
			conn.Close()

			conn, err = dial()
			if err != nil {
				break
			}
		}
	}()

	return c, nil
}

func (c *TLSPacketConn) recvLoop(conn net.Conn) error {
	br := bufio.NewReader(conn)
	for {
		var length uint16
		if err := binary.Read(br, binary.BigEndian, &length); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		p := make([]byte, int(length))
		if _, err := io.ReadFull(br, p); err != nil {
			return err
		}
		c.QueuePacketConn.QueueIncoming(p, turbotunnel.DummyAddr{})
	}
}

func (c *TLSPacketConn) sendLoopTLS(conn net.Conn) error {
	bw := bufio.NewWriter(conn)
	for p := range c.QueuePacketConn.OutgoingQueue(turbotunnel.DummyAddr{}) {
		length := uint16(len(p))
		if err := binary.Write(bw, binary.BigEndian, &length); err != nil {
			return err
		}
		if _, err := bw.Write(p); err != nil {
			return err
		}
		if err := bw.Flush(); err != nil {
			return err
		}
	}
	return nil
}
