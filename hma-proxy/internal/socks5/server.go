package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Server struct {
	ListenAddr string
	Username   string
	Password   string
	Dialer     Dialer

	ln net.Listener
	mu sync.Mutex
}

func (s *Server) Start() (net.Addr, error) {
	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	return ln.Addr(), nil
}

func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	for {
		c, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		go s.handleConn(ctx, c)
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	ln := s.ln
	s.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (s *Server) handleConn(ctx context.Context, client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(15 * time.Second))

	// 1. Greeting: VER | NMETHODS | METHODS
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}

	needAuth := s.Username != "" || s.Password != ""
	var chosen byte = 0xFF
	for _, m := range methods {
		if !needAuth && m == 0x00 {
			chosen = 0x00
			break
		}
		if needAuth && m == 0x02 {
			chosen = 0x02
			break
		}
	}
	if _, err := client.Write([]byte{0x05, chosen}); err != nil || chosen == 0xFF {
		return
	}

	// 2. Optional RFC 1929 username/password auth
	if chosen == 0x02 {
		ah := make([]byte, 2)
		if _, err := io.ReadFull(client, ah); err != nil || ah[0] != 0x01 {
			return
		}
		ubuf := make([]byte, int(ah[1]))
		if _, err := io.ReadFull(client, ubuf); err != nil {
			return
		}
		plen := make([]byte, 1)
		if _, err := io.ReadFull(client, plen); err != nil {
			return
		}
		pbuf := make([]byte, int(plen[0]))
		if _, err := io.ReadFull(client, pbuf); err != nil {
			return
		}
		if string(ubuf) != s.Username || string(pbuf) != s.Password {
			_, _ = client.Write([]byte{0x01, 0x01})
			return
		}
		if _, err := client.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	}

	// 3. Request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil {
		return
	}
	if req[0] != 0x05 {
		return
	}
	if req[1] != 0x01 { // Only CONNECT
		writeReply(client, 0x07)
		return
	}

	var host string
	switch req[3] {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(client, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x03: // Domain
		lbuf := make([]byte, 1)
		if _, err := io.ReadFull(client, lbuf); err != nil {
			return
		}
		dom := make([]byte, int(lbuf[0]))
		if _, err := io.ReadFull(client, dom); err != nil {
			return
		}
		host = string(dom)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(client, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		writeReply(client, 0x08)
		return
	}

	pbuf := make([]byte, 2)
	if _, err := io.ReadFull(client, pbuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pbuf)
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	remote, err := s.Dialer.DialContext(dialCtx, "tcp", target)
	cancel()
	if err != nil {
		writeReply(client, 0x05)
		return
	}
	defer remote.Close()

	// Clear handshake deadline for active relay
	_ = client.SetDeadline(time.Time{})

	if err := writeReply(client, 0x00); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(remote, client)
		if tc, ok := remote.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, remote)
		if tc, ok := client.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}

func writeReply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

func FormatProxyURL(addr string) string {
	return fmt.Sprintf("socks5h://%s", addr)
}
