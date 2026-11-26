package httpproxy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
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

	ln  net.Listener
	srv *http.Server
	mu  sync.Mutex
}

func (s *Server) Start() (net.Addr, error) {
	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DialContext:           s.Dialer.DialContext,
		ForceAttemptHTTP2:     false,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	s.mu.Lock()
	s.ln = ln
	s.srv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.handle(w, r, transport)
		}),
	}
	s.mu.Unlock()
	return ln.Addr(), nil
}

func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	err := s.srv.Serve(s.ln)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *Server) Close() error {
	s.mu.Lock()
	srv := s.srv
	ln := s.ln
	s.mu.Unlock()
	if srv != nil {
		return srv.Close()
	}
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func (s *Server) checkAuth(r *http.Request) bool {
	if s.Username == "" && s.Password == "" {
		return true
	}
	hdr := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(hdr, "Basic ") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(hdr, "Basic "))
	if err != nil {
		return false
	}
	return string(raw) == s.Username+":"+s.Password
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request, tr *http.Transport) {
	if !s.checkAuth(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="hma-proxy"`)
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Del("Proxy-Connection")

	resp, err := tr.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	dialCtx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	remote, err := s.Dialer.DialContext(dialCtx, "tcp", r.Host)
	cancel()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer remote.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if buf.Reader.Buffered() > 0 {
			_, _ = io.CopyN(remote, buf.Reader, int64(buf.Reader.Buffered()))
		}
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
