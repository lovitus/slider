// Package ltcp implements local TCP port forwarding.
//
// Usage:
//
//	-listen ltcp://:LOCAL_PORT/TARGET_HOST:TARGET_PORT -forward ssh://user:pass@server:22
//
// Listens on LOCAL_PORT locally and forwards each connection through the proxy
// chain to TARGET_HOST:TARGET_PORT on the remote side.
package ltcp

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/nadoo/glider/log"
	"github.com/nadoo/glider/proxy"
)

// LTCP is a local TCP port forwarder.
type LTCP struct {
	addr  string // local listen address
	raddr string // remote target address (from URL path)
	proxy proxy.Proxy
}

func init() {
	proxy.RegisterServer("ltcp", NewLTCPServer)
}

// NewLTCPServer returns a new LTCP server.
func NewLTCPServer(s string, p proxy.Proxy) (proxy.Server, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	addr := u.Host
	raddr := strings.TrimPrefix(u.Path, "/")
	if raddr == "" {
		return nil, fmt.Errorf("[ltcp] target address required in URL path, e.g. ltcp://:8080/target:80")
	}

	t := &LTCP{
		addr:  addr,
		raddr: raddr,
		proxy: p,
	}

	return t, nil
}

// ListenAndServe listens on local addr and serves connections.
func (s *LTCP) ListenAndServe() {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		log.F("[ltcp] failed to listen on %s: %v", s.addr, err)
		return
	}
	defer l.Close()

	log.F("[ltcp] listening on %s, forwarding to %s", s.addr, s.raddr)

	for {
		c, err := l.Accept()
		if err != nil {
			log.F("[ltcp] failed to accept: %v", err)
			continue
		}

		go s.Serve(c)
	}
}

// Serve serves a connection by dialing the target through the proxy chain.
func (s *LTCP) Serve(c net.Conn) {
	defer c.Close()

	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
	}

	rc, dialer, err := s.proxy.Dial("tcp", s.raddr)
	if err != nil {
		log.F("[ltcp] %s -> %s via %s, dial error: %v", c.RemoteAddr(), s.raddr, dialer.Addr(), err)
		s.proxy.Record(dialer, false)
		return
	}
	defer rc.Close()

	log.F("[ltcp] %s <-> %s via %s", c.RemoteAddr(), s.raddr, dialer.Addr())

	if err = proxy.Relay(c, rc); err != nil {
		log.F("[ltcp] %s <-> %s, relay error: %v", c.RemoteAddr(), s.raddr, err)
		if !strings.Contains(err.Error(), s.addr) {
			s.proxy.Record(dialer, false)
		}
	}
}
