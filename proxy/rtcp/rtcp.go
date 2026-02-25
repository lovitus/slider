// Package rtcp implements remote TCP port forwarding.
//
// Usage:
//
//	-listen rtcp://:REMOTE_PORT/LOCAL_HOST:LOCAL_PORT -forward ssh://user:pass@server:22
//
// Asks the last hop in the proxy chain to listen on REMOTE_PORT, and forwards
// each incoming remote connection to LOCAL_HOST:LOCAL_PORT locally.
//
// The last hop in the forward chain MUST support remote listening (e.g. ssh).
// Protocols like ss, vmess, http proxy do NOT support this — an error is shown.
package rtcp

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/nadoo/glider/log"
	"github.com/nadoo/glider/proxy"
)

// RTCP is a remote TCP port forwarder.
type RTCP struct {
	raddr string // remote listen address (on the last hop)
	laddr string // local target address
	proxy proxy.Proxy
}

func init() {
	proxy.RegisterServer("rtcp", NewRTCPServer)
}

// NewRTCPServer returns a new RTCP server.
func NewRTCPServer(s string, p proxy.Proxy) (proxy.Server, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	raddr := u.Host
	laddr := strings.TrimPrefix(u.Path, "/")
	if laddr == "" {
		return nil, fmt.Errorf("[rtcp] local target address required in URL path, e.g. rtcp://:8080/127.0.0.1:3000")
	}

	t := &RTCP{
		raddr: raddr,
		laddr: laddr,
		proxy: p,
	}

	return t, nil
}

// ListenAndServe asks the remote end to listen, then relays connections locally.
func (s *RTCP) ListenAndServe() {
	// Get the next dialer and check if it supports remote listening
	dialer := s.proxy.NextDialer("")
	rl, ok := dialer.(proxy.RemoteListener)
	if !ok {
		log.F("[rtcp] ERROR: the last hop (%s) does not support remote listening.\n"+
			"       The last hop must be ssh, socks5, or another protocol that supports listening.\n"+
			"       Protocols like ss, vmess, trojan, http do NOT support remote listening.",
			dialer.Addr())
		return
	}

	ln, err := rl.Listen("tcp", s.raddr)
	if err != nil {
		log.F("[rtcp] failed to listen on remote %s: %v", s.raddr, err)
		return
	}
	defer ln.Close()

	log.F("[rtcp] remote listening on %s, forwarding to local %s", s.raddr, s.laddr)

	for {
		rc, err := ln.Accept()
		if err != nil {
			log.F("[rtcp] accept error on remote %s: %v", s.raddr, err)
			return
		}

		go s.Serve(rc)
	}
}

// Serve serves a remote connection by dialing the local target.
func (s *RTCP) Serve(rc net.Conn) {
	defer rc.Close()

	lc, err := net.DialTimeout("tcp", s.laddr, 5*1e9)
	if err != nil {
		log.F("[rtcp] dial local %s error: %v", s.laddr, err)
		return
	}
	defer lc.Close()

	if tc, ok := lc.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
	}

	log.F("[rtcp] %s(remote) <-> %s(local)", rc.RemoteAddr(), s.laddr)

	if err = proxy.Relay(rc, lc); err != nil {
		log.F("[rtcp] %s <-> %s, relay error: %v", rc.RemoteAddr(), s.laddr, err)
	}
}
