package socks5

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/nadoo/glider/log"
	"github.com/nadoo/glider/pool"
	"github.com/nadoo/glider/proxy"
	"github.com/nadoo/glider/proxy/socks"
)

// NewSocks5Dialer returns a socks5 proxy dialer.
func NewSocks5Dialer(s string, d proxy.Dialer) (proxy.Dialer, error) {
	return NewSocks5(s, d, nil)
}

// Addr returns forwarder's address.
func (s *Socks5) Addr() string {
	if s.addr == "" {
		return s.dialer.Addr()
	}
	return s.addr
}

// Dial connects to the address addr on the network net via the SOCKS5 proxy.
func (s *Socks5) Dial(network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, errors.New("[socks5]: no support for connection type " + network)
	}

	c, err := s.dialer.Dial(network, s.addr)
	if err != nil {
		log.F("[socks5]: dial to %s error: %s", s.addr, err)
		return nil, err
	}

	if err := s.connect(c, addr); err != nil {
		c.Close()
		return nil, err
	}

	return c, nil
}

// DialUDP connects to the given address via the proxy.
func (s *Socks5) DialUDP(network, addr string) (pc net.PacketConn, writeTo net.Addr, err error) {
	c, err := s.dialer.Dial("tcp", s.addr)
	if err != nil {
		log.F("[socks5] dialudp dial tcp to %s error: %s", s.addr, err)
		return nil, nil, err
	}

	// send VER, NMETHODS, METHODS
	c.Write([]byte{Version, 1, 0})

	buf := pool.GetBuffer(socks.MaxAddrLen)
	defer pool.PutBuffer(buf)

	// read VER METHOD
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return nil, nil, err
	}

	dstAddr := socks.ParseAddr(addr)
	// write VER CMD RSV ATYP DST.ADDR DST.PORT
	c.Write(append([]byte{Version, socks.CmdUDPAssociate, 0}, dstAddr...))

	// read VER REP RSV ATYP BND.ADDR BND.PORT
	if _, err := io.ReadFull(c, buf[:3]); err != nil {
		return nil, nil, err
	}

	rep := buf[1]
	if rep != 0 {
		log.F("[socks5] server reply: %d, not succeeded", rep)
		return nil, nil, errors.New("server connect failed")
	}

	uAddr, err := socks.ReadAddrBuf(c, buf)
	if err != nil {
		return nil, nil, err
	}

	pc, nextHop, err := s.dialer.DialUDP(network, uAddr.String())
	if err != nil {
		log.F("[socks5] dialudp to %s error: %s", uAddr.String(), err)
		return nil, nil, err
	}

	pkc := NewPktConn(pc, nextHop, dstAddr, true, c)
	return pkc, nextHop, err
}

// connect takes an existing connection to a socks5 proxy server,
// and commands the server to extend that connection to target,
// which must be a canonical address with a host and port.
func (s *Socks5) connect(conn net.Conn, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return errors.New("proxy: failed to parse port number: " + portStr)
	}
	if port < 1 || port > 0xffff {
		return errors.New("proxy: port number out of range: " + portStr)
	}

	// the size here is just an estimate
	buf := make([]byte, 0, 6+len(host))

	buf = append(buf, Version)
	if len(s.user) > 0 && len(s.user) < 256 && len(s.password) < 256 {
		buf = append(buf, 2 /* num auth methods */, socks.AuthNone, socks.AuthPassword)
	} else {
		buf = append(buf, 1 /* num auth methods */, socks.AuthNone)
	}

	if _, err := conn.Write(buf); err != nil {
		return errors.New("proxy: failed to write greeting to SOCKS5 proxy at " + s.addr + ": " + err.Error())
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return errors.New("proxy: failed to read greeting from SOCKS5 proxy at " + s.addr + ": " + err.Error())
	}
	if buf[0] != Version {
		return errors.New("proxy: SOCKS5 proxy at " + s.addr + " has unexpected version " + strconv.Itoa(int(buf[0])))
	}
	if buf[1] == 0xff {
		return errors.New("proxy: SOCKS5 proxy at " + s.addr + " requires authentication")
	}

	if buf[1] == socks.AuthPassword {
		buf = buf[:0]
		buf = append(buf, 1 /* password protocol version */)
		buf = append(buf, uint8(len(s.user)))
		buf = append(buf, s.user...)
		buf = append(buf, uint8(len(s.password)))
		buf = append(buf, s.password...)

		if _, err := conn.Write(buf); err != nil {
			return errors.New("proxy: failed to write authentication request to SOCKS5 proxy at " + s.addr + ": " + err.Error())
		}

		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			return errors.New("proxy: failed to read authentication reply from SOCKS5 proxy at " + s.addr + ": " + err.Error())
		}

		if buf[1] != 0 {
			return errors.New("proxy: SOCKS5 proxy at " + s.addr + " rejected username/password")
		}
	}

	buf = buf[:0]
	buf = append(buf, Version, socks.CmdConnect, 0 /* reserved */)

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, socks.ATypIP4)
			ip = ip4
		} else {
			buf = append(buf, socks.ATypIP6)
		}
		buf = append(buf, ip...)
	} else {
		if len(host) > 255 {
			return errors.New("proxy: destination hostname too long: " + host)
		}
		buf = append(buf, socks.ATypDomain)
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = append(buf, byte(port>>8), byte(port))

	if _, err := conn.Write(buf); err != nil {
		return errors.New("proxy: failed to write connect request to SOCKS5 proxy at " + s.addr + ": " + err.Error())
	}

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return errors.New("proxy: failed to read connect reply from SOCKS5 proxy at " + s.addr + ": " + err.Error())
	}

	failure := "unknown error"
	if int(buf[1]) < len(socks.Errors) {
		failure = socks.Errors[buf[1]].Error()
	}

	if len(failure) > 0 {
		return errors.New("proxy: SOCKS5 proxy at " + s.addr + " failed to connect: " + failure)
	}

	bytesToDiscard := 0
	switch buf[3] {
	case socks.ATypIP4:
		bytesToDiscard = net.IPv4len
	case socks.ATypIP6:
		bytesToDiscard = net.IPv6len
	case socks.ATypDomain:
		_, err := io.ReadFull(conn, buf[:1])
		if err != nil {
			return errors.New("proxy: failed to read domain length from SOCKS5 proxy at " + s.addr + ": " + err.Error())
		}
		bytesToDiscard = int(buf[0])
	default:
		return errors.New("proxy: got unknown address type " + strconv.Itoa(int(buf[3])) + " from SOCKS5 proxy at " + s.addr)
	}

	if cap(buf) < bytesToDiscard {
		buf = make([]byte, bytesToDiscard)
	} else {
		buf = buf[:bytesToDiscard]
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		return errors.New("proxy: failed to read address from SOCKS5 proxy at " + s.addr + ": " + err.Error())
	}

	// Also need to discard the port number
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return errors.New("proxy: failed to read port from SOCKS5 proxy at " + s.addr + ": " + err.Error())
	}

	return nil
}

// authenticate performs the SOCKS5 auth handshake on conn.
// Extracted from connect() to be reusable for BIND.
func (s *Socks5) authenticate(conn net.Conn) error {
	buf := make([]byte, 0, 3+256+256)
	buf = append(buf, Version)
	if len(s.user) > 0 && len(s.user) < 256 && len(s.password) < 256 {
		buf = append(buf, 2, socks.AuthNone, socks.AuthPassword)
	} else {
		buf = append(buf, 1, socks.AuthNone)
	}

	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("auth greeting: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("auth greeting reply: %w", err)
	}
	if resp[0] != Version {
		return fmt.Errorf("unexpected SOCKS version %d", resp[0])
	}
	if resp[1] == 0xff {
		return errors.New("proxy requires authentication we cannot provide")
	}

	if resp[1] == socks.AuthPassword {
		authBuf := make([]byte, 0, 1+1+len(s.user)+1+len(s.password))
		authBuf = append(authBuf, 1)
		authBuf = append(authBuf, uint8(len(s.user)))
		authBuf = append(authBuf, s.user...)
		authBuf = append(authBuf, uint8(len(s.password)))
		authBuf = append(authBuf, s.password...)

		if _, err := conn.Write(authBuf); err != nil {
			return fmt.Errorf("auth request: %w", err)
		}
		if _, err := io.ReadFull(conn, resp[:2]); err != nil {
			return fmt.Errorf("auth reply: %w", err)
		}
		if resp[1] != 0 {
			return errors.New("username/password rejected")
		}
	}

	return nil
}

// Listen implements proxy.RemoteListener using SOCKS5 BIND (CMD=0x02).
// Each Accept() issues a new BIND request since SOCKS5 BIND only handles
// one inbound connection per request (RFC 1928).
func (s *Socks5) Listen(network, addr string) (net.Listener, error) {
	// Validate addr format
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("[socks5] invalid bind address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 0xffff {
		return nil, fmt.Errorf("[socks5] invalid port in bind address: %s", portStr)
	}

	// Do a probe BIND to verify the server supports it
	probeConn, err := s.dialer.Dial("tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("[socks5] dial to %s for bind probe: %w", s.addr, err)
	}

	if err := s.authenticate(probeConn); err != nil {
		probeConn.Close()
		return nil, fmt.Errorf("[socks5] auth for bind probe: %w", err)
	}

	// Send BIND command
	bindAddr := buildBindRequest(host, port)
	if _, err := probeConn.Write(bindAddr); err != nil {
		probeConn.Close()
		return nil, fmt.Errorf("[socks5] write bind request: %w", err)
	}

	// Read first reply — bound address
	boundAddr, err := readBindReply(probeConn)
	if err != nil {
		probeConn.Close()
		return nil, fmt.Errorf("[socks5] bind not supported by server %s: %w", s.addr, err)
	}

	log.F("[socks5] BIND probe succeeded, server bound on %s", boundAddr)
	probeConn.Close() // close probe, we'll open fresh connections per Accept()

	ln := &socks5Listener{
		socks:    s,
		bindHost: host,
		bindPort: port,
		addr:     boundAddr,
		done:     make(chan struct{}),
	}

	return ln, nil
}

// socks5Listener implements net.Listener using SOCKS5 BIND.
// Each Accept() dials a new connection to the SOCKS5 server and issues a BIND request.
type socks5Listener struct {
	socks    *Socks5
	bindHost string
	bindPort int
	addr     net.Addr // bound address from probe
	done     chan struct{}
	once     sync.Once
}

func (l *socks5Listener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, errors.New("listener closed")
	default:
	}

	// Dial fresh connection to SOCKS5 server
	conn, err := l.socks.dialer.Dial("tcp", l.socks.addr)
	if err != nil {
		return nil, fmt.Errorf("[socks5] dial for bind: %w", err)
	}

	// Auth handshake
	if err := l.socks.authenticate(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("[socks5] auth for bind: %w", err)
	}

	// Send BIND request
	bindReq := buildBindRequest(l.bindHost, l.bindPort)
	if _, err := conn.Write(bindReq); err != nil {
		conn.Close()
		return nil, fmt.Errorf("[socks5] write bind: %w", err)
	}

	// Read first reply — confirms server is listening
	_, err = readBindReply(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("[socks5] bind reply 1: %w", err)
	}

	// Read second reply — an incoming connection has arrived
	// This blocks until a client connects to the bound port on the SOCKS5 server
	_, err = readBindReply(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("[socks5] bind reply 2 (waiting for connection): %w", err)
	}

	// conn is now connected to the incoming client — return it
	return conn, nil
}

func (l *socks5Listener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *socks5Listener) Addr() net.Addr {
	return l.addr
}

// buildBindRequest constructs a SOCKS5 BIND request packet.
func buildBindRequest(host string, port int) []byte {
	buf := make([]byte, 0, 10+len(host))
	buf = append(buf, Version, socks.CmdBind, 0) // VER, CMD=BIND, RSV

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, socks.ATypIP4)
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, socks.ATypIP6)
			buf = append(buf, ip...)
		}
	} else {
		// Use 0.0.0.0 for "any" if host is empty
		if host == "" {
			buf = append(buf, socks.ATypIP4, 0, 0, 0, 0)
		} else {
			buf = append(buf, socks.ATypDomain, byte(len(host)))
			buf = append(buf, host...)
		}
	}

	buf = append(buf, byte(port>>8), byte(port))
	return buf
}

// readBindReply reads a SOCKS5 reply and returns the bound/connected address.
func readBindReply(conn net.Conn) (net.Addr, error) {
	buf := pool.GetBuffer(socks.MaxAddrLen)
	defer pool.PutBuffer(buf)

	// Read VER, REP, RSV
	if _, err := io.ReadFull(conn, buf[:3]); err != nil {
		return nil, fmt.Errorf("read reply header: %w", err)
	}

	if buf[1] != 0 {
		rep := buf[1]
		msg := "unknown error"
		if int(rep) < len(socks.Errors) {
			msg = socks.Errors[rep].Error()
		}
		return nil, fmt.Errorf("SOCKS5 BIND failed (rep=%d): %s", rep, msg)
	}

	// Read ATYP + address + port
	addr, err := socks.ReadAddrBuf(conn, buf)
	if err != nil {
		return nil, fmt.Errorf("read bound address: %w", err)
	}

	tcpAddr, _ := net.ResolveTCPAddr("tcp", addr.String())
	if tcpAddr != nil {
		return tcpAddr, nil
	}
	// Fallback: return a simple string-based addr
	return &simpleAddr{network: "tcp", addr: addr.String()}, nil
}

type simpleAddr struct {
	network string
	addr    string
}

func (a *simpleAddr) Network() string { return a.network }
func (a *simpleAddr) String() string  { return a.addr }
