package ssh

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nadoo/glider/log"
	"github.com/nadoo/glider/proxy"
)

// SSH is a base ssh struct with persistent client and keepalive support.
type SSH struct {
	dialer proxy.Dialer
	proxy  proxy.Proxy
	addr   string
	config *ssh.ClientConfig

	mu     sync.Mutex
	client *ssh.Client
}

func init() {
	proxy.RegisterDialer("ssh", NewSSHDialer)
}

// NewSSH returns a ssh proxy.
func NewSSH(s string, d proxy.Dialer, p proxy.Proxy) (*SSH, error) {
	u, err := url.Parse(s)
	if err != nil {
		log.F("parse err: %s", err)
		return nil, err
	}

	user := u.User.Username()
	if user == "" {
		user = "root"
	}

	config := &ssh.ClientConfig{
		User:    user,
		Timeout: time.Second * 3,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	if pass, _ := u.User.Password(); pass != "" {
		config.Auth = []ssh.AuthMethod{ssh.Password(pass)}
	}

	if key := u.Query().Get("key"); key != "" {
		keyAuth, err := privateKeyAuth(key)
		if err != nil {
			log.F("[ssh] read key file error: %s", err)
			return nil, err
		}
		config.Auth = append(config.Auth, keyAuth)
	}

	h := &SSH{
		dialer: d,
		proxy:  p,
		addr:   u.Host,
		config: config,
	}

	return h, nil
}

// NewSSHDialer returns a ssh proxy dialer.
func NewSSHDialer(s string, d proxy.Dialer) (proxy.Dialer, error) {
	return NewSSH(s, d, nil)
}

// Addr returns forwarder's address.
func (s *SSH) Addr() string {
	if s.addr == "" {
		return s.dialer.Addr()
	}
	return s.addr
}

// getClient returns a persistent SSH client, creating or reconnecting as needed.
func (s *SSH) getClient() (*ssh.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.client != nil {
		// Check if client is still alive
		_, _, err := s.client.SendRequest("keepalive@slider", true, nil)
		if err == nil {
			return s.client, nil
		}
		log.F("[ssh] client to %s is dead, reconnecting: %s", s.addr, err)
		s.client.Close()
		s.client = nil
	}

	c, err := s.dialer.Dial("tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("[ssh] dial to %s: %w", s.addr, err)
	}

	sshc, ch, req, err := ssh.NewClientConn(c, s.addr, s.config)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("[ssh] handshake with %s: %w", s.addr, err)
	}

	client := ssh.NewClient(sshc, ch, req)
	s.client = client

	// Start keepalive goroutine
	go s.keepalive(client)

	log.F("[ssh] connected to %s", s.addr)
	return client, nil
}

// keepalive sends periodic keepalive requests to detect dead connections.
func (s *SSH) keepalive(client *ssh.Client) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	failures := 0
	for range ticker.C {
		_, _, err := client.SendRequest("keepalive@slider", true, nil)
		if err != nil {
			failures++
			if failures >= 3 {
				log.F("[ssh] keepalive to %s failed %d times, closing", s.addr, failures)
				s.mu.Lock()
				if s.client == client {
					s.client = nil
				}
				s.mu.Unlock()
				client.Close()
				return
			}
		} else {
			failures = 0
		}
	}
}

// Dial connects to the address addr on the network net via the SSH tunnel.
// Uses persistent multiplexed SSH client for efficiency.
func (s *SSH) Dial(network, addr string) (net.Conn, error) {
	client, err := s.getClient()
	if err != nil {
		return nil, err
	}

	conn, err := client.Dial(network, addr)
	if err != nil {
		// Connection might be stale, force reconnect and retry once
		s.mu.Lock()
		if s.client == client {
			s.client.Close()
			s.client = nil
		}
		s.mu.Unlock()

		client, err = s.getClient()
		if err != nil {
			return nil, err
		}
		return client.Dial(network, addr)
	}

	return conn, nil
}

// Listen requests the remote SSH server to listen on the given address.
// Implements proxy.RemoteListener for rtcp support.
func (s *SSH) Listen(network, addr string) (net.Listener, error) {
	client, err := s.getClient()
	if err != nil {
		return nil, err
	}

	ln, err := client.Listen(network, addr)
	if err != nil {
		// Force reconnect and retry once
		s.mu.Lock()
		if s.client == client {
			s.client.Close()
			s.client = nil
		}
		s.mu.Unlock()

		client, err = s.getClient()
		if err != nil {
			return nil, err
		}
		return client.Listen(network, addr)
	}

	log.F("[ssh] remote listening on %s via %s", addr, s.addr)
	return ln, nil
}

// DialUDP connects to the given address via the proxy.
func (s *SSH) DialUDP(network, addr string) (pc net.PacketConn, writeTo net.Addr, err error) {
	return nil, nil, proxy.ErrNotSupported
}

func privateKeyAuth(file string) (ssh.AuthMethod, error) {
	buffer, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil, err
	}

	return ssh.PublicKeys(key), nil
}
