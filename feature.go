package main

import (
	// comment out the services you don't need to make the compiled binary smaller.
	// _ "github.com/lovitus/slider/service/xxx"

	// comment out the protocols you don't need to make the compiled binary smaller.
	_ "github.com/lovitus/slider/proxy/http"
	_ "github.com/lovitus/slider/proxy/kcp"
	_ "github.com/lovitus/slider/proxy/ltcp"
	_ "github.com/lovitus/slider/proxy/mixed"
	_ "github.com/lovitus/slider/proxy/obfs"
	_ "github.com/lovitus/slider/proxy/reject"
	_ "github.com/lovitus/slider/proxy/rtcp"
	_ "github.com/lovitus/slider/proxy/socks4"
	_ "github.com/lovitus/slider/proxy/socks5"
	_ "github.com/lovitus/slider/proxy/ss"
	_ "github.com/lovitus/slider/proxy/ssh"
	_ "github.com/lovitus/slider/proxy/ssr"
	_ "github.com/lovitus/slider/proxy/tcp"
	_ "github.com/lovitus/slider/proxy/tls"
	_ "github.com/lovitus/slider/proxy/trojan"
	_ "github.com/lovitus/slider/proxy/udp"
	_ "github.com/lovitus/slider/proxy/vless"
	_ "github.com/lovitus/slider/proxy/vmess"
	_ "github.com/lovitus/slider/proxy/ws"
)
