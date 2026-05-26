package main

import (
	// comment out the services you don't need to make the compiled binary smaller.
	_ "github.com/lovitus/slider/service/dhcpd"

	// comment out the protocols you don't need to make the compiled binary smaller.
	_ "github.com/lovitus/slider/proxy/redir"
	_ "github.com/lovitus/slider/proxy/unix"
)
