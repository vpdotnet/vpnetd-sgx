package main

import (
	"encoding/base32"
	"net"
)

var b32e = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func getLocalHosts() []string {
	ips := getLocalIPs()
	res := make([]string, 0, len(ips))

	for _, ip := range ips {
		res = append(res, b32e.EncodeToString(ip[:])+".g-dns.net")
	}

	return res
}

func getLocalIPs() (ips []net.IP) {
	// Get public interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, iface := range ifaces {
		// Skip loopback, non-up interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// Skip nil IPs, loopback, and private addresses
			if ip == nil || ip.IsLoopback() || ip.IsPrivate() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // skip ipv6
			}

			ips = append(ips, ip)
		}
	}
	return
}
