package handlers

// The safeDialContext approach below is ported from usenix17/hidewall, which is
// distributed under the MIT License:
//
//	Copyright (c) usenix17
//
//	Permission is hereby granted, free of charge, to any person obtaining a copy
//	of this software and associated documentation files (the "Software"), to deal
//	in the Software without restriction, including without limitation the rights
//	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//	copies of the Software, and to permit persons to whom the Software is
//	furnished to do so, subject to the following conditions:
//
//	The above copyright notice and this permission notice shall be included in
//	all copies or substantial portions of the Software.
//
//	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//	SOFTWARE.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// RFC 6598 CGNAT. net.IP.IsPrivate() covers only RFC 1918 and does NOT include
// this range, which is where Tailscale addresses live.
var cgnat = func() *net.IPNet {
	_, n, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		panic(err)
	}
	return n
}()

// isDisallowedIP reports whether ip is outside the public internet and must
// therefore never be dialled on behalf of a proxied request.
func isDisallowedIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil && cgnat.Contains(ip4) {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast()
}

// safeDialContext resolves the host first, rejects the dial if ANY resolved
// address is non-public, and then dials the already-resolved IP. Dialling the
// validated IP rather than the name means there is no second, unvalidated
// resolution, so DNS rebinding cannot slip past the check.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for host %q", host)
	}
	for _, ip := range ips {
		if isDisallowedIP(ip.IP) {
			return nil, fmt.Errorf("blocked request to non-public address %s (host %q)", ip.IP, host)
		}
	}

	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, ip := range ips {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// safeTransport is a package-level singleton, deliberately not a constructor.
// fetchSite runs once per proxied request, so a Clone() per call would give
// every fetch a private connection pool that nobody closes: no keep-alive
// reuse, plus idle sockets and goroutines leaking for the full IdleConnTimeout.
//
// Every redirect hop dials through safeDialContext too, so a 302 to a private
// address is blocked without a separate CheckRedirect check.
var safeTransport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = safeDialContext
	return t
}()
