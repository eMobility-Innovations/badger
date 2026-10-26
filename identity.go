package badger

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// Only the first Badger instance resolves identity. Subsequent instances use
// private process context, which cannot be supplied in an HTTP request header.
type identityContextKey struct{}
type requestIdentity struct {
	client, host, scheme, port                          string
	transport, originalHost, profile, generation, scope string
	assertions                                          http.Header
	authoritative                                       bool
}

func member(address net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(address) {
			return true
		}
	}
	return false
}

func singleHeader(req *http.Request, name string) (string, error) {
	values := req.Header.Values(name)
	if len(values) > 1 {
		return "", fmt.Errorf("ambiguous identity header")
	}
	if len(values) == 0 {
		return "", nil
	}
	return strings.TrimSpace(values[0]), nil
}

func parseAddress(value string) (net.IP, error) {
	address := net.ParseIP(strings.TrimSpace(value))
	if address == nil {
		return nil, fmt.Errorf("invalid identity address")
	}
	return address, nil
}

func (p *Badger) forwardedClient(req *http.Request, peer net.IP) (string, error) {
	forwarded, err := singleHeader(req, xForwardFor)
	if err != nil {
		return "", err
	}
	if forwarded == "" {
		return peer.String(), nil
	}
	parts := strings.Split(forwarded, ",")
	chain := make([]net.IP, 0, len(parts))
	for _, part := range parts {
		address, err := parseAddress(part)
		if err != nil {
			return "", err
		}
		chain = append(chain, address)
	}
	for i := len(chain) - 1; i >= 0; i-- {
		if !member(chain[i], p.trustedProxyIP) && !member(chain[i], p.trustIP) {
			return chain[i].String(), nil
		}
	}
	return peer.String(), nil
}

func (p *Badger) clientAddress(req *http.Request, peer net.IP) (string, error) {
	if member(peer, p.trustedProxyIP) {
		return p.forwardedClient(req, peer)
	}
	if !member(peer, p.trustIP) {
		return peer.String(), nil
	}
	header := p.customIPHeader
	if header == "" {
		header = cfConnectingIP
	}
	value, err := singleHeader(req, header)
	if err != nil {
		return "", err
	}
	if value == "" {
		return p.forwardedClient(req, peer)
	}
	address, err := parseAddress(value)
	if err != nil {
		return "", err
	}
	return address.String(), nil
}

func hostname(authority string) string {
	host, _, err := net.SplitHostPort(authority)
	if err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(authority)
}

func includes(values []string, candidate string) bool {
	for _, value := range values {
		if strings.EqualFold(value, candidate) {
			return true
		}
	}
	return false
}

func (p *Badger) publicHost(req *http.Request, trusted bool) (string, error) {
	host := req.Host
	if trusted {
		forwarded, err := singleHeader(req, "X-Forwarded-Host")
		if err != nil {
			return "", err
		}
		if forwarded != "" {
			if len(p.allowedHosts) == 0 && !strings.EqualFold(forwarded, req.Host) {
				return "", fmt.Errorf("unapproved public authority")
			}
			host = forwarded
		}
	}
	if len(p.allowedHosts) > 0 && !includes(p.allowedHosts, hostname(host)) {
		return "", fmt.Errorf("unapproved public host")
	}
	return host, nil
}

func (p *Badger) publicScheme(req *http.Request, trusted, cdn bool) (string, error) {
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}
	if trusted {
		forwarded, err := singleHeader(req, xForwardProto)
		if err != nil {
			return "", err
		}
		if forwarded != "" {
			scheme = forwarded
		}
	}
	if cdn {
		visitor, err := singleHeader(req, cfVisitor)
		if err != nil {
			return "", err
		}
		if visitor != "" {
			var value struct {
				Scheme string `json:"scheme"`
			}
			if json.Unmarshal([]byte(visitor), &value) != nil {
				return "", fmt.Errorf("invalid CDN scheme")
			}
			if value.Scheme != "" {
				scheme = value.Scheme
			}
		}
	}
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("invalid public scheme")
	}
	if len(p.allowedSchemes) > 0 && !includes(p.allowedSchemes, scheme) {
		return "", fmt.Errorf("unapproved public scheme")
	}
	return scheme, nil
}

func publicPort(req *http.Request, host, scheme string, trusted bool) (string, error) {
	_, port, _ := net.SplitHostPort(host)
	if trusted {
		forwarded, err := singleHeader(req, "X-Forwarded-Port")
		if err != nil {
			return "", err
		}
		if forwarded != "" {
			port = forwarded
		}
	}
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return "", fmt.Errorf("invalid public port")
	}
	return strconv.Itoa(value), nil
}

func (p *Badger) identity(req *http.Request) (requestIdentity, error) {
	var identity requestIdentity
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	peer, err := parseAddress(host)
	if err != nil {
		return identity, err
	}
	trusted := member(peer, p.trustIP) || member(peer, p.trustedProxyIP)
	identity.client, err = p.clientAddress(req, peer)
	if err != nil {
		return identity, err
	}
	identity.host, err = p.publicHost(req, trusted)
	if err != nil {
		return identity, err
	}
	identity.scheme, err = p.publicScheme(req, trusted, member(peer, p.trustIP) && !member(peer, p.trustedProxyIP))
	if err != nil {
		return identity, err
	}
	identity.port, err = publicPort(req, identity.host, identity.scheme, trusted)
	return identity, err
}

func (p *Badger) applyClientIdentity(req *http.Request) (string, error) {
	identity, present := req.Context().Value(identityContextKey{}).(requestIdentity)
	if present && (!p.profilelessConsumer() || !identity.authoritative) {
		original := req.Clone(req.Context())
		original.Header = identity.assertions.Clone()
		original.Host = identity.originalHost
		candidate, err := p.identity(original)
		if err != nil || candidate.client != identity.client || candidate.host != identity.host || candidate.scheme != identity.scheme || candidate.port != identity.port {
			return "", fmt.Errorf("incompatible client identity profile")
		}
	}
	if present && (identity.transport != req.RemoteAddr || identity.originalHost != req.Host ||
		req.Header.Get(xRealIP) != identity.client || req.Header.Get(xForwardFor) != identity.client ||
		req.Header.Get("X-Forwarded-Host") != identity.host || req.Header.Get(xForwardProto) != identity.scheme ||
		req.Header.Get("X-Forwarded-Port") != identity.port) {
		return "", fmt.Errorf("client identity request binding changed")
	}
	if !present {
		var err error
		identity, err = p.identity(req)
		if err != nil {
			return "", err
		}
		identity.transport, identity.originalHost = req.RemoteAddr, req.Host
		identity.assertions = req.Header.Clone()
	}
	if p.authoritativeIngress {
		identity.authoritative = true
		identity.profile, identity.generation, identity.scope = p.identityProfile, p.identityGeneration, p.identityScope
	}
	*req = *req.WithContext(context.WithValue(req.Context(), identityContextKey{}, identity))
	req.Header.Set(xForwardFor, identity.client)
	req.Header.Set(xRealIP, identity.client)
	req.Header.Set("X-Forwarded-Host", identity.host)
	req.Header.Set(xForwardProto, identity.scheme)
	req.Header.Set("X-Forwarded-Port", identity.port)
	req.Header.Del(cfVisitor)
	req.Header.Del(cfConnectingIP)
	req.Header.Del("True-Client-IP")
	if p.realIPHeader != "" {
		req.Header.Set(p.realIPHeader, identity.client)
	}
	return identity.client, nil
}

func (p *Badger) profilelessConsumer() bool {
	return !p.authoritativeIngress && p.identityProfile == "" && p.identityGeneration == "" &&
		len(p.trustedProxyIP) == 0 && len(p.allowedHosts) == 0 && len(p.allowedSchemes) == 0
}
