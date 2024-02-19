package firewall

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
)

type Firewall struct {
	allowedPrefixes []netip.Prefix
	logger          *slog.Logger
}

func New(raw string, logger *slog.Logger) (*Firewall, error) {
	if raw == "" {
		return &Firewall{}, nil
	}

	rawPrefixes := strings.Fields(strings.ReplaceAll(raw, ",", " "))
	var prefixes []netip.Prefix
	for _, rawPrefix := range rawPrefixes {
		prefix, err := netip.ParsePrefix(rawPrefix)
		if err != nil {
			return nil, fmt.Errorf("parsing prefix %q: %w", rawPrefix, err)
		}
		prefixes = append(prefixes, prefix)
		logger.Info(fmt.Sprintf("Parsed prefix %q", prefix))
	}
	return &Firewall{
		allowedPrefixes: prefixes,
		logger:          logger,
	}, nil
}

func (f *Firewall) Authorized(rawAddrPort string) bool {
	if len(f.allowedPrefixes) == 0 {
		return true
	}
	addrPort, err := netip.ParseAddrPort(rawAddrPort)
	if err != nil {
		f.logger.Info(fmt.Sprintf("Rejecting malformed address %q", rawAddrPort))
		return false
	}

	for _, allowedPrefix := range f.allowedPrefixes {
		if allowedPrefix.Contains(addrPort.Addr()) {
			return true
		}
	}

	return false

	/*
		if !strings.Contains(ipAndPort, ":") {
			return fmt.Errorf("no colon in remote address %q", ipAndPort)
		}
		parts := strings.Split(ipAndPort, ":")
		rawIPAddr := strings.Join(parts[:len(parts)-1], ":")

		ip := net.ParseIP(rawIPAddr)
		if ip == nil {
			return fmt.Errorf("failed to parse raw IP address %q", rawIPAddr)
		}

		for _, cidr := range cidrs {
			if cidr.Contains(ip) {
				return nil
			}
		}
		return fmt.Errorf("IP address %v was not part of any allowed prefix", ip)
	*/
}
