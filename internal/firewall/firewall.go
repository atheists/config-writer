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
		logger.Info("Parsed prefix", "prefix", prefix)
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
		f.logger.Info("Rejecting malformed address", "rawAddrPort",rawAddrPort))
		return false
	}

	for _, allowedPrefix := range f.allowedPrefixes {
		if allowedPrefix.Contains(addrPort.Addr()) {
			return true
		}
	}

	return false
}
