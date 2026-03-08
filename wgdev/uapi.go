package wgdev

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// ToUAPI writes the WireGuard UAPI configuration to w.
// If prev is non-nil, only changed settings are emitted (diff mode).
// If prev is nil, the full configuration is written.
//
// Unlike Runetale's wgconfig.ToUAPI, this implementation includes
// preshared_key in the output when it is non-zero.
func (cfg *Config) ToUAPI(w io.Writer, prev *Config) error {
	var stickyErr error
	set := func(key, value string) {
		if stickyErr != nil {
			return
		}
		_, err := fmt.Fprintf(w, "%s=%s\n", key, value)
		if err != nil {
			stickyErr = err
		}
	}

	if prev == nil || prev.PrivateKey != cfg.PrivateKey {
		set("private_key", keyHex(cfg.PrivateKey))
	}

	if cfg.ListenPort > 0 && (prev == nil || prev.ListenPort != cfg.ListenPort) {
		set("listen_port", strconv.Itoa(int(cfg.ListenPort)))
	}

	old := make(map[[32]byte]PeerConfig)
	if prev != nil {
		for _, p := range prev.Peers {
			old[p.PublicKey] = p
		}
	}

	for _, p := range cfg.Peers {
		oldPeer, wasPresent := old[p.PublicKey]

		needsUpdate := !wasPresent ||
			oldPeer.PresharedKey != p.PresharedKey ||
			oldPeer.Endpoint != p.Endpoint ||
			!prefixesEqual(oldPeer.AllowedIPs, p.AllowedIPs) ||
			oldPeer.PersistentKeepalive != p.PersistentKeepalive

		if !needsUpdate {
			continue
		}

		set("public_key", keyHex(p.PublicKey))

		// PSK: emit when non-zero, or when changing from non-zero to zero
		if p.HasPresharedKey() || (wasPresent && oldPeer.HasPresharedKey()) {
			set("preshared_key", keyHex(p.PresharedKey))
		}

		if p.Endpoint.IsValid() && (!wasPresent || oldPeer.Endpoint != p.Endpoint) {
			set("endpoint", p.Endpoint.String())
		}

		if !wasPresent || !prefixesEqual(oldPeer.AllowedIPs, p.AllowedIPs) {
			set("replace_allowed_ips", "true")
			for _, ipp := range p.AllowedIPs {
				set("allowed_ip", ipp.String())
			}
		}

		if !wasPresent || oldPeer.PersistentKeepalive != p.PersistentKeepalive {
			set("persistent_keepalive_interval", strconv.Itoa(int(p.PersistentKeepalive)))
		}
	}

	// Remove peers that are no longer in the config
	for pubkey := range old {
		found := false
		for _, p := range cfg.Peers {
			if p.PublicKey == pubkey {
				found = true
				break
			}
		}
		if !found {
			set("public_key", keyHex(pubkey))
			set("remove", "true")
		}
	}

	return stickyErr
}

// FromUAPI parses a WireGuard UAPI configuration from r.
// Unlike Runetale's parser, this implementation parses preshared_key.
func FromUAPI(r io.Reader) (*Config, error) {
	cfg := &Config{}
	var peer *PeerConfig
	deviceSection := true

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("wgdev: invalid UAPI line: %q", line)
		}

		if key == "public_key" {
			deviceSection = false
			k, err := parseHexKey(value)
			if err != nil {
				return nil, fmt.Errorf("wgdev: parse peer public_key: %w", err)
			}
			cfg.Peers = append(cfg.Peers, PeerConfig{PublicKey: k})
			peer = &cfg.Peers[len(cfg.Peers)-1]
			continue
		}

		if deviceSection {
			if err := parseDeviceLine(cfg, key, value); err != nil {
				return nil, err
			}
		} else if peer != nil {
			if err := parsePeerLine(peer, key, value); err != nil {
				return nil, err
			}
		}
	}

	return cfg, scanner.Err()
}

func parseDeviceLine(cfg *Config, key, value string) error {
	switch key {
	case "private_key":
		k, err := parseHexKey(value)
		if err != nil {
			return fmt.Errorf("wgdev: parse private_key: %w", err)
		}
		cfg.PrivateKey = k
	case "listen_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return fmt.Errorf("wgdev: parse listen_port: %w", err)
		}
		cfg.ListenPort = uint16(port)
	case "fwmark":
		// ignore
	default:
		return fmt.Errorf("wgdev: unknown device key: %q", key)
	}
	return nil
}

func parsePeerLine(peer *PeerConfig, key, value string) error {
	switch key {
	case "preshared_key":
		k, err := parseHexKey(value)
		if err != nil {
			return fmt.Errorf("wgdev: parse preshared_key: %w", err)
		}
		peer.PresharedKey = k
	case "endpoint":
		ep, err := netip.ParseAddrPort(value)
		if err != nil {
			return fmt.Errorf("wgdev: parse endpoint: %w", err)
		}
		peer.Endpoint = ep
	case "persistent_keepalive_interval":
		n, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return fmt.Errorf("wgdev: parse persistent_keepalive_interval: %w", err)
		}
		peer.PersistentKeepalive = uint16(n)
	case "allowed_ip":
		ipp, err := netip.ParsePrefix(value)
		if err != nil {
			return fmt.Errorf("wgdev: parse allowed_ip: %w", err)
		}
		peer.AllowedIPs = append(peer.AllowedIPs, ipp)
	case "replace_allowed_ips", "protocol_version",
		"last_handshake_time_sec", "last_handshake_time_nsec",
		"tx_bytes", "rx_bytes":
		// ignore
	case "remove":
		// ignore in parsing (handled by caller)
	default:
		return fmt.Errorf("wgdev: unknown peer key: %q", key)
	}
	return nil
}

func parseHexKey(s string) ([32]byte, error) {
	var k [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return k, err
	}
	if len(b) != 32 {
		return k, fmt.Errorf("key length %d, want 32", len(b))
	}
	copy(k[:], b)
	return k, nil
}

func prefixesEqual(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
