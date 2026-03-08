// Package wgdev provides WireGuard userspace device management with
// pre-shared key support. It wraps golang.zx2c4.com/wireguard/device
// and adds PSK-aware configuration via the UAPI protocol.
//
// This is a study implementation to understand how Runetale's wgconfig
// package can be extended to support ML-KEM derived PSKs.
package wgdev

import (
	"encoding/hex"
	"fmt"
	"net/netip"
)

// Config represents a WireGuard device configuration.
type Config struct {
	PrivateKey [32]byte
	ListenPort uint16
	Peers      []PeerConfig
}

// PeerConfig represents a WireGuard peer configuration with PSK support.
type PeerConfig struct {
	PublicKey           [32]byte
	PresharedKey        [32]byte // ML-KEM derived PSK; all-zero means no PSK
	Endpoint            netip.AddrPort
	AllowedIPs          []netip.Prefix
	PersistentKeepalive uint16
}

// HasPresharedKey reports whether this peer has a non-zero PSK configured.
func (p *PeerConfig) HasPresharedKey() bool {
	return p.PresharedKey != [32]byte{}
}

// PublicKeyHex returns the hex-encoded public key of the device's private key.
func keyHex(k [32]byte) string {
	return hex.EncodeToString(k[:])
}

// PeerWithKey returns the peer with the given public key, or nil if not found.
func (c *Config) PeerWithKey(pubkey [32]byte) *PeerConfig {
	for i := range c.Peers {
		if c.Peers[i].PublicKey == pubkey {
			return &c.Peers[i]
		}
	}
	return nil
}

// Validate checks that the config is well-formed.
func (c *Config) Validate() error {
	var zero [32]byte
	if c.PrivateKey == zero {
		return fmt.Errorf("wgdev: private key is zero")
	}
	seen := make(map[[32]byte]bool)
	for i, p := range c.Peers {
		if p.PublicKey == zero {
			return fmt.Errorf("wgdev: peer %d has zero public key", i)
		}
		if seen[p.PublicKey] {
			return fmt.Errorf("wgdev: duplicate peer public key at index %d", i)
		}
		seen[p.PublicKey] = true
	}
	return nil
}
