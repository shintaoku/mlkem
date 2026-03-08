// Package mlpsk provides post-quantum pre-shared key generation
// using ML-KEM-768 (FIPS 203) for WireGuard tunnel protection.
//
// ML-KEM produces a 32-byte shared secret that maps directly to
// WireGuard's 256-bit pre-shared key, enabling quantum-resistant
// key encapsulation without protocol changes.
package mlpsk

import (
	"crypto/mlkem"
	"fmt"
)

const (
	// SharedSecretSize is the size of the ML-KEM shared secret in bytes.
	// This matches WireGuard's PSK size (256 bits).
	SharedSecretSize = 32

	// EncapsulationKeySize is the size of an ML-KEM-768 encapsulation (public) key.
	EncapsulationKeySize = 1184

	// DecapsulationKeySeedSize is the size of an ML-KEM-768 decapsulation key seed.
	DecapsulationKeySeedSize = 64

	// CiphertextSize is the size of an ML-KEM-768 ciphertext.
	CiphertextSize = 1088
)

// KeyPair holds an ML-KEM-768 key pair for PSK generation.
type KeyPair struct {
	dk *mlkem.DecapsulationKey768
}

// GenerateKeyPair generates a new ML-KEM-768 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("mlpsk: generate key: %w", err)
	}
	return &KeyPair{dk: dk}, nil
}

// NewKeyPairFromSeed restores a key pair from a previously saved seed.
// The seed must be exactly DecapsulationKeySeedSize (64) bytes.
func NewKeyPairFromSeed(seed []byte) (*KeyPair, error) {
	if len(seed) != DecapsulationKeySeedSize {
		return nil, fmt.Errorf("mlpsk: invalid seed size %d, want %d", len(seed), DecapsulationKeySeedSize)
	}
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, fmt.Errorf("mlpsk: new key from seed: %w", err)
	}
	return &KeyPair{dk: dk}, nil
}

// Seed returns the decapsulation key seed for persistent storage.
// The returned slice is DecapsulationKeySeedSize (64) bytes.
func (kp *KeyPair) Seed() []byte {
	return kp.dk.Bytes()
}

// EncapsulationKey returns the public key bytes for distribution to peers.
// The returned slice is EncapsulationKeySize (1184) bytes.
func (kp *KeyPair) EncapsulationKey() []byte {
	return kp.dk.EncapsulationKey().Bytes()
}

// PSKExchange holds the result of an ML-KEM encapsulation.
type PSKExchange struct {
	// SharedSecret is the 32-byte shared secret to use as WireGuard PSK.
	SharedSecret [SharedSecretSize]byte

	// Ciphertext is the encapsulated key material to send to the peer
	// for decapsulation. The peer needs this plus their private key
	// to derive the same shared secret.
	Ciphertext []byte
}

// Encapsulate performs ML-KEM encapsulation against a peer's public key,
// producing a shared secret (for use as WireGuard PSK) and a ciphertext
// (to send to the peer for decapsulation).
//
// peerPublicKey must be exactly EncapsulationKeySize (1184) bytes.
func Encapsulate(peerPublicKey []byte) (*PSKExchange, error) {
	if len(peerPublicKey) != EncapsulationKeySize {
		return nil, fmt.Errorf("mlpsk: invalid public key size %d, want %d", len(peerPublicKey), EncapsulationKeySize)
	}

	ek, err := mlkem.NewEncapsulationKey768(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("mlpsk: parse encapsulation key: %w", err)
	}

	sharedSecret, ciphertext := ek.Encapsulate()

	var result PSKExchange
	copy(result.SharedSecret[:], sharedSecret)
	result.Ciphertext = ciphertext
	return &result, nil
}

// Decapsulate performs ML-KEM decapsulation using this key pair's private key
// and a ciphertext received from a peer, recovering the shared secret.
//
// The returned [SharedSecretSize]byte is identical to the shared secret
// the peer obtained from Encapsulate, suitable for use as a WireGuard PSK.
func (kp *KeyPair) Decapsulate(ciphertext []byte) ([SharedSecretSize]byte, error) {
	var psk [SharedSecretSize]byte

	if len(ciphertext) != CiphertextSize {
		return psk, fmt.Errorf("mlpsk: invalid ciphertext size %d, want %d", len(ciphertext), CiphertextSize)
	}

	sharedSecret, err := kp.dk.Decapsulate(ciphertext)
	if err != nil {
		return psk, fmt.Errorf("mlpsk: decapsulate: %w", err)
	}

	copy(psk[:], sharedSecret)
	return psk, nil
}

// EstablishPSK performs the initiator side of PSK establishment.
// It encapsulates against the responder's public key and returns the
// shared secret (to use as PSK) and the ciphertext (to send to the responder).
//
// In production, the initiator calls this with the responder's ML-KEM public
// key (received via NetworkMap), then sends the ciphertext via the coordination
// server. The responder calls KeyPair.Decapsulate to recover the same PSK.
func EstablishPSK(responderPublicKey []byte) (psk []byte, ciphertext []byte, err error) {
	exchange, err := Encapsulate(responderPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("mlpsk: establish psk: %w", err)
	}
	return exchange.SharedSecret[:], exchange.Ciphertext, nil
}

// ZeroPSK is the all-zero PSK, equivalent to WireGuard's default (no PSK).
var ZeroPSK [SharedSecretSize]byte

// IsZeroPSK reports whether the given PSK is all zeros (i.e., no PSK configured).
func IsZeroPSK(psk [SharedSecretSize]byte) bool {
	return psk == ZeroPSK
}

