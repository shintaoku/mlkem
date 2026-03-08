// Package tunnel provides E2E testing utilities for WireGuard tunnels
// with ML-KEM derived pre-shared keys.
package tunnel

import (
	"io"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// ChannelTUN is a TUN device backed by Go channels, allowing two WireGuard
// devices to be connected in-process without real network interfaces.
//
// Packets written to the TUN (by the WireGuard device after decryption)
// appear on Inbound. Packets injected via Outbound are read by the WireGuard
// device for encryption and sending.
type ChannelTUN struct {
	name string
	mtu  int

	// Inbound receives packets that the WireGuard device has decrypted
	// and written to the TUN interface (i.e., cleartext arriving from peers).
	Inbound chan []byte

	// Outbound is where test code injects cleartext packets to be encrypted
	// and sent by the WireGuard device.
	Outbound chan []byte

	events chan tun.Event
	closed chan struct{}
	once   sync.Once
}

// NewChannelTUN creates a new channel-based TUN device.
func NewChannelTUN(name string, mtu int) *ChannelTUN {
	t := &ChannelTUN{
		name:     name,
		mtu:      mtu,
		Inbound:  make(chan []byte, 256),
		Outbound: make(chan []byte, 256),
		events:   make(chan tun.Event, 4),
		closed:   make(chan struct{}),
	}
	// Signal that the TUN is up
	t.events <- tun.EventUp
	return t
}

// File is not supported for channel TUN.
func (t *ChannelTUN) File() *os.File { return nil }

// Read waits for a packet from Outbound (injected by test code) and copies
// it into the WireGuard device's read buffer.
func (t *ChannelTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, io.EOF
	case pkt := <-t.Outbound:
		n := copy(bufs[0][offset:], pkt)
		sizes[0] = n
		return 1, nil
	}
}

// Write receives a decrypted packet from the WireGuard device and sends
// it to the Inbound channel for test verification.
func (t *ChannelTUN) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, io.ErrClosedPipe
	default:
	}

	for i, buf := range bufs {
		if offset > len(buf) {
			continue
		}
		pkt := make([]byte, len(buf[offset:]))
		copy(pkt, buf[offset:])
		select {
		case t.Inbound <- pkt:
		case <-t.closed:
			return i, io.ErrClosedPipe
		}
	}
	return len(bufs), nil
}

func (t *ChannelTUN) Flush() error             { return nil }
func (t *ChannelTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *ChannelTUN) Name() (string, error)    { return t.name, nil }
func (t *ChannelTUN) Events() <-chan tun.Event { return t.events }
func (t *ChannelTUN) BatchSize() int           { return 1 }

func (t *ChannelTUN) Close() error {
	t.once.Do(func() {
		close(t.closed)
	})
	return nil
}
