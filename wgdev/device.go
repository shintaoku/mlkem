package wgdev

import (
	"fmt"
	"io"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Device wraps a wireguard-go device with PSK-aware configuration.
type Device struct {
	dev     *device.Device
	tunDev  tun.Device
	current *Config
}

// NewDevice creates a new WireGuard userspace device.
func NewDevice(tunDev tun.Device, bind conn.Bind, logger *device.Logger) *Device {
	dev := device.NewDevice(tunDev, bind, logger)
	return &Device{
		dev:    dev,
		tunDev: tunDev,
	}
}

// Configure applies the given config to the WireGuard device.
// It performs a diff against the previous config and only writes changes.
// This is analogous to Runetale's wgconfig.ReconfigDevice but with PSK support.
func (d *Device) Configure(cfg *Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	r, w := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		errc <- d.dev.IpcSetOperation(r)
		r.Close()
	}()

	writeErr := cfg.ToUAPI(w, d.current)
	w.Close()
	setErr := <-errc

	if writeErr != nil {
		return fmt.Errorf("wgdev: write UAPI: %w", writeErr)
	}
	if setErr != nil {
		return fmt.Errorf("wgdev: set operation: %w", setErr)
	}

	d.current = cfg
	return nil
}

// CurrentConfig returns the current configuration applied to the device.
func (d *Device) CurrentConfig() *Config {
	return d.current
}

// Close shuts down the WireGuard device.
func (d *Device) Close() {
	d.dev.Close()
}

// Underlying returns the raw wireguard-go device for advanced operations.
func (d *Device) Underlying() *device.Device {
	return d.dev
}
