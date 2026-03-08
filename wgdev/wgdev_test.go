package wgdev

import (
	"bytes"
	"crypto/rand"
	"net/netip"
	"strings"
	"testing"
)

func generateTestKey(t *testing.T) [32]byte {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "zero private key",
			cfg:     Config{},
			wantErr: true,
		},
		{
			name: "valid config no peers",
			cfg: Config{
				PrivateKey: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
			},
			wantErr: false,
		},
		{
			name: "peer with zero public key",
			cfg: Config{
				PrivateKey: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
				Peers:      []PeerConfig{{PublicKey: [32]byte{}}},
			},
			wantErr: true,
		},
		{
			name: "duplicate peer",
			cfg: Config{
				PrivateKey: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
				Peers: []PeerConfig{
					{PublicKey: [32]byte{1}},
					{PublicKey: [32]byte{1}},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHasPresharedKey(t *testing.T) {
	p := PeerConfig{}
	if p.HasPresharedKey() {
		t.Error("zero PSK should report false")
	}

	p.PresharedKey = [32]byte{1}
	if !p.HasPresharedKey() {
		t.Error("non-zero PSK should report true")
	}
}

func TestToUAPIFullConfig(t *testing.T) {
	privKey := generateTestKey(t)
	peerKey := generateTestKey(t)
	psk := generateTestKey(t)

	cfg := &Config{
		PrivateKey: privKey,
		ListenPort: 51820,
		Peers: []PeerConfig{
			{
				PublicKey:            peerKey,
				PresharedKey:         psk,
				Endpoint:             netip.MustParseAddrPort("192.168.1.1:51820"),
				AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
				PersistentKeepalive:  25,
			},
		},
	}

	var buf bytes.Buffer
	err := cfg.ToUAPI(&buf, nil)
	if err != nil {
		t.Fatalf("ToUAPI: %v", err)
	}

	output := buf.String()

	// Verify key fields are present
	if !strings.Contains(output, "private_key="+keyHex(privKey)) {
		t.Error("missing private_key")
	}
	if !strings.Contains(output, "listen_port=51820") {
		t.Error("missing listen_port")
	}
	if !strings.Contains(output, "public_key="+keyHex(peerKey)) {
		t.Error("missing peer public_key")
	}
	if !strings.Contains(output, "preshared_key="+keyHex(psk)) {
		t.Error("missing preshared_key")
	}
	if !strings.Contains(output, "endpoint=192.168.1.1:51820") {
		t.Error("missing endpoint")
	}
	if !strings.Contains(output, "allowed_ip=10.0.0.0/24") {
		t.Error("missing allowed_ip")
	}
	if !strings.Contains(output, "persistent_keepalive_interval=25") {
		t.Error("missing persistent_keepalive_interval")
	}
}

func TestToUAPINoPSK(t *testing.T) {
	cfg := &Config{
		PrivateKey: generateTestKey(t),
		Peers: []PeerConfig{
			{
				PublicKey:  generateTestKey(t),
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
			},
		},
	}

	var buf bytes.Buffer
	err := cfg.ToUAPI(&buf, nil)
	if err != nil {
		t.Fatalf("ToUAPI: %v", err)
	}

	// Zero PSK should not appear in output
	if strings.Contains(buf.String(), "preshared_key") {
		t.Error("zero PSK should not be emitted")
	}
}

func TestToUAPIDiffMode(t *testing.T) {
	privKey := generateTestKey(t)
	peerKey := generateTestKey(t)
	oldPSK := generateTestKey(t)
	newPSK := generateTestKey(t)

	prev := &Config{
		PrivateKey: privKey,
		Peers: []PeerConfig{
			{
				PublicKey:    peerKey,
				PresharedKey: oldPSK,
				AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
			},
		},
	}

	cfg := &Config{
		PrivateKey: privKey,
		Peers: []PeerConfig{
			{
				PublicKey:    peerKey,
				PresharedKey: newPSK,
				AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
			},
		},
	}

	var buf bytes.Buffer
	err := cfg.ToUAPI(&buf, prev)
	if err != nil {
		t.Fatalf("ToUAPI: %v", err)
	}

	output := buf.String()

	// Private key should NOT be re-emitted (unchanged)
	if strings.Contains(output, "private_key") {
		t.Error("unchanged private_key should not be emitted in diff mode")
	}

	// New PSK should be emitted
	if !strings.Contains(output, "preshared_key="+keyHex(newPSK)) {
		t.Error("changed preshared_key should be emitted")
	}
}

func TestToUAPIPeerRemoval(t *testing.T) {
	privKey := generateTestKey(t)
	peerKey := generateTestKey(t)

	prev := &Config{
		PrivateKey: privKey,
		Peers: []PeerConfig{
			{PublicKey: peerKey, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
		},
	}

	cfg := &Config{
		PrivateKey: privKey,
		Peers:      []PeerConfig{}, // peer removed
	}

	var buf bytes.Buffer
	err := cfg.ToUAPI(&buf, prev)
	if err != nil {
		t.Fatalf("ToUAPI: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "public_key="+keyHex(peerKey)) {
		t.Error("removed peer public_key should be emitted")
	}
	if !strings.Contains(output, "remove=true") {
		t.Error("remove=true should be emitted for removed peer")
	}
}

func TestFromUAPIRoundTrip(t *testing.T) {
	privKey := generateTestKey(t)
	peerKey := generateTestKey(t)
	psk := generateTestKey(t)

	cfg := &Config{
		PrivateKey: privKey,
		ListenPort: 51820,
		Peers: []PeerConfig{
			{
				PublicKey:            peerKey,
				PresharedKey:         psk,
				Endpoint:             netip.MustParseAddrPort("192.168.1.1:51820"),
				AllowedIPs:           []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
				PersistentKeepalive:  25,
			},
		},
	}

	var buf bytes.Buffer
	if err := cfg.ToUAPI(&buf, nil); err != nil {
		t.Fatalf("ToUAPI: %v", err)
	}

	parsed, err := FromUAPI(strings.NewReader(buf.String()))
	if err != nil {
		t.Fatalf("FromUAPI: %v", err)
	}

	if parsed.PrivateKey != cfg.PrivateKey {
		t.Error("private key mismatch")
	}
	if parsed.ListenPort != cfg.ListenPort {
		t.Error("listen port mismatch")
	}
	if len(parsed.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(parsed.Peers))
	}

	pp := parsed.Peers[0]
	cp := cfg.Peers[0]

	if pp.PublicKey != cp.PublicKey {
		t.Error("peer public key mismatch")
	}
	if pp.PresharedKey != cp.PresharedKey {
		t.Error("peer preshared key mismatch after round-trip")
	}
	if pp.Endpoint != cp.Endpoint {
		t.Error("peer endpoint mismatch")
	}
	if len(pp.AllowedIPs) != len(cp.AllowedIPs) || pp.AllowedIPs[0] != cp.AllowedIPs[0] {
		t.Error("peer allowed IPs mismatch")
	}
	if pp.PersistentKeepalive != cp.PersistentKeepalive {
		t.Error("peer keepalive mismatch")
	}
}

func TestFromUAPINoPSK(t *testing.T) {
	uapi := "private_key=0100000000000000000000000000000000000000000000000000000000000000\n" +
		"public_key=0200000000000000000000000000000000000000000000000000000000000000\n" +
		"allowed_ip=10.0.0.0/24\n"

	parsed, err := FromUAPI(strings.NewReader(uapi))
	if err != nil {
		t.Fatalf("FromUAPI: %v", err)
	}

	if len(parsed.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(parsed.Peers))
	}

	if parsed.Peers[0].HasPresharedKey() {
		t.Error("peer should have zero PSK when not in UAPI")
	}
}

func TestPeerWithKey(t *testing.T) {
	k1 := generateTestKey(t)
	k2 := generateTestKey(t)
	k3 := generateTestKey(t)

	cfg := Config{
		PrivateKey: generateTestKey(t),
		Peers: []PeerConfig{
			{PublicKey: k1},
			{PublicKey: k2},
		},
	}

	if p := cfg.PeerWithKey(k1); p == nil {
		t.Error("should find peer k1")
	}
	if p := cfg.PeerWithKey(k2); p == nil {
		t.Error("should find peer k2")
	}
	if p := cfg.PeerWithKey(k3); p != nil {
		t.Error("should not find peer k3")
	}
}
