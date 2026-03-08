// Command mlkem demonstrates ML-KEM-768 based pre-shared key generation
// for WireGuard tunnel protection.
//
// This is a study implementation to understand how Runetale can integrate
// post-quantum cryptography via WireGuard's PSK mechanism.
//
// Run: go run main.go
// Test all: go test ./...
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/shintaoku/mlkem/mlpsk"
	"github.com/shintaoku/mlkem/wgdev"
)

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║     ML-KEM-768 → WireGuard PSK Demo                          ║")
	fmt.Println("║     Post-Quantum Key Encapsulation for Runetale              ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	demoMLKEMBasics()
	demoKeyPersistence()
	demoPSKEstablishment()
	demoWireGuardConfig()
}

func demoMLKEMBasics() {
	fmt.Println("── Step 1: ML-KEM-768 Basics ──────────────────────────────────")
	fmt.Println()

	kp, err := mlpsk.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("  Decapsulation Key (seed): %d bytes\n", len(kp.Seed()))
	fmt.Printf("  Encapsulation Key:        %d bytes\n", len(kp.EncapsulationKey()))
	fmt.Printf("  Shared Secret (PSK):      %d bytes (= WireGuard PSK size)\n", mlpsk.SharedSecretSize)
	fmt.Printf("  Ciphertext:               %d bytes\n", mlpsk.CiphertextSize)
	fmt.Println()
}

func demoKeyPersistence() {
	fmt.Println("── Step 2: Key Persistence (seed round-trip) ──────────────────")
	fmt.Println()

	kp1, err := mlpsk.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	seed := kp1.Seed()
	fmt.Printf("  Original seed:  %s...\n", hex.EncodeToString(seed[:16]))

	kp2, err := mlpsk.NewKeyPairFromSeed(seed)
	if err != nil {
		log.Fatal(err)
	}

	match := hex.EncodeToString(kp1.EncapsulationKey()) == hex.EncodeToString(kp2.EncapsulationKey())
	fmt.Printf("  Restored seed:  %s...\n", hex.EncodeToString(kp2.Seed()[:16]))
	fmt.Printf("  Public keys match: %v\n", match)
	fmt.Println()
}

func demoPSKEstablishment() {
	fmt.Println("── Step 3: PSK Establishment (Node A → Node B) ────────────────")
	fmt.Println()

	fmt.Println("  [Node B] Generate ML-KEM key pair")
	nodeB, err := mlpsk.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  [Node B] Public key: %s...%s (%d bytes)\n",
		hex.EncodeToString(nodeB.EncapsulationKey()[:8]),
		hex.EncodeToString(nodeB.EncapsulationKey()[len(nodeB.EncapsulationKey())-8:]),
		len(nodeB.EncapsulationKey()))
	fmt.Println()

	fmt.Println("  [Server] Distributes Node B's public key via NetworkMap")
	fmt.Println()

	fmt.Println("  [Node A] Encapsulate with Node B's public key")
	exchange, err := mlpsk.Encapsulate(nodeB.EncapsulationKey())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  [Node A] Shared secret: %s\n", hex.EncodeToString(exchange.SharedSecret[:]))
	fmt.Printf("  [Node A] Ciphertext:    %s...%s (%d bytes)\n",
		hex.EncodeToString(exchange.Ciphertext[:8]),
		hex.EncodeToString(exchange.Ciphertext[len(exchange.Ciphertext)-8:]),
		len(exchange.Ciphertext))
	fmt.Println()

	fmt.Println("  [Server] Relays ciphertext to Node B")
	fmt.Println()

	fmt.Println("  [Node B] Decapsulate with private key")
	pskB, err := nodeB.Decapsulate(exchange.Ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  [Node B] Shared secret: %s\n", hex.EncodeToString(pskB[:]))
	fmt.Println()

	fmt.Printf("  ✓ Secrets match: %v\n", pskB == exchange.SharedSecret)
	fmt.Printf("  ✓ Secret size = %d bytes = WireGuard PSK (256 bits)\n", len(pskB))
	fmt.Println()

	fmt.Println("  Security properties:")
	fmt.Println("    • Server sees ciphertext but CANNOT derive the shared secret")
	fmt.Println("    • A quantum computer CANNOT break ML-KEM-768 (FIPS 203)")
	fmt.Println("    • Each encapsulation produces a unique secret (randomized)")
	fmt.Println()
}

func demoWireGuardConfig() {
	fmt.Println("── Step 4: WireGuard UAPI Config with PSK ─────────────────────")
	fmt.Println()

	nodeB, _ := mlpsk.GenerateKeyPair()
	exchange, _ := mlpsk.Encapsulate(nodeB.EncapsulationKey())
	psk := exchange.SharedSecret

	// Simulated WireGuard keys (random for demo)
	var privKey, peerPubKey [32]byte
	copy(privKey[:], []byte("abcdefghijklmnopqrstuvwxyz123456"))
	copy(peerPubKey[:], []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"))

	cfg := &wgdev.Config{
		PrivateKey: privKey,
		ListenPort: 51820,
		Peers: []wgdev.PeerConfig{
			{
				PublicKey:    peerPubKey,
				PresharedKey: psk,
			},
		},
	}

	fmt.Println("  UAPI output (with ML-KEM PSK):")
	fmt.Println("  " + strings.Repeat("─", 50))

	var buf strings.Builder
	cfg.ToUAPI(&buf, nil)
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		fmt.Printf("  │ %s\n", line)
	}
	fmt.Println("  " + strings.Repeat("─", 50))
	fmt.Println()

	fmt.Println("  Comparison with Runetale's current wgconfig:")
	fmt.Println("    • Runetale: Peer struct has NO PresharedKey field")
	fmt.Println("    • Runetale: writer.go does NOT emit preshared_key")
	fmt.Println("    • Runetale: parser.go explicitly IGNORES preshared_key")
	fmt.Println("    • This demo: All three are implemented and working")
	fmt.Println()

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Run 'go test ./...' to see full E2E tunnel tests")
	fmt.Println("  including actual packet transit through ML-KEM PSK tunnels")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	os.Exit(0)
}
