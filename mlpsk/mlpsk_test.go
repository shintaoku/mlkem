package mlpsk

import (
	"bytes"
	"crypto/mlkem"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	seed := kp.Seed()
	if len(seed) != DecapsulationKeySeedSize {
		t.Errorf("seed size = %d, want %d", len(seed), DecapsulationKeySeedSize)
	}

	ek := kp.EncapsulationKey()
	if len(ek) != EncapsulationKeySize {
		t.Errorf("encapsulation key size = %d, want %d", len(ek), EncapsulationKeySize)
	}
}

func TestKeyPairFromSeed(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	seed := kp1.Seed()
	kp2, err := NewKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("NewKeyPairFromSeed: %v", err)
	}

	if !bytes.Equal(kp1.EncapsulationKey(), kp2.EncapsulationKey()) {
		t.Error("restored key pair has different public key")
	}

	if !bytes.Equal(kp1.Seed(), kp2.Seed()) {
		t.Error("restored key pair has different seed")
	}
}

func TestKeyPairFromSeedInvalidSize(t *testing.T) {
	_, err := NewKeyPairFromSeed([]byte("too short"))
	if err == nil {
		t.Error("expected error for invalid seed size")
	}
}

func TestEncapsulateDecapsulate(t *testing.T) {
	responder, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	exchange, err := Encapsulate(responder.EncapsulationKey())
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	if len(exchange.Ciphertext) != CiphertextSize {
		t.Errorf("ciphertext size = %d, want %d", len(exchange.Ciphertext), CiphertextSize)
	}

	psk, err := responder.Decapsulate(exchange.Ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if psk != exchange.SharedSecret {
		t.Error("shared secrets do not match")
	}
}

func TestSharedSecretSize(t *testing.T) {
	responder, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	exchange, err := Encapsulate(responder.EncapsulationKey())
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	if len(exchange.SharedSecret) != SharedSecretSize {
		t.Errorf("shared secret size = %d, want %d (WireGuard PSK size)", len(exchange.SharedSecret), SharedSecretSize)
	}
}

func TestEncapsulateInvalidPublicKey(t *testing.T) {
	_, err := Encapsulate([]byte("invalid"))
	if err == nil {
		t.Error("expected error for invalid public key")
	}
}

func TestDecapsulateInvalidCiphertext(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	_, err = kp.Decapsulate([]byte("invalid"))
	if err == nil {
		t.Error("expected error for invalid ciphertext")
	}
}

func TestDecapsulateWrongKey(t *testing.T) {
	responder, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	wrongKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	exchange, err := Encapsulate(responder.EncapsulationKey())
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	// ML-KEM decapsulation with wrong key produces a different shared secret
	// (it does NOT return an error — this is by design for IND-CCA2 security)
	wrongPSK, err := wrongKey.Decapsulate(exchange.Ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate with wrong key: %v", err)
	}

	if wrongPSK == exchange.SharedSecret {
		t.Error("decapsulation with wrong key should produce different shared secret")
	}
}

func TestEstablishPSK(t *testing.T) {
	responder, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	pskBytes, ciphertext, err := EstablishPSK(responder.EncapsulationKey())
	if err != nil {
		t.Fatalf("EstablishPSK: %v", err)
	}

	if len(pskBytes) != SharedSecretSize {
		t.Errorf("PSK size = %d, want %d", len(pskBytes), SharedSecretSize)
	}

	responderPSK, err := responder.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if !bytes.Equal(pskBytes, responderPSK[:]) {
		t.Error("initiator and responder PSKs do not match")
	}
}

func TestBidirectionalPSK(t *testing.T) {
	nodeA, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair A: %v", err)
	}
	nodeB, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair B: %v", err)
	}

	// A→B encapsulation
	exchangeAB, err := Encapsulate(nodeB.EncapsulationKey())
	if err != nil {
		t.Fatalf("Encapsulate A→B: %v", err)
	}

	// B→A encapsulation
	exchangeBA, err := Encapsulate(nodeA.EncapsulationKey())
	if err != nil {
		t.Fatalf("Encapsulate B→A: %v", err)
	}

	// Each direction produces a different shared secret
	if exchangeAB.SharedSecret == exchangeBA.SharedSecret {
		t.Error("A→B and B→A should produce different shared secrets (each encapsulation is randomized)")
	}

	// But each side can recover the same secret for a given direction
	pskB, err := nodeB.Decapsulate(exchangeAB.Ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate B: %v", err)
	}
	if pskB != exchangeAB.SharedSecret {
		t.Error("B could not recover A→B shared secret")
	}

	pskA, err := nodeA.Decapsulate(exchangeBA.Ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate A: %v", err)
	}
	if pskA != exchangeBA.SharedSecret {
		t.Error("A could not recover B→A shared secret")
	}
}

func TestIsZeroPSK(t *testing.T) {
	var zero [SharedSecretSize]byte
	if !IsZeroPSK(zero) {
		t.Error("zero PSK not detected")
	}

	nonZero := [SharedSecretSize]byte{1}
	if IsZeroPSK(nonZero) {
		t.Error("non-zero PSK incorrectly detected as zero")
	}
}

func TestMultipleEncapsulationsDifferentSecrets(t *testing.T) {
	responder, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	ex1, err := Encapsulate(responder.EncapsulationKey())
	if err != nil {
		t.Fatalf("Encapsulate 1: %v", err)
	}

	ex2, err := Encapsulate(responder.EncapsulationKey())
	if err != nil {
		t.Fatalf("Encapsulate 2: %v", err)
	}

	if ex1.SharedSecret == ex2.SharedSecret {
		t.Error("two encapsulations to the same key should produce different shared secrets")
	}

	if bytes.Equal(ex1.Ciphertext, ex2.Ciphertext) {
		t.Error("two encapsulations to the same key should produce different ciphertexts")
	}

	// But both should decapsulate correctly
	psk1, err := responder.Decapsulate(ex1.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	psk2, err := responder.Decapsulate(ex2.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if psk1 != ex1.SharedSecret {
		t.Error("first decapsulation mismatch")
	}
	if psk2 != ex2.SharedSecret {
		t.Error("second decapsulation mismatch")
	}
}

func TestConstantsMatchMLKEM768(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}

	if len(dk.Bytes()) != DecapsulationKeySeedSize {
		t.Errorf("DecapsulationKeySeedSize = %d, actual dk seed = %d", DecapsulationKeySeedSize, len(dk.Bytes()))
	}
	if len(dk.EncapsulationKey().Bytes()) != EncapsulationKeySize {
		t.Errorf("EncapsulationKeySize = %d, actual ek = %d", EncapsulationKeySize, len(dk.EncapsulationKey().Bytes()))
	}

	_, ct := dk.EncapsulationKey().Encapsulate()
	if len(ct) != CiphertextSize {
		t.Errorf("CiphertextSize = %d, actual ct = %d", CiphertextSize, len(ct))
	}
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	for b.Loop() {
		_, err := GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncapsulate(b *testing.B) {
	kp, err := GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	ek := kp.EncapsulationKey()

	b.ResetTimer()
	for b.Loop() {
		_, err := Encapsulate(ek)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecapsulate(b *testing.B) {
	kp, err := GenerateKeyPair()
	if err != nil {
		b.Fatal(err)
	}
	ex, err := Encapsulate(kp.EncapsulationKey())
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for b.Loop() {
		_, err := kp.Decapsulate(ex.Ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}
