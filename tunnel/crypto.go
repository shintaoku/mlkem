package tunnel

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/curve25519"
)

func cryptoRand() io.Reader {
	return rand.Reader
}

func curve25519ScalarBaseMult(dst, scalar *[32]byte) {
	pub, err := curve25519.X25519(scalar[:], curve25519.Basepoint)
	if err != nil {
		panic("curve25519: " + err.Error())
	}
	copy(dst[:], pub)
}
