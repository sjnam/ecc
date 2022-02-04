package ecc

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"testing"
)

func TestECDSA(t *testing.T) {
	priv, Hx, Hy, _ := elliptic.GenerateKey(secp256k1, rand.Reader)
	h := sha512.Sum512([]byte("Hello, world."))

	r, s := Sign(priv, secp256k1, h[:])
	if !Verify(Hx, Hy, secp256k1, h[:], r, s) {
		t.Error("invalid signature")
	}
}
