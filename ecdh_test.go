package ecc

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestECDH(t *testing.T) {
	aliPriv, aliPubX, aliPubY, _ := elliptic.GenerateKey(secp256k1, rand.Reader)
	bobPriv, bobPubX, bobPubY, _ := elliptic.GenerateKey(secp256k1, rand.Reader)

	ssx1, ssy1 := secp256k1.ScalarMult(aliPubX, aliPubY, bobPriv)
	ssx2, ssy2 := secp256k1.ScalarMult(bobPubX, bobPubY, aliPriv)

	aliSharedSecret := elliptic.Marshal(secp256k1, ssx1, ssy1)
	bobSharedSecret := elliptic.Marshal(secp256k1, ssx2, ssy2)

	if !bytes.Equal(aliSharedSecret, bobSharedSecret) {
		t.Errorf("sharedSecret1: 0x%x\nsharedSecret2: 0x%x",
			aliSharedSecret, bobSharedSecret)
	}
}
