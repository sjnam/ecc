package ecc

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	testAllCurves(t, testSignAndVerify)
}

func testSignAndVerify(t *testing.T, ec *Curve) {
	priv, pubX, pubY, _ := elliptic.GenerateKey(ec, rand.Reader)

	hashed := []byte("testing")
	r, s := ec.Sign(priv, hashed)

	if !ec.Verify(pubX, pubY, hashed, r, s) {
		t.Errorf("Verify failed")
	}

	hashed[0] ^= 0xff
	if ec.Verify(pubX, pubY, hashed, r, s) {
		t.Errorf("Verify always works!")
	}
}

func TestECDH(t *testing.T) {
	testAllCurves(t, testECDH)
}

func testECDH(t *testing.T, curve *Curve) {
	aPriv, aPubX, aPubY, _ := elliptic.GenerateKey(curve, rand.Reader)
	bPriv, bPubX, bPubY, _ := elliptic.GenerateKey(curve, rand.Reader)

	// encryption with ECDH
	aSharedSecret := curve.Encrypt(aPriv, bPubX, bPubY)
	bSharedSecret := curve.Encrypt(bPriv, aPubX, aPubY)
	if !bytes.Equal(aSharedSecret, bSharedSecret) {
		t.Errorf("sharedSecret1: 0x%x\nsharedSecret2: 0x%x",
			aSharedSecret, bSharedSecret)
	}
}
