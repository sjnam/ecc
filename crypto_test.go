package ecc

import (
	"bytes"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	testAllCurves(t, testSignAndVerify)
}

func testSignAndVerify(t *testing.T, ec *EllipticCurve) {
	priv, pubX, pubY, _ := ec.GenerateKey()

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

func testECDH(t *testing.T, ec *EllipticCurve) {
	aPriv, aPubX, aPubY, _ := ec.GenerateKey()
	bPriv, bPubX, bPubY, _ := ec.GenerateKey()

	// encryption with ECDH
	aSharedSecret := ec.Encrypt(aPriv, bPubX, bPubY)
	bSharedSecret := ec.Encrypt(bPriv, aPubX, aPubY)
	if !bytes.Equal(aSharedSecret, bSharedSecret) {
		t.Errorf("sharedSecret1: 0x%x\nsharedSecret2: 0x%x",
			aSharedSecret, bSharedSecret)
	}
}
