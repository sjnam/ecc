package ecc

import (
	"bytes"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	testAllCurves(t, testSignAndVerify)
}

func testSignAndVerify(t *testing.T, curve *Curve) {
	priv, pubX, pubY, _ := curve.GenerateKey()
	hashed := []byte("testing")
	r, s := curve.Sign(priv, hashed)
	if !curve.Verify(pubX, pubY, hashed, r, s) {
		t.Errorf("Verify failed")
		return
	}

	hashed[0] ^= 0xff
	if curve.Verify(pubX, pubY, hashed, r, s) {
		t.Errorf("Verify always works!")
	}
}

func BenchmarkSign(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve *Curve) {
		priv, _, _, err := curve.GenerateKey()
		if err != nil {
			b.Fatal(err)
		}
		hashed := []byte("testing")

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			curve.Sign(priv, hashed)
		}
	})
}

func BenchmarkVerify(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve *Curve) {
		priv, pubX, pubY, err := curve.GenerateKey()
		if err != nil {
			b.Fatal(err)
		}
		hashed := []byte("testing")
		r, s := curve.Sign(priv, hashed)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !curve.Verify(pubX, pubY, hashed, r, s) {
				b.Fatal("verify failed")
			}
		}
	})
}

func TestECDH(t *testing.T) {
	testAllCurves(t, testECDH)
}

func testECDH(t *testing.T, curve *Curve) {
	aPriv, aPubX, aPubY, _ := curve.GenerateKey()
	bPriv, bPubX, bPubY, _ := curve.GenerateKey()

	// encryption with ECDH
	aSharedSecret := curve.Encrypt(aPriv, bPubX, bPubY)
	bSharedSecret := curve.Encrypt(bPriv, aPubX, aPubY)
	if !bytes.Equal(aSharedSecret, bSharedSecret) {
		t.Errorf("sharedSecret1: 0x%x\nsharedSecret2: 0x%x",
			aSharedSecret, bSharedSecret)
	}
}
