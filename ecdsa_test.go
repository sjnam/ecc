package ecc

import (
	"crypto/rand"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve *Curve) {
		priv, pubX, pubY, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Errorf("GeneateKey failed: %v", err)
			return
		}
		hashed := []byte("testing")
		r, s := curve.Sign(priv, hashed)
		if !curve.Verify(pubX, pubY, hashed, r, s) {
			t.Errorf("Verify failed")
			return
		}
	})
}

func BenchmarkSignAndVerify(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve *Curve) {
		priv, pubX, pubY, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		hashed := []byte("testing")

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r, s := curve.Sign(priv, hashed)
			if !curve.Verify(pubX, pubY, hashed, r, s) {
				b.Fatal("verify failed")
			}
		}
	})
}
