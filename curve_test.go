package ecc

import (
	"bytes"
	"math/big"
	"testing"
)

var toy, small, secp256k1, p521 *Curve

func init() {
	toy = &Curve{
		Name: "toy curve",
		P:    big.NewInt(29),
		A:    big.NewInt(4),
		B:    big.NewInt(20),
		Gx:   big.NewInt(1),
		Gy:   big.NewInt(5),
		N:    big.NewInt(37),
		H:    big.NewInt(1),
	}
	toy.BitSize = toy.N.BitLen()

	small = &Curve{
		Name: "small curve",
		P:    big.NewInt(229),
		A:    big.NewInt(1),
		B:    big.NewInt(44),
		Gx:   big.NewInt(5),
		Gy:   big.NewInt(116),
		N:    big.NewInt(239),
		H:    big.NewInt(1),
	}
	small.BitSize = small.N.BitLen()

	secp256k1 = &Curve{Name: "secp256k1"}
	secp256k1.P, _ = new(big.Int).SetString("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 0)
	secp256k1.A = big.NewInt(0)
	secp256k1.B = big.NewInt(7)
	secp256k1.Gx, _ = new(big.Int).SetString("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 0)
	secp256k1.Gy, _ = new(big.Int).SetString("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 0)
	secp256k1.N, _ = new(big.Int).SetString("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 0)
	secp256k1.H = big.NewInt(1)
	secp256k1.BitSize = 256

	// See FIPS 186-3, section D.2.5
	p521 = &Curve{Name: "p521"}
	p521.P, _ = new(big.Int).SetString("0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 0)
	p521.A = big.NewInt(-3)
	p521.B, _ = new(big.Int).SetString("0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 0)
	p521.Gx, _ = new(big.Int).SetString("0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 0)
	p521.Gy, _ = new(big.Int).SetString("0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 0)
	p521.N, _ = new(big.Int).SetString("0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 0)
	p521.H = big.NewInt(1)
	p521.BitSize = 521
}

func testAllCurves(t *testing.T, f func(*testing.T, *Curve)) {
	tests := []struct {
		name string
		*Curve
	}{
		{"TOY", toy},
		{"SMALL", small},
		{"SECP256K1", secp256k1},
		{"P521", p521},
	}
	if testing.Short() {
		tests = tests[:1]
	}
	for _, test := range tests {
		curve := test.Curve
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f(t, curve)
		})
	}
}

func TestOnCurve(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve *Curve) {
		if !curve.IsOnCurve(curve.Gx, curve.Gy) {
			t.Error("basepoint is not on the curve")
		}
	})
}

func TestOffCurve(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve *Curve) {
		x, y := new(big.Int).SetInt64(1), new(big.Int).SetInt64(1)
		if curve.IsOnCurve(x, y) {
			t.Errorf("point off curve is claimed to be on the curve")
		}

		byteLen := (curve.Params().BitSize + 7) / 8
		b := make([]byte, 1+2*byteLen)
		b[0] = 4 // uncompressed point
		x.FillBytes(b[1 : 1+byteLen])
		y.FillBytes(b[1+byteLen : 1+2*byteLen])

		x1, y1 := curve.Unmarshal(b)
		if x1 != nil || y1 != nil {
			t.Errorf("unmarshaling a point not on the curve succeeded")
		}
	})
}

func TestInfinity(t *testing.T) {
	testAllCurves(t, testInfinity)
}

func testInfinity(t *testing.T, curve *Curve) {
	_, x, y, _ := curve.GenerateKey()
	x, y = curve.ScalarMult(x, y, curve.N.Bytes())
	if x.Sign() != 0 || y.Sign() != 0 {
		t.Errorf("x^q != ∞")
	}

	x, y = curve.ScalarBaseMult([]byte{0})
	if x.Sign() != 0 || y.Sign() != 0 {
		t.Errorf("b^0 != ∞")
		x.SetInt64(0)
		y.SetInt64(0)
	}

	x2, y2 := curve.Double(x, y)
	if x2.Sign() != 0 || y2.Sign() != 0 {
		t.Errorf("2∞ != ∞")
	}

	baseX := curve.Gx
	baseY := curve.Gy

	x3, y3 := curve.Add(baseX, baseY, x, y)
	if x3.Cmp(baseX) != 0 || y3.Cmp(baseY) != 0 {
		t.Errorf("x+∞ != x")
	}

	x4, y4 := curve.Add(x, y, baseX, baseY)
	if x4.Cmp(baseX) != 0 || y4.Cmp(baseY) != 0 {
		t.Errorf("∞+x != x")
	}

	if curve.IsOnCurve(x, y) {
		t.Errorf("IsOnCurve(∞) == true")
	}

	if xx, yy := curve.Unmarshal(curve.Marshal(x, y)); xx != nil || yy != nil {
		t.Errorf("Unmarshal(Marshal(∞)) did not return an error")
	}
	// We don't test UnmarshalCompressed(MarshalCompressed(∞)) because there are
	// two valid points with x = 0.
	if xx, yy := curve.Unmarshal([]byte{0x00}); xx != nil || yy != nil {
		t.Errorf("Unmarshal(∞) did not return an error")
	}
}

func TestKeyGeneration(t *testing.T) {
	testAllCurves(t, testKeyGeneration)
}

func testKeyGeneration(t *testing.T, curve *Curve) {
	_, x, y, err := curve.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if !curve.IsOnCurve(x, y) {
		t.Errorf("public key invalid: %s", err)
	}
}

func TestMarshal(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve *Curve) {
		_, x, y, err := curve.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		serialized := curve.Marshal(x, y)
		xx, yy := curve.Unmarshal(serialized)
		if xx == nil {
			t.Fatal("failed to unmarshal")
		}
		if xx.Cmp(x) != 0 || yy.Cmp(y) != 0 {
			t.Fatal("unmarshal returned different values")
		}
	})
}

func TestUnmarshalToLargeCoordinates(t *testing.T) {
	// See https://golang.org/issues/20482.
	testAllCurves(t, testUnmarshalToLargeCoordinates)
}

func testUnmarshalToLargeCoordinates(t *testing.T, curve *Curve) {
	p := curve.P
	byteLen := (p.BitLen() + 7) / 8

	// Set x to be greater than curve's parameter P – specifically, to P+5.
	// Set y to mod_sqrt(x^3 - 3x + B)) so that (x mod P = 5 , y) is on the
	// curve.
	x := new(big.Int).Add(p, big.NewInt(5))
	y := curve.polynomial(x)
	y.ModSqrt(y, p)

	invalid := make([]byte, byteLen*2+1)
	invalid[0] = 4 // uncompressed encoding
	x.FillBytes(invalid[1 : 1+byteLen])
	y.FillBytes(invalid[1+byteLen:])

	if X, Y := curve.Unmarshal(invalid); X != nil || Y != nil {
		t.Errorf("Unmarshal accepts invalid X coordinate")
	}
}

// TestInvalidCoordinates tests big.Int values that are not valid field elements
// (negative or bigger than P). They are expected to return false from
// IsOnCurve, all other behavior is undefined.
func TestInvalidCoordinates(t *testing.T) {
	testAllCurves(t, testInvalidCoordinates)
}

func testInvalidCoordinates(t *testing.T, curve *Curve) {
	checkIsOnCurveFalse := func(name string, x, y *big.Int) {
		if curve.IsOnCurve(x, y) {
			t.Errorf("IsOnCurve(%s) unexpectedly returned true", name)
		}
	}

	p := curve.P
	_, x, y, _ := curve.GenerateKey()
	xx, yy := new(big.Int), new(big.Int)

	// Check if the sign is getting dropped.
	xx.Neg(x)
	checkIsOnCurveFalse("-x, y", xx, y)
	yy.Neg(y)
	checkIsOnCurveFalse("x, -y", x, yy)
	//
	// Check if negative values are reduced modulo P.
	xx.Sub(x, p)
	checkIsOnCurveFalse("x-P, y", xx, y)
	yy.Sub(y, p)
	checkIsOnCurveFalse("x, y-P", x, yy)

	// Check if positive values are reduced modulo P.
	xx.Add(x, p)
	checkIsOnCurveFalse("x+P, y", xx, y)
	yy.Add(y, p)
	checkIsOnCurveFalse("x, y+P", x, yy)

	// Check if the overflow is dropped.
	xx.Add(x, new(big.Int).Lsh(big.NewInt(1), 535))
	checkIsOnCurveFalse("x+2⁵³⁵, y", xx, y)
	yy.Add(y, new(big.Int).Lsh(big.NewInt(1), 535))
	checkIsOnCurveFalse("x, y+2⁵³⁵", x, yy)

	// Check if P is treated like zero (if possible).
	// y^2 = x^3 - 3x + B
	// y = mod_sqrt(x^3 - 3x + B)
	// y = mod_sqrt(B) if x = 0
	// If there is no modsqrt, there is no point with x = 0, can't test x = P.
	if yy := new(big.Int).ModSqrt(curve.B, p); yy != nil {
		if !curve.IsOnCurve(big.NewInt(0), yy) {
			t.Fatal("(0, mod_sqrt(B)) is not on the curve?")
		}
		checkIsOnCurveFalse("P, y", p, yy)
	}
}

func TestMarshalCompressed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping other curves on short test")
	}

	testAllCurves(t, func(t *testing.T, curve *Curve) {
		_, x, y, err := curve.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		testMarshalCompressed(t, curve, x, y, nil)
	})
}

func testMarshalCompressed(t *testing.T, curve *Curve, x, y *big.Int, want []byte) {
	if !curve.IsOnCurve(x, y) {
		t.Fatal("invalid test point")
	}
	got := curve.MarshalCompressed(x, y)
	if want != nil && !bytes.Equal(got, want) {
		t.Errorf("got unexpected MarshalCompressed result: got %x, want %x", got, want)
	}

	X, Y := curve.UnmarshalCompressed(got)
	if X == nil || Y == nil {
		t.Fatalf("UnmarshalCompressed failed unexpectedly")
	}

	if !curve.IsOnCurve(X, Y) {
		t.Error("UnmarshalCompressed returned a point not on the curve")
	}
	if X.Cmp(x) != 0 || Y.Cmp(y) != 0 {
		t.Errorf("point did not round-trip correctly: got (%v, %v), want (%v, %v)", X, Y, x, y)
	}
}

func TestLargeIsOnCurve(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve *Curve) {
		large := big.NewInt(1)
		large.Lsh(large, 1000)
		if curve.IsOnCurve(large, large) {
			t.Errorf("(2^1000, 2^1000) is reported on the curve")
		}
	})
}

func benchmarkAllCurves(t *testing.B, f func(*testing.B, *Curve)) {
	tests := []struct {
		name  string
		curve *Curve
	}{
		{"TOY", toy},
		{"SMALL", small},
		{"SECP256K1", secp256k1},
		{"P521", p521},
	}
	for _, test := range tests {
		curve := test.curve
		t.Run(test.name, func(t *testing.B) {
			f(t, curve)
		})
	}
}

func BenchmarkScalarBaseMult(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve *Curve) {
		priv, _, _, _ := curve.GenerateKey()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			curve.ScalarBaseMult(priv)
		}
	})
}

func BenchmarkScalarMult(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve *Curve) {
		_, x, y, _ := curve.GenerateKey()
		priv, _, _, _ := curve.GenerateKey()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			x, y = curve.ScalarMult(x, y, priv)
		}
	})
}

func BenchmarkMarshalUnmarshal(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve *Curve) {
		_, x, y, _ := curve.GenerateKey()
		b.Run("Uncompressed", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf := curve.Marshal(x, y)
				xx, yy := curve.Unmarshal(buf)
				if xx.Cmp(x) != 0 || yy.Cmp(y) != 0 {
					b.Error("Unmarshal output different from Marshal input")
				}
			}
		})
		b.Run("Compressed", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				buf := curve.Marshal(x, y)
				xx, yy := curve.Unmarshal(buf)
				if xx.Cmp(x) != 0 || yy.Cmp(y) != 0 {
					b.Error("Unmarshal output different from Marshal input")
				}
			}
		})
	})
}
