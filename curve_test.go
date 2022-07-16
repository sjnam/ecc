package ecc

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"
)

var s256, p224, p256, p384, p521 *EllipticCurve

func init() {
	s256 = &EllipticCurve{Name: "secp256k1"}
	s256.P, _ = new(big.Int).SetString("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 0)
	s256.A = big.NewInt(0)
	s256.B = big.NewInt(7)
	s256.Gx, _ = new(big.Int).SetString("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 0)
	s256.Gy, _ = new(big.Int).SetString("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 0)
	s256.N, _ = new(big.Int).SetString("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 0)
	s256.H = big.NewInt(1)
	s256.BitSize = 256

	// See FIPS 186-3, section D.2.2
	p224 = &EllipticCurve{Name: "p224"}
	p224.P, _ = new(big.Int).SetString("0xffffffffffffffffffffffffffffffff000000000000000000000001", 0)
	p224.A = big.NewInt(-3)
	p224.B, _ = new(big.Int).SetString("0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 0)
	p224.Gx, _ = new(big.Int).SetString("0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", 0)
	p224.Gy, _ = new(big.Int).SetString("0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 0)
	p224.N, _ = new(big.Int).SetString("0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", 0)
	p224.H = big.NewInt(1)
	p224.BitSize = 224

	// See FIPS 186-3, section D.2.3
	p256 = &EllipticCurve{Name: "p256"}
	p256.P, _ = new(big.Int).SetString("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 0)
	p256.A = big.NewInt(-3)
	p256.B, _ = new(big.Int).SetString("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 0)
	p256.Gx, _ = new(big.Int).SetString("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 0)
	p256.Gy, _ = new(big.Int).SetString("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 0)
	p256.N, _ = new(big.Int).SetString("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 0)
	p256.H = big.NewInt(1)
	p256.BitSize = 256

	// See FIPS 186-4, section D.1.2.4
	p384 = &EllipticCurve{Name: "p384"}
	p384.P, _ = new(big.Int).SetString("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 0)
	p384.A = big.NewInt(-3)
	p384.B, _ = new(big.Int).SetString("0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 0)
	p384.Gx, _ = new(big.Int).SetString("0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 0)
	p384.Gy, _ = new(big.Int).SetString("0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 0)
	p384.N, _ = new(big.Int).SetString("0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 0)
	p384.H = big.NewInt(1)
	p384.BitSize = 384

	// See FIPS 186-3, section D.2.5
	p521 = &EllipticCurve{Name: "p521"}
	p521.P, _ = new(big.Int).SetString("0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 0)
	p521.A = big.NewInt(-3)
	p521.B, _ = new(big.Int).SetString("0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 0)
	p521.Gx, _ = new(big.Int).SetString("0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 0)
	p521.Gy, _ = new(big.Int).SetString("0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 0)
	p521.N, _ = new(big.Int).SetString("0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 0)
	p521.H = big.NewInt(1)
	p521.BitSize = 521
}

func testAllCurves(t *testing.T, f func(*testing.T, *EllipticCurve)) {
	tests := []struct {
		name string
		*EllipticCurve
	}{
		{"S256", s256},
		{"P224", p224},
		{"P256", p256},
		{"P384", p384},
		{"P521", p521},
	}
	if testing.Short() {
		tests = tests[:1]
	}
	for _, test := range tests {
		curve := test.EllipticCurve
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f(t, curve)
		})
	}
}

func TestOnCurve(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve *EllipticCurve) {
		if !curve.IsOnCurve(curve.Gx, curve.Gy) {
			t.Error("basepoint is not on the curve")
		}
	})
}

func TestOffCurve(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve *EllipticCurve) {
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

func testInfinity(t *testing.T, curve *EllipticCurve) {
	_, x, y, _ := curve.GenerateKey(rand.Reader)
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

func testKeyGeneration(t *testing.T, ec *EllipticCurve) {
	_, x, y, err := ec.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !ec.IsOnCurve(x, y) {
		t.Errorf("public key invalid: %s", err)
	}
}

func TestMarshal(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve *EllipticCurve) {
		_, x, y, err := curve.GenerateKey(rand.Reader)
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

func testUnmarshalToLargeCoordinates(t *testing.T, curve *EllipticCurve) {
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

	if curve == p256 {
		// This is a point on the curve with a small y value, small enough that
		// we can add p and still be within 32 bytes.
		x, _ = new(big.Int).SetString("31931927535157963707678568152204072984517581467226068221761862915403492091210", 10)
		y, _ = new(big.Int).SetString("5208467867388784005506817585327037698770365050895731383201516607147", 10)
		y.Add(y, p)

		if p.Cmp(y) > 0 || y.BitLen() != 256 {
			t.Fatal("y not within expected range")
		}

		// marshal
		x.FillBytes(invalid[1 : 1+byteLen])
		y.FillBytes(invalid[1+byteLen:])

		if X, Y := curve.Unmarshal(invalid); X != nil || Y != nil {
			t.Errorf("Unmarshal accepts invalid Y coordinate")
		}
	}
}

// TestInvalidCoordinates tests big.Int values that are not valid field elements
// (negative or bigger than P). They are expected to return false from
// IsOnCurve, all other behavior is undefined.
func TestInvalidCoordinates(t *testing.T) {
	testAllCurves(t, testInvalidCoordinates)
}

func testInvalidCoordinates(t *testing.T, curve *EllipticCurve) {
	checkIsOnCurveFalse := func(name string, x, y *big.Int) {
		if curve.IsOnCurve(x, y) {
			t.Errorf("IsOnCurve(%s) unexpectedly returned true", name)
		}
	}

	p := curve.P
	_, x, y, _ := curve.GenerateKey(rand.Reader)
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
	t.Run("P-256/03", func(t *testing.T) {
		data, _ := hex.DecodeString("031e3987d9f9ea9d7dd7155a56a86b2009e1e0ab332f962d10d8beb6406ab1ad79")
		x, _ := new(big.Int).SetString("13671033352574878777044637384712060483119675368076128232297328793087057702265", 10)
		y, _ := new(big.Int).SetString("66200849279091436748794323380043701364391950689352563629885086590854940586447", 10)
		testMarshalCompressed(t, p256, x, y, data)
	})
	t.Run("P-256/02", func(t *testing.T) {
		data, _ := hex.DecodeString("021e3987d9f9ea9d7dd7155a56a86b2009e1e0ab332f962d10d8beb6406ab1ad79")
		x, _ := new(big.Int).SetString("13671033352574878777044637384712060483119675368076128232297328793087057702265", 10)
		y, _ := new(big.Int).SetString("49591239931264812013903123569363872165694192725937750565648544718012157267504", 10)
		testMarshalCompressed(t, p256, x, y, data)
	})

	t.Run("Invalid", func(t *testing.T) {
		data, _ := hex.DecodeString("02fd4bf61763b46581fd9174d623516cf3c81edd40e29ffa2777fb6cb0ae3ce535")
		X, Y := p256.UnmarshalCompressed(data)
		if X != nil || Y != nil {
			t.Error("expected an error for invalid encoding")
		}
	})

	if testing.Short() {
		t.Skip("skipping other curves on short test")
	}

	testAllCurves(t, func(t *testing.T, curve *EllipticCurve) {
		_, x, y, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		testMarshalCompressed(t, curve, x, y, nil)
	})
}

func testMarshalCompressed(t *testing.T, curve *EllipticCurve, x, y *big.Int, want []byte) {
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
	testAllCurves(t, func(t *testing.T, curve *EllipticCurve) {
		large := big.NewInt(1)
		large.Lsh(large, 1000)
		if curve.IsOnCurve(large, large) {
			t.Errorf("(2^1000, 2^1000) is reported on the curve")
		}
	})
}

func benchmarkAllCurves(t *testing.B, f func(*testing.B, *EllipticCurve)) {
	tests := []struct {
		name  string
		curve *EllipticCurve
	}{
		{"S256", s256},
		{"P256", p256},
		{"P224", p224},
		{"P384", p384},
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
	benchmarkAllCurves(b, func(b *testing.B, curve *EllipticCurve) {
		priv, _, _, _ := curve.GenerateKey(rand.Reader)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			x, _ := curve.ScalarBaseMult(priv)
			// Prevent the compiler from optimizing out the operation.
			priv[0] ^= byte(x.Bits()[0])
		}
	})
}

func BenchmarkScalarMult(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve *EllipticCurve) {
		_, x, y, _ := curve.GenerateKey(rand.Reader)
		priv, _, _, _ := curve.GenerateKey(rand.Reader)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			x, y = curve.ScalarMult(x, y, priv)
		}
	})
}

func BenchmarkMarshalUnmarshal(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve *EllipticCurve) {
		_, x, y, _ := curve.GenerateKey(rand.Reader)
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
