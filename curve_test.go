package ecc

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func sampleCurves() map[string]*Curve {
	curves := make(map[string]*Curve)

	curves["TOY"] = &Curve{
		P:       big.NewInt(29),
		A:       big.NewInt(4),
		B:       big.NewInt(20),
		Gx:      big.NewInt(1),
		Gy:      big.NewInt(5),
		N:       big.NewInt(37),
		H:       big.NewInt(1),
		BitSize: 6,
	}

	curves["SMALL"] = &Curve{
		P:       big.NewInt(229),
		A:       big.NewInt(1),
		B:       big.NewInt(44),
		Gx:      big.NewInt(5),
		Gy:      big.NewInt(116),
		N:       big.NewInt(239),
		H:       big.NewInt(1),
		BitSize: 8,
	}

	curves["S256"] = &Curve{
		P: BigFromDecimal("11579208923731619542357098500868790785326998466564" +
			"0564039457584007908834671663"),
		A: big.NewInt(0),
		B: big.NewInt(7),
		Gx: BigFromDecimal("55066263022277343669578718895168534326250603453777" +
			"594175500187360389116729240"),
		Gy: BigFromDecimal("32670510020758816978083085130507043184471273380659" +
			"243275938904335757337482424"),
		N: BigFromDecimal("11579208923731619542357098500868790785283756427907" +
			"4904382605163141518161494337"),
		H:       big.NewInt(1),
		BitSize: 256,
	}

	curves["P384"] = &Curve{
		P: BigFromDecimal("394020061963944792122790401001436138050797392704654" +
			"46667948293404245721771496870329047266088258938001861606973112319"),
		A: big.NewInt(-3),
		B: BigFromHex("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088" +
			"f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
		Gx: BigFromHex("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741" +
			"e082542a385502f25dbf55296c3a545e3872760ab7"),
		Gy: BigFromHex("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da31" +
			"13b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
		N: BigFromDecimal("394020061963944792122790401001436138050797392704654" +
			"46667946905279627659399113263569398956308152294913554433653942643"),
		H:       big.NewInt(1),
		BitSize: 384,
	}
	return curves
}

func testAllCurves(t *testing.T, f func(*testing.T, *Curve)) {
	for name, c := range sampleCurves() {
		c := c
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f(t, c)
		})
	}
}

func TestOnCurve(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve *Curve) {
		if !curve.IsOnCurve(curve.Gx, curve.Gy) {
			t.Error("base Point is not on the curve")
		}
	})
}

func TestOffCurve(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve *Curve) {
		x, y := new(big.Int).SetInt64(1), new(big.Int).SetInt64(1)
		if curve.IsOnCurve(x, y) {
			t.Errorf("Point off curve is claimed to be on the curve")
		}

		byteLen := (curve.BitSize + 7) / 8
		b := make([]byte, 1+2*byteLen)
		b[0] = 4 // uncompressed Point
		x.FillBytes(b[1 : 1+byteLen])
		y.FillBytes(b[1+byteLen : 1+2*byteLen])

		x1, y1 := curve.Unmarshal(b)
		if x1 != nil || y1 != nil {
			t.Errorf("unmarshaling a Point not on the curve succeeded")
		}
	})
}

func TestInfinity(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve *Curve) {
		_, x, y, _ := curve.GenerateKey(rand.Reader)
		x, y = curve.ScalarMult(x, y, curve.N)
		if x.Sign() != 0 || y.Sign() != 0 {
			t.Errorf("x^q != ∞")
		}

		x, y = curve.ScalarBaseMult(new(big.Int))
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
	})
}

func TestKeyGeneration(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve *Curve) {
		_, x, y, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if !curve.IsOnCurve(x, y) {
			t.Errorf("public key invalid")
		}
	})
}

// TestInvalidCoordinates tests big.Int values that are not valid field elements
// (negative or bigger than P). They are expected to return false from
// IsOnCurve, all other behavior is undefined.
func TestInvalidCoordinates(t *testing.T) {
	testAllCurves(t, func(t *testing.T, curve *Curve) {
		checkIsOnCurveFalse := func(name string, x, y *big.Int) {
			if curve.IsOnCurve(x, y) {
				t.Errorf("IsOnCurve(%s) unexpectedly returned true", name)
			}
		}

		p := curve.P
		_, x, y, _ := curve.GenerateKey(rand.Reader)
		for x.Sign() == 0 || y.Sign() == 0 {
			_, x, y, _ = curve.GenerateKey(rand.Reader)
		}
		xx, yy := new(big.Int), new(big.Int)

		// Check if the sign is getting dropped.
		xx.Neg(x)
		checkIsOnCurveFalse("-x, y", xx, y)
		yy.Neg(y)
		checkIsOnCurveFalse("x, -y", x, yy)

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
		// y^2 = x^3 + ax + b
		// y = mod_sqrt(x^3 + ax + b)
		// y = mod_sqrt(B) if x = 0
		// If there is no modsqrt, there is no Point with x = 0, can't test x = P.
		if yy := new(big.Int).ModSqrt(curve.B, p); yy != nil {
			if !curve.IsOnCurve(big.NewInt(0), yy) {
				t.Fatal("(0, mod_sqrt(B)) is not on the curve?")
			}
			checkIsOnCurveFalse("P, y", p, yy)
		}
	})
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
	for name, c := range sampleCurves() {
		t.Run(name, func(t *testing.B) {
			f(t, c)
		})
	}
}

func BenchmarkScalarMult(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve *Curve) {
		_, x, y, _ := curve.GenerateKey(rand.Reader)
		priv, _, _, _ := curve.GenerateKey(rand.Reader)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			x, y = curve.ScalarMult(x, y, priv)
		}
	})
}
