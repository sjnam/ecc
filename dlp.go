package ecc

import (
	"crypto/elliptic"
	"math/big"
	"math/rand"
	"time"
)

// Shanks' Baby-Step Giant-Step algorithm for ECDLP
func Shanks(curve ECurve, hx, hy *big.Int) int64 {
	htab := make(map[string]int64)

	ss := new(big.Int).Sqrt(curve.N)
	s := ss.Int64()
	vx, vy := new(big.Int), new(big.Int)
	mx, my := curve.ScalarBaseMult(ss.Bytes())

	// Giant step
	for j := int64(0); j <= curve.N.Int64(); j += s {
		k := elliptic.Marshal(curve, vx, vy)
		htab[string(k)] = j / s
		vx, vy = curve.Add(vx, vy, mx, my)
	}

	vx, vy = vx.Set(hx), vy.Set(hy)
	gix, giy := new(big.Int).Set(curve.Gx), new(big.Int).Neg(curve.Gy)

	// Baby step
	for i := int64(0); i <= s; i++ {
		k := elliptic.Marshal(curve, vx, vy)
		if m, ok := htab[string(k)]; ok {
			return i + m*s
		}
		vx, vy = curve.Add(vx, vy, gix, giy)
	}

	return -1
}

// PollardRho algorithm for the ECDLP
func PollardRho(c ECurve, hx, hy *big.Int) int64 {
	z := new(big.Int).Div(c.P, big.NewInt(3))
	zz := new(big.Int).Add(z, z)
	f := func(x, y, a, b *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int) {
		if x.Cmp(z) <= 0 { // S1
			rx, ry := c.Add(c.Gx, c.Gy, x, y)
			a.Add(a, big.NewInt(1))
			return rx, ry, a.Mod(a, c.N), b
		} else if x.Cmp(zz) <= 0 { // S2
			rx, ry := c.ScalarMult(x, y, big.NewInt(2).Bytes())
			a.Add(a, a)
			b.Add(b, b)
			return rx, ry, a.Mod(a, c.N), b.Mod(b, c.N)
		} else { // S3
			rx, ry := c.Add(hx, hy, x, y)
			b.Add(b, big.NewInt(1))
			return rx, ry, a, b.Mod(b, c.N)
		}
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	for j := 0; j < 3; j++ {
		a1, b1 := new(big.Int).Rand(rnd, c.N), new(big.Int).Rand(rnd, c.N)
		aPx1, aPy1 := c.ScalarBaseMult(a1.Bytes())
		bQx1, bQy1 := c.ScalarMult(hx, hy, b1.Bytes())
		rx1, ry1 := c.Add(aPx1, aPy1, bQx1, bQy1)

		a2, b2 := new(big.Int).Rand(rnd, c.N), new(big.Int).Rand(rnd, c.N)
		aPx2, aPy2 := c.ScalarBaseMult(a2.Bytes())
		bQx2, bQy2 := c.ScalarMult(hx, hy, b2.Bytes())
		rx2, ry2 := c.Add(aPx2, aPy2, bQx2, bQy2)

		for k := 0; k < int(c.N.Int64()); k++ {
			rx1, ry1, a1, b1 = f(rx1, ry1, a1, b1)
			rx2, ry2, a2, b2 = f(rx2, ry2, a2, b2)
			rx2, ry2, a2, b2 = f(rx2, ry2, a2, b2)

			if rx1.Cmp(rx2) == 0 && ry1.Cmp(ry2) == 0 {
				if b1.Cmp(b2) == 0 {
					break
				}
				a1.Sub(a1, a2)
				a1.Mod(a1, c.N)
				b2.Sub(b2, b1)
				b2.Mod(b2, c.N)
				b2.ModInverse(b2, c.N)
				a1.Mul(a1, b2)
				a1.Mod(a1, c.N)
				return a1.Int64()
			}
		}
	}

	return 0
}
