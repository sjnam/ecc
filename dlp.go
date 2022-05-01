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
func PollardRho(c ECurve, hx, hy *big.Int) *big.Int {
	f := func(x, y, a, b *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int) {
		k := new(big.Int).Mod(x, big.NewInt(3)).Int64()
		if k == 0 { // S1
			x, y = c.Add(c.Gx, c.Gy, x, y)
			a.Add(a, big.NewInt(1))
			return x, y, a.Mod(a, c.N), b
		} else if k == 1 { // S2
			x, y = c.ScalarMult(x, y, big.NewInt(2).Bytes())
			a.Add(a, a)
			b.Add(b, b)
			return x, y, a.Mod(a, c.N), b.Mod(b, c.N)
		} else { // S3
			x, y = c.Add(hx, hy, x, y)
			b.Add(b, big.NewInt(1))
			return x, y, a, b.Mod(b, c.N)
		}
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	setup := func() (*big.Int, *big.Int, *big.Int, *big.Int) {
		a, b := new(big.Int).Rand(rnd, c.N), new(big.Int).Rand(rnd, c.N)
		px, py := c.ScalarBaseMult(a.Bytes())
		qx, qy := c.ScalarMult(hx, hy, b.Bytes())
		x, y := c.Add(px, py, qx, qy)
		return x, y, a, b
	}

	for j := 0; j < 3; j++ {
		x1, y1, a1, b1 := setup()
		x2, y2, a2, b2 := setup()

		for { // k := 0; k < int(c.N.Int64()); k++ {
			x1, y1, a1, b1 = f(x1, y1, a1, b1)
			x2, y2, a2, b2 = f(x2, y2, a2, b2)
			x2, y2, a2, b2 = f(x2, y2, a2, b2)

			if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
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
				return a1
			}
		}
	}

	return big.NewInt(-1)
}
