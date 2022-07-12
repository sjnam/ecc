package ecc

import (
	"math/big"
	"math/rand"
	"time"
)

// PollardRho algorithm for the ECDLP
func (c *EllipticCurve) PollardRho(px, py, hx, hy *big.Int) *big.Int {
	N := c.N
	one := big.NewInt(1)
	two := big.NewInt(2)
	three := big.NewInt(3)

	f := func(x, y, a, b *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int) {
		switch new(big.Int).Mod(x, three).Int64() {
		case 0: // S1: P+R, a+1, b
			x, y = c.Add(px, py, x, y)
			a.Add(a, one)
			return x, y, a.Mod(a, N), b
		case 1: // S2: 2R, 2a, 2b
			x, y = c.ScalarMult(x, y, two.Bytes())
			a.Add(a, a)
			b.Add(b, b)
			return x, y, a.Mod(a, N), b.Mod(b, N)
		default: // S3: Q+R, a, b+1
			x, y = c.Add(hx, hy, x, y)
			b.Add(b, one)
			return x, y, a, b.Mod(b, N)
		}
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	setup := func() (*big.Int, *big.Int, *big.Int, *big.Int) {
		a, b := new(big.Int).Rand(rnd, N), new(big.Int).Rand(rnd, N)
		vx, vy := c.ScalarMult(px, py, a.Bytes())
		ux, uy := c.ScalarMult(hx, hy, b.Bytes())
		x, y := c.Add(vx, vy, ux, uy)
		return x, y, a, b
	}

	for i := 0; i < 100; i++ {
		x1, y1, a1, b1 := setup()
		x2, y2, a2, b2 := setup()
		for j := 0; j < 10000; j++ {
			x1, y1, a1, b1 = f(x1, y1, a1, b1)
			x2, y2, a2, b2 = f(f(x2, y2, a2, b2))
			if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
				if b1.Cmp(b2) == 0 {
					break
				}
				a1.Sub(a1, a2)
				a1.Mod(a1, N)
				b2.Sub(b2, b1)
				b2.Mod(b2, N)
				b2.ModInverse(b2, N)
				a1.Mul(a1, b2)
				a1.Mod(a1, N)
				tx, ty := c.ScalarMult(px, py, a1.Bytes())
				if tx.Cmp(hx) == 0 && ty.Cmp(hy) == 0 {
					return a1
				}
				break
			}
		}
	}

	return new(big.Int)
}

func CRT(a, n []*big.Int) *big.Int {
	p := new(big.Int).Set(n[0])
	for _, n1 := range n[1:] {
		p.Mul(p, n1)
	}
	var x, q, s, z big.Int
	for i, n1 := range n {
		q.Div(p, n1)
		z.GCD(nil, &s, n1, &q)
		if z.Int64() != 1 {
			return nil
		}
		x.Add(&x, s.Mul(a[i], s.Mul(&s, &q)))
	}
	return x.Mod(&x, p)
}
