package ecc

import (
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

// Shanks Baby-Step Giant-Step algorithm for ECDLP
func (ec *EllipticCurve) Shanks(px, py, hx, hy *big.Int) *big.Int {
	ec.Gx, ec.Gy = px, py

	tab := make(map[string]int64)
	ss := new(big.Int).Sqrt(ec.N)
	s := ss.Int64()
	vx, vy := new(big.Int), new(big.Int)
	mx, my := ec.ScalarBaseMult(ss.Bytes())

	// Giant step
	for j := int64(0); j <= ec.N.Int64(); j += s {
		k := ec.Marshal(vx, vy)
		tab[string(k)] = j / s
		vx, vy = ec.Add(vx, vy, mx, my)
	}

	vx, vy = vx.Set(hx), vy.Set(hy)
	gix, giy := new(big.Int).Set(ec.Gx), new(big.Int).Neg(ec.Gy)

	// Baby step
	for i := int64(0); i <= s; i++ {
		k := ec.Marshal(vx, vy)
		if m, ok := tab[string(k)]; ok {
			return new(big.Int).SetInt64(i + m*s)
		}
		vx, vy = ec.Add(vx, vy, gix, giy)
	}
	return new(big.Int)
}

// PollardRho algorithm for the ECDLP
func (ec *EllipticCurve) PollardRho(px, py, hx, hy *big.Int) *big.Int {
	ec.Gx, ec.Gy = px, py

	f := func(x, y, a, b *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int) {
		k := new(big.Int).Mod(x, big.NewInt(3)).Int64()
		if k == 0 { // S1: P+R, a+1, b
			x, y = ec.Add(ec.Gx, ec.Gy, x, y)
			a.Add(a, big.NewInt(1))
			return x, y, a.Mod(a, ec.N), b
		} else if k == 1 { // S2: 2R, 2a, 2b
			x, y = ec.ScalarMult(x, y, big.NewInt(2).Bytes())
			a.Add(a, a)
			b.Add(b, b)
			return x, y, a.Mod(a, ec.N), b.Mod(b, ec.N)
		} else { // S3: Q+R, a, b+1
			x, y = ec.Add(hx, hy, x, y)
			b.Add(b, big.NewInt(1))
			return x, y, a, b.Mod(b, ec.N)
		}
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	setup := func() (*big.Int, *big.Int, *big.Int, *big.Int) {
		a, b := new(big.Int).Rand(rnd, ec.N), new(big.Int).Rand(rnd, ec.N)
		vx, vy := ec.ScalarBaseMult(a.Bytes())
		ux, uy := ec.ScalarMult(hx, hy, b.Bytes())
		x, y := ec.Add(vx, vy, ux, uy)
		return x, y, a, b
	}

	for i := 0; i < 1000000; i++ {
		x1, y1, a1, b1 := setup()
		x2, y2, a2, b2 := setup()

		for k := 0; k < int(ec.N.Int64()); k++ {
			x1, y1, a1, b1 = f(x1, y1, a1, b1)
			x2, y2, a2, b2 = f(x2, y2, a2, b2)
			x2, y2, a2, b2 = f(x2, y2, a2, b2)

			if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
				if b1.Cmp(b2) == 0 {
					break
				}

				a1.Sub(a1, a2)
				a1.Mod(a1, ec.N)
				b2.Sub(b2, b1)
				b2.Mod(b2, ec.N)
				b2.ModInverse(b2, ec.N)
				a1.Mul(a1, b2)
				a1.Mod(a1, ec.N)

				tx, ty := ec.ScalarBaseMult(a1.Bytes())
				if tx.Cmp(hx) == 0 && ty.Cmp(hy) == 0 {
					return a1
				}
				break
			}
		}
	}

	return new(big.Int)
}

var (
	ZERO = big.NewInt(0)
	ONE  = big.NewInt(1)
)

func crt(a, n []*big.Int) (*big.Int, error) {
	p := new(big.Int).Set(n[0])
	for _, n1 := range n[1:] {
		p.Mul(p, n1)
	}
	var x, q, s, z big.Int
	for i, n1 := range n {
		q.Div(p, n1)
		z.GCD(nil, &s, n1, &q)
		if z.Cmp(ONE) != 0 {
			return nil, fmt.Errorf("%d not coprime", n1)
		}
		x.Add(&x, s.Mul(a[i], s.Mul(&s, &q)))
	}
	return x.Mod(&x, p), nil
}
