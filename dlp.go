package ecc

import (
	"math/big"
	"math/rand"
	"sort"
	"time"
)

// Shank algorithm for the ECDLP
func (c *Curve) Shank(px, py, hx, hy *big.Int) *big.Int {
	if !c.IsOnCurve(px, py) {
		return nil
	}

	sqrtN := new(big.Int).Sqrt(c.N)
	sqrtN.Add(sqrtN, big.NewInt(1))
	rx, ry := new(big.Int), new(big.Int)
	precomputed := make(map[string]*big.Int)

	for a := big.NewInt(1); a.Cmp(sqrtN) <= 0; a.Add(a, big.NewInt(1)) {
		rx, ry = c.Add(rx, ry, px, py)
		precomputed[string(c.Marshal(rx, ry))] = new(big.Int).Set(a)
	}

	rx, ry = hx, hy
	npx, npy := c.Neg(px, py)
	sx, sy := c.ScalarMult(npx, npy, sqrtN)

	for b := new(big.Int); b.Cmp(sqrtN) <= 0; b.Add(b, big.NewInt(1)) {
		a, ok := precomputed[string(c.Marshal(rx, ry))]
		if ok {
			return new(big.Int).Add(a, new(big.Int).Mul(sqrtN, b))
		}
		rx, ry = c.Add(rx, ry, sx, sy)
	}

	return nil
}

// PollardRho algorithm for the ECDLP
func (c *Curve) PollardRho(px, py, hx, hy *big.Int) *big.Int {
	if !c.IsOnCurve(px, py) {
		return nil
	}

	N := c.N

	f := func(x, y, a, b *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int) {
		switch new(big.Int).Mod(x, big.NewInt(3)).Int64() {
		case 0: // S1: P+R, a+1, b
			x, y = c.Add(px, py, x, y)
			a.Add(a, big.NewInt(1))
			return x, y, a.Mod(a, N), b
		case 1: // S2: 2R, 2a, 2b
			x, y = c.ScalarMult(x, y, big.NewInt(2))
			a.Add(a, a)
			b.Add(b, b)
			return x, y, a.Mod(a, N), b.Mod(b, N)
		default: // S3: Q+R, a, b+1
			x, y = c.Add(hx, hy, x, y)
			b.Add(b, big.NewInt(1))
			return x, y, a, b.Mod(b, N)
		}
	}

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	setup := func() (*big.Int, *big.Int, *big.Int, *big.Int) {
		a, b := new(big.Int).Rand(rnd, N), new(big.Int).Rand(rnd, N)
		vx, vy := c.ScalarMult(px, py, a)
		ux, uy := c.ScalarMult(hx, hy, b)
		x, y := c.Add(vx, vy, ux, uy)
		return x, y, a, b
	}

	for i := 0; i < 100000; i++ {
		x1, y1, a1, b1 := setup()
		x2, y2, a2, b2 := setup()
		for j := 0; j < 1000; j++ {
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
				tx, ty := c.ScalarMult(px, py, a1)
				if tx.Cmp(hx) == 0 && ty.Cmp(hy) == 0 {
					return a1
				}
				break
			}
		}
	}

	return nil
}

func factorize(n *big.Int) []*big.Int {
	pollardRho := func(n *big.Int) *big.Int {
		xStatic := big.NewInt(2)
		cycleSize := uint64(2)
		x := big.NewInt(2)
		factor := big.NewInt(1)
		for i := 1; factor.Cmp(big.NewInt(1)) == 0; i++ {
			if i == 20 {
				return nil
			}
			for c := uint64(1); c <= cycleSize && factor.Cmp(big.NewInt(1)) <= 0; c++ {
				x.Mul(x, x)
				x.Add(x, big.NewInt(1))
				x.Mod(x, n)
				factor.GCD(nil, nil, new(big.Int).Sub(x, xStatic), n)
			}
			cycleSize *= 2
			xStatic.Set(x)
		}
		return factor
	}

	var factors []*big.Int
	nn := new(big.Int).Set(n)
	for nn.Bit(0) == 0 {
		nn.Rsh(nn, 1)
		factors = append(factors, big.NewInt(2))
	}
	if nn.Cmp(big.NewInt(1)) == 0 {
		return factors
	}
	if nn.ProbablyPrime(5) {
		return append(factors, nn)
	}

	for f := pollardRho(nn); f != nil && f.Cmp(nn) != 0; f = pollardRho(nn) {
		factors = append(factors, f)
		nn.Div(nn, f)
		if nn.ProbablyPrime(5) {
			return append(factors, nn)
		}
	}
	return factors
}

// PohligHellman algorithm for the ECDLP
func (c *Curve) PohligHellman(px, py, hx, hy *big.Int) *big.Int {
	if !c.IsOnCurve(px, py) {
		return nil
	}

	N := new(big.Int).Set(c.N)
	factors := factorize(N)
	sort.SliceStable(factors, func(i, j int) bool {
		return factors[i].Cmp(factors[j]) < 0
	})

	var res []*big.Int
	for i, j := 0, 0; i < len(factors); i = j {
		fi := factors[i]
		k := new(big.Int).Set(fi)
		for j = i + 1; j < len(factors) && factors[j].Cmp(fi) == 0; j++ {
			k.Mul(k, fi)
		}
		res = append(res, k)
	}

	dlp := c.Shank
	if c.BitSize > 100 {
		dlp = c.PollardRho
	}

	var dLogs []*big.Int
	for _, factor := range res {
		c.N.Set(factor)
		t := new(big.Int).Div(N, factor)
		x, y := c.ScalarMult(px, py, t)
		qx, qy := c.ScalarMult(hx, hy, t)
		k := dlp(x, y, qx, qy)
		if k == nil {
			return nil
		}
		dLogs = append(dLogs, k)
	}
	c.N.Set(N)

	return crt(dLogs, res)
}
