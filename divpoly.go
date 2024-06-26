package ecc

import "math/big"

func (c *Curve) poly() Poly {
	return NewPolyFromBigInt(c.B, c.A, new(big.Int), big.NewInt(1))
}

func cache(c *Curve, n int64, dp Poly) Poly {
	c.dpCache[n] = dp
	return dp
}

func (c *Curve) DivPoly(n int64) Poly {
	if c.dpCache == nil {
		c.dpCache = make(map[int64]Poly)
	}

	if d, ok := c.dpCache[n]; ok {
		return d
	}

	q, f := c.P, c.poly()
	a, b := int(c.A.Int64()), int(c.B.Int64())

	switch n {
	case 0:
		return cache(c, n, NewPolyFromInt(0))
	case 1:
		return cache(c, n, NewPolyFromInt(1))
	case 2:
		return cache(c, n, f.Mul(NewPolyFromInt(4), q))
	case 3:
		return cache(c, n, NewPolyFromInt(-a*a, 12*b, 6*a, 0, 3).sanitize(c.P))
	case 4:
		return cache(c, n,
			NewPolyFromInt(-64*b*b-8*a*a*a, -32*a*b, -40*a*a, 160*b, 40*a, 0, 8).
				Mul(f, q))
	}

	m := n / 2

	p2m := c.DivPoly(m - 2)
	p1m := c.DivPoly(m - 1)
	pm := c.DivPoly(m)
	pm1 := c.DivPoly(m + 1)
	pm2 := c.DivPoly(m + 2)

	p1me2 := p1m.Exp(big.NewInt(2), q)
	pme3 := pm.Exp(big.NewInt(3), q)
	pm1e2 := pm1.Exp(big.NewInt(2), q)
	pm1e3 := pm1.Exp(big.NewInt(3), q)

	var dp Poly
	if n&0x1 == 1 {
		denominator := f.Mul(f, q).Mul(NewPolyFromInt(16), q)
		t1 := pm2.Mul(pme3, q)
		t2 := p1m.Mul(pm1e3, q)
		if m&0x1 == 0 {
			t1, _ = t1.Div(denominator, q)
		} else {
			t2, _ = t2.Div(denominator, q)
		}
		dp = t1.Sub(t2, q)
	} else {
		dp = pm.Mul(pm2.Mul(p1me2, q).Sub(p2m.Mul(pm1e2, q), q), q)
		dp, _ = dp.Div(c.dpCache[2], q)
	}

	return cache(c, n, dp)
}
