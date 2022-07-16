package ecc

import (
	"math/big"
)

var (
	one   = big.NewInt(1)
	two   = big.NewInt(2)
	three = big.NewInt(3)
)

// Chinese remainder theorem
func crt(a, n []*big.Int) *big.Int {
	p := big.NewInt(1)
	for _, n1 := range n {
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

func pollardRho(n *big.Int) *big.Int {
	xStatic := big.NewInt(2)
	cycleSize := 2
	x := big.NewInt(2)
	factor := new(big.Int).Set(one)
	for i := 0; factor.Cmp(one) == 0; i++ {
		if i == 20 {
			return big.NewInt(-1)
		}
		for c := 1; c <= cycleSize && factor.Cmp(one) <= 0; c++ {
			x.Mul(x, x)
			x.Add(x, one)
			x.Mod(x, n)
			factor.GCD(nil, nil, new(big.Int).Sub(x, xStatic), n)
		}
		cycleSize *= 2
		xStatic.Set(x)
	}
	return factor
}

func factorize(n *big.Int) []*big.Int {
	var factors []*big.Int
	nn := new(big.Int).Set(n)
	for nn.Bit(0) == 0 {
		nn.Rsh(nn, 1)
		factors = append(factors, big.NewInt(2))
	}
	if nn.Cmp(one) == 0 {
		return factors
	}
	if nn.ProbablyPrime(5) {
		return append(factors, nn)
	}

	f := pollardRho(nn)
	for f.Cmp(nn) != 0 {
		factors = append(factors, f)

		nn.Div(nn, f)
		if nn.ProbablyPrime(5) {
			return append(factors, nn)
		}
		f = pollardRho(nn)
		if f.Sign() < 0 {
			break
		}
	}
	return factors
}
