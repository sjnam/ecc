package ecc

import (
	"math/big"
	"testing"
)

func TestShanks(t *testing.T) {
	curve.P = big.NewInt(7919)
	curve.A = big.NewInt(1001)
	curve.B = big.NewInt(75)
	curve.N = big.NewInt(7889)
	curve.BitSize = 16

	px := big.NewInt(4023)
	py := big.NewInt(6036)

	cases := []struct {
		x, y, k int64
	}{
		{1075, 54, 1275},
		{4135, 3169, 4334},
		{2599, 759, 3430},
		{7285, 7905, 4508},
		{758, 574, 6864},
	}

	for _, c := range cases {
		k := Shanks(curve, px, py, big.NewInt(c.x), big.NewInt(c.y))
		if k == -1 || k != c.k {
			t.Errorf("(%d,%d) want: %d, got: %d", c.x, c.y, c.k, k)
		}
	}

	n := 0
	for i := 0; i < len(cases); i++ {
		c := cases[i]
		k := PollardRho(curve, px, py, big.NewInt(c.x), big.NewInt(c.y))
		if k == -1 || k != c.k {
			n++
			if n > 10 {
				t.Errorf("(%d,%d) want: %d, got: %d", c.x, c.y, c.k, k)
			}
			i--
			continue
		}
		n = 0
	}
}
