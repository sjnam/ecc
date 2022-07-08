package ecc

import (
	"math/big"
	"testing"
)

func TestECDLP(t *testing.T) {
	curve := new(EllipticCurve)
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
		k := curve.Shanks(px, py, big.NewInt(c.x), big.NewInt(c.y))
		if k == -1 || k != c.k {
			t.Errorf("[Shanks] (%d,%d) want: %d, got: %d", c.x, c.y, c.k, k)
		}
		k = curve.PollardRho(px, py, big.NewInt(c.x), big.NewInt(c.y))
		if k == -1 || k != c.k {
			t.Errorf("[PollardRho] (%d,%d) want: %d, got: %d", c.x, c.y, c.k, k)
		}
	}
}
