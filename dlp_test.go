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
		x, y, k *big.Int
	}{
		{big.NewInt(1075), big.NewInt(54), big.NewInt(1275)},
		{big.NewInt(4135), big.NewInt(3169), big.NewInt(4334)},
		{big.NewInt(2599), big.NewInt(759), big.NewInt(3430)},
		{big.NewInt(7285), big.NewInt(7905), big.NewInt(4508)},
		{big.NewInt(758), big.NewInt(574), big.NewInt(6864)},
	}

	for _, c := range cases {
		k := curve.Shanks(px, py, c.x, c.y)
		if k.Sign() == 0 || k.Cmp(c.k) != 0 {
			t.Errorf("[Shanks] (%d,%d) want: %d, got: %d", c.x, c.y, c.k, k)
		}
		k = curve.PollardRho(px, py, c.x, c.y)
		if k.Sign() == 0 || k.Cmp(c.k) != 0 {
			t.Errorf("[PollardRho] (%d,%d) want: %d, got: %d", c.x, c.y, c.k, k)
		}
	}
}
