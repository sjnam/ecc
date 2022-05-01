package ecc

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestShanks(t *testing.T) {
	curve.CurveParams = &elliptic.CurveParams{Name: "DLP-Test"}
	curve.P = big.NewInt(7919)
	curve.A = big.NewInt(1001)
	curve.B = big.NewInt(75)
	curve.Gx = big.NewInt(4023)
	curve.Gy = big.NewInt(6036)
	curve.N = big.NewInt(7889)
	curve.BitSize = 16

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
		k := Shanks(curve, big.NewInt(c.x), big.NewInt(c.y))
		if k == -1 || k != c.k {
			t.Errorf("(%d,%d) want: %d, got: %d", c.x, c.y, c.k, k)
		}
	}

	xx, yy := new(big.Int), new(big.Int)
	for i := int64(1); i < curve.N.Int64(); i++ {
		xx, yy = curve.Add(xx, yy, curve.Gx, curve.Gy)
		k := Shanks(curve, xx, yy)
		if k != i {
			t.Errorf("(%d,%d) want: %d, got: %d", xx, yy, i, k)
		}
	}
}
