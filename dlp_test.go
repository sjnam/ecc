package ecc

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestShanks(t *testing.T) {
	curve.CurveParams = &elliptic.CurveParams{Name: "test"}
	curve.P = big.NewInt(29)
	curve.A = big.NewInt(4)
	curve.B = big.NewInt(20)
	curve.Gx = big.NewInt(8)
	curve.Gy = big.NewInt(10)
	curve.N = big.NewInt(37)
	curve.BitSize = 6

	cases := []struct {
		x, y, k int64
	}{
		{2, 6, 7},
		{6, 17, 4},
		{19, 16, 17},
		{5, 22, 11},
		{24, 22, 24},
		{13, 23, 29},
		{16, 27, 34},
		{0, 7, 35},
	}

	for _, c := range cases {
		k := Shanks(curve, big.NewInt(c.x), big.NewInt(c.y))
		if k == nil || k.Int64() != c.k {
			t.Errorf("(%d,%d) want: %d, got: %d", c.x, c.y, c.k, k)
		}
	}
}
