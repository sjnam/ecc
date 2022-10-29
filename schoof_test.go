package ecc

import (
	"math/big"
	"testing"
)

func TestSchoof(t *testing.T) {
	cases := []*Curve{
		{
			P: big.NewInt(97),
			A: big.NewInt(46),
			B: big.NewInt(74),
			N: big.NewInt(80),
		},
		{
			P: big.NewInt(19),
			A: big.NewInt(2),
			B: big.NewInt(1),
			N: big.NewInt(27),
		},
		{
			P: big.NewInt(7919),
			A: big.NewInt(1001),
			B: big.NewInt(75),
			N: big.NewInt(7889),
		},
	}

	for _, c := range cases {
		got, err := c.Schoof()
		if err != nil {
			t.Errorf("got error: %v", err)
			return
		}
		if got.Cmp(c.N) != 0 {
			t.Errorf("got: %d, want: %d", got, c.N)
		}
	}
}
