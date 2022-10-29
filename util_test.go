package ecc

import (
	"math/big"
	"testing"
)

func TestNextPrime(t *testing.T) {
	cases := []struct {
		a, want *big.Int
	}{
		{
			big.NewInt(1),
			big.NewInt(2),
		},
		{
			big.NewInt(2),
			big.NewInt(3),
		},
		{
			big.NewInt(17),
			big.NewInt(19),
		},
		{
			big.NewInt(1234567890),
			big.NewInt(1234567891),
		},
	}

	for _, c := range cases {
		r := nextPrime(c.a)
		if r.Cmp(c.want) != 0 {
			t.Errorf("got: %v, want: %v", r, c.want)
		}
	}
}
