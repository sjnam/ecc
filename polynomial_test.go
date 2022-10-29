package ecc

import (
	"fmt"
	"math/big"
	"testing"
)

func TestPrettyPrint(t *testing.T) {
	cases := []struct {
		p   Poly
		ans string
	}{
		{
			NewPolyFromInt(0),
			"[0]",
		},
		{
			NewPolyFromInt(5, -4, 3, 3),
			"[3x^3 + 3x^2 - 4x + 5]",
		},
		{
			NewPolyFromInt(5, 6, 2),
			"[2x^2 + 6x + 5]",
		},
		{
			NewPolyFromInt(5, -2, 0, 2, 1, 3),
			"[3x^5 + x^4 + 2x^3 - 2x + 5]",
		},
		{
			NewPolyFromInt(2, 1, 0, -1, -2),
			"[-2x^4 - x^3 + x + 2]",
		},
		{
			NewPolyFromInt(1, 2, 2, 0, 1, 1),
			"[x^5 + x^4 + 2x^2 + 2x + 1]",
		},
	}
	for _, c := range cases {
		s := fmt.Sprintf("%v", c.p)
		if s != c.ans {
			t.Errorf("Stringify %v should be %v", s, c.ans)
		}
	}
}

func TestAdd(t *testing.T) {
	cases := []struct {
		p   Poly
		q   Poly
		m   *big.Int
		ans Poly
	}{
		{
			NewPolyFromInt(0),
			NewPolyFromInt(0),
			big.NewInt(2),
			NewPolyFromInt(0),
		},
		{
			NewPolyFromInt(4, 0, 0, 3, 0, 1),
			NewPolyFromInt(0, 0, 0, 4, 0, 0, 2),
			big.NewInt(4),
			NewPolyFromInt(0, 0, 0, 3, 0, 1, 2),
		},
	}
	for _, c := range cases {
		res := (c.p).Add(c.q, c.m)
		if res.Cmp(c.ans) != 0 {
			t.Errorf("%v + %v != %v (your answer was %v)\n", c.p, c.q, c.ans, res)
		}
	}
}

func BenchmarkAddIntPolynomial(b *testing.B) {
	p := NewPolyFromInt(4, 0, 0, 3, 0, 1)
	q := NewPolyFromInt(0, 0, 0, 4, 0, 0, 6)
	m := big.NewInt(11)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Add(q, m)
	}
}

func TestSub(t *testing.T) {
	cases := []struct {
		p   Poly
		q   Poly
		m   *big.Int
		ans Poly
	}{
		{
			NewPolyFromInt(0),
			NewPolyFromInt(0),
			big.NewInt(2),
			NewPolyFromInt(0),
		},
		{
			NewPolyFromInt(4, 0, 0, 3, 0, 1),
			NewPolyFromInt(0, 0, 0, 4, 0, 0, 6),
			big.NewInt(11),
			NewPolyFromInt(4, 0, 0, 10, 0, 1, 5),
		},
	}
	for _, c := range cases {
		res := (c.p).Sub(c.q, c.m)
		if res.Cmp(c.ans) != 0 {
			t.Errorf("%v - %v != %v (your answer was %v)\n", c.p, c.q, c.ans, res)
		}
	}
}

func BenchmarkSub(b *testing.B) {
	p := NewPolyFromInt(4, 0, 0, 3, 0, 1)
	q := NewPolyFromInt(0, 0, 0, 4, 0, 0, 6)
	m := big.NewInt(11)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Sub(q, m)
	}
}

func TestMultiply(t *testing.T) {
	cases := []struct {
		p   Poly
		q   Poly
		m   *big.Int
		ans Poly
	}{
		{
			NewPolyFromInt(0),
			NewPolyFromInt(0),
			big.NewInt(2),
			NewPolyFromInt(0),
		},
		{
			NewPolyFromInt(4, 0, 0, 3, 0, 1),
			NewPolyFromInt(0, 0, 0, 4, 0, 0, 6),
			big.NewInt(11),
			NewPolyFromInt(0, 0, 0, 5, 0, 0, 3, 0, 4, 7, 0, 6),
		},
	}
	for _, c := range cases {
		res := (c.p).Mul(c.q, c.m)
		if res.Cmp(c.ans) != 0 {
			t.Errorf("%v * %v != %v (your answer was %v)\n", c.p, c.q, c.ans, res)
		}
	}
}

func BenchmarkMultiply(b *testing.B) {
	p := NewPolyFromInt(4, 0, 0, 3, 0, 1)
	q := NewPolyFromInt(0, 0, 0, 4, 0, 0, 6)
	m := big.NewInt(11)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Mul(q, m)
	}
}

func TestDivide(t *testing.T) {
	cases := []struct {
		p, q     Poly
		m        *big.Int
		quo, rem Poly
	}{
		{
			NewPolyFromInt(2, 0, 2, 1),
			NewPolyFromInt(1, 0, 1),
			big.NewInt(3),
			NewPolyFromInt(2, 1),
			NewPolyFromInt(0, 2),
		},
		{
			NewPolyFromInt(5, 0, 0, 4, 7, 0, 3),
			NewPolyFromInt(4, 0, 0, 3, 1),
			big.NewInt(11),
			NewPolyFromInt(1, 2, 3),
			NewPolyFromInt(1, 3, 10, 1),
		},
		{
			NewPolyFromInt(184, 187, 234, 0, 39, 245, 13, 268, 288, 250, 164, 0, 64, 258, 14, 113, 43, 161),
			NewPolyFromInt(48, 0, 43, 22, 56, 84, 45, 67, 0, 34, 53),
			big.NewInt(307),
			NewPolyFromInt(98, 35, 0, 0, 23, 55, 44, 32),
			NewPolyFromInt(85, 42, 11, 23, 45),
		},
		{
			NewPolyFromInt(4, 0, 0, 1),
			NewPolyFromInt(3, 1, 4, 1),
			big.NewInt(7),
			NewPolyFromInt(1),
			NewPolyFromInt(1, 6, 3),
		},
	}
	for _, c := range cases {
		q, r := (c.p).Div(c.q, c.m)
		if q.Cmp(c.quo) != 0 || r.Cmp(c.rem) != 0 {
			t.Errorf("%v / %v != %v (%v) (your answer was %v (%v))\n", c.p, c.q, c.quo, c.rem, q, r)
		}
	}
}

func TestExp(t *testing.T) {
	cases := []struct {
		p   Poly
		e   *big.Int
		m   *big.Int
		ans Poly
	}{
		{
			NewPolyFromInt(1, 1),
			big.NewInt(2),
			big.NewInt(7),
			NewPolyFromInt(1, 2, 1),
		},
		{
			NewPolyFromInt(1, 1),
			big.NewInt(3),
			big.NewInt(7),
			NewPolyFromInt(1, 3, 3, 1),
		},
		{
			NewPolyFromInt(1, 1),
			big.NewInt(4),
			big.NewInt(7),
			NewPolyFromInt(1, 4, 6, 4, 1),
		},
	}
	for _, c := range cases {
		res := c.p.Exp(c.e, c.m)
		if res.Cmp(c.ans) != 0 {
			t.Errorf("%v^%v != %v (your answer was %v)\n", c.p, c.e, c.ans, res)
		}
	}
}

func TestDeriv(t *testing.T) {
	cases := []struct {
		p   Poly
		m   *big.Int
		ans Poly
	}{
		{
			NewPolyFromInt(5),
			big.NewInt(7),
			NewPolyFromInt(0),
		},
		{
			NewPolyFromInt(0, 8),
			big.NewInt(7),
			NewPolyFromInt(1),
		},
		{
			NewPolyFromInt(4, 0, 0, 1),
			big.NewInt(7),
			NewPolyFromInt(0, 0, 3),
		},
		{
			NewPolyFromInt(1, 2, 3, 4, 5),
			big.NewInt(23),
			NewPolyFromInt(2, 6, 12, 20),
		},
	}

	for _, c := range cases {
		res := c.p.Deriv(c.m)
		if res.Cmp(c.ans) != 0 {
			t.Errorf("Deriv(%v) != %v (your answer was %v)\n", c.p, c.ans, res)
		}
	}
}

func TestPolyGCD(t *testing.T) {
	cases := []struct {
		p   Poly
		q   Poly
		m   *big.Int
		ans Poly
	}{
		{
			NewPolyFromInt(4, 0, 0, 1),
			NewPolyFromInt(3, 1, 4, 1),
			big.NewInt(7),
			NewPolyFromInt(1),
		},
		{
			NewPolyFromInt(6, 7, 1),
			NewPolyFromInt(-6, -5, 1),
			big.NewInt(7),
			NewPolyFromInt(1, 1),
		},
		{
			NewPolyFromInt(3, 0, 3).Mul(NewPolyFromInt(4, 5, 6, 7), big.NewInt(13)),
			NewPolyFromInt(3, 0, 3).Mul(NewPolyFromInt(5, 6, 7, 8, 9), big.NewInt(13)),
			big.NewInt(13),
			NewPolyFromInt(1, 0, 1),
		},
	}
	for _, c := range cases {
		res := (c.p).GCD(c.q, c.m)
		if res.Cmp(c.ans) != 0 {
			t.Errorf("GCD(%v, %v) != %v (your answer was %v)\n", c.p, c.q, c.ans, res)
		}
	}
}

func TestModInverse(t *testing.T) {
	cases := []struct {
		h   Poly
		p   Poly
		m   *big.Int
		ans Poly
	}{
		{
			NewPolyFromInt(1, 1, 0, 1, 1, 0, 0, 0, 1),
			NewPolyFromInt(1, 1, 0, 0, 1, 0, 1),
			big.NewInt(2),
			NewPolyFromInt(0, 1, 0, 1, 0, 0, 1, 1),
		},
		{
			NewPolyFromInt(1, 1, 0, 0, 1),
			NewPolyFromInt(0, 0, 1),
			big.NewInt(2),
			NewPolyFromInt(1, 0, 1, 1),
		},
		{
			NewPolyFromInt(1, 0, 1, 1),
			NewPolyFromInt(1, 0, 1),
			big.NewInt(2),
			NewPolyFromInt(1, 1, 1),
		},
		{
			NewPolyFromInt(-1, 0, 0, 0, 0, 1),
			NewPolyFromInt(1, 0, 1),
			big.NewInt(3),
			NewPolyFromInt(2, 1, 1, 2, 2),
		},
	}
	for _, c := range cases {
		q := c.p.ModInverse(c.h, c.m)
		if q.Cmp(c.ans) != 0 {
			t.Errorf("ModInverse got %v != want %v", q, c.ans)
		}
	}
}

func TestEval(t *testing.T) {
	cases := []struct {
		p         Poly
		x, m, ans *big.Int
	}{
		{
			NewPolyFromInt(0),
			big.NewInt(0),
			big.NewInt(2),
			big.NewInt(0),
		},
		{
			NewPolyFromInt(0),
			big.NewInt(1),
			big.NewInt(2),
			big.NewInt(0),
		},
		{
			NewPolyFromInt(6, 2, 0, 4, 1),
			big.NewInt(2),
			big.NewInt(10),
			big.NewInt(8),
		},
		{
			NewPolyFromInt(45545, 343424, 5545, 3445435, 0, 343434, 4665, 5452, 34344, 534556, 4345345, 5656, 434525, 53333, 36645),
			big.NewInt(394),
			big.NewInt(1046527),
			big.NewInt(636194),
		},
	}
	for _, c := range cases {
		res := (c.p).Eval(c.x, c.m)
		if res.Cmp(c.ans) != 0 {
			t.Errorf("poly(x) = %v, poly(%v) != %v (your answer was %v)\n", c.p, c.x, c.ans, res)
		}
	}
}
