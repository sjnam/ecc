package ecc

import (
	"fmt"
	"math/big"
)

// https://github.com/jukworks/polynomial

// Poly Data structure for a poly
// Just an array in reverse
// f(x) = 3x^3 + 2x + 1 => [1 2 0 3]
type Poly []*big.Int

// NewPolyFromBigInt generates a poly with given integers.
func NewPolyFromBigInt(a ...*big.Int) Poly {
	alen := len(a)
	p := make(Poly, alen)

	for i := 0; i < alen; i++ {
		p[i] = new(big.Int).Set(a[i])
	}

	return p
}

// NewPolyFromInt generates a poly with given integers.
func NewPolyFromInt(a ...int) Poly {
	alen := len(a)
	p := make(Poly, alen)

	for i := 0; i < alen; i++ {
		p[i] = new(big.Int).SetInt64(int64(a[i]))
	}

	return p
}

// trim makes sure that the highest coefficient never has zero value
// when you add or subtract two polynomials, sometimes the highest coefficient
// goes zero if you don't remove the highest and zero coefficient,
// Deg() returns the wrong result
func (p Poly) trim() Poly {
	deg := len(p) - 1
	if p[deg].Sign() != 0 {
		return p
	}

	last := 0
	for i := deg; i > 0; i-- {
		// why i > 0, not i >=0? do not remove the constant
		if p[i].Sign() != 0 {
			last = i
			break
		}
	}

	return p[:last+1]
}

// sanitize does modular arithmetic with m
func (p Poly) sanitize(m *big.Int) Poly {
	for i := 0; i < len(p); i++ {
		p[i].Mod(p[i], m)
	}

	return p.trim()
}

// Clone does deep-copy
// adjust increases the degree of copied poly
// adjust cannot have a negative integer
// for example, P = x + 1 and adjust = 2, Clone() returns x^3 + x^2
func (p Poly) Clone(adjust int) Poly {
	if adjust < 0 {
		return NewPolyFromInt(0)
	}

	q := make(Poly, len(p)+adjust)
	for i := 0; i < adjust; i++ {
		q[i] = new(big.Int)
	}
	copy(q[adjust:], p)

	return q
}

// isZero checks if P = 0
func (p Poly) isZero() bool {
	return p.Deg() == 0 && p[0].Sign() == 0
}

// Deg returns the degree
// if p = x^3 + 2x^2 + 5, Deg() returns 3
func (p Poly) Deg() int {
	return len(p) - 1
}

// String pretty print
func (p Poly) String() string {
	s := "["
	for i := len(p) - 1; i >= 0; i-- {
		switch p[i].Sign() {
		case -1:
			if i == len(p)-1 {
				s += "-"
			} else {
				s += " - "
			}
			if i == 0 || p[i].Cmp(big.NewInt(-1)) != 0 {
				s += p[i].String()[1:]
			}
		case 0:
			continue
		case 1:
			if i < len(p)-1 {
				s += " + "
			}
			if i == 0 || p[i].Cmp(big.NewInt(1)) != 0 {
				s += p[i].String()
			}
		}
		if i > 0 {
			s += "x"
			if i > 1 {
				s += "^" + fmt.Sprintf("%d", i)
			}
		}
	}
	if s == "[" {
		s += "0"
	}
	s += "]"

	return s
}

// Cmp compares two polynomials and returns -1, 0, or 1
// if P == Q, returns 0
// if P > Q, returns 1
// if P < Q, returns -1
func (p Poly) Cmp(q Poly) int {
	if len(p) > len(q) {
		return 1
	}
	if len(p) < len(q) {
		return -1
	}

	for i := 0; i < len(p); i++ {
		s := p[i].Cmp(q[i])
		if s != 0 {
			return s
		}
	}

	return 0
}

// Add adds two polynomials
// modulo m can be nil
func (p Poly) Add(q Poly, m *big.Int) Poly {
	if p.Cmp(q) < 0 {
		return q.Add(p, m)
	}

	r := p.Clone(0)

	for i := 0; i < len(q); i++ {
		r[i] = new(big.Int).Add(p[i], q[i])
	}

	for i := 0; i < len(q); i++ {
		r[i].Mod(r[i], m)
	}

	return r.trim()
}

// Neg returns a poly Q = -P
func (p Poly) Neg() Poly {
	q := make(Poly, len(p))
	for i := 0; i < len(p); i++ {
		q[i] = new(big.Int).Neg(p[i])
	}

	return q
}

// Sub subtracts P from Q
// Since we already have Add(), Sub() does Add(P, -Q)
func (p Poly) Sub(q Poly, m *big.Int) Poly {
	swap := false
	s, t := p, q
	if p.Cmp(q) < 0 {
		swap = true
		s, t = t, s
	}

	r := make(Poly, len(s))

	ln := len(t)
	if !swap {
		for i := 0; i < ln; i++ {
			r[i] = new(big.Int).Sub(s[i], t[i])
		}
		copy(r[ln:], s[ln:])
	} else {
		for i := 0; i < ln; i++ {
			r[i] = new(big.Int).Sub(t[i], s[i])
		}
		for i := ln; i < len(s); i++ {
			r[i] = new(big.Int).Neg(s[i])
		}
	}

	for i := 0; i < len(s); i++ {
		r[i].Mod(r[i], m)
	}

	return r.trim()
}

// Mul returns P * Q
func (p Poly) Mul(q Poly, m *big.Int) Poly {
	r := make(Poly, len(p)+len(q)-1)
	for i := 0; i < len(r); i++ {
		r[i] = new(big.Int)
	}

	for i := 0; i < len(p); i++ {
		for j := 0; j < len(q); j++ {
			r[i+j].Add(r[i+j], new(big.Int).Mul(p[i], q[j]))
		}
	}

	return r.sanitize(m)
}

func (p Poly) MulInt(a int, m *big.Int) Poly {
	return p.Mul(NewPolyFromInt(a), m)
}

// Exp returns P^e mod M
func (p Poly) Exp(e *big.Int, m *big.Int) Poly {
	r := NewPolyFromInt(1)

	for _, b := range e.Bytes() {
		for bitNum := 0; bitNum < 8; bitNum++ {
			r = r.Mul(r, m)
			if b&0x80 == 0x80 {
				r = r.Mul(p, m)
			}
			b <<= 1
		}
	}

	return r.trim()
}

// Div returns (P / Q, P % Q)
func (p Poly) Div(q Poly, m *big.Int) (Poly, Poly) {
	p.sanitize(m)

	if len(p) < len(q) {
		return NewPolyFromInt(0), p.Clone(0)
	}

	quo := make(Poly, len(p)-len(q)+1)
	for i := 0; i < len(quo); i++ {
		quo[i] = new(big.Int)
	}
	rem := p

	qd := q.Deg()
	for {
		td := len(rem) - 1 // rem.Deg()
		rd := td - qd
		if rd < 0 || rem.isZero() {
			break
		}

		r := quo[rd]
		r.ModInverse(q[qd], m)
		r.Mul(r, rem[td]).Mod(r, m)

		u := make(Poly, len(q)+rd)
		for i := 0; i < rd; i++ {
			u[i] = new(big.Int)
		}
		x := u[rd:]
		for i := 0; i < len(q); i++ {
			x[i] = new(big.Int).Mul(q[i], r)
		}

		rem = rem.Sub(u, m)
	}

	return quo, rem
}

func (p Poly) Monic(m *big.Int) Poly {
	q := NewPolyFromBigInt(p[p.Deg()])
	q, _ = p.Div(q, m)
	return q
}

// Deriv derivative
func (p Poly) Deriv(m *big.Int) Poly {
	if len(p) == 1 {
		return NewPolyFromInt(0)
	}

	r := make(Poly, len(p)-1)
	for i := 1; i < len(p); i++ {
		r[i-1] = new(big.Int).Mul(p[i], big.NewInt(int64(i)))
		r[i-1].Mod(r[i-1], m)
	}

	return r.trim()
}

func (p Poly) GCD(q Poly, m *big.Int) Poly {
	g, _, _ := p.ExtendedGCD(q, m)
	return g
}

func (p Poly) ExtendedGCD(q Poly, m *big.Int) (Poly, Poly, Poly) {
	oldR, r := p, q
	oldS, s := NewPolyFromInt(1), NewPolyFromInt(0)
	oldT, t := NewPolyFromInt(0), NewPolyFromInt(1)

	for !r.isZero() {
		quo, _ := oldR.Div(r, m)
		oldR, r = r, oldR.Sub(quo.Mul(r, m), m)
		oldS, s = s, oldS.Sub(quo.Mul(s, m), m)
		oldT, t = t, oldT.Sub(quo.Mul(t, m), m)
	}

	return oldR.Monic(m), oldS, oldT
}

func (p Poly) ModInverse(h Poly, m *big.Int) Poly {
	if m.Cmp(big.NewInt(1)) == 0 {
		return NewPolyFromInt(0)
	}

	mono := NewPolyFromInt(1)
	t, newT := NewPolyFromInt(0), mono
	r, newR := h, p

	for !newR.isZero() {
		quo, _ := r.Div(newR, m)
		r, newR = newR, r.Sub(quo.Mul(newR, m), m)
		t, newT = newT, t.Sub(quo.Mul(newT, m), m)
	}

	if len(r) > 1 {
		return nil
	}
	x, _ := mono.Div(r, m)

	return x.Mul(t, m)
}

// Eval returns p(v) where v is the given big integer
func (p Poly) Eval(x *big.Int, m *big.Int) *big.Int {
	ans := new(big.Int).Set(p[p.Deg()])
	for i := p.Deg() - 1; i >= 0; i-- {
		ans.Mul(ans, x)
		ans.Add(ans, p[i])
		ans.Mod(ans, m)
	}

	return ans
}
