package ecc

import (
	"errors"
	"log"
	"math/big"
)

// https://cocalc.com/share/public_paths/600832aafc89f1098d5415b39eec4fbaa63ccab1

// Elements of endo(E[ell]) are represented as pairs (a,b*y), with a,b in Fp[x]/(h(x)),
// where h is the ell-th divpoly (or a factor of it, for example, the kernel poly
// of an isogeny)
// The y is implicit, but must be accounted for when applying the group law --
// using the curve equation y^2=f(x) we can replace y^2 with poly(x) whenever it appears
// (this effectively hides all the y's)

// In many of the functions below we pass in both A and poly
// where poly is the image of x^3+Ax+B in Fp[x]/(h(x)) -- we need both because
// if deg(h)<= 3 we cannot recover A from (x^3+Ax+B) mod h(x)

type qring struct {
	h Poly
	q *big.Int
}

// endo is the Frobenius endomorphism
type endo struct {
	qr   *qring
	x, y Poly
}

type trace struct {
	tr  *big.Int
	err error
}

var (
	// global variable for factor of the division poly when zeroDivisionError's
	divPolyFactor Poly

	zeroDivisionError = errors.New("divided by zero")
	noCharacterPoly   = errors.New("frobenius satisfies no character poly")
)

func (qr *qring) poly(p Poly) Poly {
	_, r := p.Div(qr.h, qr.q)
	return r
}

func newEnd(qr *qring, x, y Poly) *endo {
	return &endo{
		qr: qr,
		x:  qr.poly(x),
		y:  qr.poly(y),
	}
}

func eq(pe, qe *endo) bool {
	return pe.x.Cmp(qe.x) == 0 && pe.y.Cmp(qe.y) == 0
}

// add endomorphisms P and Q in End(E[ell])
func add(pe, qe *endo, A *big.Int, f Poly) (*endo, error) {
	if pe == nil {
		return qe, nil
	}
	if qe == nil {
		return pe, nil
	}

	h, q := pe.qr.h, pe.qr.q
	qpoly := pe.qr.poly

	a1, b1 := pe.x, pe.y
	a2, b2 := qe.x, qe.y

	if a1.Cmp(a2) == 0 {
		if b1.Cmp(b2) == 0 {
			return dbl(pe, A, f)
		}
		return nil, nil
	}

	b := b2.Sub(b1, q)
	a := a2.Sub(a1, q)
	inv := a.ModInverse(h, q)
	if inv == nil {
		divPolyFactor = a
		return nil, zeroDivisionError
	}

	m := qpoly(b.Mul(inv, q))
	m2 := qpoly(m.Mul(m, q))
	a3 := qpoly(f.Mul(m2, q)).Sub(a1.Add(a2, q), q)
	b3 := qpoly(m.Mul(a1.Sub(a3, q), q)).Sub(b1, q)

	return newEnd(pe.qr, a3, b3), nil
}

// double the endomorphism P in End(E[ell])
func dbl(pe *endo, A *big.Int, f Poly) (*endo, error) {
	if pe == nil {
		return nil, nil
	}

	h, q := pe.qr.h, pe.qr.q
	qpoly := pe.qr.poly

	a1, b1 := pe.x, pe.y
	m := qpoly(a1.Mul(a1, q))
	m = m.MulInt(3, q)
	m[0].Add(m[0], A)
	m[0].Mod(m[0], q)
	de := qpoly(b1.Mul(f, q)).MulInt(2, q)
	inv := de.ModInverse(h, q)
	if inv == nil {
		divPolyFactor = de
		return nil, zeroDivisionError
	}

	m = qpoly(m.Mul(inv, q))
	a3 := qpoly(f.Mul(m.Mul(m, q), q)).Sub(a1.MulInt(2, q), q)
	b3 := qpoly(m.Mul(a1.Sub(a3, q), q)).Sub(b1, q)

	return newEnd(pe.qr, a3, b3), nil
}

// negate the endomorphism P in End(E[ell])
func neg(pe *endo) *endo {
	if pe == nil {
		return nil
	}

	return newEnd(pe.qr, pe.x, pe.y.Neg())
}

// compute the scalar multiple n*P in End(E[ell]) using double and add
func smul(pe *endo, n *big.Int, A *big.Int, f Poly) (*endo, error) {
	var err error

	if n == nil {
		return nil, nil
	}

	re := newEnd(pe.qr, pe.x, pe.y)
	for i, b := range n.Bytes() {
		j := 0
		if i == 0 {
			for j = 1; b&0x80 != 0x80; j++ {
				b <<= 1
			}
			b <<= 1
		}
		for bitNum := j; bitNum < 8; bitNum++ {
			if re, err = dbl(re, A, f); err != nil {
				return nil, err
			}
			if b&0x80 == 0x80 {
				if re, err = add(re, pe, A, f); err != nil {
					return nil, err
				}
			}
			b <<= 1
		}
	}

	return re, nil
}

func square(pe *endo, f Poly) *endo {
	q2 := new(big.Int).Exp(pe.qr.q, big.NewInt(2), nil)

	xq2 := make(chan Poly)
	go func() {
		defer close(xq2)
		xq2 <- exp(pe.qr, NewPolyFromInt(0, 1), q2)
	}()

	yq2 := make(chan Poly)
	go func() {
		defer close(yq2)
		yq2 <- exp(pe.qr, f, new(big.Int).Div(q2, big.NewInt(2)))
	}()

	return newEnd(pe.qr, <-xq2, <-yq2)
}

func exp(qr *qring, p Poly, e *big.Int) Poly {
	qpoly := qr.poly
	r := NewPolyFromInt(1)

	for _, b := range e.Bytes() {
		for bitNum := 0; bitNum < 8; bitNum++ {
			r = qpoly(r.Mul(r, qr.q))
			if b&0x80 == 0x80 {
				r = qpoly(r.Mul(p, qr.q))
			}
			b <<= 1
		}
	}

	return r
}

func irreducible(qr *qring) bool {
	h, q := qr.h, qr.q
	x := NewPolyFromInt(0, 1)
	xq := exp(qr, x, q).Sub(x, q)

	return xq.GCD(h, q).Cmp(NewPolyFromInt(1)) == 0
}

// traceMod computes the trace of Frobenius of E modulo ell
func traceMod(c *Curve, ell *big.Int) <-chan interface{} {
	ch := make(chan interface{})

	go func() {
		defer close(ch)

		A, q := c.A, c.P
		f := c.poly()
		qr := &qring{c.divpoly(ell.Int64()).Monic(q), q}

		if ell.Cmp(big.NewInt(2)) == 0 {
			if irreducible(&qring{f, q}) {
				ch <- &trace{big.NewInt(1), nil}
				return
			}
			ch <- &trace{big.NewInt(0), nil}
			return
		}

		var err error
		for {
			switch err {
			case zeroDivisionError:
				qr.h = qr.h.GCD(divPolyFactor, q)
				log.Printf("found %d-divpoly factor of degree %d\n",
					ell, qr.h.Deg())
			case noCharacterPoly:
				ch <- &trace{nil, err}
				return
			}

			xq := exp(qr, NewPolyFromInt(0, 1), q)
			yq := exp(qr, f, new(big.Int).Div(q, big.NewInt(2)))
			pi := newEnd(qr, xq, yq)
			pi2 := square(pi, f)

			var Q, S *endo
			id := newEnd(qr, NewPolyFromInt(0, 1), NewPolyFromInt(1))
			if Q, err = smul(id, new(big.Int).Mod(q, ell), A, f); err != nil {
				continue
			}
			if S, err = add(pi2, Q, A, f); err != nil {
				continue
			}

			if S == nil {
				ch <- &trace{big.NewInt(0), nil}
				return
			}
			if eq(S, pi) {
				ch <- &trace{big.NewInt(1), nil}
				return
			}
			if eq(neg(S), pi) {
				ch <- &trace{big.NewInt(-1), nil}
				return
			}

			P := newEnd(qr, pi.x, pi.y)
			for t := int64(2); t < ell.Int64()-1; t++ {
				if P, err = add(P, pi, A, f); err != nil {
					break
				}
				if eq(P, S) {
					ch <- &trace{big.NewInt(t), nil}
					return
				}
			}
		}
	}()

	return ch
}

// Schoof computes the trace of Frobenius of E(Elliptic curve)
func (c *Curve) Schoof() (*big.Int, error) {
	q := c.P
	l, M := big.NewInt(2), big.NewInt(1)
	fsq := new(big.Int).Mul(new(big.Int).Sqrt(q), big.NewInt(4))

	log.Printf("%s q= %v\n", c.poly(), q)

	done := make(chan interface{})
	defer close(done)

	var ell []*big.Int
	var worker []<-chan interface{}
	for M.Cmp(fsq) <= 0 {
		ell = append(ell, l)
		ec := &Curve{
			P: c.P,
			A: c.A,
			B: c.B,
		}
		worker = append(worker, traceMod(ec, l))
		M.Mul(M, l)
		l = nextPrime(l)
	}

	var tr []*big.Int
	i := 0
	for s := range toTrace(done, fanIn(done, worker...)) {
		if s.err != nil {
			return nil, s.err
		}
		log.Println("trace", s.tr, "mod", ell[i])
		tr = append(tr, s.tr)
		i++
	}

	t := crt(tr, ell) // chinese remainder theorem
	if t.Cmp(new(big.Int).Div(M, big.NewInt(2))) >= 0 {
		t.Sub(t, M)
	}

	log.Printf("trace of Frobenius of E = %d\n", t)

	t.Neg(t)
	t.Add(t, q).Add(t, big.NewInt(1))

	return t, nil
}
