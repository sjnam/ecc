package ecc

import (
	"math/big"
	"sync"
)

func bigFromDecimal(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("ecc: internal error: invalid encoding")
	}
	return b
}

func bigFromHex(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("ecc: internal error: invalid encoding")
	}
	return b
}

func nextPrime(n *big.Int) *big.Int {
	if n.Cmp(big.NewInt(1)) <= 0 {
		return big.NewInt(2)
	}
	if n.Cmp(big.NewInt(2)) == 0 {
		return big.NewInt(3)
	}

	p := new(big.Int).Set(n)
	if p.Bits()[0]&0x1 == 0 {
		p.Add(p, big.NewInt(1))
		if p.ProbablyPrime(20) {
			return p
		}
	}

	for {
		p.Add(p, big.NewInt(2))
		if p.ProbablyPrime(20) {
			break
		}
	}

	return p
}

// Chinese remainder theorem
func crt(a, n []*big.Int) *big.Int {
	if a == nil || n == nil {
		return nil
	}
	p := big.NewInt(1)
	for _, x := range n {
		p.Mul(p, x)
	}
	var c, q, s, z big.Int
	for i, x := range n {
		q.Div(p, x)
		z.GCD(nil, &s, x, &q)
		if z.Int64() != 1 {
			return nil
		}
		c.Add(&c, s.Mul(a[i], s.Mul(&s, &q)))
	}
	return c.Mod(&c, p)
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method
// (exponentiation modulo P - 2, per Euler's theorem).
func fermatInverse(k, N *big.Int) *big.Int {
	return new(big.Int).Exp(k, new(big.Int).Sub(N, big.NewInt(2)), N)
}

func fanIn(done <-chan interface{}, channels ...<-chan interface{}) <-chan interface{} {
	var wg sync.WaitGroup
	multiplexedStream := make(chan interface{})

	multiplex := func(c <-chan interface{}) {
		defer wg.Done()
		for s := range c {
			select {
			case <-done:
				return
			case multiplexedStream <- s:
			}
		}
	}

	wg.Add(len(channels))
	for _, c := range channels {
		go multiplex(c)
	}

	go func() {
		wg.Wait()
		close(multiplexedStream)
	}()

	return multiplexedStream
}

func toTrace(done <-chan interface{}, stream <-chan interface{}) <-chan *trace {
	ch := make(chan *trace)
	go func() {
		defer close(ch)
		for v := range stream {
			select {
			case <-done:
				return
			case ch <- v.(*trace):
			}
		}
	}()
	return ch
}
