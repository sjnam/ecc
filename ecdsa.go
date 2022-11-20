package ecc

import (
	"crypto/rand"
	"math/big"
)

// hashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
// we use the left-most bits of the hash to match the bit-length of the order of
// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
func (c *Curve) hashToInt(hash []byte) *big.Int {
	orderBits := c.N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the signature as a pair of integers.
func (c *Curve) Sign(priv *big.Int, hash []byte) (r, s *big.Int) {
	N := c.N
	var k *big.Int
	for {
		k, r, _, _ = c.GenerateKey(rand.Reader)
		r.Mod(r, N)
		if r.Sign() == 0 {
			continue
		}
		kInv := FermatInverse(k, N)

		z := c.hashToInt(hash)
		s = new(big.Int).Set(priv)
		s.Mul(s, r)
		s.Add(s, z)
		s.Mul(s, kInv)
		s.Mod(s, N)
		if s.Sign() != 0 {
			return
		}
	}
}

// Verify verifies the signature in r, s of hash using the public key, pub.
func (c *Curve) Verify(hx, hy *big.Int, hash []byte, r, s *big.Int) bool {
	N := c.N
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	u1 := c.hashToInt(hash)
	u2 := FermatInverse(s, N)
	u1.Mul(u1, u2)
	u1.Mod(u1, N)
	u2.Mul(u2, r)
	u2.Mod(u2, N)

	x, y := c.CombinedMult(hx, hy, u1, u2)
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	x.Mod(x, N)
	return x.Cmp(r) == 0
}
