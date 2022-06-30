package ecc

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

// Encrypt encrypts with ECDH
func (ec *ECurve) Encrypt(priv []byte, pubX, pubY *big.Int) []byte {
	ssx, ssy := ec.ScalarMult(pubX, pubY, priv)
	return elliptic.Marshal(ec, ssx, ssy)
}

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large,
// and we mirror that too.
func hashToInt(hash []byte, ec *ECurve) *big.Int {
	orderBits := ec.N.BitLen()
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

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method.
// This has better constant-time properties than Euclid's method (implemented
// in math/big.Int.ModInverse) although math/big itself isn't strictly
// constant-time, so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length. It
// returns the signature as a pair of integers. The security of the private key
// depends on the entropy of rand.
func (ec *ECurve) Sign(priv []byte, hash []byte) (r, s *big.Int) {
	N := ec.N
	d := new(big.Int).SetBytes(priv)

	for {
		k, xp, _, _ := elliptic.GenerateKey(ec, rand.Reader)
		r = new(big.Int).Mod(xp, N)
		if r.Sign() == 0 {
			continue
		}

		z := hashToInt(hash, ec)
		s = new(big.Int).SetBytes(k)
		s = fermatInverse(s, N)
		u := new(big.Int).Mul(r, d)
		u.Add(u, z)
		s.Mul(s, u)
		s.Mod(s, N)
		if s.Sign() != 0 {
			return
		}
	}
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
func (ec *ECurve) Verify(Hx, Hy *big.Int, hash []byte, r, s *big.Int) bool {
	N := ec.N
	z := hashToInt(hash, ec)

	w := fermatInverse(s, N)
	u1 := new(big.Int).Mul(w, z)
	u1.Mod(u1, N)
	u2 := new(big.Int).Mul(w, r)
	u2.Mod(u2, N)

	x, _ := ec.CombinedMult(Hx, Hy, u1.Bytes(), u2.Bytes())
	x.Mod(x, N)

	return x.Cmp(r) == 0
}
