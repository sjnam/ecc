package ecc

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large,
// and we mirror that too.
func hashToInt(hash []byte, ec *EllipticCurve) *big.Int {
	orderBits := ec.Params().N.BitLen()
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
// returns the signature as a pair of integers. The security of the private key
// depends on the entropy of rand.
func Sign(priv []byte, ec *EllipticCurve, hash []byte) (r, s *big.Int) {
	N := ec.Params().N
	d := new(big.Int).SetBytes(priv)

	for {
		k, xp, _, _ := elliptic.GenerateKey(ec, rand.Reader)

		r = new(big.Int).Mod(xp, N)
		if r.Sign() == 0 {
			continue
		}

		z := hashToInt(hash, ec)
		s = new(big.Int).SetBytes(k)
		s.ModInverse(s, N)
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
func Verify(Hx, Hy *big.Int, ec *EllipticCurve, hash []byte, r, s *big.Int) bool {
	N := ec.Params().N
	z := hashToInt(hash, ec)

	w := new(big.Int).ModInverse(s, N)
	u1 := new(big.Int).Mul(w, z)
	u1.Mod(u1, N)
	u2 := new(big.Int).Mul(w, r)
	u2.Mod(u2, N)

	x1, y1 := ec.ScalarBaseMult(u1.Bytes())
	x2, y2 := ec.ScalarMult(Hx, Hy, u2.Bytes())
	x, _ := ec.Add(x1, y1, x2, y2)
	x.Mod(x, N)

	return x.Cmp(r) == 0
}
