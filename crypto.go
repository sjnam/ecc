package ecc

import (
	"crypto/elliptic"
	"math/big"
)

// Encrypt encrypts with ECDH
func (curve *Curve) Encrypt(priv []byte, pubX, pubY *big.Int) []byte {
	ssx, ssy := curve.ScalarMult(pubX, pubY, priv)
	return elliptic.Marshal(curve, ssx, ssy)
}

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large,
// and we mirror that too.
func (curve *Curve) hashToInt(hash []byte) *big.Int {
	orderBits := curve.BitSize
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
func (curve *Curve) Sign(priv []byte, hash []byte) (r, s *big.Int) {
	var k []byte
	N := curve.N
	s = new(big.Int).SetBytes(priv)
	z := curve.hashToInt(hash)

	for {
		k, r, _, _ = curve.GenerateKey()
		if r.Mod(r, N).Sign() == 0 {
			continue
		}
		s.Mul(r, s)
		s.Add(s, z)
		kInv := new(big.Int).SetBytes(k)
		s.Mul(s, kInv.ModInverse(kInv, N))
		s.Mod(s, N)
		if s.Sign() != 0 {
			return
		}
	}
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
func (curve *Curve) Verify(hx, hy *big.Int, hash []byte, r, s *big.Int) bool {
	N := curve.N
	u1 := curve.hashToInt(hash)
	u2 := s.ModInverse(s, N)
	u1.Mul(u1, u2)
	u1.Mod(u1, N)
	u2.Mul(u2, r)
	u2.Mod(u2, N)

	x, y := curve.CombinedMult(hx, hy, u1.Bytes(), u2.Bytes())
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	return x.Mod(x, N).Cmp(r) == 0
}
