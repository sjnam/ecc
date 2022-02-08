package ecc

import (
	"crypto/elliptic"
	"math/big"
)

// Shanks' Baby-Step Giant-Step algorithm for ECDLP
func Shanks(curve ECurve, hx, hy *big.Int) *big.Int {
	htab := make(map[string]*big.Int)

	s := new(big.Int).Sqrt(curve.N)
	vx, vy := new(big.Int), new(big.Int)
	mx, my := curve.ScalarBaseMult(s.Bytes())

	for j := new(big.Int); j.Cmp(curve.N) <= 0; j.Add(j, s) {
		k := elliptic.Marshal(curve, vx, vy)
		htab[string(k)] = new(big.Int).Div(j, s)
		vx, vy = curve.Add(vx, vy, mx, my)
	}

	vx, vy = vx.Set(hx), vy.Set(hy)
	gix, giy := new(big.Int).Set(curve.Gx), new(big.Int).Neg(curve.Gy)
	one := new(big.Int).SetInt64(1)
	for i := new(big.Int); i.Cmp(s) <= 0; i.Add(i, one) {
		k := elliptic.Marshal(curve, vx, vy)
		if m, ok := htab[string(k)]; ok {
			return i.Add(i, new(big.Int).Mul(m, s))
		}
		vx, vy = curve.Add(vx, vy, gix, giy)
	}

	return nil
}

// PollardRho algorithm for the ECDLP
func PollardRho(curve ECurve, hx, hy *big.Int) *big.Int {
	return nil
}
