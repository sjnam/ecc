package ecc

import (
	"crypto/elliptic"
	"math/big"
)

// Shanks' Baby-Step Giant-Step algorithm for ECDLP
func Shanks(curve ECurve, hx, hy *big.Int) int64 {
	htab := make(map[string]int64)

	ss := new(big.Int).Sqrt(curve.N)
	s := ss.Int64()
	vx, vy := new(big.Int), new(big.Int)
	mx, my := curve.ScalarBaseMult(ss.Bytes())

	// Giant step
	for j := int64(0); j <= curve.N.Int64(); j += s {
		k := elliptic.Marshal(curve, vx, vy)
		htab[string(k)] = j / s
		vx, vy = curve.Add(vx, vy, mx, my)
	}

	vx, vy = vx.Set(hx), vy.Set(hy)
	gix, giy := new(big.Int).Set(curve.Gx), new(big.Int).Neg(curve.Gy)

	// Baby step
	for i := int64(0); i <= s; i++ {
		k := elliptic.Marshal(curve, vx, vy)
		if m, ok := htab[string(k)]; ok {
			return i + m*s
		}
		vx, vy = curve.Add(vx, vy, gix, giy)
	}

	return -1
}

// PollardRho algorithm for the ECDLP
func PollardRho(curve ECurve, hx, hy *big.Int) *big.Int {
	return nil
}
