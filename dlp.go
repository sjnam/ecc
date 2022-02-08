package ecc

import (
	"crypto/elliptic"
	"math/big"
)

// Shanks' Baby-Step Giant-Step Method
func Shanks(curve ECurve, hx, hy *big.Int) *big.Int {
	table := make(map[string]*big.Int)

	k := new(big.Int).Sqrt(curve.N)
	vx, vy := new(big.Int), new(big.Int)
	mx, my := curve.ScalarBaseMult(k.Bytes())

	for i := new(big.Int); i.Cmp(curve.N) <= 0; i.Add(i, k) {
		v := elliptic.Marshal(curve, vx, vy)
		table[string(v)] = new(big.Int).Div(i, k)
		vx, vy = curve.Add(vx, vy, mx, my)
	}

	vx, vy = new(big.Int).Set(hx), new(big.Int).Set(hy)
	gInvX := new(big.Int).Set(curve.Gx)
	gInvY := new(big.Int).Neg(curve.Gy)
	one := new(big.Int).SetInt64(1)
	for i := new(big.Int); i.Cmp(k) <= 0; i.Add(i, one) {
		v := elliptic.Marshal(curve, vx, vy)
		m, ok := table[string(v)]
		if ok {
			return new(big.Int).Add(i, new(big.Int).Mul(m, k))
		}
		vx, vy = curve.Add(vx, vy, gInvX, gInvY)
	}

	return nil
}
