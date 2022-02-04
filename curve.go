package ecc

// This code is based from golang's crypto/elliptic
//
// This package operates, internally, on Jacobian coordinates. For a given
// (x, y) position on the curve, the Jacobian coordinates are (x1, y1, z1)
// where x = x1/z1² and y = y1/z1³. The greatest speedups come when the whole
// calculation can be performed within the transform (as in ScalarMult and
// ScalarBaseMult). But even for Add and Double, it's faster to apply and
// reverse the transform than to operate in affine coordinates.

import (
	"crypto/elliptic"
	"math/big"
)

// EllipticCurve represents a short-form Weierstrass curve. y² = x³ + ax + b
// Note that the point at infinity (0, 0) is not considered on the curve, and
// although it can be returned by Add, Double, ScalarMult, or ScalarBaseMult, it
// can't be marshaled or unmarshaled, and IsOnCurve will return false for it.
type EllipticCurve struct {
	P       *big.Int // the order of the underlying field
	A, B    *big.Int // the constant of the BitCurve equation
	Gx, Gy  *big.Int // (x,y) of the base point
	N       *big.Int // the order of the subgroup
	H       *big.Int // the cofactor of the subgroup
	BitSize int      // the size of the underlying field
}

// Params returns the parameters for the curve.
func (ec *EllipticCurve) Params() *elliptic.CurveParams {
	N := new(big.Int).Mul(ec.N, ec.H)
	return &elliptic.CurveParams{
		P:       ec.P,
		N:       N.Mod(N, ec.P),
		B:       ec.B,
		Gx:      ec.Gx,
		Gy:      ec.Gy,
		BitSize: ec.BitSize,
	}
}

// IsOnCurve reports whether the given (x,y) lies on the curve.
func (ec *EllipticCurve) IsOnCurve(x, y *big.Int) bool {
	// y² = x³ + ax + b
	y2 := new(big.Int).Mul(y, y)          //y²
	y2.Mod(y2, ec.P)                      //y²%P
	x3 := new(big.Int).Mul(x, x)          //x²
	x3.Mul(x3, x)                         //x³
	x3.Add(x3, new(big.Int).Mul(x, ec.A)) // x³+AX
	x3.Add(x3, ec.B)                      //x³+B
	x3.Mod(x3, ec.P)                      //(x³+B)%P
	return x3.Cmp(y2) == 0
}

// zForAffine returns a Jacobian Z value for the affine point (x, y). If x and
// y are zero, it assumes that they represent the point at infinity because (0,
// 0) is not on the any of the curves handled here.
func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}

// affineFromJacobian reverses the Jacobian transform. See the comment at the
// top of the file.
func (ec *EllipticCurve) affineFromJacobian(x, y, z *big.Int) (
	xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}
	zInv := new(big.Int).ModInverse(z, ec.P)
	zInvSq := new(big.Int).Mul(zInv, zInv)
	xOut = new(big.Int).Mul(x, zInvSq)
	xOut.Mod(xOut, ec.P)
	zInvSq.Mul(zInvSq, zInv)
	yOut = new(big.Int).Mul(y, zInvSq)
	yOut.Mod(yOut, ec.P)
	return
}

// Add returns the sum of (x1,y1) and (x2,y2)
func (ec *EllipticCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	return ec.affineFromJacobian(ec.addJacobian(x1, y1, z1, x2, y2, z2))
}

// addJacobian takes two points in Jacobian coordinates, (x1, y1, z1) and
// (x2, y2, z2) and returns their sum, also in Jacobian form.
func (ec *EllipticCurve) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (
	*big.Int, *big.Int, *big.Int) {
	// See http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-2007-bl
	x3, y3, z3 := new(big.Int), new(big.Int), new(big.Int)
	if z1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		z3.Set(z2)
		return x3, y3, z3
	}
	if z2.Sign() == 0 {
		x3.Set(x1)
		y3.Set(y1)
		z3.Set(z1)
		return x3, y3, z3
	}

	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, ec.P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, ec.P)

	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, ec.P)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, ec.P)
	h := new(big.Int).Sub(u2, u1)
	xEqual := h.Sign() == 0
	if h.Sign() == -1 {
		h.Add(h, ec.P)
	}
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	j := new(big.Int).Mul(h, i)

	s1 := new(big.Int).Mul(y1, z2)
	s1.Mul(s1, z2z2)
	s1.Mod(s1, ec.P)
	s2 := new(big.Int).Mul(y2, z1)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, ec.P)
	r := new(big.Int).Sub(s2, s1)
	if r.Sign() == -1 {
		r.Add(r, ec.P)
	}
	yEqual := r.Sign() == 0
	if xEqual && yEqual {
		return ec.doubleJacobian(x1, y1, z1)
	}
	r.Lsh(r, 1)
	v := new(big.Int).Mul(u1, i)

	x3 = x3.Set(r)
	x3.Mul(x3, x3)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, ec.P)

	y3 = y3.Set(r)
	v.Sub(v, x3)
	y3.Mul(y3, v)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y3.Sub(y3, s1)
	y3.Mod(y3, ec.P)

	z3 = z3.Add(z1, z2)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	if z3.Sign() == -1 {
		z3.Add(z3, ec.P)
	}
	z3.Sub(z3, z2z2)
	if z3.Sign() == -1 {
		z3.Add(z3, ec.P)
	}
	z3.Mul(z3, h)
	z3.Mod(z3, ec.P)

	return x3, y3, z3
}

// Double returns 2*(x,y)
func (ec *EllipticCurve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	return ec.affineFromJacobian(ec.doubleJacobian(x1, y1, z1))
}

// doubleJacobian takes a point in Jacobian coordinates, (x, y, z), and
// returns its double, also in Jacobian form.
func (ec *EllipticCurve) doubleJacobian(x, y, z *big.Int) (
	*big.Int, *big.Int, *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl
	xx := new(big.Int).Mul(x, x) //X1²
	xx.Mod(xx, ec.P)
	yy := new(big.Int).Mul(y, y) //Y1²
	yy.Mod(yy, ec.P)
	yyyy := new(big.Int).Mul(yy, yy) //YY²
	yyyy.Mod(yyyy, ec.P)
	zz := new(big.Int).Mul(z, z) //Z1²
	zz.Mod(zz, ec.P)

	s := new(big.Int).Add(x, yy) //X1+YY
	s.Mul(s, s)                  //(X1+YY)²
	s.Mod(s, ec.P)
	s.Sub(s, xx) //(X1+B)²-XX
	if s.Sign() == -1 {
		s.Add(s, ec.P)
	}
	s.Sub(s, yyyy) //(X1+B)²-XX-YYYY
	if s.Sign() == -1 {
		s.Add(s, ec.P)
	}
	s.Mul(s, big.NewInt(2)) //2*((X1+B)²-XX-YYYY)
	s.Mod(s, ec.P)

	m := new(big.Int).Mul(big.NewInt(3), xx)                   //3*XX
	m.Add(m, new(big.Int).Mul(ec.A, new(big.Int).Mul(zz, zz))) //3*XX+A*ZZ²
	m.Mod(m, ec.P)

	t := new(big.Int).Mul(m, m)                   //M²
	t.Add(t, new(big.Int).Mul(s, big.NewInt(-2))) //M²-2*S
	if t.Sign() == -1 {
		t.Add(t, ec.P)
	}
	t.Mod(t, ec.P)

	x3 := t
	s.Sub(s, t) //S-T
	if s.Sign() == -1 {
		s.Add(s, ec.P)
	}
	y3 := new(big.Int).Mul(m, s)               //M*(S-T)
	y3.Add(y3, yyyy.Mul(yyyy, big.NewInt(-8))) //M*(S-T)-8*YYYY
	if y3.Sign() == -1 {
		y3.Add(y3, ec.P)
	}
	y3.Mod(y3, ec.P)
	z3 := new(big.Int).Add(y, z) //Y1+Z1
	z3.Mul(z3, z3)               //(Y1+Z1)²
	z3.Sub(z3, yy)               //(Y1+Z1)²-YY
	if z3.Sign() == -1 {
		z3.Add(z3, ec.P)
	}
	z3.Sub(z3, zz) //(Y1+Z1)²-YY-ZZ
	if z3.Sign() == -1 {
		z3.Add(z3, ec.P)
	}
	z3.Mod(z3, ec.P)

	return x3, y3, z3
}

// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
func (ec *EllipticCurve) ScalarMult(Bx, By *big.Int, k []byte) (
	*big.Int, *big.Int) {
	Bz := new(big.Int).SetInt64(1)
	x, y, z := new(big.Int), new(big.Int), new(big.Int)
	for _, b := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			x, y, z = ec.doubleJacobian(x, y, z)
			if b&0x80 == 0x80 {
				x, y, z = ec.addJacobian(Bx, By, Bz, x, y, z)
			}
			b <<= 1
		}
	}
	return ec.affineFromJacobian(x, y, z)
}

// ScalarBaseMult returns k*G, where G is the base point of the group and k is
// an integer in big-endian form.
func (ec *EllipticCurve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return ec.ScalarMult(ec.Gx, ec.Gy, k)
}
