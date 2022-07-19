package ecc

// A lot of code is borrowed from golang's crypto/elliptic
//
// This package operates, internally, on Jacobian coordinates. For a given
// (x, y) position on the curve, the Jacobian coordinates are (x1, y1, z1)
// where x = x1/z1² and y = y1/z1³. The greatest speedups come when the whole
// calculation can be performed within the transform (as in ScalarMult and
// ScalarBaseMult). But even for Add and Double, it's faster to apply and
// reverse the transform than to operate in affine coordinates.

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

// Curve represents a short-form Weierstrass curve. (y² = x³ + ax + b)
// The behavior of Add, Double, and ScalarMult when the input is not a point on
// the curve is undefined.
//
// Note that the conventional point at infinity (0, 0) is not considered on the
// curve, although it can be returned by Add, Double, ScalarMult, or
// ScalarBaseMult (but not the Unmarshal or UnmarshalCompressed functions).
type Curve struct {
	P       *big.Int // the order of the underlying field
	A       *big.Int // the constant of the Curve equation
	B       *big.Int // the constant of the Curve equation
	Gx, Gy  *big.Int // (x,y) of the base point
	N       *big.Int // the order of the base point
	H       *big.Int // the cofactor of the subgroup
	BitSize int      // the size of the underlying field
	Name    string   // the canonical name of the curve
}

// Params returns the parameters for the curve.
func (curve *Curve) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:       curve.P,
		N:       curve.N,
		B:       curve.B,
		Gx:      curve.Gx,
		Gy:      curve.Gy,
		BitSize: curve.BitSize,
		Name:    curve.Name,
	}
}

// polynomial returns y² = x³ + Ax + B.
func (curve *Curve) polynomial(x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)             // x²
	x3.Mul(x3, x)                            // x³
	x3.Add(x3, new(big.Int).Mul(x, curve.A)) // x³+AX
	x3.Add(x3, curve.B)                      // x³+AX+B
	x3.Mod(x3, curve.P)                      //(x³+AX+B)%P
	return x3
}

// IsOnCurve reports whether the given (x,y) lies on the curve.
func (curve *Curve) IsOnCurve(x, y *big.Int) bool {
	if x.Sign() < 0 || x.Cmp(curve.P) >= 0 ||
		y.Sign() < 0 || y.Cmp(curve.P) >= 0 {
		return false
	}

	y2 := new(big.Int).Mul(y, y) // y²
	y2.Mod(y2, curve.P)          // y²%P
	return curve.polynomial(x).Cmp(y2) == 0
}

// zForAffine returns a Jacobian Z value for the affine point (x, y). If x and
// y are zero, it assumes that they represent the point at infinity because (0,
// 0) is not on any of the curves handled here.
func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}

// affineFromJacobian reverses the Jacobian transform. See the comment at the
// top of the file.
func (curve *Curve) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	zInv := new(big.Int).ModInverse(z, curve.P)
	zInvSq := new(big.Int).Mul(zInv, zInv)
	xOut = new(big.Int).Mul(x, zInvSq)
	xOut.Mod(xOut, curve.P)
	zInvSq.Mul(zInvSq, zInv)
	yOut = new(big.Int).Mul(y, zInvSq)
	yOut.Mod(yOut, curve.P)
	return
}

// Add returns the sum of (x1,y1) and (x2,y2)
func (curve *Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	panicIfNotOnCurve(curve, x1, y1)
	panicIfNotOnCurve(curve, x2, y2)

	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	return curve.affineFromJacobian(curve.addJacobian(x1, y1, z1, x2, y2, z2))
}

// addJacobian takes two points in Jacobian coordinates, (x1, y1, z1) and
// (x2, y2, z2) and returns their sum, also in Jacobian form.
func (curve *Curve) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (x3, y3, z3 *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-2007-bl
	P := curve.P
	x3, y3, z3 = new(big.Int), new(big.Int), new(big.Int)
	if z1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		z3.Set(z2)
		return
	}
	if z2.Sign() == 0 {
		x3.Set(x1)
		y3.Set(y1)
		z3.Set(z1)
		return
	}

	z1z1 := new(big.Int).Mul(z1, z1) // Z1Z1 = Z1²
	z1z1.Mod(z1z1, P)
	z2z2 := new(big.Int).Mul(z2, z2) // Z2Z2 = Z2²
	z2z2.Mod(z2z2, P)

	u1 := new(big.Int).Mul(x1, z2z2) // U1 = X1*Z2Z2
	u1.Mod(u1, P)
	u2 := new(big.Int).Mul(x2, z1z1) // U2 = X2*Z1Z1
	u2.Mod(u2, P)

	s1 := new(big.Int).Mul(y1, z2) // S1 = Y1*Z2*Z2Z2
	s1.Mul(s1, z2z2)
	s1.Mod(s1, P)
	s2 := new(big.Int).Mul(y2, z1) // S2 = Y2*Z1*Z1Z1
	s2.Mul(s2, z1z1)
	s2.Mod(s2, P)

	h := new(big.Int).Sub(u2, u1) // H = U2-U1
	xEqual := h.Sign() == 0
	if h.Sign() == -1 {
		h.Add(h, P)
	}

	i := new(big.Int).Lsh(h, 1) // I = (2*H)2
	i.Mul(i, i)
	j := new(big.Int).Mul(h, i) // J = H*I

	r := new(big.Int).Sub(s2, s1) // r = 2*(S2-S1)
	if r.Sign() == -1 {
		r.Add(r, P)
	}
	yEqual := r.Sign() == 0
	if xEqual && yEqual {
		return curve.doubleJacobian(x1, y1, z1)
	}
	r.Lsh(r, 1)

	v := new(big.Int).Mul(u1, i) // V = U1*I

	x3.Set(r) // X3 = r2-J-2*V
	x3.Mul(x3, x3)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, P)

	y3.Set(r) // Y3 = r*(V-X3)-2*S1*J
	v.Sub(v, x3)
	y3.Mul(y3, v)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y3.Sub(y3, s1)
	y3.Mod(y3, P)

	z3.Add(z1, z2) // Z3 = ((Z1+Z2)2-Z1Z1-Z2Z2)*H
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	if z3.Sign() == -1 {
		z3.Add(z3, P)
	}
	z3.Sub(z3, z2z2)
	if z3.Sign() == -1 {
		z3.Add(z3, P)
	}
	z3.Mul(z3, h)
	z3.Mod(z3, P)

	return
}

// Double returns 2*(x,y)
func (curve *Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	panicIfNotOnCurve(curve, x1, y1)

	z1 := zForAffine(x1, y1)
	return curve.affineFromJacobian(curve.doubleJacobian(x1, y1, z1))
}

// doubleJacobian takes a point in Jacobian coordinates, (x, y, z), and
// returns its double, also in Jacobian form.
func (curve *Curve) doubleJacobian(x, y, z *big.Int) (x3, y3, z3 *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl
	P := curve.P
	xx := new(big.Int).Mul(x, x) // XX = X1²
	xx.Mod(xx, P)
	yy := new(big.Int).Mul(y, y) // YY = Y1²
	yy.Mod(yy, P)
	yyyy := new(big.Int).Mul(yy, yy) // YYYY = YY²
	yyyy.Mod(yyyy, P)
	zz := new(big.Int).Mul(z, z) // ZZ = Z1²
	zz.Mod(zz, P)
	zzzz := new(big.Int).Mul(zz, zz) // ZZ²
	zzzz.Mod(zzzz, P)

	s := new(big.Int).Add(x, yy) // X1+YY
	s.Mul(s, s)                  //(X1+YY)²
	s.Sub(s, xx)                 //(X1+YY)²-XX
	if s.Sign() == -1 {
		s.Add(s, P)
	}
	s.Sub(s, yyyy) //(X1+YY)²-XX-YYYY
	if s.Sign() == -1 {
		s.Add(s, P)
	}
	s.Lsh(s, 1) // 2*((X1+YY)²-XX-YYYY)
	s.Mod(s, P)

	m := new(big.Int).Lsh(xx, 1)      // 2*XX
	m.Add(m, xx)                      // 3*XX
	m.Add(m, zzzz.Mul(curve.A, zzzz)) // 3*XX+A*ZZ²
	m.Mod(m, P)

	t := new(big.Int).Mul(m, m)      // M²
	t.Sub(t, new(big.Int).Lsh(s, 1)) // M²-2*S
	if t.Sign() == -1 {
		t.Add(t, P)
	}
	t.Mod(t, P)

	x3 = t
	s.Sub(s, t) // S-T
	if s.Sign() == -1 {
		s.Add(s, P)
	}
	y3 = new(big.Int).Mul(m, s)   // M*(S-T)
	y3.Sub(y3, yyyy.Lsh(yyyy, 3)) // M*(S-T)-8*YYYY
	if y3.Sign() == -1 {
		y3.Add(y3, P)
	}
	y3.Mod(y3, P)
	z3 = new(big.Int).Add(y, z) // Y1+Z1
	z3.Mul(z3, z3)              //(Y1+Z1)²
	z3.Sub(z3, yy)              //(Y1+Z1)²-YY
	if z3.Sign() == -1 {
		z3.Add(z3, P)
	}
	z3.Sub(z3, zz) //(Y1+Z1)²-YY-ZZ
	if z3.Sign() == -1 {
		z3.Add(z3, P)
	}
	z3.Mod(z3, P)

	return
}

// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
func (curve *Curve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	panicIfNotOnCurve(curve, Bx, By)

	Bz := new(big.Int).SetInt64(1)
	x, y, z := new(big.Int), new(big.Int), new(big.Int)
	for _, b := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			x, y, z = curve.doubleJacobian(x, y, z)
			if b&0x80 == 0x80 {
				x, y, z = curve.addJacobian(Bx, By, Bz, x, y, z)
			}
			b <<= 1
		}
	}
	return curve.affineFromJacobian(x, y, z)
}

// ScalarBaseMult returns k*G, where G is the base point of the group and k is
// an integer in big-endian form.
func (curve *Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

// CombinedMult implements fast multiplication
// S1*g + S2*p (g - generator, p - arbitrary point)
func (curve *Curve) CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int) {
	x1, y1 := curve.ScalarBaseMult(baseScalar)
	x2, y2 := curve.ScalarMult(bigX, bigY, scalar)
	return curve.Add(x1, y1, x2, y2)
}

// Unmarshal converts a point, serialized by Marshal, into an x, y pair. It is
// an error if the point is not in uncompressed form, is not on the curve, or is
// the point at infinity. On error, x = nil.
func (curve *Curve) Unmarshal(data []byte) (x, y *big.Int) {
	byteLen := (curve.BitSize + 7) / 8
	if len(data) != 1+2*byteLen {
		return nil, nil
	}
	if data[0] != 4 { // uncompressed form
		return nil, nil
	}
	p := curve.P
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return nil, nil
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}
	return
}

// UnmarshalCompressed converts a point, serialized by MarshalCompressed, into
// an x, y pair. It is an error if the point is not in compressed form, is not
// on the curve, or is the point at infinity. On error, x = nil.
func (curve *Curve) UnmarshalCompressed(data []byte) (x, y *big.Int) {
	byteLen := (curve.BitSize + 7) / 8
	if len(data) != 1+byteLen {
		return nil, nil
	}
	if data[0] != 2 && data[0] != 3 { // compressed form
		return nil, nil
	}
	p := curve.P
	x = new(big.Int).SetBytes(data[1:])
	if x.Cmp(p) >= 0 {
		return nil, nil
	}
	y = curve.polynomial(x)
	y = y.ModSqrt(y, p)
	if y == nil {
		return nil, nil
	}
	if byte(y.Bit(0)) != data[0]&1 {
		y.Neg(y).Mod(y, p)
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}
	return
}

// GenerateKey returns a public/private key pair.
func (curve *Curve) GenerateKey() (priv []byte, x, y *big.Int, err error) {
	var k *big.Int
	if curve.BitSize < 9 {
		k, err = rand.Int(rand.Reader, curve.N)
		if err != nil {
			return
		}
		if k.Sign() == 0 {
			k.SetInt64(1)
		}
		priv = k.Bytes()
		x, y = curve.ScalarBaseMult(priv)
	} else {
		priv, x, y, err = elliptic.GenerateKey(curve, rand.Reader)
	}
	return
}

func panicIfNotOnCurve(curve *Curve, x, y *big.Int) {
	// (0, 0) is the point at infinity by convention. It's ok to operate on it,
	// although IsOnCurve is documented to return false for it. See Issue 37294.
	if x.Sign() == 0 && y.Sign() == 0 {
		return
	}

	if !curve.IsOnCurve(x, y) {
		panic("crypto/elliptic: attempted operation on invalid point")
	}
}
