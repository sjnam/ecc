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
	"io"
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

// polynomial returns y² = x³ + ax + b.
func (curve *Curve) polynomial(x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	aX := new(big.Int).Mul(x, curve.A)

	x3.Add(x3, aX)
	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)
	return x3
}

// IsOnCurve reports whether the given (x,y) lies on the curve.
func (curve *Curve) IsOnCurve(x, y *big.Int) bool {
	P := curve.P
	if x.Sign() < 0 || x.Cmp(P) >= 0 ||
		y.Sign() < 0 || y.Cmp(P) >= 0 {
		return false
	}

	// y² = x³ + ax + b
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, P)

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
// top of the file. If the point is ∞ it returns 0, 0.
func (curve *Curve) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	zinv := new(big.Int).ModInverse(z, curve.P)
	zinvsq := new(big.Int).Mul(zinv, zinv)

	xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, curve.P)
	zinvsq.Mul(zinvsq, zinv)
	yOut = new(big.Int).Mul(y, zinvsq)
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
func (curve *Curve) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
	P := curve.P

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
	z1z1.Mod(z1z1, P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, P)

	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, P)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, P)
	h := new(big.Int).Sub(u2, u1)
	xEqual := h.Sign() == 0
	if h.Sign() == -1 {
		h.Add(h, P)
	}
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	j := new(big.Int).Mul(h, i)

	s1 := new(big.Int).Mul(y1, z2)
	s1.Mul(s1, z2z2)
	s1.Mod(s1, P)
	s2 := new(big.Int).Mul(y2, z1)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, P)
	r := new(big.Int).Sub(s2, s1)
	if r.Sign() == -1 {
		r.Add(r, P)
	}
	yEqual := r.Sign() == 0
	if xEqual && yEqual {
		return curve.doubleJacobian(x1, y1, z1)
	}
	r.Lsh(r, 1)
	v := new(big.Int).Mul(u1, i)

	x3.Set(r)
	x3.Mul(x3, x3)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, P)

	y3.Set(r)
	v.Sub(v, x3)
	y3.Mul(y3, v)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y3.Sub(y3, s1)
	y3.Mod(y3, P)

	z3.Add(z1, z2)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	z3.Mod(z3, P)

	return x3, y3, z3
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
	xx := new(big.Int).Mul(x, x)
	xx.Mod(xx, P)
	yy := new(big.Int).Mul(y, y)
	yy.Mod(yy, P)
	yyyy := new(big.Int).Mul(yy, yy)
	yyyy.Mod(yyyy, P)
	zz := new(big.Int).Mul(z, z)
	zz.Mod(zz, P)
	zzzz := new(big.Int).Mul(zz, zz)
	zzzz.Mod(zzzz, P)

	s := new(big.Int).Add(x, yy)
	s.Mul(s, s)
	s.Sub(s, xx)
	if s.Sign() == -1 {
		s.Add(s, P)
	}
	s.Sub(s, yyyy)
	if s.Sign() == -1 {
		s.Add(s, P)
	}
	s.Lsh(s, 1)
	s.Mod(s, P)

	m := new(big.Int).Lsh(xx, 1)
	m.Add(m, xx)
	m.Add(m, zzzz.Mul(curve.A, zzzz))
	m.Mod(m, P)

	t := new(big.Int).Mul(m, m)
	t.Sub(t, new(big.Int).Lsh(s, 1))
	if t.Sign() == -1 {
		t.Add(t, P)
	}
	t.Mod(t, P)

	x3 = t
	s.Sub(s, t)
	if s.Sign() == -1 {
		s.Add(s, P)
	}
	y3 = new(big.Int).Mul(m, s)
	y3.Sub(y3, yyyy.Lsh(yyyy, 3))
	if y3.Sign() == -1 {
		y3.Add(y3, P)
	}
	y3.Mod(y3, P)
	z3 = new(big.Int).Add(y, z)
	z3.Mul(z3, z3)
	z3.Sub(z3, yy)
	if z3.Sign() == -1 {
		z3.Add(z3, P)
	}
	z3.Sub(z3, zz)
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
	// return curve.Add(x1, y1, x2, y2)
	return curve.Add(x1, y1, x2, y2)
}

var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}

// GenerateKey returns a public/private key pair.
func (curve *Curve) GenerateKey() (priv []byte, x, y *big.Int, err error) {
	N := curve.N
	bitSize := N.BitLen()
	byteLen := (bitSize + 7) / 8
	if byteLen == 1 {
		byteLen = 2
	}
	priv = make([]byte, byteLen)

	for x == nil {
		_, err = io.ReadFull(rand.Reader, priv)
		if err != nil {
			return
		}
		// We have to mask off any excess bits in the case that the size of the
		// underlying field is not a whole number of bytes.
		priv[0] &= mask[bitSize%8]
		// This is because, in tests, rand will return all zeros, and we don't
		// want to get the point at infinity and loop forever.
		priv[1] ^= 0x42

		// If the scalar is out of range, sample another random number.
		if new(big.Int).SetBytes(priv).Cmp(N) >= 0 {
			continue
		}

		x, y = curve.ScalarBaseMult(priv)
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
	// y² = x³ + ax + b
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

func panicIfNotOnCurve(curve *Curve, x, y *big.Int) {
	// (0, 0) is the point at infinity by convention. It's ok to operate on it,
	// although IsOnCurve is documented to return false for it. See Issue 37294.
	if x.Sign() == 0 && y.Sign() == 0 {
		return
	}

	if !curve.IsOnCurve(x, y) {
		panic("ecc: attempted operation on invalid point")
	}
}
