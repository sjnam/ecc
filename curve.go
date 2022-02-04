package ecurve

// This code is based from https://github.com/ethereum/go-ethereum/blob/master/crypto/secp256k1/curve.go
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

const (
	// number of bits in big.Word
	wordBits = 32 << (uint64(^big.Word(0)) >> 63)
	// number of bytes in big.Word
	wordBytes = wordBits / 8
)

// readBits encodes the absolute value of bigint as big-endian bytes. Callers
// must ensure that buf has enough space. If buf is too short the result will
// be incomplete.
func readBits(bigint *big.Int, buf []byte) {
	i := len(buf)
	for _, d := range bigint.Bits() {
		for j := 0; j < wordBytes && i > 0; j++ {
			i--
			buf[i] = byte(d)
			d >>= 8
		}
	}
}

type EllipticCurve struct {
	P       *big.Int // the order of the underlying field
	A, B    *big.Int // the constant of the BitCurve equation
	Gx, Gy  *big.Int // (x,y) of the base point
	N       *big.Int // the order of the subgroup
	H       *big.Int // the cofactor of the subgroup
	BitSize int      // the size of the underlying field
}

func (ec *EllipticCurve) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:       ec.P,
		N:       new(big.Int).Mul(ec.N, ec.H),
		B:       ec.B,
		Gx:      ec.Gx,
		Gy:      ec.Gy,
		BitSize: ec.BitSize,
	}
}

func NewEllipticCurve(p, a, b *big.Int) *EllipticCurve {
	return &EllipticCurve{
		P: p,
		A: a,
		B: b,
	}
}

// IsOnCurve returns true if the given (x,y) lies on the Curve.
func (ec *EllipticCurve) IsOnCurve(x, y *big.Int) bool {
	// y² = x³ + ax + b
	y2 := new(big.Int).Mul(y, y) //y²
	y2.Mod(y2, ec.P)             //y²%P

	x3 := new(big.Int).Mul(x, x) //x²
	x3.Mul(x3, x)                //x³

	x3.Add(x3, new(big.Int).Mul(x, ec.A)) // x³+AX
	x3.Add(x3, ec.B)                      //x³+B
	x3.Mod(x3, ec.P)                      //(x³+B)%P

	return x3.Cmp(y2) == 0
}

// affineFromJacobian reverses the Jacobian transform. See the comment at the
// top of the file.
func (ec *EllipticCurve) affineFromJacobian(x, y, z *big.Int) (
	xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	zinv := new(big.Int).ModInverse(z, ec.P)
	zinvsq := new(big.Int).Mul(zinv, zinv)

	xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, ec.P)
	zinvsq.Mul(zinvsq, zinv)
	yOut = new(big.Int).Mul(y, zinvsq)
	yOut.Mod(yOut, ec.P)
	return
}

// Add returns the sum of (x1,y1) and (x2,y2)
func (ec *EllipticCurve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	// If one point is at infinity, return the other point.
	// Adding the point at infinity to any point will preserve the other point.
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return x2, y2
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return x1, y1
	}
	z := new(big.Int).SetInt64(1)
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		return ec.affineFromJacobian(ec.doubleJacobian(x1, y1, z))
	}
	return ec.affineFromJacobian(ec.addJacobian(x1, y1, z, x2, y2, z))
}

// addJacobian takes two points in Jacobian coordinates, (x1, y1, z1) and
// (x2, y2, z2) and returns their sum, also in Jacobian form.
func (ec *EllipticCurve) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (
	*big.Int, *big.Int, *big.Int) {
	// See http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-2007-bl
	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, ec.P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, ec.P)

	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, ec.P)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, ec.P)
	h := new(big.Int).Sub(u2, u1)
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
	r.Lsh(r, 1)
	v := new(big.Int).Mul(u1, i)

	x3 := new(big.Int).Set(r)
	x3.Mul(x3, x3)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, ec.P)

	y3 := new(big.Int).Set(r)
	v.Sub(v, x3)
	y3.Mul(y3, v)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y3.Sub(y3, s1)
	y3.Mod(y3, ec.P)

	z3 := new(big.Int).Add(z1, z2)
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
	z1 := new(big.Int).SetInt64(1)
	return ec.affineFromJacobian(ec.doubleJacobian(x1, y1, z1))
}

// doubleJacobian takes a point in Jacobian coordinates, (x, y, z), and
// returns its double, also in Jacobian form.
func (ec *EllipticCurve) doubleJacobian(x, y, z *big.Int) (
	*big.Int, *big.Int, *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl
	xx := new(big.Int).Mul(x, x)     //X1²
	yy := new(big.Int).Mul(y, y)     //Y1²
	yyyy := new(big.Int).Mul(yy, yy) //YY²
	zz := new(big.Int).Mul(z, z)     //Z1²

	s := new(big.Int).Add(x, yy) //X1+YY
	s.Mul(s, s)                  //(X1+YY)²
	s.Sub(s, xx)                 //(X1+B)²-XX
	if s.Sign() == -1 {
		s.Add(s, ec.P)
	}
	s.Sub(s, yyyy) //(X1+B)²-XX-YYYY
	if s.Sign() == -1 {
		s.Add(s, ec.P)
	}
	s.Mul(s, big.NewInt(2)) //2*((X1+B)²-XX-YYYY)

	m := new(big.Int).Mul(big.NewInt(3), xx)                   //3*XX
	m.Add(m, new(big.Int).Mul(ec.A, new(big.Int).Mul(zz, zz))) //3*XX+A*ZZ²

	t := new(big.Int).Mul(m, m)                   //M²
	t.Add(t, new(big.Int).Mul(s, big.NewInt(-2))) //M²-2*S
	if t.Sign() == -1 {
		t.Add(t, ec.P)
	}

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

	return x3, y3, z3
}

func (ec *EllipticCurve) ScalarMult(Bx, By *big.Int, k []byte) (
	*big.Int, *big.Int) {
	x, y := new(big.Int), new(big.Int)
	for _, b := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			x, y = ec.Double(x, y)
			if b&0x80 == 0x80 {
				x, y = ec.Add(x, y, Bx, By)
			}
			b <<= 1
		}
	}
	return x, y
}

// ScalarBaseMult returns k*G, where G is the base point of the group and k is
// an integer in big-endian form.
func (ec *EllipticCurve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return ec.ScalarMult(ec.Gx, ec.Gy, k)
}

// Marshal converts a point into the form specified in section 4.3.6 of ANSI
// X9.62.
func (ec *EllipticCurve) Marshal(x, y *big.Int) []byte {
	byteLen := (ec.BitSize + 7) >> 3
	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point flag
	readBits(x, ret[1:1+byteLen])
	readBits(y, ret[1+byteLen:])
	return ret
}

// Unmarshal converts a point, serialised by Marshal, into an x, y pair. On
// error, x = nil.
func (ec *EllipticCurve) Unmarshal(data []byte) (x, y *big.Int) {
	byteLen := (ec.BitSize + 7) >> 3
	if len(data) != 1+2*byteLen {
		return
	}
	if data[0] != 4 { // uncompressed form
		return
	}
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	return
}
