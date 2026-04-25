package ecc

import (
	"crypto/rand"
	"io"
	"math/big"
)

// The elliptic curve E is in Weierstrass form y^2=poly(x)=x^3+Ax+B
// This package operates, internally, on Jacobian coordinates. For a given
// (x, y) position on the curve, the Jacobian coordinates are (x1, y1, z1)
// where x = x1/z1² and y = y1/z1³. The greatest speedups come when the whole
// calculation can be performed within the transform (as in ScalarMult and
// ScalarBaseMult). But even for Add and Double, it's faster to apply and
// reverse the transform than to operate in affine coordinates.

// Curve represents a short-form Weierstrass curve. (y² = x³ + ax + b)
// The behavior of Add, Double, and ScalarMult when the input is not a Point on
// the curve is undefined.
//
// Note that the conventional Point at infinity (0, 0) is not considered on the
// curve, although it can be returned by Add, Double, ScalarMult, or
// ScalarBaseMult (but not the Unmarshal or UnmarshalCompressed functions).
type Curve struct {
	P       *big.Int       // the order of the underlying field
	A       *big.Int       // the constant of the Curve equation
	B       *big.Int       // the constant of the Curve equation
	Gx, Gy  *big.Int       // (x,y) of the base Point
	N       *big.Int       // the order of the base Point
	H       *big.Int       // the cofactor of the subgroup
	BitSize int            // the size of the underlying field
	Name    string         // the canonical name of the curve
	dpCache map[int64]Poly // division polynomial
	bmt     *baseMultTable // fixed-base comb table for ScalarBaseMult
}

// baseMultTable holds precomputed affine multiples of G arranged into
// fixed-width windows, used by ScalarBaseMult. rows[i][d-1] equals
// d * 2^(w*i) * G for d in 1..(2^w - 1).
type baseMultTable struct {
	w    int
	nWin int
	rows [][]basePoint
}

type basePoint struct{ x, y *big.Int }

// evaluatePolynomial returns y² = x³ + ax + b.
func (c *Curve) evaluatePolynomial(x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, new(big.Int).Mul(x, c.A))
	x3.Add(x3, c.B)
	x3.Mod(x3, c.P)
	return x3
}

// IsOnCurve reports whether the given (x,y) lies on the curve.
func (c *Curve) IsOnCurve(x, y *big.Int) bool {
	P := c.P
	if x.Sign() < 0 || x.Cmp(P) >= 0 || y.Sign() < 0 || y.Cmp(P) >= 0 {
		return false
	}

	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, P)

	return c.evaluatePolynomial(x).Cmp(y2) == 0
}

// Neg returns the inverse of Point (x, y), which is the Point (x, -y)
func (c *Curve) Neg(x, y *big.Int) (*big.Int, *big.Int) {
	panicIfNotOnCurve(c, x, y)

	ny := new(big.Int).Neg(y)
	ny.Mod(ny, c.P)

	return new(big.Int).Set(x), ny
}

// zForAffine returns a Jacobian Z value for the affine Point (x, y). If x and
// y are zero, it assumes that they represent the Point at infinity because (0,
// 0) is not on any of the curves handled here.
func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}

// affineFromJacobian reverses the Jacobian transform. See the comment at the
// top of the file. If the Point is ∞ it returns 0, 0.
func (c *Curve) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}
	P := c.P
	zinv := new(big.Int).ModInverse(z, P)
	zinvsq := new(big.Int).Mul(zinv, zinv)

	xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, P)
	zinvsq.Mul(zinvsq, zinv)
	yOut = new(big.Int).Mul(y, zinvsq)
	yOut.Mod(yOut, P)
	return
}

// Add returns the sum of (x1,y1) and (x2,y2)
func (c *Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	panicIfNotOnCurve(c, x1, y1)
	panicIfNotOnCurve(c, x2, y2)

	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	return c.affineFromJacobian(c.addJacobian(x1, y1, z1, x2, y2, z2))
}

// addJacobian takes two points in Jacobian coordinates, (x1, y1, z1) and
// (x2, y2, z2) and returns their sum, also in Jacobian form.
func (c *Curve) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (x3, y3, z3 *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
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

	P := c.P
	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, P)

	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, P)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, P)
	h := new(big.Int).Sub(u2, u1)
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
	if h.Sign() == 0 && r.Sign() == 0 {
		return c.doubleJacobian(x1, y1, z1)
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

	return
}

// addJacobianMixed adds (x1,y1,z1) and (x2,y2,1). The caller must guarantee
// that the second operand has z=1 (i.e., is in affine form). Saves the
// z2*z2, y1*z2*z2², and z2-related multiplications versus addJacobian.
func (c *Curve) addJacobianMixed(x1, y1, z1, x2, y2 *big.Int) (x3, y3, z3 *big.Int) {
	// EFD: g1p/auto-shortw-jacobian-3.html#addition-madd-2007-bl
	x3, y3, z3 = new(big.Int), new(big.Int), new(big.Int)
	if z1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		z3.SetInt64(1)
		return
	}
	P := c.P

	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, P)

	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, P)

	s2 := new(big.Int).Mul(y2, z1)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, P)

	h := new(big.Int).Sub(u2, x1)
	if h.Sign() == -1 {
		h.Add(h, P)
	}
	hh := new(big.Int).Mul(h, h)
	hh.Mod(hh, P)

	i := new(big.Int).Lsh(hh, 2)
	j := new(big.Int).Mul(h, i)
	j.Mod(j, P)

	r := new(big.Int).Sub(s2, y1)
	if r.Sign() == -1 {
		r.Add(r, P)
	}
	if h.Sign() == 0 && r.Sign() == 0 {
		return c.doubleJacobian(x1, y1, z1)
	}
	r.Lsh(r, 1)

	v := new(big.Int).Mul(x1, i)
	v.Mod(v, P)

	x3.Mul(r, r)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, P)

	vmx := new(big.Int).Sub(v, x3)
	y3.Mul(r, vmx)
	twoY1J := new(big.Int).Mul(y1, j)
	twoY1J.Lsh(twoY1J, 1)
	y3.Sub(y3, twoY1J)
	y3.Mod(y3, P)

	z3.Add(z1, h)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	if z3.Sign() == -1 {
		z3.Add(z3, P)
	}
	z3.Sub(z3, hh)
	if z3.Sign() == -1 {
		z3.Add(z3, P)
	}
	z3.Mod(z3, P)

	return
}

// doubleAffine and addAffine are internal helpers that skip
// panicIfNotOnCurve. They are used by precomputation paths where inputs
// are derived from c.Gx, c.Gy and are therefore on the curve by construction.
func (c *Curve) doubleAffine(x, y *big.Int) (*big.Int, *big.Int) {
	z := zForAffine(x, y)
	return c.affineFromJacobian(c.doubleJacobian(x, y, z))
}

func (c *Curve) addAffine(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	return c.affineFromJacobian(c.addJacobian(x1, y1, z1, x2, y2, z2))
}

// Double returns 2*(x,y)
func (c *Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	panicIfNotOnCurve(c, x1, y1)

	z1 := zForAffine(x1, y1)
	return c.affineFromJacobian(c.doubleJacobian(x1, y1, z1))
}

// doubleJacobian takes a Point in Jacobian coordinates, (x, y, z), and
// returns its double, also in Jacobian form.
func (c *Curve) doubleJacobian(x, y, z *big.Int) (x3, y3, z3 *big.Int) {
	// See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl
	P := c.P
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
	m.Add(m, zzzz.Mul(c.A, zzzz))
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

// ScalarMult returns k*(Bx,By). The scalar k is treated as its absolute value
// (matching the legacy behavior of iterating k.Bytes()).
func (c *Curve) ScalarMult(Bx, By, k *big.Int) (*big.Int, *big.Int) {
	panicIfNotOnCurve(c, Bx, By)

	if k.Sign() == 0 || (Bx.Sign() == 0 && By.Sign() == 0) {
		return new(big.Int), new(big.Int)
	}

	const w = 5
	naf := computeWNAF(k, w)
	if len(naf) == 0 {
		return new(big.Int), new(big.Int)
	}

	// Precompute odd Jacobian multiples of P: pre[d] = (2d+1)*P for d in [0, nPre).
	nPre := 1 << (w - 2)
	preX := make([]*big.Int, nPre)
	preY := make([]*big.Int, nPre)
	preZ := make([]*big.Int, nPre)
	preX[0] = new(big.Int).Set(Bx)
	preY[0] = new(big.Int).Set(By)
	preZ[0] = big.NewInt(1)
	if nPre > 1 {
		twoX, twoY, twoZ := c.doubleJacobian(Bx, By, preZ[0])
		for i := 1; i < nPre; i++ {
			preX[i], preY[i], preZ[i] = c.addJacobian(
				preX[i-1], preY[i-1], preZ[i-1], twoX, twoY, twoZ)
		}
	}

	// Iterate the wNAF digits from MSB. The first non-zero digit short-circuits
	// the leading run of doublings on (0,0,0).
	x, y, z := new(big.Int), new(big.Int), new(big.Int)
	started := false
	for i := len(naf) - 1; i >= 0; i-- {
		if started {
			x, y, z = c.doubleJacobian(x, y, z)
		}
		d := naf[i]
		if d == 0 {
			continue
		}
		idx := int(d) / 2
		if d < 0 {
			idx = int(-d) / 2
		}
		if !started {
			x.Set(preX[idx])
			y.Set(preY[idx])
			z.Set(preZ[idx])
			if d < 0 {
				y.Sub(c.P, y)
			}
			started = true
			continue
		}
		if d > 0 {
			x, y, z = c.addJacobian(x, y, z, preX[idx], preY[idx], preZ[idx])
		} else {
			ny := new(big.Int).Sub(c.P, preY[idx])
			x, y, z = c.addJacobian(x, y, z, preX[idx], ny, preZ[idx])
		}
	}

	return c.affineFromJacobian(x, y, z)
}

// computeWNAF returns the width-w non-adjacent form of |k|, LSB-first.
// Each digit is 0 or an odd integer in [-(2^(w-1)-1), 2^(w-1)-1].
func computeWNAF(k *big.Int, w int) []int8 {
	if k.Sign() == 0 {
		return nil
	}
	twoW := int64(1) << w
	halfW := int64(1) << (w - 1)
	kt := new(big.Int).Abs(k)
	naf := make([]int8, 0, kt.BitLen()+1)
	for kt.Sign() > 0 {
		var d int8
		if kt.Bit(0) == 1 {
			var v int64
			for i := 0; i < w; i++ {
				v |= int64(kt.Bit(i)) << uint(i)
			}
			if v >= halfW {
				v -= twoW
			}
			d = int8(v)
			if v >= 0 {
				kt.Sub(kt, big.NewInt(v))
			} else {
				kt.Add(kt, big.NewInt(-v))
			}
		}
		naf = append(naf, d)
		kt.Rsh(kt, 1)
	}
	return naf
}

// ScalarBaseMult returns k*G, where G is the base Point of the group.
// Uses a lazily-built fixed-base comb table when c.N and c.BitSize are set;
// falls back to ScalarMult otherwise.
func (c *Curve) ScalarBaseMult(k *big.Int) (*big.Int, *big.Int) {
	if c.N == nil || c.N.Sign() == 0 || c.BitSize <= 0 {
		return c.ScalarMult(c.Gx, c.Gy, k)
	}

	kk := k
	if kk.Sign() < 0 || kk.Cmp(c.N) >= 0 {
		kk = new(big.Int).Mod(kk, c.N)
	}
	if kk.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	if c.bmt == nil {
		c.bmt = c.precomputeBaseMultTable(4)
	}
	bmt := c.bmt
	w := bmt.w

	x, y, z := new(big.Int), new(big.Int), new(big.Int)
	for i := 0; i < bmt.nWin; i++ {
		var v int
		for j := 0; j < w; j++ {
			v |= int(kk.Bit(w*i+j)) << j
		}
		if v == 0 {
			continue
		}
		p := bmt.rows[i][v-1]
		// Defensive: skip if a precomputed multiple lands on infinity (only
		// possible for pathologically small N relative to BitSize).
		if p.x.Sign() == 0 && p.y.Sign() == 0 {
			continue
		}
		x, y, z = c.addJacobianMixed(x, y, z, p.x, p.y)
	}

	return c.affineFromJacobian(x, y, z)
}

// precomputeBaseMultTable builds a window-w fixed-base comb table for c.Gx,c.Gy.
// rows[i][d-1] = d * 2^(w*i) * G in affine form, for d in 1..(2^w-1).
func (c *Curve) precomputeBaseMultTable(w int) *baseMultTable {
	nEntries := (1 << w) - 1
	nWin := (c.BitSize + w - 1) / w
	rows := make([][]basePoint, nWin)

	bx, by := new(big.Int).Set(c.Gx), new(big.Int).Set(c.Gy)
	for i := 0; i < nWin; i++ {
		rows[i] = make([]basePoint, nEntries)
		rows[i][0] = basePoint{new(big.Int).Set(bx), new(big.Int).Set(by)}
		for d := 2; d <= nEntries; d++ {
			var nx, ny *big.Int
			if d == 2 {
				nx, ny = c.doubleAffine(rows[i][0].x, rows[i][0].y)
			} else {
				nx, ny = c.addAffine(rows[i][d-2].x, rows[i][d-2].y, bx, by)
			}
			rows[i][d-1] = basePoint{nx, ny}
		}
		if i < nWin-1 {
			for j := 0; j < w; j++ {
				bx, by = c.doubleAffine(bx, by)
			}
		}
	}
	return &baseMultTable{w: w, nWin: nWin, rows: rows}
}

// CombinedMult calculates P=mG+nQ, where G is the generator and Q=(x,y,z).
func (c *Curve) CombinedMult(xQ, yQ, m, n *big.Int) (xP, yP *big.Int) {
	x1, y1 := c.ScalarBaseMult(m)
	x2, y2 := c.ScalarMult(xQ, yQ, n)
	return c.Add(x1, y1, x2, y2)
}

// GenerateKey returns a public/private key pair.
func (c *Curve) GenerateKey(rnd io.Reader) (priv, x, y *big.Int, err error) {
	nMinus1 := new(big.Int).Set(c.N)
	nMinus1.Sub(nMinus1, big.NewInt(1))
	for x == nil {
		if priv, err = rand.Int(rnd, nMinus1); err != nil {
			return
		}
		priv.Add(priv, big.NewInt(1))
		x, y = c.ScalarBaseMult(priv)
	}
	return
}

// Marshal converts a Point on the curve into the uncompressed form specified in
// SEC 1, Version 2.0, Section 2.3.3. If the Point is not on the curve (or is
// the conventional Point at infinity), the behavior is undefined.
func (c *Curve) Marshal(x, y *big.Int) []byte {
	byteLen := (c.BitSize + 7) / 8

	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed Point

	x.FillBytes(ret[1 : 1+byteLen])
	y.FillBytes(ret[1+byteLen : 1+2*byteLen])

	return ret
}

// MarshalCompressed converts a Point on the curve into the compressed form
// specified in SEC 1, Version 2.0, Section 2.3.3. If the Point is not on the
// curve (or is the conventional Point at infinity), the behavior is undefined.
func (c *Curve) MarshalCompressed(x, y *big.Int) []byte {
	byteLen := (c.BitSize + 7) / 8
	compressed := make([]byte, 1+byteLen)
	compressed[0] = byte(y.Bit(0)) | 2
	x.FillBytes(compressed[1:])
	return compressed
}

// Unmarshal converts a Point, serialized by Marshal, into an x, y pair. It is
// an error if the Point is not in uncompressed form, is not on the curve, or is
// the Point at infinity. On error, x = nil.
func (c *Curve) Unmarshal(data []byte) (x, y *big.Int) {
	byteLen := (c.BitSize + 7) / 8
	if len(data) != 1+2*byteLen {
		return nil, nil
	}
	if data[0] != 4 { // uncompressed form
		return nil, nil
	}
	p := c.P
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return nil, nil
	}
	if !c.IsOnCurve(x, y) {
		return nil, nil
	}
	return
}

// UnmarshalCompressed converts a Point, serialized by MarshalCompressed, into
// an x, y pair. It is an error if the Point is not in compressed form, is not
// on the curve, or is the Point at infinity. On error, x = nil.
func (c *Curve) UnmarshalCompressed(data []byte) (x, y *big.Int) {
	byteLen := (c.BitSize + 7) / 8
	if len(data) != 1+byteLen {
		return nil, nil
	}
	if data[0] != 2 && data[0] != 3 { // compressed form
		return nil, nil
	}
	p := c.P
	x = new(big.Int).SetBytes(data[1:])
	if x.Cmp(p) >= 0 {
		return nil, nil
	}
	// y² = x³ + ax + b
	y = c.evaluatePolynomial(x)
	y = y.ModSqrt(y, p)
	if y == nil {
		return nil, nil
	}
	if byte(y.Bit(0)) != data[0]&1 {
		y.Neg(y).Mod(y, p)
	}
	if !c.IsOnCurve(x, y) {
		return nil, nil
	}
	return
}

func panicIfNotOnCurve(curve *Curve, x, y *big.Int) {
	// (0, 0) is the Point at infinity by convention. It's ok to operate on it,
	// although IsOnCurve is documented to return false for it.
	if x.Sign() == 0 && y.Sign() == 0 {
		return
	}

	if !curve.IsOnCurve(x, y) {
		panic("ecc: attempted operation on invalid Point")
	}
}
