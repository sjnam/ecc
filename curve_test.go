package ecc

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"
)

func testCurve() *ECurve {
	curve := new(ECurve)
	curve.P = big.NewInt(97)
	curve.A = big.NewInt(2)
	curve.B = big.NewInt(3)
	return curve
}

func TestAdd(t *testing.T) {
	curve := testCurve()

	cases := []struct {
		px, py, qx, qy int64
		wantX, wantY   *big.Int
	}{
		{
			17, 10, 95, 31,
			big.NewInt(1), big.NewInt(54),
		},
		{
			17, 10, 1, 43,
			big.NewInt(95), big.NewInt(66),
		},
	}

	for _, c := range cases {
		rx, ry := curve.Add(big.NewInt(c.px), big.NewInt(c.py),
			big.NewInt(c.qx), big.NewInt(c.qy))
		if c.wantX.Cmp(rx) != 0 || c.wantY.Cmp(ry) != 0 {
			t.Errorf("Add() == (%v,%v), want (%v, %v)", rx, ry, c.wantX, c.wantY)
		}
	}
}

func TestDouble(t *testing.T) {
	curve := testCurve()

	cases := []struct {
		px, py       int64
		wantX, wantY *big.Int
	}{
		{
			3, 6,
			big.NewInt(80), big.NewInt(10),
		},
		{
			80, 10,
			big.NewInt(3), big.NewInt(91),
		},
		{
			3, 91,
			big.NewInt(80), big.NewInt(87),
		},
	}

	for _, c := range cases {
		rx, ry := curve.Double(big.NewInt(c.px), big.NewInt(c.py))
		if c.wantX.Cmp(rx) != 0 || c.wantY.Cmp(ry) != 0 {
			t.Errorf("Double() == (%v,%v), want (%v, %v)",
				rx, ry, c.wantX, c.wantY)
		}
	}
}

func TestScalarMult(t *testing.T) {
	curve := testCurve()

	cases := []struct {
		px, py, k    int64
		wantX, wantY *big.Int
	}{
		{
			3, 6, 1,
			big.NewInt(3), big.NewInt(6),
		},
		{
			3, 6, 2,
			big.NewInt(80), big.NewInt(10),
		},
		{
			3, 6, 3,
			big.NewInt(80), big.NewInt(87),
		},
		{
			3, 6, 4,
			big.NewInt(3), big.NewInt(91),
		},
		{
			3, 6, 5,
			big.NewInt(0), big.NewInt(0),
		},
		{
			3, 6, 6,
			big.NewInt(3), big.NewInt(6),
		},
	}

	for _, c := range cases {
		rx, ry := curve.ScalarMult(big.NewInt(c.px), big.NewInt(c.py),
			big.NewInt(c.k).Bytes())
		if c.wantX.Cmp(rx) != 0 || c.wantY.Cmp(ry) != 0 {
			t.Errorf("ScalarMult() == (%v,%v), want (%v, %v)",
				rx, ry, c.wantX, c.wantY)
		}
	}
}

func TestScalarMultiplication(t *testing.T) {
	curve := new(ECurve)
	curve.P = big.NewInt(7919)
	curve.A = big.NewInt(1001)
	curve.B = big.NewInt(75)
	curve.N = big.NewInt(7889)

	xx, yy := new(big.Int), new(big.Int)
	xp, yp := big.NewInt(4023), big.NewInt(6036)

	ord := uint64(1)
	for ; ; ord++ {
		xx, yy = curve.Add(xx, yy, xp, yp)
		if xx.Sign() == 0 && yy.Sign() == 0 {
			if ord != curve.N.Uint64() {
				t.Fatal("error")
			}
			break
		}
	}

	buf := new(bytes.Buffer)
	var num uint64 = 6837283728876
	_ = binary.Write(buf, binary.BigEndian, num)
	x1, y1 := curve.ScalarMult(xp, yp, buf.Bytes())

	buf.Reset()
	num = num % ord
	_ = binary.Write(buf, binary.BigEndian, num)
	x2, y2 := curve.ScalarMult(xp, yp, buf.Bytes())

	if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
		t.Fatal("error")
	}
}
