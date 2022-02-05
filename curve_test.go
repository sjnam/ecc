package ecc

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

var simple, secp256k1 *EllipticCurve

func init() {
	// simple curve
	simple = &EllipticCurve{
		P: big.NewInt(97),
		A: big.NewInt(2),
		B: big.NewInt(3),
	}

	// secp256k1 curve
	p, _ := new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 0)
	a, b := big.NewInt(0), big.NewInt(7)
	gx, _ := new(big.Int).SetString("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 0)
	gy, _ := new(big.Int).SetString("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 0)
	n, _ := new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0)
	h := big.NewInt(1)

	secp256k1 = &EllipticCurve{
		P:       p,
		A:       a,
		B:       b,
		Gx:      gx,
		Gy:      gy,
		N:       n,
		H:       h,
		BitSize: 256,
	}
}

func TestAdd(t *testing.T) {
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
		rx, ry := simple.Add(big.NewInt(c.px), big.NewInt(c.py),
			big.NewInt(c.qx), big.NewInt(c.qy))
		if c.wantX.Cmp(rx) != 0 || c.wantY.Cmp(ry) != 0 {
			t.Errorf("Add() == (%v,%v), want (%v, %v)", rx, ry, c.wantX, c.wantY)
		}
	}
}

func TestDouble(t *testing.T) {
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
		rx, ry := simple.Double(big.NewInt(c.px), big.NewInt(c.py))
		if c.wantX.Cmp(rx) != 0 || c.wantY.Cmp(ry) != 0 {
			t.Errorf("Double() == (%v,%v), want (%v, %v)",
				rx, ry, c.wantX, c.wantY)
		}
	}
}

func TestScalarMult(t *testing.T) {
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
		rx, ry := simple.ScalarMult(big.NewInt(c.px), big.NewInt(c.py),
			big.NewInt(c.k).Bytes())
		if c.wantX.Cmp(rx) != 0 || c.wantY.Cmp(ry) != 0 {
			t.Errorf("ScalarMult() == (%v,%v), want (%v, %v)",
				rx, ry, c.wantX, c.wantY)
		}
	}
}

func TestMarshalCompressed(t *testing.T) {
	_, pubX, pubY, err := elliptic.GenerateKey(secp256k1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialized := secp256k1.MarshalCompressed(pubX, pubY)
	xx, yy := secp256k1.UnmarshalCompressed(serialized)
	if xx == nil {
		t.Fatal("fail to unmarshal")
	}

	if pubX.Cmp(xx) != 0 || pubY.Cmp(yy) != 0 {
		t.Error("unmarshalCompressed returned different values")
	}
}

func TestSECP256k1(t *testing.T) {
	cases := []struct {
		priv       string
		pubX, pubY string
	}{
		{
			"0xe32868331fa8ef0138de0de85478346aec5e3912b6029ae71691c384237a3eeb",
			"0x86b1aa5120f079594348c67647679e7ac4c365b2c01330db782b0ba611c1d677",
			"0x5f4376a23eed633657a90f385ba21068ed7e29859a7fab09e953cc5b3e89beba",
		},
		{
			"0xcef147652aa90162e1fff9cf07f2605ea05529ca215a04350a98ecc24aa34342",
			"0x4034127647bb7fdab7f1526c7d10be8b28174e2bba35b06ffd8a26fc2c20134a",
			"0x9e773199edc1ea792b150270ea3317689286c9fe239dd5b9c5cfd9e81b4b632",
		},
	}

	for _, c := range cases {
		priv, _ := new(big.Int).SetString(c.priv, 0)
		pubX, pubY := secp256k1.ScalarBaseMult(priv.Bytes())
		gotX := fmt.Sprintf("0x%x", pubX)
		gotY := fmt.Sprintf("0x%x", pubY)
		if gotX != c.pubX || gotY != c.pubY {
			t.Errorf("want: (%s,%s)\ngot: (%s,%s)", c.pubX, c.pubY, gotX, gotY)
		}
	}
}
