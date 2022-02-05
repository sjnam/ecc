package ecc

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"math/big"
	"testing"
)

var secp256k1 *Curve

func init() {
	// secp256k1 curve
	p, _ := new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 0)
	a, b := big.NewInt(0), big.NewInt(7)
	gx, _ := new(big.Int).SetString("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 0)
	gy, _ := new(big.Int).SetString("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 0)
	n, _ := new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0)
	h := big.NewInt(1)

	secp256k1 = &Curve{
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

func TestECDH(t *testing.T) {
	aliPriv, aliPubX, aliPubY, _ := elliptic.GenerateKey(secp256k1, rand.Reader)
	bobPriv, bobPubX, bobPubY, _ := elliptic.GenerateKey(secp256k1, rand.Reader)

	ssx1, ssy1 := secp256k1.ScalarMult(aliPubX, aliPubY, bobPriv)
	ssx2, ssy2 := secp256k1.ScalarMult(bobPubX, bobPubY, aliPriv)

	aliSharedSecret := elliptic.Marshal(secp256k1, ssx1, ssy1)
	bobSharedSecret := elliptic.Marshal(secp256k1, ssx2, ssy2)

	if !bytes.Equal(aliSharedSecret, bobSharedSecret) {
		t.Errorf("sharedSecret1: 0x%x\nsharedSecret2: 0x%x",
			aliSharedSecret, bobSharedSecret)
	}
}

func TestECDSA(t *testing.T) {
	priv, Hx, Hy, _ := elliptic.GenerateKey(secp256k1, rand.Reader)
	h := sha512.Sum512([]byte("Hello, world."))

	r, s := Sign(priv, secp256k1, h[:])
	if !Verify(Hx, Hy, secp256k1, h[:], r, s) {
		t.Error("invalid signature")
	}
}
