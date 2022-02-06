package ecc

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"math/big"
	"testing"
)

var secp256k1 *ECurve

func init() {
	P, _ := new(big.Int).SetString("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 0)
	Gx, _ := new(big.Int).SetString("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 0)
	Gy, _ := new(big.Int).SetString("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 0)
	N, _ := new(big.Int).SetString("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 0)

	secp256k1 = &ECurve{
		P:       P,
		A:       big.NewInt(0),
		B:       big.NewInt(7),
		Gx:      Gx,
		Gy:      Gy,
		N:       N,
		H:       big.NewInt(1),
		BitSize: 256,
	}
}

func TestECDH(t *testing.T) {
	aPriv, aPubX, aPubY, _ := elliptic.GenerateKey(secp256k1, rand.Reader)
	bPriv, bPubX, bPubY, _ := elliptic.GenerateKey(secp256k1, rand.Reader)

	ssx1, ssy1 := secp256k1.ScalarMult(aPubX, aPubY, bPriv)
	ssx2, ssy2 := secp256k1.ScalarMult(bPubX, bPubY, aPriv)

	aSharedSecret := elliptic.Marshal(secp256k1, ssx1, ssy1)
	bSharedSecret := elliptic.Marshal(secp256k1, ssx2, ssy2)

	if !bytes.Equal(aSharedSecret, bSharedSecret) {
		t.Errorf("sharedSecret1: 0x%x\nsharedSecret2: 0x%x",
			aSharedSecret, bSharedSecret)
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
