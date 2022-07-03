package ecc

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"math/big"
	"testing"
)

var secp256k1, p224, p256, p521 *EllipticCurve

func init() {
	secp256k1 = new(EllipticCurve)
	secp256k1.Name = "secp256k1"
	secp256k1.P, _ = new(big.Int).SetString("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 0)
	secp256k1.A = big.NewInt(0)
	secp256k1.B = big.NewInt(7)
	secp256k1.Gx, _ = new(big.Int).SetString("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 0)
	secp256k1.Gy, _ = new(big.Int).SetString("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 0)
	secp256k1.N, _ = new(big.Int).SetString("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 0)
	secp256k1.H = big.NewInt(1)
	secp256k1.BitSize = 256

	// See FIPS 186-3, section D.2.2
	p224 = new(EllipticCurve)
	p224.Name = "p224"
	p224.P, _ = new(big.Int).SetString("0xffffffffffffffffffffffffffffffff000000000000000000000001", 0)
	p224.A = big.NewInt(-3)
	p224.B, _ = new(big.Int).SetString("0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 0)
	p224.Gx, _ = new(big.Int).SetString("0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", 0)
	p224.Gy, _ = new(big.Int).SetString("0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 0)
	p224.N, _ = new(big.Int).SetString("0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", 0)
	p224.H = big.NewInt(1)
	p224.BitSize = 224

	// See FIPS 186-3, section D.2.3
	p256 = new(EllipticCurve)
	p256.Name = "p256"
	p256.P, _ = new(big.Int).SetString("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 0)
	p256.A = big.NewInt(-3)
	p256.B, _ = new(big.Int).SetString("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 0)
	p256.Gx, _ = new(big.Int).SetString("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 0)
	p256.Gy, _ = new(big.Int).SetString("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 0)
	p256.N, _ = new(big.Int).SetString("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 0)
	p256.H = big.NewInt(1)
	p256.BitSize = 256

	// See FIPS 186-3, section D.2.5
	p521 = new(EllipticCurve)
	p521.Name = "p521"
	p521.P, _ = new(big.Int).SetString("0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 0)
	p521.A = big.NewInt(-3)
	p521.B, _ = new(big.Int).SetString("0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 0)
	p521.Gx, _ = new(big.Int).SetString("0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 0)
	p521.Gy, _ = new(big.Int).SetString("0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 0)
	p521.N, _ = new(big.Int).SetString("0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 0)
	p521.H = big.NewInt(1)
	p521.BitSize = 521
}

func TestECDH(t *testing.T) {
	curves := []*EllipticCurve{secp256k1, p224, p256, p521}
	for _, c := range curves {
		aPriv, aPubX, aPubY, _ := elliptic.GenerateKey(c, rand.Reader)
		bPriv, bPubX, bPubY, _ := elliptic.GenerateKey(c, rand.Reader)

		// encryption with ECDH
		aSharedSecret := c.Encrypt(aPriv, bPubX, bPubY)
		bSharedSecret := c.Encrypt(bPriv, aPubX, aPubY)
		if !bytes.Equal(aSharedSecret, bSharedSecret) {
			t.Errorf("[%s] sharedSecret1: 0x%x\nsharedSecret2: 0x%x",
				c.Name, aSharedSecret, bSharedSecret)
		}
	}
}

func TestECDSA(t *testing.T) {
	curves := []*EllipticCurve{secp256k1, p224, p256, p521}
	for _, c := range curves {
		priv, Hx, Hy, _ := elliptic.GenerateKey(c, rand.Reader)
		h := sha512.Sum512([]byte("Hello, world."))
		r, s := c.Sign(priv, h[:])
		if !c.Verify(Hx, Hy, h[:], r, s) {
			t.Errorf("[%s] invalid signature", c.Name)
		}
	}
}
