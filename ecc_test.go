package ecc

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"math/big"
	"testing"
)

var curves []elliptic.Curve
var secp256k1, p224, p256, p521 ECurve

func init() {
	secp256k1.CurveParams = &elliptic.CurveParams{Name: "secp256k1"}
	secp256k1.P, _ = new(big.Int).SetString("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 0)
	secp256k1.Gx, _ = new(big.Int).SetString("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 0)
	secp256k1.Gy, _ = new(big.Int).SetString("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 0)
	secp256k1.N, _ = new(big.Int).SetString("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 0)
	secp256k1.A = big.NewInt(0)
	secp256k1.B = big.NewInt(7)
	secp256k1.H = big.NewInt(1)
	secp256k1.BitSize = 256
	secp256k1.CurveParams.N = secp256k1.N.Set(secp256k1.N)

	// See FIPS 186-3, section D.2.5
	p521.CurveParams = &elliptic.CurveParams{Name: "P-521"}
	p521.P, _ = new(big.Int).SetString("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151", 10)
	p521.N, _ = new(big.Int).SetString("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449", 10)
	p521.B, _ = new(big.Int).SetString("051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16)
	p521.Gx, _ = new(big.Int).SetString("c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16)
	p521.Gy, _ = new(big.Int).SetString("11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16)
	p521.A = big.NewInt(-3)
	p521.H = big.NewInt(1)
	p521.BitSize = 521
	p521.CurveParams.N = p521.N.Set(p521.N)

	// See FIPS 186-3, section D.2.2
	p224.CurveParams = &elliptic.CurveParams{Name: "P-224"}
	p224.P, _ = new(big.Int).SetString("26959946667150639794667015087019630673557916260026308143510066298881", 10)
	p224.N, _ = new(big.Int).SetString("26959946667150639794667015087019625940457807714424391721682722368061", 10)
	p224.B, _ = new(big.Int).SetString("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 16)
	p224.Gx, _ = new(big.Int).SetString("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", 16)
	p224.Gy, _ = new(big.Int).SetString("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16)
	p224.A = big.NewInt(-3)
	p224.H = big.NewInt(1)
	p224.BitSize = 224
	p224.CurveParams.N = p224.N.Set(p224.N)

	// See FIPS 186-3, section D.2.3
	p256.CurveParams = &elliptic.CurveParams{Name: "P-256"}
	p256.P, _ = new(big.Int).SetString("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10)
	p256.N, _ = new(big.Int).SetString("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10)
	p256.B, _ = new(big.Int).SetString("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
	p256.Gx, _ = new(big.Int).SetString("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
	p256.Gy, _ = new(big.Int).SetString("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
	p256.A = big.NewInt(-3)
	p256.H = big.NewInt(1)
	p256.BitSize = 256
	p256.CurveParams.N = p256.N.Set(p256.N)

	curves = []elliptic.Curve{secp256k1, p521, p224, p256}
}

func TestECDH(t *testing.T) {
	for _, c := range curves {
		aPriv, aPubX, aPubY, _ := elliptic.GenerateKey(c, rand.Reader)
		bPriv, bPubX, bPubY, _ := elliptic.GenerateKey(c, rand.Reader)
		ssx1, ssy1 := c.ScalarMult(aPubX, aPubY, bPriv)
		ssx2, ssy2 := c.ScalarMult(bPubX, bPubY, aPriv)
		aSharedSecret := elliptic.Marshal(c, ssx1, ssy1)
		bSharedSecret := elliptic.Marshal(c, ssx2, ssy2)
		if !bytes.Equal(aSharedSecret, bSharedSecret) {
			t.Errorf("[%s] sharedSecret1: 0x%x\nsharedSecret2: 0x%x",
				c.Params().Name, aSharedSecret, bSharedSecret)
		}
	}
}

func TestECDSA(t *testing.T) {
	for _, c := range curves {
		priv, Hx, Hy, _ := elliptic.GenerateKey(c, rand.Reader)
		h := sha512.Sum512([]byte("Hello, world."))
		r, s := Sign(priv, c, h[:])
		if !Verify(Hx, Hy, c, h[:], r, s) {
			t.Errorf("[%s] invalid signature", c.Params().Name)
		}
	}
}
