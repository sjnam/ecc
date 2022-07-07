package ecc

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"testing"
)

func TestECDH(t *testing.T) {
	curves := []*EllipticCurve{s256, p224, p256, p521}
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
	curves := []*EllipticCurve{s256, p224, p256, p521}
	for _, c := range curves {
		priv, Hx, Hy, _ := elliptic.GenerateKey(c, rand.Reader)
		h := sha512.Sum512([]byte("Hello, world."))
		r, s := c.Sign(priv, h[:])
		if !c.Verify(Hx, Hy, h[:], r, s) {
			t.Errorf("[%s] invalid signature", c.Name)
		}
	}
}
