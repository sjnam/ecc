package ecc

import (
	"math/big"
	"testing"
)

func TestECDLP(t *testing.T) {
	curve := new(EllipticCurve)
	curve.P = big.NewInt(7919)
	curve.A = big.NewInt(1001)
	curve.B = big.NewInt(75)
	curve.N = big.NewInt(7889)
	curve.BitSize = 16

	px := big.NewInt(4023)
	py := big.NewInt(6036)

	cases := []struct {
		x, y, k *big.Int
	}{
		{big.NewInt(1075), big.NewInt(54), big.NewInt(1275)},
		{big.NewInt(4135), big.NewInt(3169), big.NewInt(4334)},
		{big.NewInt(2599), big.NewInt(759), big.NewInt(3430)},
		{big.NewInt(7285), big.NewInt(7905), big.NewInt(4508)},
		{big.NewInt(758), big.NewInt(574), big.NewInt(6864)},
	}

	for _, c := range cases {
		k := curve.PollardRho(px, py, c.x, c.y)
		if k.Sign() == 0 || k.Cmp(c.k) != 0 {
			t.Errorf("[PollardRho] (%d,%d) want: %d, got: %d", c.x, c.y, c.k, k)
		}
	}
}

func TestPohligHellman(t *testing.T) {
	// https://hgarrereyn.gitbooks.io/th3g3ntl3man-ctf-writeups/content/2017/picoCTF_2017/problems/cryptography/ECC2/ECC2.html
	c := &EllipticCurve{
		H: new(big.Int).SetInt64(1),
	}
	c.P, _ = new(big.Int).SetString("93556643250795678718734474880013829509320385402690660619699653921022012489089", 10)
	c.A, _ = new(big.Int).SetString("66001598144012865876674115570268990806314506711104521036747533612798434904785", 10)
	c.B, _ = new(big.Int).SetString("25255205054024371783896605039267101837972419055969636393425590261926131199030", 10)
	c.Gx, _ = new(big.Int).SetString("56027910981442853390816693056740903416379421186644480759538594137486160388926", 10)
	c.Gy, _ = new(big.Int).SetString("65533262933617146434438829354623658858649726233622196512439589744498050226926", 10)
	c.N, _ = new(big.Int).SetString("93556643250795678718734474880013829509196181230338248789325711173791286325820", 10)
	c.BitSize = c.N.BitLen()

	Qx, _ := new(big.Int).SetString("61124499720410964164289905006830679547191538609778446060514645905829507254103", 10)
	Qy, _ := new(big.Int).SetString("2595146854028317060979753545310334521407008629091560515441729386088057610440", 10)

	var factors []*big.Int
	for _, f := range []int64{4, 3, 5, 7, 137, 593, 24337, 25589, 3637793, 5733569} {
		factors = append(factors, big.NewInt(f))
	}

	N := new(big.Int).Set(c.N)
	var dLogs []*big.Int
	for _, factor := range factors {
		c.N.Set(factor)
		t := new(big.Int).Div(N, factor)
		px, py := c.ScalarBaseMult(t.Bytes())
		qx, qy := c.ScalarMult(Qx, Qy, t.Bytes())
		dLogs = append(dLogs, c.PollardRho(px, py, qx, qy))
	}

	want, _ := new(big.Int).SetString("152977126447386808276536247114", 10)
	l := CRT(dLogs, factors)
	if l.Cmp(want) != 0 {
		t.Errorf("[Pohlig Hellman] want: %d, got: %d", want, l)
	}
}
