package ecc

import (
	"math/big"
	"testing"
)

func TestECDLP(t *testing.T) {
	if !testing.Short() {
		return
	}
	t.Run("ecdlp", func(t *testing.T) {
		t.Parallel()
		curve := &Curve{
			P:  big.NewInt(7919),
			A:  big.NewInt(1001),
			B:  big.NewInt(75),
			Gx: big.NewInt(4023),
			Gy: big.NewInt(6036),
			N:  big.NewInt(7889),
		}
		curve.BitSize = curve.N.BitLen()

		for m := big.NewInt(1); m.Cmp(curve.N) < 0; m.Add(m, big.NewInt(1)) {
			px, py := curve.Gx, curve.Gy
			hx, hy := curve.ScalarBaseMult(m)
			k := curve.Shank(px, py, hx, hy)
			if k == nil || k.Cmp(m) != 0 {
				t.Errorf("[Shank] (%d,%d) want: %d, got: %d", hx, hy, m, k)
			}

			k = curve.PollardRho(px, py, hx, hy)
			if k == nil || k.Cmp(m) != 0 {
				t.Errorf("[PollardRho] (%d,%d) want: %d, got: %d", hx, hy, m, k)
			}

			k = curve.PohligHellman(px, py, hx, hy)
			if k == nil || k.Cmp(m) != 0 {
				t.Errorf("[PohligHellman] (%d,%d) want: %d, got: %d", hx, hy, m, k)
			}
		}
	})

	t.Run("PohligHellman-1", func(t *testing.T) {
		t.Parallel()
		// https://gist.github.com/jproney/7e6cb7a40a8bf342e978a900a32e4dfc
		curve := &Curve{
			H: big.NewInt(1),
			P: bigFromDecimal("93556643250795678718734474880013829509320385402690660619699653921022012489089"),
			A: bigFromDecimal("66001598144012865876674115570268990806314506711104521036747533612798434904785"),
			B: bigFromDecimal("25255205054024371783896605039267101837972419055969636393425590261926131199030"),
			N: bigFromDecimal("93556643250795678718734474880013829509196181230338248789325711173791286325820"),
		}
		curve.BitSize = curve.N.BitLen()

		want := bigFromDecimal("124194987912445918487544544020")
		px := bigFromDecimal("56027910981442853390816693056740903416379421186644480759538594137486160388926")
		py := bigFromDecimal("65533262933617146434438829354623658858649726233622196512439589744498050226926")
		hx := bigFromDecimal("79745356646949069441279781387743208137742538544495675881933883371885177103895")
		hy := bigFromDecimal("34529309219406689418881493671300037164559702076524725195399995669560101677178")

		k := curve.PohligHellman(px, py, hx, hy)
		if k == nil || k.Cmp(want) != 0 {
			t.Errorf("[PohligHellman-1] (%d,%d) want: %d, got: %d", hx, hy, want, k)
		}
	})

	t.Run("PohligHellman-2", func(t *testing.T) {
		t.Parallel()
		curve := &Curve{
			P: bigFromDecimal("4516284508517"),
			A: big.NewInt(7),
			B: big.NewInt(1),
			N: bigFromDecimal("4516285972627"),
		}
		curve.BitSize = curve.N.BitLen()

		want := big.NewInt(21345332)
		px := bigFromDecimal("816487529800")
		py := bigFromDecimal("1845320358420")
		hx, hy := curve.ScalarMult(px, py, want)

		k := curve.PohligHellman(px, py, hx, hy)
		if k == nil || k.Cmp(want) != 0 {
			t.Errorf("[PohligHellman-2] (%d,%d) want: %d, got: %d", hx, hy, want, k)
		}
	})
}
