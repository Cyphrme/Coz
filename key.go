package coz

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// KeyCanon is the canonical form of a Coz key.
var KeyCanon = []string{"alg", "pub"}

// Key is a Coz key. See `README.md` for details on Coz key. Fields `alg` and
// `tmb` must be in correct relative order for thumbprint canon because JSON
// marshal uses struct order.
//
// Standard Coz key Fields
//
//	`alg` - Specific key algorithm. E.g. "ES256" or "Ed25519".
//	`prv` - Private component. E.g. "bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA".
//	`now` - Unix time of when the key was created. E.g. 1626069600.
//	`tag` - Human readable, non-programmatic label. E.g. "My Coz key".
//	`rvk` - Unix time of key revocation. See docs on `rvk`. E.g. 1626069601.
//	`tmb` - Key thumbprint. E.g. "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg".
//	`typ` - Application label for key. E.g. "coz/key".
//	`pub` - Public component. E.g. "2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g".
type Key struct {
	Alg SEAlg     `json:"alg,omitempty"`
	Prv B64       `json:"prv,omitempty"`
	Now Timestamp `json:"now,omitempty"`
	Tag string    `json:"tag,omitempty"`
	Rvk Timestamp `json:"rvk,omitempty"`
	Tmb B64       `json:"tmb,omitempty"`
	Typ string    `json:"typ,omitempty"`
	Pub B64       `json:"pub,omitempty"`
}

// String implements Stringer. Returns empty on error.
func (c Key) String() string {
	b, err := Marshal(c)
	if err != nil {
		return ""
	}
	return string(b)
}

// NewKey generates a new Coz key.
func NewKey(alg SEAlg) (c *Key, err error) {
	c = new(Key)
	c.Alg = alg

	switch c.Alg.SigAlg() {
	default:
		return nil, fmt.Errorf("NewKey: unsupported alg %q", alg)
	case ES224, ES256, ES384, ES512:
		eck, err := ecdsa.GenerateKey(c.Alg.Curve().EllipticCurve(), rand.Reader)
		if err != nil {
			return nil, err
		}

		prvBytes := make([]byte, alg.PrvSize())
		c.Prv = eck.D.FillBytes(prvBytes) // Left pads bytes
		c.Pub = PadInts(eck.X, eck.Y, alg.PubSize())
	case Ed25519, Ed25519ph:
		pub, pri, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		// ed25519.GenerateKey returns "private key" that is the seed || publicKey.
		// Remove public key for 32 byte "seed", which is used as the private key.
		c.Prv = []byte(pri[:32])
		c.Pub = B64(pub)
	}

	c.Now = Now()
	return c, c.Thumbprint()
}

// NewKey generates a new signing Coz key.
func NewSigningKey(alg SigAlg) (c *Key, err error) {
	return NewKey(SEAlg(alg))
}

// Thumbprint generates `tmb` which is the digest of canon [alg, pub].  Pub must be
// set and be a valid length.  On error, tmb is set to nil.
func (c *Key) Thumbprint() (err error) {
	c.Tmb, err = Thumbprint(c)
	return err
}

// Thumbprint generates `tmb` which is the digest of canon [alg, pub].  Pub must be
// set and be a valid length.  On error, tmb is set to nil.
func Thumbprint(c *Key) (tmb B64, err error) {
	if len(c.Pub) != c.Alg.PubSize() {
		return nil, fmt.Errorf("Thumbprint: incorrect pub length for alg %q; expected %q; given %q", c.Alg, c.Alg.Hash().Size(), len(tmb))
	}
	b, err := Marshal(c)
	if err != nil {
		return nil, err
	}
	return CanonicalHash(b, KeyCanon, c.Alg.Hash())
}

// UnmarshalJSON always populates `tmb` even if it isn't given.
func (c *Key) UnmarshalJSON(b []byte) error {
	err := checkDuplicate(json.NewDecoder(bytes.NewReader(b)))
	if err != nil {
		return err
	}

	type key2 Key // Break infinite unmarshal loop
	czk2 := new(key2)
	err = json.Unmarshal(b, czk2)
	if err != nil {
		return err
	}

	*c = *(*Key)(czk2)
	err = c.Correct() // Correct sets tmb.
	if err != nil {
		return err
	}
	return nil
}

// Sign uses a private Coz key to sign a digest.
//
// Sign() and Verify() do not check if the Coz is correct, such as checking
// pay.alg and pay.tmb matches with Key.  Use SignPay, SignCoz, SignPayJSON,
// and/or VerifyCoz if needing Coz validation.
func (c *Key) Sign(digest B64) (sig B64, err error) {
	if len(c.Prv) != c.Alg.PrvSize() {
		return nil, fmt.Errorf("Sign: incorrect prv length for alg %q; expected %q, given %q", c.Alg, c.Alg.PrvSize(), len(c.Prv))
	}

	switch c.Alg.SigAlg().Genus() {
	default:
		return nil, fmt.Errorf("Sign: unsupported alg %q", c.Alg)
	case ECDSA:
		curve := c.Alg.Curve().EllipticCurve()
		d := new(big.Int).SetBytes(c.Prv)
		// Go 1.24+ requires PublicKey.X and PublicKey.Y to be populated.
		var pubX, pubY *big.Int
		if len(c.Pub) == c.Alg.PubSize() {
			// Extract X and Y from existing c.Pub (stored as X||Y concatenation).
			half := c.Alg.PubSize() / 2
			pubX = new(big.Int).SetBytes(c.Pub[:half])
			pubY = new(big.Int).SetBytes(c.Pub[half:])
		} else {
			// Compute public key from private key using scalar base multiplication.
			pubX, pubY = curve.ScalarBaseMult(c.Prv)
		}
		prk := ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: curve,
				X:     pubX,
				Y:     pubY,
			},
			D: d,
		}
		r, s, err := ecdsa.Sign(rand.Reader, &prk, digest)
		if err != nil {
			return nil, err
		}

		// S canonicalization generates signature with low-S.
		err = ToLowS(c, s)
		if err != nil {
			return nil, err
		}

		// ECDSA Sig is R || S rounded up to byte left padded.
		return PadInts(r, s, c.Alg.SigAlg().SigSize()), nil
	case EdDSA:
		pk := ed25519.NewKeyFromSeed(c.Prv)
		// Alternatively, concat prv with pub
		// b := make([]coz.B64, 64)
		// prv := append(b, c.Prv, c.Pub)
		return ed25519.Sign(pk, digest), nil
	}
}

// SignPay signs coz.Pay and returns a new Coz with coz.Sig populated. If set,
// SignPay checks that `pay.alg` and `key.alg` match and that `pay.tmb` is
// correct according to `key`.
//
// If `pay.Now` is non-zero, SignPay updates it to the current Unix timestamp
// before signing. This is the recommended behavior for most use cases. To sign
// without modifying `now`, use SignPayRaw.
//
// SignPay works with contextual cozies that lack pay.alg and/or pay.tmb and
// uses key as a source of truth.
func (c *Key) SignPay(p *Pay) (coz *Coz, err error) {
	// Auto-update now if present (non-zero).
	if p.Now != 0 {
		p.Now = Now()
	}
	return c.signPayJSON(p, nil)
}

// SignPayRaw signs coz.Pay without modifying any fields. Unlike SignPay,
// it does not update `pay.Now`. Use this when you need exact control over
// the payload being signed.
func (c *Key) SignPayRaw(p *Pay) (coz *Coz, err error) {
	return c.signPayJSON(p, nil)
}

// SignPayJSON signs a json `coz.pay`. If the JSON contains a non-zero `now`
// field, it is updated to the current Unix timestamp before signing. See
// documentation on SignPay.
func (c *Key) SignPayJSON(pay json.RawMessage) (coz *Coz, err error) {
	p := new(Pay)
	err = json.Unmarshal(pay, p)
	if err != nil {
		return nil, err
	}
	// Auto-update now if present (non-zero).
	if p.Now != 0 {
		p.Now = Now() // Use Now() per existing code logic.
		return c.signPayJSON(p, nil)

		// This shouldn't be needed.
		// // Use orderedMap to update "now" without dropping custom fields
		// // or mutating the JSON field order.
		// om := newOrderedMap()
		// err = json.Unmarshal(pay, om)
		// if err != nil {
		// 	return nil, err
		// }
		// om.Set("now", p.Now)
		// b, err := om.MarshalJSON()
		// if err != nil {
		// 	return nil, err
		// }
		// return c.signPayJSON(p, b)
	}
	return c.signPayJSON(p, pay)
}

// signPayJSON efficiently consolidates common code between SignPay and
// SignPayJSON. Parameter p must be given and b is optional.  If b is nil, b is
// generated from p. If b is not nil b is compacted.
func (c *Key) signPayJSON(p *Pay, b json.RawMessage) (coz *Coz, err error) {
	if p.Alg != "" && c.Alg != p.Alg {
		return nil, fmt.Errorf("SignPay: key alg %q and coz alg %q do not match", c.Alg, p.Alg)
	}
	if len(p.Tmb) != 0 && !bytes.Equal(c.Tmb, p.Tmb) {
		return nil, fmt.Errorf("SignPay: key tmb %q and coz tmb %q do not match", c.Tmb, p.Tmb)
	}

	if b == nil {
		b, err = Marshal(p)
		if err != nil {
			return nil, err
		}
	} else {
		b, err = compact(b)
		if err != nil {
			return nil, err
		}
	}

	d, err := Hash(c.Alg.Hash(), b)
	if err != nil {
		return nil, err
	}
	sig, err := c.Sign(d)
	if err != nil {
		return nil, err
	}

	coz = new(Coz)
	coz.Pay = b
	coz.Sig = sig
	return coz, nil
}

// SignCoz signs `coz.pay` and sets `coz.sig`. Since SignPayJSON may modify
// `pay.now` if present, SignCoz also updates `cz.Pay` to match the signed
// payload. See documentation on SignPay.
func (c *Key) SignCoz(cz *Coz) (err error) {
	coz, err := c.SignPayJSON(cz.Pay)
	if err != nil {
		return err
	}
	cz.Pay = coz.Pay // Pay may have been modified (e.g., now updated).
	cz.Sig = coz.Sig
	return nil
}

// Verify uses a Coz key to verify a digest.  Typically digest is `cad`.
//
// Sign() and Verify() do not check if the coz is correct, such as checking
// pay.alg and pay.tmb matches with Key.  Use SignPay, SignCoz, SignPayJSON,
// and/or VerifyCoz if needing Coz validation.
func (c *Key) Verify(digest, sig B64) (valid bool) {
	if len(c.Pub) != c.Alg.PubSize() {
		return false
	}
	switch c.Alg.SigAlg() {
	default:
		return false
	case ES224, ES256, ES384, ES512:
		size := c.Alg.SigAlg().SigSize() / 2
		r := big.NewInt(0).SetBytes(sig[:size])
		s := big.NewInt(0).SetBytes(sig[size:])

		// S canonicalization. Only accept low-S.
		lowS, err := IsLowS(c, s)
		if !lowS || err != nil {
			return false
		}

		return ecdsa.Verify(c.ToPubEcdsa(), digest, r, s)
	case Ed25519, Ed25519ph:
		return ed25519.Verify(ed25519.PublicKey(c.Pub), digest, sig)
	}
}

// VerifyCoz cryptographically verifies `pay` with given `sig`.  If set
// VerifyCoz checks that `pay.alg` and `key.alg` match and that `pay.tmb` is
// correct according to `key`. Always returns false on error.
//
// VerifyCoz works with contextual cozies that lack pay.alg and/or
// pay.tmb and uses key as a source of truth.
func (c *Key) VerifyCoz(cz *Coz) (bool, error) {
	p := new(Pay)
	err := json.Unmarshal(cz.Pay, p)
	if err != nil {
		return false, err
	}
	if p.Alg != "" && c.Alg != p.Alg {
		return false, fmt.Errorf("VerifyCoz: key.alg %q and coz.alg %q do not match", c.Alg, p.Alg)
	}
	if len(p.Tmb) != 0 && !bytes.Equal(c.Tmb, p.Tmb) {
		return false, fmt.Errorf("VerifyCoz: key tmb %q and coz tmb %q do not match", c.Tmb, p.Tmb)
	}

	b, err := compact(cz.Pay)
	if err != nil {
		return false, err
	}

	d, err := Hash(c.Alg.Hash(), b)
	if err != nil {
		return false, err
	}

	return c.Verify(d, cz.Sig), nil
}

// Valid cryptographically validates a private Coz Key by signing a message and
// verifying the resulting signature with the given "pub".
//
// Valid always returns false on public keys.  Use function "Verify" for public
// keys with signed message.  See also function Correct.
func (c *Key) Valid() (valid bool) {
	// fmt.Printf("Valid key: %v\n", c)
	d, err := Hash(c.Alg.Hash(), []byte("7AtyaCHO2BAG06z0W1tOQlZFWbhxGgqej4k9-HWP3DE-zshRbrE-69DIfgY704_FDYez7h_rEI1WQVKhv5Hd5Q"))
	if err != nil {
		return false
	}
	sig, err := c.Sign(d)
	if err != nil {
		return false
	}
	return c.Verify(d, sig)
}

// Correct is an advanced function for checking for the correct construction of
// a Coz key if it can be known from the given inputs. Key must have at least
// one of [`tmb`, `pub`,`prv`] and `alg` set.  Correct may return no error on
// cryptographically invalid public keys.  Using input information, if possible
// to definitively know the given key is incorrect, Correct returns an error,
// but if plausibly correct, Correct returns no error. Correct answers the
// question: "Is the given Coz key reasonable using the information provided?".
// Correct is useful for sanity checking public keys without signed messages,
// sanity checking `tmb` only keys, and validating private keys. Use function
// "Verify" instead for verifying public keys when a signed message is
// available. Correct is considered an advanced function. Please understand it
// thoroughly before use.
//
// Correct:
//
//  1. Checks the length of `pub` and/or `tmb` against `alg`.
//  2. If `pub` and `tmb` are present, verifies correct `tmb`.
//  3. If `prv` is present, verifies correct `tmb` and `pub` if present, and
//     verifies the key by verifying a generated signature.
//  4. If possible, sets tmb and/or pub.
//
// Functions that call correct can check for correctness by `if key.Correct() != nil`
func (c *Key) Correct() (err error) {
	if c.Alg == "" {
		return errors.New("Correct: alg must be set")
	}
	if len(c.Tmb) == 0 && len(c.Pub) == 0 && len(c.Prv) == 0 {
		return errors.New("Correct: at least one of [pub, tmb, prv] must be set")
	}

	// prv is set.
	// Calculate pub from prv and compare with given value.
	if len(c.Prv) != 0 {
		givenPub := c.Pub
		c.Pub = c.calcPub()
		if len(givenPub) != 0 && !bytes.Equal(c.Pub, givenPub) {
			return fmt.Errorf("Correct: incorrect Pub; expected %q, given %q, ", c.Pub, givenPub)
		}
		if !c.Valid() {
			return fmt.Errorf("Correct: key is invalid")
		}
	}

	// pub is set.
	// Calculate tmb from pub and compare with given value.
	if len(c.Pub) != 0 {
		if len(c.Pub) != c.Alg.PubSize() {
			return fmt.Errorf("Correct: incorrect pub length for alg %q; expected %q, given %q", c.Alg, c.Alg.PubSize(), len(c.Pub))
		}
		givenTmb := c.Tmb
		err := c.Thumbprint()
		if err != nil {
			return err
		}
		if len(givenTmb) != 0 && !bytes.Equal(c.Tmb, givenTmb) {
			return fmt.Errorf("Correct: incorrect tmb; expected %q, given %q", c.Tmb, givenTmb)
		}
	}

	// tmb only key.  (Coz assumes `pub` is calculable from `prv`, so at this point
	// `tmb` should always be set. See `checksum_and_seed.md` for exposition.
	if len(c.Tmb) != c.Alg.Hash().Size() {
		return fmt.Errorf("Correct: incorrect tmb length for alg %q; expected %q, given %q", c.Alg, c.Alg.Hash().Size(), len(c.Tmb))
	}
	return nil
}

// Revoke returns a signed revoke coz and sets `rvk` on the key itself.
func (c *Key) Revoke() (coz *Coz, err error) {
	err = c.Correct()
	if err != nil {
		return nil, fmt.Errorf("Revoke: Coz key is not correct; %s", err)
	}

	r := new(Pay)
	r.Alg = c.Alg
	r.Now = Now()
	r.Rvk = r.Now
	r.Tmb = c.Tmb
	// If needing "typ" populated, use Sign.

	coz = new(Coz)
	coz.Pay, err = r.MarshalJSON()
	if err != nil {
		return
	}

	err = c.SignCoz(coz)
	if err != nil {
		return nil, err
	}
	c.Rvk = r.Now // Sets `Key.Rvk` to the same value as the self-revoke coz.
	return coz, nil
}

// IsRevoked returns true if the given Key is marked as revoked.
func (c Key) IsRevoked() bool {
	return isRevoke(c.Rvk)
}

// calcPub recalculates 'pub' from 'prv' and returns 'pub'. 'pub' will not be set on the
// key from here. Algorithms are constant-time.
// https://cs.opensource.google/go/go/+/refs/tags/go1.18.3:src/crypto/elliptic/elliptic.go;l=455;drc=7f9494c277a471f6f47f4af3036285c0b1419816
func (c *Key) calcPub() B64 {
	switch c.Alg.SigAlg() {
	default:
		return nil
	case ES224, ES256, ES384, ES512:
		pukx, puky := c.Alg.Curve().EllipticCurve().ScalarBaseMult(c.Prv)
		return PadInts(pukx, puky, c.Alg.PubSize())
	case Ed25519, Ed25519ph:
		return []byte(ed25519.NewKeyFromSeed(c.Prv)[32:])
	}
}

// ToPubEcdsa converts a Coz Key to ecdsa.PublicKey.
func (c *Key) ToPubEcdsa() (key *ecdsa.PublicKey) {
	size := c.Alg.PubSize() / 2
	return &ecdsa.PublicKey{
		Curve: c.Alg.Curve().EllipticCurve(),
		X:     new(big.Int).SetBytes(c.Pub[:size]),
		Y:     new(big.Int).SetBytes(c.Pub[size:]),
	}
}

// curveOrders contains curve group orders.
var curveOrders = map[SigAlg]*big.Int{
	ES224: elliptic.P224().Params().N,
	ES256: elliptic.P256().Params().N,
	ES384: elliptic.P384().Params().N,
	ES512: elliptic.P521().Params().N,
}

// curveHalfOrders contains curve group orders halved for ToLowS.  From
// https://github.com/golang/go/issues/54549
var curveHalfOrders = map[SigAlg]*big.Int{
	// Logical right shift divides a number by 2 discreetly.
	ES224: new(big.Int).Rsh(elliptic.P224().Params().N, 1),
	ES256: new(big.Int).Rsh(elliptic.P256().Params().N, 1),
	ES384: new(big.Int).Rsh(elliptic.P384().Params().N, 1),
	ES512: new(big.Int).Rsh(elliptic.P521().Params().N, 1),
}

// IsLowS checks if S is a low-S for ECDSA.  See Coz docs on low-S.
func IsLowS(c *Key, s *big.Int) (bool, error) {
	if c.Alg.Genus() != ECDSA {
		return false, fmt.Errorf("IsLowS: alg %q is not ECDSA", c.Alg)
	}
	return s.Cmp(curveHalfOrders[c.Alg.SigAlg()]) != 1, nil
}

// ToLowS converts high-S to low-S or if already low-S returns itself.
// It does this by (N - S) where N is the order.  See Coz docs on low-S.
func ToLowS(c *Key, s *big.Int) error {
	lowS, err := IsLowS(c, s)
	if err != nil {
		return err
	}
	if !lowS {
		s.Sub(c.Alg.Curve().EllipticCurve().Params().N, s)
		return nil
	}
	return nil
}

// ECDSAToLowSSig generates low-S signature from existing ecdsa signatures (high
// or low-S).  This is useful for migrating signatures from non-Coz systems
// that may have high S signatures. See Coz docs on low-S.
func ECDSAToLowSSig(c *Key, coz *Coz) (err error) {
	if c.Alg.Genus() != ECDSA {
		return nil
	}
	size := c.Alg.SigAlg().SigSize() / 2
	r := big.NewInt(0).SetBytes(coz.Sig[:size])
	s := big.NewInt(0).SetBytes(coz.Sig[size:])

	// low-S
	err = ToLowS(c, s)
	if err != nil {
		return err
	}
	coz.Sig = PadInts(r, s, c.Alg.SigSize())

	// Make sure the possible mutation of the signature is valid.
	valid, err := c.VerifyCoz(coz)
	if !valid {
		return err
	}

	return nil
}
