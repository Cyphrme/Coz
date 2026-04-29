/*
Package coz, see the README at https://github.com/Cyphrme/Coze

This library exports some functions that may be helpful for other applications,
but should not be considered apart of the Coz specification API.

  - ECDSAToLowSSig
  - IsLowS
  - ToLowS
  - Marshal
  - MarshalPretty

Other auxiliary types and functions, like B64, are reasonable exports for
package coz, especially since compatible implementations are absent from the Go
standard library.
*/
package coz

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"golang.org/x/crypto/sha3"
)

// Coz is for signed Coz objects (cozies).  See the Coz docs (README.md) for
// more on the construction of `coz`.
//
//	Pay: The raw Payload.  The payload can contain any arbitrary fields,
//	  not just Coz fields.
//	Key: Key used to sign the message. Must be a pointer, otherwise
//	  json.Marshal will not marshal on zero type.
//	  See: https://github.com/golang/go/issues/11939.
//	Can: "Canon" Pay's fields in order of appearance.
//	Cad: "Canonical Digest" Pay's compactified form digest.
//	Sig: Signature over `cad`.
//	Czd: "Coz digest" with canon ["cad","sig"].
//	Parsed: The standard Coz pay fields ["alg","now","tmb","typ"] parsed
//	  from `Pay`.  `Parsed` is populated by Meta() and is JSON ignored.
type Coz struct {
	Pay json.RawMessage `json:"pay,omitempty"`
	Key *Key            `json:"key,omitempty"`
	Can []string        `json:"can,omitempty"`
	Cad B64             `json:"cad,omitempty"`
	Sig B64             `json:"sig,omitempty"`
	Czd B64             `json:"czd,omitempty"`

	Parsed *Pay `json:"-"`
}

// String implements fmt.Stringer.  Without this method `pay` prints as bytes.
// On error, returns the error as a string.
func (cz Coz) String() string {
	b, err := Marshal(cz)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// Meta calculates [can, cad, czd] and sets Coz.Parsed
// ["alg","now","tmb","typ"] from Pay. Coz.Pay, Coz.Pay.Alg, and Coz.Sig must
// be set.  Meta resets Parsed ("alg","now","tmb","typ") to zero before
// populating Parsed from Pay. If needing to use for contextual cozies, use
// "MetaWithAlg".
//
// Meta does no cryptographic verification.
func (cz *Coz) Meta() (err error) {
	if cz.Pay == nil || cz.Sig == nil {
		return errors.New("Meta: pay and/or sig is nil")
	}
	// Reset coz.parsed to zero.
	cz.Parsed = new(Pay)
	return cz.MetaWithAlg("")
}

// MetaWithAlg is for contextual cozies that may be lacking `alg` in `pay`, but
// `alg` in otherwise known.  MetaWithAlg recalculates [can, cad, czd] and sets
// Coz.Parsed ("alg","now","tmb","typ") from Pay.  Does not calculate `czd`
// if Coz.Sig is empty.
//
// Errors on
// 1. Invalid JSON.
// 2. No alg is given. (both coz.pay.alg and alg are empty).
// 3. Mismatched Pay.Alg and parameter alg if both are set.
//
// MetaWithAlg does no cryptographic verification.
func (cz *Coz) MetaWithAlg(alg SEAlg) (err error) {
	// Ensure Parsed is allocated.
	if cz.Parsed == nil {
		cz.Parsed = new(Pay)
	}

	// Set Parsed from Pay.
	err = json.Unmarshal(cz.Pay, cz.Parsed)
	if err != nil {
		return err
	}
	if alg == "" {
		alg = cz.Parsed.Alg
	}
	if cz.Parsed.Alg != "" && alg != cz.Parsed.Alg {
		return fmt.Errorf("MetaWithAlg: input alg %q and pay.alg %q are unequal", alg, cz.Parsed.Alg)
	}
	b, err := compact(cz.Pay)
	if err != nil {
		return err
	}
	cz.Cad, err = Hash(alg.Hash(), b)
	if err != nil {
		return err
	}
	cz.Can, err = Canon(b)
	if err != nil {
		return err
	}
	cz.Czd = nil // Zero `czd` in case Coz.Sig is not set.
	if len(cz.Sig) != 0 {
		cz.Czd, err = GenCzd(alg.Hash(), cz.Cad, cz.Sig)
		return err
	}
	return nil
}

// UnmarshalJSON unmarshals checks for duplicates and unmarshals `coz`.
// See notes on Pay.UnmarshalJSON.
func (cz *Coz) UnmarshalJSON(b []byte) error {
	err := checkDuplicate(json.NewDecoder(bytes.NewReader(b)))
	if err != nil {
		return err
	}

	type coz2 Coz // Break infinite unmarshal loop
	cz2 := new(coz2)
	cz2.Parsed = cz.Parsed
	cz2.Key = cz.Key
	err = json.Unmarshal(b, cz2)
	if err != nil {
		return err
	}
	*cz = *(*Coz)(cz2)
	return nil
}

// CzdCanon is the canon for a `czd`.
var CzdCanon = []string{"cad", "sig"}

// RVK_MAX_SIZE is the maximum allowed payload size in bytes for revoke
// messages. This limit prevents denial-of-service attacks using oversized
// revoke payloads. Set to 0 to disable the limit. Default is 2048 bytes.
var RVK_MAX_SIZE = 2048

// GenCzd generates and returns `czd`.
func GenCzd(hash HshAlg, cad B64, sig B64) (czd B64, err error) {
	return Hash(hash, fmt.Appendf(nil, `{"cad":%q,"sig":%q}`, cad, sig))
}

// Pay contains the standard Coz pay fields as well as custom struct given by
// third party applications.  This allows embedding third party structs into Pay
// for creating custom cozies (see example ExampleKey_SignPay).
//
// The JSON tags on [Alg, Iat, Tmb, Typ, Rvk, Struct] are ineffective due to the
// custom MarshalJSON(), however they are present for documentation.
//
// `Struct` will be marshaled when not empty. The custom marshaller promotes
// fields inside `Struct` to be top level fields inside of `pay`. The tag
// `json:"-"` is ignored by the custom marshaller, and  is set to "-" so that the
// default marshaller does not include it.
type Pay struct {
	Alg SEAlg     `json:"alg,omitempty"` // e.g. "ES256"
	Now Timestamp `json:"now,omitempty"` // e.g. 1623132000
	Tmb B64       `json:"tmb,omitempty"` // e.g. "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
	Typ string    `json:"typ,omitempty"` // e.g. "cyphr.me/msg/create"

	// Rvk is only for revoke messages.
	Rvk Timestamp `json:"rvk,omitempty"` // e.g. 1623132000

	// Custom arbitrary struct given by application.
	Struct any `json:"-"`
}

// Coz returns a new coz with only Pay populated.
func (p *Pay) Coz() (coz *Coz, err error) {
	coz = new(Coz)
	coz.Pay, err = Marshal(p)
	return coz, err
}

// String implements fmt.Stringer.
// On error, returns the error as a string.
func (p Pay) String() string {
	b, err := p.MarshalJSON()
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// MarshalJSON promotes the embedded field "Struct" to top level JSON.
// Solution from Jonathan Hall:
// https://jhall.io/posts/go-json-tricks-embedded-marshaler
func (p *Pay) MarshalJSON() ([]byte, error) {
	type pay2 Pay // Break infinite Marshal loop

	pay, err := Marshal((*pay2)(p))
	if err != nil {
		return nil, err
	}
	if p.Struct == nil {
		return pay, nil
	}

	s, err := json.Marshal(p.Struct)
	if err != nil {
		return nil, err
	}
	// Concatenate the two:
	s[0] = ','
	return append(pay[:len(pay)-1], s...), nil
}

// UnmarshalJSON unmarshals both Pay and if given custom Pay.Struct. Throws an
// error on duplicate. (Duplicate related, see
// https://github.com/golang/go/issues/48298)
func (p *Pay) UnmarshalJSON(b []byte) error {
	err := checkDuplicate(json.NewDecoder(bytes.NewReader(b)))
	if err != nil {
		return err
	}

	type pay2 Pay // Break infinite unmarshal loop
	p2 := new(pay2)
	err = json.Unmarshal(b, p2)
	if err != nil {
		return err
	}

	// Inner custom application struct.
	customHandled := false
	// Case 1: Caller pre-set a custom struct pointer on *p.
	if p.Struct != nil {
		if _, ok := p.Struct.(map[string]json.RawMessage); !ok {

			str := p.Struct
			if err = json.Unmarshal(b, str); err != nil {
				return err
			}
			p2.Struct = str
			customHandled = true
		}
		// If it was the internal map, fall through to case 2 (re-capture extras)
	}
	// Case 2: Manual unmarshal to capture extra fields from raw JSON
	if !customHandled {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err == nil {
			// Remove known Coz fields so only custom fields remain
			for _, k := range []string{"alg", "now", "tmb", "typ", "rvk"} {
				delete(m, k)
			}
			if len(m) > 0 {
				p2.Struct = m
			}
		}
	}

	// Enforce revoke message max size to prevent DoS attacks.
	if p2.Rvk > 0 && RVK_MAX_SIZE > 0 && len(b) > RVK_MAX_SIZE {
		return fmt.Errorf("Pay.UnmarshalJSON: revoke message size %d exceeds RVK_MAX_SIZE %d", len(b), RVK_MAX_SIZE)
	}

	*p = *(*Pay)(p2)
	return nil
}

// PadInts creates a big-endian byte slice with given size that is the left
// padded concatenation of two input integers. Parameter `size` must be even.
// From Go's packages, X, Y, R, and S are type big.Int of varying size. Before
// encoding to fixed size string, left padding of bytes is needed.
//
// Algorithm notes: EdDSA is little-endian while ECDSA is big-endian. EdDSA
// should not be used with this function.
//
// For ECDSA, Coz's `x` and `sig` is left padded concatenation of X || Y and R
// || S respectively.
//
// Note: ES512's signature size is 132 bytes (and not 128, 131, or 130.25),
// because R and S are each respectively rounded up and padded to 528 and for a
// total signature size of 1056 bits.
// See https://datatracker.ietf.org/doc/html/rfc4754#section-7
func PadInts(r, s *big.Int, size int) (out B64) {
	if !(size%2 == 0) {
		panic("size must be even.")
	}

	out = make([]byte, size)
	half := size / 2

	rb := r.Bytes()
	copy(out[half-len(rb):], rb)

	sb := s.Bytes()
	copy(out[half+(half-(len(sb))):], sb)

	return out
}

// Marshaler is a UTF-8 marshaller for Go structs. Go's `json.Marshal`
// removes the valid characters "&". "<", ">". See note on Marshal.  (Note that
// Marshaler follows the Go "-er" convention for interfaces while marshaller is
// spelled with two l's)
type Marshaler interface {
	CozMarshal() ([]byte, error)
}

// Marshal is a JSON friendly marshaller.  json.Marshal preemptively replaces
// the valid JSON and UTF-8 characters "&". "<", ">" with the "slash u" unicode
// escapes (e.g. \u0026) in the name of HTML friendliness, for example:
// https://play.golang.org/p/o2hiX0c62oN. As JSON is not HTML, preemptive HTML
// escaping is incorrect.  (The JSON spec calls for no such measures and other
// industry encoders do no such preemptive escaping.)  Where JSON may include
// these legitimate characters, like sanitized arbitrary user data, json.Marshal
// should not be used. The Go team is aware that the existing implementation has
// this and other concerns but has not yet released a new version.  Joe Tsai is
// working on fixes in a yet-to-be-released Tailscale's "JSONv2" package, which
// we hope to use upon release.
// https://pkg.go.dev/github.com/go-json-experiment/json.  The package also
// enumerates other JSON best practices that may be of concern for anyone
// concerned with the aforementioned issue.
// https://github.com/go-json-experiment/json#behavior-changes.  See
// https://github.com/Cyphrme/Coze/issues/15 for other JSON encoding concerns.
//
// Go structs already require unique fields, so unlike coz.UnmarshalJSON or
// pay.UnmarshalJSON, marshaling will not sanitize for duplicates.
func Marshal(i any) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(i)
	if err != nil {
		return nil, err
	}
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}

// MarshalPretty uses 4 spaces for each level. Spaces are used instead of tabs
// because some applications display tabs as 8 spaces, which is excessive.
func MarshalPretty(i any) ([]byte, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetIndent("", "    ")
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(i)
	if err != nil {
		return nil, err
	}
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}

// Hash hashes msg and returns the digest. Returns nil on error. Errors on
// invalid HshAlg or if the resulting digest is empty (as a sanity check).
//
// For algorithms that support arbitrary sized digests, Hash only returns a
// static size.  (SHAKE128 returns 32 bytes and SHAKE256 returns 64 bytes.)
func Hash(h HshAlg, msg []byte) (digest B64, err error) {
	switch h {
	case SHAKE128:
		digest = make([]byte, 32)
		sha3.ShakeSum128(digest, msg)
	case SHAKE256:
		digest = make([]byte, 64)
		sha3.ShakeSum256(digest, msg)
	default:
		hash := h.goHash()
		if hash == nil {
			return nil, fmt.Errorf("Hash: invalid HshAlg %q", h)
		}
		_, err = hash.Write(msg)
		if err != nil {
			return nil, err
		}
		digest = hash.Sum(nil)
	}

	if len(digest) == 0 { // sanity check
		return nil, fmt.Errorf("Hash: digest is empty; given HshAlg %q", h)
	}
	return digest, nil
}

// IsRevoke returns true if the given Key is marked as revoked.
func (p *Pay) IsRevoke() bool {
	return isRevoke(p.Rvk)
}

func isRevoke(rvk Timestamp) bool {
	// rvk is not allowed to be larger than 2^53 -1.  This library assumes that
	// Unmarshal will error on rvk's that do not meet the specification
	// requirements, so no error is needed here.
	if rvk > MaxSafeTimestamp {
		return false
	}
	return rvk > 0
}

// ErrJSONDuplicate allows applications to check for JSON duplicate error.
type ErrJSONDuplicate error

// checkDuplicate checks for JSON duplicates. See notes on Marshal and the
// README FAQ on duplicate fields.
func checkDuplicate(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}

	// Is it a delimiter?
	delim, ok := t.(json.Delim)
	if !ok {
		return nil // scaler type, nothing to do
	}

	switch delim {
	case '{':
		keys := make(map[string]bool)
		for d.More() {
			t, err := d.Token() // Get field key.
			if err != nil {
				return err
			}

			key := t.(string)
			if keys[key] { // Check for duplicates.
				return ErrJSONDuplicate(fmt.Errorf("Coz: JSON duplicate field %q", key))
			}
			keys[key] = true

			// Recursive, Check value in case value is object.
			err = checkDuplicate(d)
			if err != nil {
				return err
			}
		}
		// consume trailing }
		if _, err := d.Token(); err != nil {
			return err
		}

	case '[':
		for d.More() {
			if err := checkDuplicate(d); err != nil {
				return err
			}
		}
		// consume trailing ]
		if _, err := d.Token(); err != nil {
			return err
		}
	}
	return nil
}

// Timestamp is positive UTC Unix time in seconds with a max value of 2^53 - 1.
// This ensures safe round-trip representation in environments like JavaScript
// that use IEEE 754 double-precision floats for numbers couldn't just be like
// Unix and use int64.
//
// Timestamp is exported for external libraries. Go's Time.time is overqualified
// for Coz's use, and type int64 isn't specific to "positive UTC Unix Timestamp
// with max value 2^53 -1".  (Also note that int64 is signed, not just positive.)
//
// This library assumes that the json.Unmarshal interface is extended by this
// library, for Timestamp and Pay, and will error on timestamps that do not meet
// the specification requirements, so no error is needed specifically on this
// type.
//
// To keep the ability to detect negative inputs early, instead of wrapping
// around to huge positive numbers, for validation purposes, signed int64 +
// explicit t < 0 check is safer and clearer than uint64.
type Timestamp int64

func Now() Timestamp {
	return Timestamp(time.Now().Unix())
}

// MaxSafeTimestamp is the value of 2^53 - 1
const MaxSafeTimestamp Timestamp = 9007199254740991

// Valid checks whether the timestamp is within the allowed range.
// Returns an error if invalid, nil if valid.
//
// This is useful for validation outside of JSON unmarshaling
// (e.g. manual construction, tests, or custom serialization).
func (t Timestamp) Valid() error {
	if t < 0 || t > MaxSafeTimestamp {
		return fmt.Errorf("coz.Timestamp: value given %d is invalid. Must be between 0 and %d inclusive", t, MaxSafeTimestamp)
	}
	return nil
}

// MarshalJSON implements json.Marshaler with range validation.
func (t Timestamp) MarshalJSON() ([]byte, error) {
	if err := t.Valid(); err != nil {
		return nil, err
	}
	return json.Marshal(int64(t))
}

// UnmarshalJSON implements json.Unmarshaler with range validation.
func (t *Timestamp) UnmarshalJSON(data []byte) error {
	var i int64
	if err := json.Unmarshal(data, &i); err != nil {
		return fmt.Errorf("coz.Timestamp.UnmarshalJSON: %w", err)
	}

	tmp := Timestamp(i)
	if err := tmp.Valid(); err != nil {
		return err
	}
	*t = tmp
	return nil
}

// String implements fmt.Strings so it prints the number cleanly, without needing casts.
func (t Timestamp) String() string {
	return strconv.FormatInt(int64(t), 10)
}

// Time returns a time.Time
func (t Timestamp) Time() time.Time {
	return time.Unix(int64(t), 0).UTC()
}
