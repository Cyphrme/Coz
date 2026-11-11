package coz

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"slices"
)

// Canon returns the current canon from raw JSON.
//
// It returns only top level fields with no recursion or promotion of embedded
// fields. Errors if raw is not a JSON object.
func Canon(raw jsontext.Value) (can []string, err error) {
	can, err = checkJSON(raw)
	if err != nil {
		return nil, err
	}
	if raw.Kind() != '{' {
		return nil, errors.New("Canon: JSON value is not an object")
	}
	if can == nil {
		can = []string{}
	}
	return can, nil
}

// Canonical returns the canonical form. Input canon is optional and may be nil.
// If canon is nil, input JSON is only compactified.
//
// Interface "canon" may be `[]string`, `struct“, or `nil`.  If "canon" is a
// struct or slice it must be properly ordered.  If canon is nil, [json.Unmarshal]
// will place the input into a UTF-8 ordered map.
//
// In the Go version of Coz, the canonical form of a struct is (currently)
// achieved by unmarshalling and remarshalling.
func Canonical(input []byte, canon any) (b []byte, err error) {
	if canon == nil {
		return compact(input)
	}

	s, ok := canon.([]string)
	if ok {
		// Unmarshal into a map to get all values, then marshal in canon order.
		m := make(map[string]any)
		err = json.Unmarshal(input, &m)
		if err != nil {
			return nil, jsonErr(err)
		}

		o := orderedObject{m: m}
		for _, k := range s {
			if _, ok := m[k]; ok && !slices.Contains(o.keys, k) {
				o.keys = append(o.keys, k)
			}
		}
		return Marshal(o)
	}

	// Unmarshal the given bytes into the given canonical format.
	err = json.Unmarshal(input, &canon)
	if err != nil {
		return nil, jsonErr(err)
	}

	return Marshal(canon)
}

// orderedObject marshals m as a JSON object in the order of keys.
type orderedObject struct {
	keys []string
	m    map[string]any
}

// MarshalJSONTo implements [json.MarshalerTo].
func (o orderedObject) MarshalJSONTo(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	for _, k := range o.keys {
		if err := enc.WriteToken(jsontext.String(k)); err != nil {
			return err
		}
		if err := json.MarshalEncode(enc, o.m[k]); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

// CanonicalHash accepts []byte and optional canon and returns digest.
//
// If input is already in canonical form, Hash() may also be called instead.
func CanonicalHash(input []byte, canon any, hash HshAlg) (digest B64, err error) {
	input, err = Canonical(input, canon)
	if err != nil {
		return nil, err
	}
	return Hash(hash, input)
}

// Compact is a helper that compactifies JSON. Errors on duplicates and invalid
// UTF-8.
func compact(msg jsontext.Value) ([]byte, error) {
	v := slices.Clone(msg)
	err := v.Compact(jsontext.AllowDuplicateNames(false), jsontext.AllowInvalidUTF8(false))
	if err != nil {
		return nil, jsonErr(err)
	}
	return v, nil
}
