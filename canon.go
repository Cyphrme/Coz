package coz

import (
	"bytes"
	"encoding/json"
)

// Canon returns the current canon from raw JSON.
//
// It returns only top level fields with no recursion or promotion of embedded
// fields.
func Canon(raw json.RawMessage) (can []string, err error) {
	o := newOrderedMap()
	err = json.Unmarshal(raw, &o)
	if err != nil {
		return nil, err
	}
	return o.Keys(), nil
}

// Canonical returns the canonical form. Input canon is optional and may be nil.
// If canon is nil, input JSON is only compactified.
//
// Interface "canon" may be `[]string`, `struct“, or `nil`.  If "canon" is a
// struct or slice it must be properly ordered.  If canon is nil, json.Unmarshal
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
		// Unmarshal into a map to get all values, then insert into orderedMap
		// in canon order so that Marshal emits keys in the correct sequence.
		m := make(map[string]any)
		err = json.Unmarshal(input, &m)
		if err != nil {
			return nil, err
		}

		om := newOrderedMap()
		for i := 0; i < len(s); i++ {
			if val, ok := m[s[i]]; ok {
				om.Set(s[i], val)
			}
		}

		return Marshal(om)
	}

	// Unmarshal the given bytes into the given canonical format.
	err = json.Unmarshal(input, &canon)
	if err != nil {
		return nil, err
	}

	return Marshal(canon)
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

// Compact is a helper that compactifies JSON.
func compact(msg json.RawMessage) ([]byte, error) {
	var b bytes.Buffer
	err := json.Compact(&b, msg)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
