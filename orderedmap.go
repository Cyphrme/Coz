// orderedMap is used because encoding/json has no way to preserve the order of
// map keys. See https://github.com/golang/go/issues/27179.
//
// Using JSONv2 is the future goal, which solves field order, other issues,
// and has other best practices.When Go Coz is migrated to JSONv2, as long as
// JSONv2 provides ordering, orderedMap will be deprecated. See
// https://github.com/Cyphrme/Coz/issues/15

// The MIT License (MIT)
//
// Copyright (c) 2023 Cypherpunk LLC and contributors
// Copyright (c) 2017 Ian Coleman
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, Subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or Substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package coz

import (
	"bytes"
	"encoding/json"
	"sort"
)

type pair struct {
	key   string
	value any
}

func (kv *pair) Key() string {
	return kv.key
}

func (kv *pair) Value() any {
	return kv.value
}

type byPair struct {
	Pairs    []*pair
	LessFunc func(a *pair, j *pair) bool
}

func (a byPair) Len() int           { return len(a.Pairs) }
func (a byPair) Swap(i, j int)      { a.Pairs[i], a.Pairs[j] = a.Pairs[j], a.Pairs[i] }
func (a byPair) Less(i, j int) bool { return a.LessFunc(a.Pairs[i], a.Pairs[j]) }

type orderedMap struct {
	keys   []string
	values map[string]any
}

func newOrderedMap() *orderedMap {
	o := orderedMap{}
	o.keys = []string{}
	o.values = map[string]any{}
	return &o
}

func (o *orderedMap) Get(key string) (any, bool) {
	val, ok := o.values[key]
	return val, ok
}

func (o *orderedMap) Set(key string, value any) {
	_, ok := o.values[key]
	if !ok {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

func (o *orderedMap) Delete(key string) {
	// check key is in use
	_, ok := o.values[key]
	if !ok {
		return
	}
	// remove from keys
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
	// remove from values
	delete(o.values, key)
}

func (o *orderedMap) Keys() []string {
	return o.keys
}

func (o *orderedMap) Values() []any {
	v := make([]any, len(o.keys))
	for i, k := range o.keys {
		v[i] = o.values[k]
	}
	return v
}

// SortKeys sorts the map keys using the provided sort func.
func (o *orderedMap) SortKeys(sortFunc func(keys []string)) {
	sortFunc(o.keys)
}

// Sort sorts the map using the provided less func.
func (o *orderedMap) Sort(lessFunc func(a *pair, b *pair) bool) {
	pairs := make([]*pair, len(o.keys))
	for i, key := range o.keys {
		pairs[i] = &pair{key, o.values[key]}
	}

	sort.Sort(byPair{pairs, lessFunc})

	for i, pair := range pairs {
		o.keys[i] = pair.key
	}
}

// MarshalJSON must return no duplicates, and should since orderedMap keys are
// unique.
func (o orderedMap) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		// add key
		if err := encoder.Encode(k); err != nil {
			return nil, err
		}
		buf.WriteByte(':')
		// add value
		if err := encoder.Encode(o.values[k]); err != nil {
			return nil, err
		}
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func (o *orderedMap) UnmarshalJSON(b []byte) error {
	// Ensure that there were no duplicates fields.  JSON should error on
	// duplicates. "Last value wins" is bad practice.  See
	// https://esdiscuss.org/topic/json-duplicate-keys and the Coz docs on
	// duplicate JSON keys.
	_, err := checkDuplicate(json.NewDecoder(bytes.NewReader(b)))
	if err != nil {
		return err
	}

	if o.values == nil {
		o.values = map[string]any{}
	}
	err = json.Unmarshal(b, &o.values)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if _, err = dec.Token(); err != nil { // skip '{'
		return err
	}
	o.keys = make([]string, 0, len(o.values))
	return decodeOrderedMap(dec, o)
}

// decodeOrderedMap
func decodeOrderedMap(dec *json.Decoder, o *orderedMap) error {
	hasKey := make(map[string]bool, len(o.values))
	for {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok && delim == '}' {
			return nil
		}
		key := token.(string)
		if hasKey[key] {
			// duplicate key
			for j, k := range o.keys {
				if k == key {
					copy(o.keys[j:], o.keys[j+1:])
					break
				}
			}
			o.keys[len(o.keys)-1] = key
		} else {
			hasKey[key] = true
			o.keys = append(o.keys, key)
		}

		token, err = dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				if values, ok := o.values[key].(map[string]any); ok {
					newMap := orderedMap{
						keys:   make([]string, 0, len(values)),
						values: values,
					}
					if err = decodeOrderedMap(dec, &newMap); err != nil {
						return err
					}
					o.values[key] = newMap
				} else if oldMap, ok := o.values[key].(orderedMap); ok {
					newMap := orderedMap{
						keys:   make([]string, 0, len(oldMap.values)),
						values: oldMap.values,
					}
					if err = decodeOrderedMap(dec, &newMap); err != nil {
						return err
					}
					o.values[key] = newMap
				} else if err = decodeOrderedMap(dec, &orderedMap{}); err != nil {
					return err
				}
			case '[':
				if values, ok := o.values[key].([]any); ok {
					if err = decodeSlice(dec, values); err != nil {
						return err
					}
				} else if err = decodeSlice(dec, []any{}); err != nil {
					return err
				}
			}
		}
	}
}

func decodeSlice(dec *json.Decoder, s []any) error {
	for index := 0; ; index++ {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				if index < len(s) {
					if values, ok := s[index].(map[string]any); ok {
						newMap := orderedMap{
							keys:   make([]string, 0, len(values)),
							values: values,
						}
						if err = decodeOrderedMap(dec, &newMap); err != nil {
							return err
						}
						s[index] = newMap
					} else if oldMap, ok := s[index].(orderedMap); ok {
						newMap := orderedMap{
							keys:   make([]string, 0, len(oldMap.values)),
							values: oldMap.values,
						}
						if err = decodeOrderedMap(dec, &newMap); err != nil {
							return err
						}
						s[index] = newMap
					} else if err = decodeOrderedMap(dec, &orderedMap{}); err != nil {
						return err
					}
				} else if err = decodeOrderedMap(dec, &orderedMap{}); err != nil {
					return err
				}
			case '[':
				if index < len(s) {
					if values, ok := s[index].([]any); ok {
						if err = decodeSlice(dec, values); err != nil {
							return err
						}
					} else if err = decodeSlice(dec, []any{}); err != nil {
						return err
					}
				} else if err = decodeSlice(dec, []any{}); err != nil {
					return err
				}
			case ']':
				return nil
			}
		}
	}
}
