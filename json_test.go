package coz

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// jsonGoldenUser is a third party struct used by the JSON golden tests.
type jsonGoldenUser struct {
	S  string
	N  int `json:",omitempty"`
	Z  int
	NS []string
	NM map[string]int
	B  []byte
}

// jsonGoldenEdKey is a deterministic Ed25519 key for golden signatures.
func jsonGoldenEdKey() *Key {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	k := &Key{Alg: SEAlg(Ed25519), Prv: B64(seed), Pub: B64(pub)}
	if err := k.Correct(); err != nil {
		panic(err)
	}
	return k
}

// jsonGoldenCases pins the exact bytes produced by Coz's JSON functions so
// that changes to the JSON implementation cannot silently change canonical
// output, digests, or signatures.
var jsonGoldenCases = []struct {
	name string
	f    func() ([]byte, error)
}{
	{"Marshal all runes", func() ([]byte, error) {
		h := sha256.New()
		for r := rune(0); r <= utf8.MaxRune; r++ {
			if !utf8.ValidRune(r) {
				continue
			}
			b, err := Marshal(string(r))
			if err != nil {
				return nil, err
			}
			h.Write(b)
		}
		return fmt.Appendf(nil, "%x", h.Sum(nil)), nil
	}},
	{"Marshal special characters", func() ([]byte, error) {
		return Marshal("<&> \u2028\u2029 \x00\x1f\x7f\t\n\"\\/ é\ufffd")
	}},
	{"Marshal map", func() ([]byte, error) {
		return Marshal(map[string]any{"z": 1, "a": []any{1, "<&>"}, "m": map[string]int{"y": 1, "b": 2}})
	}},
	{"Marshal numbers", func() ([]byte, error) {
		return Marshal([]any{nil, 1.0, 1e21, 1e-7, 0.1, 12345678901234567890.0, float32(0.1)})
	}},
	{"Marshal user struct", func() ([]byte, error) {
		return Marshal(jsonGoldenUser{S: "<&>\u2028", B: []byte{1, 2, 255}})
	}},
	{"MarshalPretty map", func() ([]byte, error) {
		return MarshalPretty(map[string]any{"z": 1, "e": map[string]any{}, "a": []any{}, "n": []any{map[string]any{"<": "&"}}})
	}},
	{"Marshal GoldenKey", func() ([]byte, error) { return Marshal(GoldenKey) }},
	{"MarshalPretty GoldenKey", func() ([]byte, error) { return MarshalPretty(GoldenKey) }},
	{"Marshal Params", func() ([]byte, error) { return Marshal(Alg(ES256).Params()) }},
	{"Marshal Pay", func() ([]byte, error) {
		return Marshal(&Pay{Alg: SEAlg(ES256), Now: 1623132000, Tmb: MustDecode(GoldenTmb), Typ: "<&>", Rvk: 1})
	}},
	{"Marshal Pay with typed Struct", func() ([]byte, error) {
		return Marshal(&Pay{Alg: SEAlg(ES256), Struct: &jsonGoldenUser{S: "<&>\u2028"}})
	}},
	{"Marshal Pay with map Struct", func() ([]byte, error) {
		return Marshal(&Pay{Alg: SEAlg(ES256), Struct: map[string]any{"z": 1, "a": "x"}})
	}},
	{"Marshal Pay round trip", func() ([]byte, error) {
		p := new(Pay)
		err := json.Unmarshal([]byte(`{"z":1,"alg":"ES256","a":"<&>","now":1,"m":{"b":1,"a":2}}`), p)
		if err != nil {
			return nil, err
		}
		return Marshal(p)
	}},
	{"Marshal Coz", func() ([]byte, error) {
		cz := new(Coz)
		if err := json.Unmarshal([]byte(GoldenCozWKey), cz); err != nil {
			return nil, err
		}
		return Marshal(cz)
	}},
	{"MarshalPretty Coz", func() ([]byte, error) {
		cz := new(Coz)
		if err := json.Unmarshal([]byte(GoldenCoz), cz); err != nil {
			return nil, err
		}
		return MarshalPretty(cz)
	}},
	{"Canon", func() ([]byte, error) {
		c, err := Canon([]byte(`{"z":1,"alg":"ES256","a":{"y":1,"b":2},"\u00e9":1}`))
		return fmt.Appendf(nil, "%q", c), err
	}},
	{"Canonical nil", func() ([]byte, error) {
		return Canonical([]byte(" {\"z\" : 1, \"a\":\"<&>\u2028\\u0041\", \"m\":{\"b\":1.0,\"a\":[ 1e3 ]}} "), nil)
	}},
	{"Canonical canon", func() ([]byte, error) {
		return Canonical([]byte(`{"z":1,"a":"<&>","m":{"b":1,"a":[2]},"x":"\u2028","n":1.0}`), []string{"m", "a", "x", "n", "missing"})
	}},
	{"Canonical struct", func() ([]byte, error) {
		return Canonical([]byte(`{"z":1,"msg":"<&>"}`), &CustomStruct{})
	}},
	{"Thumbprint", func() ([]byte, error) {
		t, err := Thumbprint(&GoldenKey)
		return []byte(t.String()), err
	}},
	{"Meta GoldenCoz", func() ([]byte, error) {
		cz := new(Coz)
		if err := json.Unmarshal([]byte(GoldenCoz), cz); err != nil {
			return nil, err
		}
		err := cz.Meta()
		return fmt.Appendf(nil, "%q %s %s", cz.Can, cz.Cad, cz.Czd), err
	}},
	{"Meta special characters", func() ([]byte, error) {
		cz := new(Coz)
		err := json.Unmarshal([]byte("{\"pay\":{\"alg\":\"ES256\",\"msg\":\"<&>\u2028\\u0041\",\"z\":{\"b\":1,\"a\":[]}},\"sig\":\"AA\"}"), cz)
		if err != nil {
			return nil, err
		}
		err = cz.Meta()
		return fmt.Appendf(nil, "%q %s %s", cz.Can, cz.Cad, cz.Czd), err
	}},
	{"Ed25519 SignPayRaw", func() ([]byte, error) {
		k := jsonGoldenEdKey()
		cz, err := k.SignPayRaw(&Pay{Alg: k.Alg, Tmb: k.Tmb, Now: 1, Typ: "<&>"})
		if err != nil {
			return nil, err
		}
		return Marshal(cz)
	}},
	{"Ed25519 SignPayRaw user struct", func() ([]byte, error) {
		k := jsonGoldenEdKey()
		cz, err := k.SignPayRaw(&Pay{Alg: k.Alg, Now: 1, Struct: &jsonGoldenUser{S: "a"}})
		if err != nil {
			return nil, err
		}
		return Marshal(cz)
	}},
	{"Ed25519 SignPayJSON", func() ([]byte, error) {
		k := jsonGoldenEdKey()
		cz, err := k.SignPayJSON([]byte("{\"alg\":\"Ed25519\", \"msg\":\"<&>\u2028\\u0041\",\"z\":{\"b\":1,\"a\":[]},\"n\":1.0}"))
		if err != nil {
			return nil, err
		}
		return Marshal(cz)
	}},
}

func TestJSONGolden(t *testing.T) {
	for _, c := range jsonGoldenCases {
		b, err := c.f()
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if string(b) != jsonGolden[c.name] {
			t.Errorf("%s:\n got: %q\nwant: %q", c.name, b, jsonGolden[c.name])
		}
	}
}

// TestJSONStrict tests that duplicates, invalid UTF-8, and trailing data
// error for every JSON input.
func TestJSONStrict(t *testing.T) {
	inputs := []struct {
		name, json, err string
	}{
		{"duplicate", `{"alg":"ES256","alg":"ES384"}`, `Coz: JSON duplicate field "alg"`},
		{"duplicate escaped", `{"alg":"ES256","\u0061lg":"ES384"}`, `Coz: JSON duplicate field "alg"`},
		{"duplicate nested", `{"a":{"b":1,"b":2}}`, `Coz: JSON duplicate field "b"`},
		{"duplicate in array", `{"a":[1,{"b":1,"b":2}]}`, `Coz: JSON duplicate field "b"`},
		{"invalid UTF-8 value", "{\"a\":\"\xff\"}", "invalid UTF-8"},
		{"invalid UTF-8 name", "{\"\xff\":1}", "invalid UTF-8"},
		{"lone surrogate", `{"a":"\ud800"}`, "invalid surrogate pair"},
		{"reversed surrogates", `{"a":"\udc00\ud800"}`, "invalid surrogate pair"},
		{"trailing data", `{"a":1} {"b":2}`, "after top-level value"},
	}
	funcs := []struct {
		name string
		f    func([]byte) error
	}{
		{"json.Unmarshal Pay", func(b []byte) error { return json.Unmarshal(b, new(Pay)) }},
		{"json.Unmarshal typed Pay", func(b []byte) error { return json.Unmarshal(b, &Pay{Struct: &CustomStruct{}}) }},
		{"json.Unmarshal Key", func(b []byte) error { return json.Unmarshal(b, new(Key)) }},
		{"json.Unmarshal Coz", func(b []byte) error { return json.Unmarshal(b, new(Coz)) }},
		{"json.Unmarshal Coz pay", func(b []byte) error {
			return json.Unmarshal(slices.Concat([]byte(`{"pay":`), b, []byte(`}`)), new(Coz))
		}},
		{"Canon", func(b []byte) error { _, err := Canon(b); return err }},
		{"Canonical nil", func(b []byte) error { _, err := Canonical(b, nil); return err }},
		{"Canonical canon", func(b []byte) error { _, err := Canonical(b, []string{"a"}); return err }},
		{"Canonical struct", func(b []byte) error { _, err := Canonical(b, &CustomStruct{}); return err }},
		{"Meta", func(b []byte) error { return (&Coz{Pay: b, Sig: MustDecode(GoldenSig)}).Meta() }},
		{"SignPayJSON", func(b []byte) error { _, err := GoldenKey.SignPayJSON(b); return err }},
		{"VerifyCoz", func(b []byte) error {
			_, err := GoldenKey.VerifyCoz(&Coz{Pay: b, Sig: MustDecode(GoldenSig)})
			return err
		}},
	}
	for _, in := range inputs {
		for _, f := range funcs {
			if f.name == "json.Unmarshal Coz pay" && in.name == "trailing data" {
				continue // Not trailing data inside of a coz.
			}
			err := f.f([]byte(in.json))
			if err == nil || !strings.Contains(err.Error(), in.err) {
				t.Errorf("%s: %s: want error containing %q, got: %v", f.name, in.name, in.err, err)
			}
		}
	}

	// Marshal errors on invalid UTF-8 instead of replacing it with U+FFFD.
	if _, err := Marshal("a\xffb"); err == nil {
		t.Error("Marshal: invalid UTF-8 should error")
	}
	if _, err := Marshal(Pay{Typ: "a\xffb"}); err == nil {
		t.Error("Marshal Pay: invalid UTF-8 should error")
	}
}

// TestJSONCaseSensitive tests that field names are case-sensitive, so that a
// name like "ALG" or "Alg" cannot be parsed as "alg".
func TestJSONCaseSensitive(t *testing.T) {
	for in, alg := range map[string]SEAlg{
		`{"alg":"ES256","ALG":"ES384"}`: SEAlg(ES256),
		`{"ALG":"ES384","alg":"ES256"}`: SEAlg(ES256),
		`{"Alg":"ES256"}`:               "",
	} {
		p := new(Pay)
		if err := json.Unmarshal([]byte(in), p); err != nil {
			t.Fatal(err)
		}
		if p.Alg != alg {
			t.Errorf("%s: got alg %q, want %q", in, p.Alg, alg)
		}
		cz := new(Coz)
		if err := json.Unmarshal([]byte(`{"pay":`+in+`,"sig":"AA"}`), cz); err != nil {
			t.Fatal(err)
		}
		err := cz.Meta()
		if alg == "" && err == nil {
			t.Errorf("%s: Meta without alg should error", in)
		}
		if alg != "" && (err != nil || cz.Parsed.Alg != alg) {
			t.Errorf("%s: Meta got alg %q, err %v, want %q", in, cz.Parsed.Alg, err, alg)
		}
	}
	cz := new(Coz)
	if err := json.Unmarshal([]byte(`{"Pay":{"alg":"ES256"},"SIG":"AA"}`), cz); err != nil {
		t.Fatal(err)
	}
	if cz.Pay != nil || cz.Sig != nil {
		t.Errorf("Coz fields should be case-sensitive, got: %s", cz)
	}
}

// TestJSONHTML tests that "<", ">", and "&" are not escaped and that there is
// no trailing newline.
func TestJSONHTML(t *testing.T) {
	want := `{"alg":"ES256","typ":"<&>"}`
	p := &Pay{Alg: SEAlg(ES256), Typ: "<&>"}
	for name, f := range map[string]func() ([]byte, error){
		"Marshal":         func() ([]byte, error) { return Marshal(p) },
		"Pay.MarshalJSON": p.MarshalJSON,
		"Canonical nil":   func() ([]byte, error) { return Canonical([]byte(want), nil) },
		"Canonical canon": func() ([]byte, error) { return Canonical([]byte(want), []string{"alg", "typ"}) },
		"Canonical struct": func() ([]byte, error) {
			return Canonical([]byte(want), &struct {
				Alg string `json:"alg"`
				Typ string `json:"typ"`
			}{})
		},
	} {
		b, err := f()
		if err != nil {
			t.Fatal(name, err)
		}
		if string(b) != want {
			t.Errorf("%s: got %s, want %s", name, b, want)
		}
	}
	b, err := Marshal(&Pay{Struct: &CustomStruct{Msg: "<&>"}})
	if err != nil || string(b) != `{"msg":"<&>"}` {
		t.Errorf("Marshal Pay.Struct: got %s, %v", b, err)
	}
	b, err = MarshalPretty(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"<&>"`)) || bytes.HasSuffix(b, []byte("\n")) {
		t.Errorf("MarshalPretty: got %q", b)
	}
}

// TestJSONOrder tests that field order is preserved.
func TestJSONOrder(t *testing.T) {
	in := []byte(`{"z":1,"alg":"ES256","a":{"y":1,"b":2},"m":[3,1],"now":1}`)
	want := []string{"z", "alg", "a", "m", "now"}
	can, err := Canon(in)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(can, want) {
		t.Errorf("Canon: got %q, want %q", can, want)
	}

	p := new(Pay)
	if err = json.Unmarshal(in, p); err != nil {
		t.Fatal(err)
	}
	b, err := Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if can, _ = Canon(b); !slices.Equal(can, want) {
		t.Errorf("Pay round trip: got %q, want %q", can, want)
	}

	b, err = Canonical(in, []string{"now", "missing", "z", "now"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"now":1,"z":1}` {
		t.Errorf("Canonical: got %s", b)
	}

	cz := &Coz{Pay: in, Sig: MustDecode(GoldenSig)}
	if err = cz.Meta(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cz.Can, want) {
		t.Errorf("Meta: got %q, want %q", cz.Can, want)
	}
}

// TestCanonNotObject tests that non-object JSON errors instead of panicking.
func TestCanonNotObject(t *testing.T) {
	for _, in := range []string{`null`, `[]`, `"a"`, `1`} {
		if _, err := Canon([]byte(in)); err == nil {
			t.Errorf("Canon(%s) should error", in)
		}
		cz := new(Coz)
		if err := json.Unmarshal([]byte(`{"pay":`+in+`,"sig":"AA"}`), cz); err != nil {
			continue
		}
		if err := cz.MetaWithAlg(SEAlg(ES256)); err == nil {
			t.Errorf("Meta with pay %s should error", in)
		}
	}
}

// TestPayMarshalStruct tests Pay with an empty Pay or an empty Struct.
func TestPayMarshalStruct(t *testing.T) {
	for in, want := range map[string]string{
		`{"a":1}`:               `{"a":1}`,
		`{"a":1,"alg":"ES256"}`: `{"a":1,"alg":"ES256"}`,
		`{"alg":"ES256"}`:       `{"alg":"ES256"}`,
		`{}`:                    `{}`,
	} {
		p := new(Pay)
		if err := json.Unmarshal([]byte(in), p); err != nil {
			t.Fatal(err)
		}
		b, err := Marshal(p)
		if err != nil || string(b) != want {
			t.Errorf("%s: got %s, %v, want %s", in, b, err, want)
		}
	}
	for _, s := range []any{map[string]any{}, &struct{}{}} {
		b, err := Marshal(&Pay{Alg: SEAlg(ES256), Struct: s})
		if err != nil || string(b) != `{"alg":"ES256"}` {
			t.Errorf("%T: got %s, %v", s, b, err)
		}
		b, err = Marshal(&Pay{Struct: s})
		if err != nil || string(b) != `{}` {
			t.Errorf("%T: got %s, %v", s, b, err)
		}
	}
	for _, s := range []any{(*CustomStruct)(nil), []int{1}, map[string]any{"alg": "ES384"}} {
		if b, err := Marshal(&Pay{Alg: SEAlg(ES256), Struct: s}); err == nil {
			t.Errorf("%T: should error, got %s", s, b)
		}
	}
}

// jsonGolden was generated from the encoding/json (v1) implementation.
var jsonGolden = map[string]string{
	"Marshal all runes":              "ae6d9cc0986cec05302180c9d6f278e9cab5b54998db9d37f50ad867d6897081",
	"Marshal special characters":     "\"<&> \\u2028\\u2029 \\u0000\\u001f\x7f\\t\\n\\\"\\\\/ é�\"",
	"Marshal map":                    "{\"a\":[1,\"<&>\"],\"m\":{\"b\":2,\"y\":1},\"z\":1}",
	"Marshal numbers":                "[null,1,1e+21,1e-7,0.1,12345678901234567000,0.1]",
	"Marshal user struct":            "{\"S\":\"<&>\\u2028\",\"Z\":0,\"NS\":null,\"NM\":null,\"B\":\"AQL/\"}",
	"MarshalPretty map":              "{\n    \"a\": [],\n    \"e\": {},\n    \"n\": [\n        {\n            \"<\": \"&\"\n        }\n    ],\n    \"z\": 1\n}",
	"Marshal GoldenKey":              "{\"alg\":\"ES256\",\"prv\":\"bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA\",\"now\":1623132000,\"tag\":\"Zami's Majuscule Key.\",\"tmb\":\"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg\",\"pub\":\"2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g\"}",
	"MarshalPretty GoldenKey":        "{\n    \"alg\": \"ES256\",\n    \"prv\": \"bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA\",\n    \"now\": 1623132000,\n    \"tag\": \"Zami's Majuscule Key.\",\n    \"tmb\": \"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg\",\n    \"pub\": \"2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g\"\n}",
	"Marshal Params":                 "{\"Name\":\"ES256\",\"Genus\":\"ECDSA\",\"Family\":\"EC\",\"Use\":\"sig\",\"Hash\":\"SHA-256\",\"HashSize\":32,\"HashSizeB64\":43,\"PubSize\":64,\"PubSizeB64\":86,\"PrvSize\":32,\"PrvSizeB64\":43,\"Curve\":\"P-256\",\"SigSize\":64,\"SigSizeB64\":86}",
	"Marshal Pay":                    "{\"alg\":\"ES256\",\"now\":1623132000,\"tmb\":\"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg\",\"typ\":\"<&>\",\"rvk\":1}",
	"Marshal Pay with typed Struct":  "{\"alg\":\"ES256\",\"S\":\"<&>\\u2028\",\"Z\":0,\"NS\":null,\"NM\":null,\"B\":null}",
	"Marshal Pay with map Struct":    "{\"alg\":\"ES256\",\"a\":\"x\",\"z\":1}",
	"Marshal Pay round trip":         "{\"z\":1,\"alg\":\"ES256\",\"a\":\"<&>\",\"now\":1,\"m\":{\"a\":2,\"b\":1}}",
	"Marshal Coz":                    "{\"pay\":{\"msg\":\"Coz is a cryptographic JSON messaging specification.\",\"alg\":\"ES256\",\"now\":1623132000,\"tmb\":\"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg\",\"typ\":\"cyphr.me/msg/create\"},\"key\":{\"alg\":\"ES256\",\"prv\":\"bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA\",\"now\":1623132000,\"tag\":\"Zami's Majuscule Key.\",\"tmb\":\"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg\",\"pub\":\"2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g\"},\"sig\":\"OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg\"}",
	"MarshalPretty Coz":              "{\n    \"pay\": {\n        \"msg\": \"Coz is a cryptographic JSON messaging specification.\",\n        \"alg\": \"ES256\",\n        \"now\": 1623132000,\n        \"tmb\": \"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg\",\n        \"typ\": \"cyphr.me/msg/create\"\n    },\n    \"sig\": \"OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg\"\n}",
	"Canon":                          "[\"z\" \"alg\" \"a\" \"é\"]",
	"Canonical nil":                  "{\"z\":1,\"a\":\"<&>\u2028\\u0041\",\"m\":{\"b\":1.0,\"a\":[1e3]}}",
	"Canonical canon":                "{\"m\":{\"a\":[2],\"b\":1},\"a\":\"<&>\",\"x\":\"\\u2028\",\"n\":1}",
	"Canonical struct":               "{\"msg\":\"<&>\"}",
	"Thumbprint":                     "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
	"Meta GoldenCoz":                 "[\"msg\" \"alg\" \"now\" \"tmb\" \"typ\"] XzrXMGnY0QFwAKkr43Hh-Ku3yUS8NVE0BdzSlMLSuTU xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo",
	"Meta special characters":        "[\"alg\" \"msg\" \"z\"] G1r6xXG1Stwa6KgHREPwwePqfAHMvYW0KhOhR8-l_T8 yn9Pd855puw35kvq6clWC2I83s-kHTxkY0z6BGOaGME",
	"Ed25519 SignPayRaw":             "{\"pay\":{\"alg\":\"Ed25519\",\"now\":1,\"tmb\":\"O_rHz3mCqb4PEacPyeprz7tyES2wUhZdusPKGiJ41j9OK2e8IZv-Yyx6oNiUU0XjUaIs1XFaogi8j5FS6AZu8A\",\"typ\":\"<&>\"},\"sig\":\"ENtkQxQFhsUkLGqU2i904DL1ByKOr4aXJ2kiYCMwOZ6nL5DtLJCcP_pUYriZ7g9sRUqSH6fSSnaqXa2wo5VnBQ\"}",
	"Ed25519 SignPayRaw user struct": "{\"pay\":{\"alg\":\"Ed25519\",\"now\":1,\"S\":\"a\",\"Z\":0,\"NS\":null,\"NM\":null,\"B\":null},\"sig\":\"khi6Z9grKHd-DRjmVKK8lnl50AibuPICiOCYTdkE5cIfIaNdBpy3YBBgUk6wcDrmXHcA_I9dq0DVdabNIAN6Cg\"}",
	"Ed25519 SignPayJSON":            "{\"pay\":{\"alg\":\"Ed25519\",\"msg\":\"<&>\\u2028\\u0041\",\"z\":{\"b\":1,\"a\":[]},\"n\":1.0},\"sig\":\"Ly-WLExh5PNRHi6MWyMZMeqs4aR8E_q7O_S29n4tEFcVy8zI1K4-IQ0d7QwMF3Q0TKQcmJuZj3ELik1u9s56AA\"}",
}
