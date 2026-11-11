package coz

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
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
	"Marshal Pay with typed Struct":  "{\"alg\":\"ES256\",\"S\":\"\\u003c\\u0026\\u003e\\u2028\",\"Z\":0,\"NS\":null,\"NM\":null,\"B\":null}",
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
