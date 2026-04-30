package coz

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// ExampleCoz_verifyBinary demonstrates verifying the README's example coz where
// there is a reference to an external binary payload.
func ExampleCoz_verifyBinary() {
	var goldenVerifyBinary = json.RawMessage(`{
 "pay": {
  "alg": "ES256",
  "file_name": "coz_logo_icon_256.png",
  "id": "oDBDAg4xplHQby6iQ2lZMS1Jz4Op0bNoD5LK3KxEUZo",
  "now": 1623132000,
  "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
  "typ": "cyphr.me/file/create"
 },
 "sig": "AV_gPaDCEd9OEyA1oZPo7LwpypzXkk2htmA-bEobpmcA4Vc7xNcaFPVaEBgU8DDCAZcQZcBHgRlOIjNk9g-Mkw"
}`)

	coz := new(Coz)
	err := json.Unmarshal(goldenVerifyBinary, coz)
	if err != nil {
		panic(err)
	}

	fmt.Println(GoldenKey.VerifyCoz(coz))
	// Output:
	// true <nil>
}

func ExamplePay_embedded() {
	// Example custom struct.
	type User struct {
		DisplayName string
		FirstName   string
		LastName    string
		Email       string `json:",omitempty"` // Example of non-required field.
	}

	user := User{
		DisplayName: "Coz",
		FirstName:   "Foo",
		LastName:    "Bar",
	}

	// Example of converting a custom struct to a coz.
	pay := Pay{
		Alg:    GoldenKey.Alg,
		Tmb:    GoldenKey.Tmb,
		Struct: &user,
	}

	coz, err := GoldenKey.SignPay(&pay)
	if err != nil {
		panic(err)
	}

	v, err := GoldenKey.VerifyCoz(coz)
	if err != nil {
		panic(err)
	}

	// Set sig to nil for deterministic printout
	coz.Sig = nil
	fmt.Println(v)
	fmt.Printf("%+v\n", coz)

	// Output:
	// true
	// {"pay":{"alg":"ES256","tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","DisplayName":"Coz","FirstName":"Foo","LastName":"Bar"}}
}

// ExamplePay_dig demonstrates using the `dig` (digest) field in a coz payload.
// `dig` is used to reference external content by its digest. The digest
// algorithm must match `pay.alg`'s hash (e.g., ES256 uses SHA-256).
func ExamplePay_dig() {
	// Content whose digest will be included in the payload.
	content := "Coz is a cryptographic JSON messaging specification."

	// Calculate the SHA-256 digest of the content.
	// ES256's hash algorithm is SHA-256, so dig's algorithm matches alg.
	dig, err := Hash(SHA256, []byte(content))
	if err != nil {
		panic(err)
	}

	// Custom struct with a dig field for the digest.
	type PayWithDig struct {
		Dig B64 `json:"dig,omitempty"`
	}

	pay := Pay{
		Alg:    GoldenKey.Alg,
		Tmb:    GoldenKey.Tmb,
		Typ:    "cyphr.me/file",
		Struct: &PayWithDig{Dig: dig},
	}

	coz, err := GoldenKey.SignPay(&pay)
	if err != nil {
		panic(err)
	}

	v, err := GoldenKey.VerifyCoz(coz)
	if err != nil {
		panic(err)
	}

	// Set sig to nil for deterministic printout
	coz.Sig = nil
	fmt.Println(v)
	fmt.Println(coz)

	// Output:
	// true
	// {"pay":{"alg":"ES256","tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/file","dig":"YBG8cU5hkhPdyEJDhRB0Qk90NZuU0B34dnMQbkFMtBI"}}
}

// ExamplePay_jsonUnmarshal tests round trip unmarshalling a Pay (with "custom"
// type `msg`, which does not appear in Pay; there is no Pay.MSG).  Round trip
// unmarshal, marshal, and unmarshal again. Also tests order for type Pay (not
// type Coz);  GoldenPay's order is `msg`, `alg`, `now`, `tmb`, `typ`.
func ExamplePay_jsonUnmarshal() {
	pay := &Pay{}
	err := json.Unmarshal([]byte(GoldenPay), pay)
	if err != nil {
		panic(err)
	}

	marshaled, err := json.Marshal(pay)
	if err != nil {
		panic(err)
	}

	// And one last round trip Unmarshal
	roundTrip := &Pay{}
	err = json.Unmarshal(marshaled, roundTrip)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", marshaled)
	fmt.Printf("%s\n", roundTrip)

	// Output:
	// {"msg":"Coz is a cryptographic JSON messaging specification.","alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create"}
	// {"msg":"Coz is a cryptographic JSON messaging specification.","alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create"}
}

// ExamplePay_jsonUnmarshalCustomManual demonstrates "manually" unmarshalling,
// that is calling package json.Unmarshal instead of the Coz helpers. This test
// requires Pay.Struct to be properly populated from an json.Unmarshal.
func ExamplePay_jsonUnmarshalCustomManual() {
	var pay Pay
	err := json.Unmarshal([]byte(GoldenPay), &pay)
	if err != nil {
		panic(err)
	}
	fmt.Println(pay)

	// Output:
	// {"msg":"Coz is a cryptographic JSON messaging specification.","alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create"}
}

// ExamplePay_jsonMarshalCustom demonstrates marshalling Pay with a custom
// structure.
func ExamplePay_jsonMarshalCustom() {
	customStruct := CustomStruct{
		Msg: "Coz is a cryptographic JSON messaging specification.",
	}

	inputPay := Pay{
		Alg:    SEAlg(ES256),
		Now:    1623132000, // Static for demonstration.  Use time.Now().Unix().
		Tmb:    MustDecode("U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"),
		Typ:    "cyphr.me/msg/create",
		Struct: customStruct,
	}

	// May also call inputPay.MarshalJSON() or Marshal(&inputPay) instead.
	s, err := Marshal(&inputPay)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(s))

	// Output:
	// {"alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create","msg":"Coz is a cryptographic JSON messaging specification."}
}

// ExamplePay_jsonUnmarshalCustom demonstrates unmarshalling Pay with a custom
// structure.
func ExamplePay_jsonUnmarshalCustom() {
	pay := new(Pay)
	var emptyCustomStruct CustomStruct
	pay.Struct = &emptyCustomStruct
	err := json.Unmarshal([]byte(GoldenPay), &pay)
	if err != nil {
		fmt.Printf("Unmarshal error: %s\n", err)
	}
	fmt.Println(pay)
	fmt.Println(pay.Struct)

	// Output:
	// {"alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create","msg":"Coz is a cryptographic JSON messaging specification."}
	// &{Coz is a cryptographic JSON messaging specification.}
}

// ExamplePay_String_custom demonstrates fmt.Stringer on Pay with a custom
// structure.
func ExamplePay_String_custom() {
	customStruct := CustomStruct{
		Msg: "Coz is a cryptographic JSON messaging specification.",
	}

	inputPay := Pay{
		Alg:    SEAlg(ES256),
		Now:    1623132000, // Static for demonstration.  Use time.Now().Unix().
		Tmb:    MustDecode("U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"),
		Typ:    "cyphr.me/msg/create",
		Struct: customStruct,
	}
	fmt.Println(inputPay)

	// Output:
	// {"alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create","msg":"Coz is a cryptographic JSON messaging specification."}
}

// Example demonstrating that unmarshalling a `pay` that has duplicate field
// names results in an error.
func ExamplePay_UnmarshalJSON_duplicate() {
	h := &Pay{}
	msg := []byte(`{"alg":"ES256","alg":"ES384"}`)
	err := json.Unmarshal(msg, h)
	fmt.Println(err)

	// Output:
	// Coz: JSON duplicate field "alg"
}

// Example demonstrating that unmarshalling a `coz` that has duplicate field
// names results in an error.
func ExampleCoz_UnmarshalJSON_duplicate() {
	h := &Pay{}
	msg := []byte(`{"coz":{"pay":"ES256","pay":"ES384"}}`)
	err := json.Unmarshal(msg, h)
	fmt.Println(err)

	// Output:
	// Coz: JSON duplicate field "pay"
}

// ExampleCoz_embed demonstrates how to embed a JSON `coz` into a third party
// JSON structure.
func ExampleCoz_embed() {
	cz := new(Coz)
	err := json.Unmarshal([]byte(GoldenCoz), cz)
	if err != nil {
		panic(err)
	}

	type Outer struct {
		Name string `json:"name"`
		Coz  Coz    `json:"coz"` // Embed a Coz into a larger, application defined JSON structure.
	}
	b, _ := json.Marshal(Outer{Name: "Bob", Coz: *cz})
	fmt.Printf("%s", b)

	// Output:
	// {"name":"Bob","coz":{"pay":{"msg":"Coz is a cryptographic JSON messaging specification.","alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create"},"sig":"OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg"}}
}

func ExampleCoz_String() {
	cz := new(Coz)
	err := json.Unmarshal([]byte(GoldenCoz), cz)
	if err != nil {
		panic(err)
	}
	fmt.Println(cz)

	// Output:
	// {"pay":{"msg":"Coz is a cryptographic JSON messaging specification.","alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create"},"sig":"OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg"}
}

// TestPay_SignPayJSON_CustomFields tests that custom fields in a JSON payload
// are preserved when SignPayJSON auto-updates the "now" field.
// TODO I think we can test order on this as well.
func TestPay_SignPayJSON_CustomFields(t *testing.T) {
	// A JSON payload with an arbitrary custom field "custom_field".
	payJSON := json.RawMessage([]byte(`{
		"alg": "ES256",
		"now": 1000,
		"tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
		"typ": "cyphr.me/test",
		"msg": "Coz custom field test",
		"custom_field": "should be preserved"
	}`))

	coz, err := GoldenKey.SignPayJSON(payJSON)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the signature.
	valid, err := GoldenKey.VerifyCoz(coz)
	if !valid || err != nil {
		t.Fatalf("Coz failed to verify: %v", err)
	}

	// Verify "custom_field" is still in the payload.
	var payMap map[string]interface{}
	if err := json.Unmarshal(coz.Pay, &payMap); err != nil {
		t.Fatal(err)
	}

	if val, ok := payMap["custom_field"]; !ok || val != "should be preserved" {
		t.Errorf("Custom field was dropped or modified: %v", payMap)
	}

	// Verify "now" was updated.
	if now, ok := payMap["now"].(float64); !ok || int64(now) <= 1000 {
		t.Errorf("Now field was not updated correctly: %v", payMap["now"])
	}
}

// TestPay_SignPayJSON_FieldOrder tests that SignPayJSON preserves the byte-level
// field ordering of the input payload after the "now" auto-update.  Custom
// fields are deliberately anti-alphabetical ("z_last" before "a_first") so that
// any map-based remarshal will detectably reorder them.
func TestPay_SignPayJSON_FieldOrder(t *testing.T) {
	payJSON := json.RawMessage([]byte(`{
		"alg": "ES256",
		"now": 1000,
		"tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
		"typ": "cyphr.me/test",
		"z_last": "should appear first",
		"a_first": "should appear second"
	}`))

	cz, err := GoldenKey.SignPayJSON(payJSON)
	if err != nil {
		t.Fatal(err)
	}

	// Verify signature is valid.
	valid, err := GoldenKey.VerifyCoz(cz)
	if !valid || err != nil {
		t.Fatalf("Coz failed to verify: %v", err)
	}

	out := string(cz.Pay)

	// Verify both custom fields are present.
	if !strings.Contains(out, `"z_last"`) {
		t.Fatalf("z_last field dropped from payload: %s", out)
	}
	if !strings.Contains(out, `"a_first"`) {
		t.Fatalf("a_first field dropped from payload: %s", out)
	}

	// Verify field ordering: "z_last" must appear before "a_first" in the
	// output bytes, matching the input order.  If SignPayJSON round-trips
	// through a map, Go's json.Marshal will alphabetize the keys and this
	// assertion will fail.
	zIdx := strings.Index(out, `"z_last"`)
	aIdx := strings.Index(out, `"a_first"`)
	if zIdx >= aIdx {
		t.Errorf("SignPayJSON destroyed field order: z_last at byte %d, a_first at byte %d.\nPayload: %s", zIdx, aIdx, out)
	}

	// Verify "now" was updated (not the original seed value).
	var payMap map[string]interface{}
	if err := json.Unmarshal(cz.Pay, &payMap); err != nil {
		t.Fatal(err)
	}
	if now, ok := payMap["now"].(float64); !ok || int64(now) <= 1000 {
		t.Errorf("Now field was not updated correctly: %v", payMap["now"])
	}
}

func ExampleCoz_Meta() {
	cz := new(Coz)
	err := json.Unmarshal([]byte(GoldenCoz), cz)
	if err != nil {
		panic(err)
	}

	err = cz.Meta()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", cz)

	// Output:
	//{"pay":{"msg":"Coz is a cryptographic JSON messaging specification.","alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create"},"can":["msg","alg","now","tmb","typ"],"cad":"XzrXMGnY0QFwAKkr43Hh-Ku3yUS8NVE0BdzSlMLSuTU","sig":"OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg","czd":"xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo"}
}

func ExampleCoz_MetaWithAlg() {
	cz := new(Coz)
	err := json.Unmarshal([]byte(GoldenCoz), cz)
	if err != nil {
		panic(err)
	}

	// coz.pay.alg given and parameter alg given.
	err = cz.MetaWithAlg(SEAlg(ES256))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", cz)

	// coz.pay.alg given and parameter alg not given.  (Alg is parsed from pay).
	err = cz.MetaWithAlg("")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", cz)

	// Test mismatch alg, which must error.
	err = cz.MetaWithAlg(SEAlg(ES224))
	if err == nil {
		fmt.Println("Test must error")
	}

	// Test no coz.pay.alg or alg given, which must error.
	// Will error with Hash: invalid HshAlg "UnknownHshAlg")
	cz2 := new(Coz)
	err = json.Unmarshal(GoldenCozNoAlg, cz2)
	if err != nil {
		panic(err)
	}
	err = cz2.Meta()
	if err == nil {
		fmt.Println("Test must error")
	}

	// Test no coz.pay.alg but alg is given (contextual coz)
	err = cz2.MetaWithAlg(SEAlg(ES256))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", cz2)

	// Test no coz.pay.alg or coz.sig, so czd should not be calculated
	cz3 := new(Coz)
	err = json.Unmarshal(GoldenPayNoAlg, &cz3.Pay)
	if err != nil {
		panic(err)
	}
	err = cz3.MetaWithAlg(SEAlg(ES256))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", cz3)

	// Output:
	// {"pay":{"msg":"Coz is a cryptographic JSON messaging specification.","alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create"},"can":["msg","alg","now","tmb","typ"],"cad":"XzrXMGnY0QFwAKkr43Hh-Ku3yUS8NVE0BdzSlMLSuTU","sig":"OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg","czd":"xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo"}
	// {"pay":{"msg":"Coz is a cryptographic JSON messaging specification.","alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create"},"can":["msg","alg","now","tmb","typ"],"cad":"XzrXMGnY0QFwAKkr43Hh-Ku3yUS8NVE0BdzSlMLSuTU","sig":"OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg","czd":"xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo"}
	// {"pay":{"msg":"Coz is a cryptographic JSON messaging specification.","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create"},"can":["msg","now","tmb","typ"],"cad":"BZxsmjnmvPrvEQHZ6Ux0IR1QPFRhpjSmkpAjKvUMtfc","sig":"37R-VP0BaR31_vjtOgdZP7lpanTMdQy07xz83o_I7mFMMt2BdoZwdXOAn0dxtKpPrhPPNxBTe-O12ifeiCnONQ","czd":"NShGQ0KdJ4Bnx6TlXyKCaYG-4Q_Pxf3IK61_lLG0VxE"}
	// {"pay":{"msg":"Coz is a cryptographic JSON messaging specification.","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create"},"can":["msg","now","tmb","typ"],"cad":"BZxsmjnmvPrvEQHZ6Ux0IR1QPFRhpjSmkpAjKvUMtfc"}
}

func ExampleCoz_MetaWithAlg_contextual() {
	// Test MetaWithAlg using no sig, which should calc what it can.
	cz := new(Coz)
	err := json.Unmarshal([]byte(GoldenCoz), cz)
	if err != nil {
		panic(err)
	}
	cz.Sig = []byte{} // set sig to nothing.
	err = cz.MetaWithAlg("")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", cz)

	// Empty coz with coz.parsed.alg
	cz = new(Coz)
	err = json.Unmarshal(GoldenEmptyCoz, cz)
	if err != nil {
		panic(err)
	}
	err = cz.MetaWithAlg(GoldenKey.Alg)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", cz)

	// Output:
	// {"pay":{"msg":"Coz is a cryptographic JSON messaging specification.","alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create"},"can":["msg","alg","now","tmb","typ"],"cad":"XzrXMGnY0QFwAKkr43Hh-Ku3yUS8NVE0BdzSlMLSuTU"}
	// {"pay":{},"cad":"RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o","sig":"UG0KP-cElD3mPoN8LRVd4_uoNzMwmpUm3pKxt-iy6So8f1JxmxMcO9JFzsmecFXyt5PjsOTZdUKyV6eZRNl-hg","czd":"nib9RLKirNz50PA2Sv6uZnA03_wdMmA1dyAoUi0OhVY"}
}

// ExampleCoz_jsonUnmarshal tests unmarshalling a coz.
func ExampleCoz_jsonUnmarshal() {
	cz := new(Coz)
	err := json.Unmarshal([]byte(GoldenCoz), cz)
	if err != nil {
		panic(err)
	}

	// remarshal for comparison
	b, err := Marshal(cz)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))

	// Output:
	//{"pay":{"msg":"Coz is a cryptographic JSON messaging specification.","alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create"},"sig":"OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg"}
}

func ExampleCoz_jsonMarshal() {
	cz := new(Coz)
	err := json.Unmarshal([]byte(GoldenCoz), cz)
	if err != nil {
		panic(err)
	}

	b, err := Marshal(cz)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+s\n", b)

	// Output:
	//{"pay":{"msg":"Coz is a cryptographic JSON messaging specification.","alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create"},"sig":"OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg"}
}

func ExampleCoz_jsonMarshalPretty() {
	cz := new(Coz)
	err := json.Unmarshal([]byte(GoldenCoz), cz)
	if err != nil {
		panic(err)
	}

	b, err := MarshalPretty(cz)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+s\n", b)

	// Output:
	// 	{
	//     "pay": {
	//         "msg": "Coz is a cryptographic JSON messaging specification.",
	//         "alg": "ES256",
	//         "now": 1623132000,
	//         "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
	//         "typ": "cyphr.me/msg/create"
	//     },
	//     "sig": "OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg"
	// }
}

// ExampleMarshal_jsonRawMessage demonstrates using empty string, two quote
// characters, and nil for json.RawMessage.  When using json.RawMessage, it
// should always be valid JSON or nil or otherwise it will result in an error.
func ExampleMarshal_jsonRawMessage() {
	o := json.RawMessage([]byte("")) // empty string
	anon := struct {
		Obj *json.RawMessage `json:"obj,omitempty"`
	}{
		Obj: &o,
	}

	// Incorrect usage with pointer to a zero value string.
	// Pointer to empty string will fail Marshal since an empty string is not
	// valid JSON., while the value `""` will pass.
	b, err := Marshal(anon)         // fails
	fmt.Printf("%s\n%+v\n", err, b) // Error is populated and b is empty because of error.

	// Correct usage with quotes characters.
	quotes := []byte("\"\"") // string with two quote characters
	anon.Obj = (*json.RawMessage)(&quotes)
	b, err = Marshal(anon)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", b)

	// Correct usage with with `nil`, which prints as the JSON "null".
	o = nil
	anon.Obj = &o
	b, err = Marshal(anon)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", b)

	// Output:
	// json: error calling MarshalJSON for type *json.RawMessage: unexpected end of JSON input
	// []
	// {"obj":""}
	// {"obj":null}
}

func Example_checkDuplicateKeys() {

	data := `{"a": "x", "b":"y", "c": {"z": 1, "zz": 2}}`
	keys, err := checkDuplicate(json.NewDecoder(strings.NewReader(data)))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(keys)

	// Output:
	// [a b c]
}

func Test_checkDuplicate(t *testing.T) {
	// Happy path; no duplicate.  Should not error.
	data := `{"a": "x", "b":"y", "c": {"z": 1, "zz": 2}}`
	keys, err := checkDuplicate(json.NewDecoder(strings.NewReader(data)))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(keys, []string{"a", "b", "c"}) {
		t.Fatalf("Top level keys returned incorrectly. Got: %v", keys)
	}

	// Duplicate, should error.
	data = `{"a": "aValue", "a":true,"c":["field_3 string 1","field3 string2"], "d": {"z": 1, "zz": 2}}`
	_, err = checkDuplicate(json.NewDecoder(strings.NewReader(data)))
	if err == nil {
		t.Fatal("Should have found duplicate.")
	}

	// Recursive check with duplicate in inner struct.  Should error.
	data = `{"a": "aValue", "b":"bValue", "c": {"z": 1, "z": 2}}`
	_, err = checkDuplicate(json.NewDecoder(strings.NewReader(data)))
	if err == nil {
		t.Fatal("Recursive check should have found duplicate.")
	}
}

// Example demonstrating RVK_MAX_SIZE enforcement for revoke messages.
func Example_rvk_max_size() {
	// Save original and restore after test.
	original := RVK_MAX_SIZE
	defer func() { RVK_MAX_SIZE = original }()

	// Set a very small limit for testing.
	RVK_MAX_SIZE = 50

	// A revoke payload that exceeds the limit.
	p := &Pay{}
	oversized := []byte(`{"alg":"ES256","now":1623132000,"rvk":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"}`)
	err := json.Unmarshal(oversized, p)
	fmt.Println(err)

	// A normal (non-revoke) payload of the same size should succeed.
	p2 := &Pay{}
	normal := []byte(`{"alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create"}`)
	err = json.Unmarshal(normal, p2)
	fmt.Println(err)

	// Setting RVK_MAX_SIZE to 0 disables the limit.
	RVK_MAX_SIZE = 0
	p3 := &Pay{}
	err = json.Unmarshal(oversized, p3)
	fmt.Println(err)

	// Output:
	// Pay.UnmarshalJSON: revoke message size 101 exceeds RVK_MAX_SIZE 50
	// <nil>
	// <nil>
}

// Demonstrates expectations for values that are non-integer, negative, too
// large, and normal values for `rvk` and `now`.  Because this is so critical,
// tests are exhaustive for every condition for both `now` and `rvk`.
func Example_now_rvk_correct_incorrect() {
	p := &Pay{}

	// Try 2^53 - 1 as type string which must error since `rvk`/`now` is of type integer. (Errors.)
	err := json.Unmarshal([]byte(`{"rvk":"9007199254740991"}`), p)
	if err != nil {
		fmt.Println(err)
	}

	err = json.Unmarshal([]byte(`{"now":"9007199254740991"}`), p)
	if err != nil {
		fmt.Println(err)
	}

	// 2^53 which is too big.
	err = json.Unmarshal([]byte(`{"rvk":9007199254740992}`), p)
	if err != nil {
		fmt.Println(err)
	}

	err = json.Unmarshal([]byte(`{"now":9007199254740992}`), p)
	if err != nil {
		fmt.Println(err)
	}

	//  Negative 2^53 + 1 must error as rvk must be positive. (Errors.)
	err = json.Unmarshal([]byte(`{"rvk":-9007199254740991}`), p)
	if err != nil {
		fmt.Println(err)
	}

	err = json.Unmarshal([]byte(`{"now":-9007199254740991}`), p)
	if err != nil {
		fmt.Println(err)
	}

	//  Negative 1 must error as rvk must be positive. (Errors.)
	err = json.Unmarshal([]byte(`{"rvk":-1}`), p)
	if err != nil {
		fmt.Println(err)
	}

	err = json.Unmarshal([]byte(`{"now":-1}`), p)
	if err != nil {
		fmt.Println(err)
	}

	// Finally, 2^53 - 1 as an integer, the largest valid rvk value, which is
	// okay. (Passes)
	err = json.Unmarshal([]byte(`{"rvk":9007199254740991}`), p)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(p)

	err = json.Unmarshal([]byte(`{"now":9007199254740991}`), p)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(p)

	// 0 is okay.  Not revoked. Go omits zero value for JSON. (Passes)
	err = json.Unmarshal([]byte(`{"rvk":0}`), p)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(p)

	err = json.Unmarshal([]byte(`{"now":0}`), p)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(p)

	// 1 is okay. Revoked. (Passes)
	err = json.Unmarshal([]byte(`{"rvk":1}`), p)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(p)

	err = json.Unmarshal([]byte(`{"now":1}`), p)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(p)

	// Output:
	// coz.Timestamp.UnmarshalJSON: json: cannot unmarshal string into Go value of type int64
	// coz.Timestamp.UnmarshalJSON: json: cannot unmarshal string into Go value of type int64
	// coz.Timestamp: value given 9007199254740992 is invalid. Must be between 0 and 9007199254740991 inclusive
	// coz.Timestamp: value given 9007199254740992 is invalid. Must be between 0 and 9007199254740991 inclusive
	// coz.Timestamp: value given -9007199254740991 is invalid. Must be between 0 and 9007199254740991 inclusive
	// coz.Timestamp: value given -9007199254740991 is invalid. Must be between 0 and 9007199254740991 inclusive
	// coz.Timestamp: value given -1 is invalid. Must be between 0 and 9007199254740991 inclusive
	// coz.Timestamp: value given -1 is invalid. Must be between 0 and 9007199254740991 inclusive
	// {"rvk":9007199254740991}
	// {"now":9007199254740991}
	// {}
	// {}
	// {"rvk":1}
	// {"now":1}
}

// ExampleTimestamp_marshal tests JSON.Marshaler.  This is not exhaustive as
// Example_now_rvk_correct_incorrect is assumed to be exhaustive.
func ExampleTimestamp_marshal() {
	// Max safe value (passes)
	p := Pay{
		Now: 1623132000,
		Rvk: 9007199254740991, // Max safe value
	}
	_, err := Marshal(p)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(p)

	// Above max safe value (errors)
	p = Pay{
		Now: 9007199254740992, // Max safe value +1
	}

	_, err = Marshal(p)
	if err != nil {
		fmt.Println(err)
	}

	// Negative value (errors)
	p = Pay{Now: -1}
	_, err = Marshal(p)
	if err != nil {
		fmt.Println(err)
	}

	// Output:
	// {"now":1623132000,"rvk":9007199254740991}
	// json: error calling MarshalJSON for type coz.Timestamp: coz.Timestamp: value given 9007199254740992 is invalid. Must be between 0 and 9007199254740991 inclusive
	// json: error calling MarshalJSON for type coz.Timestamp: coz.Timestamp: value given -1 is invalid. Must be between 0 and 9007199254740991 inclusive
}
