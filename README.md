[![pkg.go.dev][GoBadge]][GoDoc]

![Coz][CozLogo]

[Try Coz out!](https://cyphr.me/coz)

[Presentation][Presentation]

# Coz

**Coz** is a cryptographic JSON messaging specification that uses digital
signatures and hashes to ensure secure, human-readable, and interoperable
communication.

### Example Coz

```JSON
{
  "pay": {
    "msg": "Coz is a cryptographic JSON messaging specification.",
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/msg/create"
  },
  "sig": "OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg"
}
```

### Coz Design Goals

1. Idiomatic JSON
2. Human readable
3. Limited scope
4. Providing defined cipher suites

See also [the Coz philosophy](#the-coz-philosophy-of-abstraction)

### Coz Fields

Coz defines standard fields for the objects `pay`, `key`, and `coz`.
Applications may include additional fields as desired. While all fields are
optional, omitting standard fields may limit compatibility. Binary values are
encoded as [RFC 4648 base 64 URI canonical with padding truncated][RFC4648]
(b64ut). JSON components are serialized into UTF-8 for signing, verification,
and hashing. All JSON fields must be unique, and unmarshalling JSON with
duplicate fields must result in an error. All timestamp values should be UTC
Unix time.

#### All Coz Standard Fields

![Coz Standard Fields](docs/img/coz_standard_fields.png)

## Pay

`pay` contains the fields `alg`, `now`, `tmb`, and `typ` and optionally any
additional application fields. In the first example `msg` is additional.

### `pay` Standard Fields

- `alg` - Specific cryptographic algorithm. E.g. `"ES256"`
- `now` - Unix time of message signature. E.g. `1623132000`
- `tmb` - Thumbprint of the signature's key. E.g. `"U5XUZ..."`
- `typ` - Type of `pay`. E.g. `"cyphr.me/msg/create"`
- `msg` - Message payload (string). E.g. `"Coz is a cryptographic JSON messaging specification."`
- `dig` - Digest of external content. E.g. `"LSgWE4v..."`

`typ`'s value may be used by applications as desired. The value is recommended
to denote API information such as versioning, expected fields, and/or other
application defined programmatic functions. In the first example,
`"typ":"cyphr.me/msg"` denotes a `pay` with the fields
`["msg","alg","now","tmb","typ"]` as defined by an application.

## Coz Key

### Example Public Coz Key

```JSON
{
  "alg":"ES256",
  "now":1623132000,
  "pub":"2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
  "tag":"Coz Example Key",
  "tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
}
```

### Example Private Coz Key

```JSON
{
  "alg":"ES256",
  "now":1623132000,
  "prv":"bNstg4_H3m3SlROufwRSEgibLrBuRq9114OvdapcpVA",
  "pub":"2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
  "tag":"Coz Example Key",
  "tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
}
```

### `key` Standard Fields

- `key` - Key object. E.g. `"key":{"alg":"ES256", ...}`
- `alg` - Algorithm. E.g. `"ES256"`
- `now` - Key creation Unix time. E.g. `1623132000`
- `prv` - Private component. E.g. `"bNstg4..."`
- `pub` - Public component. E.g. `"2nTOaF..."`
- `tmb` - Thumbprint. E.g. `"U5XUZ..."`
- `typ` - Application defined programmatic type. E.g. `"cyphr.me/key"`
- `rvk` - Key revocation Unix time. E.g. `1623132000`

The private component `prv` is not included in `tmb` generation. Also note that
`tag` must not be used programmatically while `typ` may be used
programmatically.

## Coz object

The JSON name `coz` may be used to wrap a coz.

```JSON
{
  "coz":{
    "pay": {
      "msg": "Coz is a cryptographic JSON messaging specification.",
      "alg": "ES256",
      "now": 1623132000,
      "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
      "typ": "cyphr.me/msg/create"
    },
    "sig": "OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg"
  }
}
```

### `coz` Standard Fields

- `coz` "Coz" Coz object. E.g. `{"coz":{"pay":..., sig:...}}`
- `can` "Canon" Canon of `pay`. E.g. `["msg","alg","now","tmb","typ"]`
- `cad` "Canon digest" Digest of `pay`. E.g. `"XzrXMG..."`
- `czd` "Coz digest" Digest of `["cad","sig"]`. E.g. `xrYMu8...`
- `pay` "Payload" Signed payload. E.g. `"pay":{"msg":...,"alg":...}`
- `sig` "Signature" Signature over `cad`. E.g. `"sig":"OJ4_ti..."`

`sig` is the signature over the raw bytes of `cad` (the b64ut-decoded digest).
`cad` is not rehashed before signing. `czd`'s hashing algorithm must align with
`alg` in `pay`. `czd` refers to a particular signed message just as `cad` refers
to a particular payload. `cad` and `czd` are calculated from brace to brace,
including the braces. `cad` and `czd` are recalculatable and are recommended to
be omitted from cozies, although they may be useful for reference.

As an added technical constraint, because `sig` and `czd` are used as
identifiers, `sig` must be non-malleable. Malleable schemes like ECDSA must
perform signature canonicalization that constrains signatures to a non-malleable
form.

### Verbose `coz`

Including unnecessary labels is not recommended. For example, the JSON object
`{"pay":{...},"sig":...}` doesn't need the label `coz` if implicitly known by
applications. The following may generally be omitted: `key` may be looked up
by applications by using `tmb`, the fields `can`, `cad`, and `czd` are
recalculatable, and the label `coz` may be inferred.

A tautologic coz:

```JSON
{
  "coz": {
    "pay": {
      "msg": "Coz is a cryptographic JSON messaging specification.",
      "alg": "ES256",
      "now": 1623132000,
      "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
      "typ": "cyphr.me/msg/create"
    },
    "key": {
      "alg":"ES256",
      "now":1623132000,
      "pub":"2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g",
      "tag":"Coz Example Key",
      "tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg"
    },
    "can": ["msg","alg","now","tmb","typ"],
    "cad": "XzrXMGnY0QFwAKkr43Hh-Ku3yUS8NVE0BdzSlMLSuTU",
    "czd": "xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo",
    "sig": "OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg"
  }
}
```

Simplified:

```JSON
{
  "pay": {
    "msg": "Coz is a cryptographic JSON messaging specification.",
    "alg": "ES256",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/msg/create"
  },
  "sig": "OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg"
}
```

## Canon

A **canon** is a list of fields used for normalization, e.g. `["alg","pub"]`.
Coz objects are canonicalized for creating digests, signing, and verification.
The canon of `pay` is the currently present fields in order of appearance. The
following Coz fields have predefined canons:

- `cad`'s canon is `pay`'s canon.
- `tmb`'s canon is `["alg","pub"]`.
- `czd`'s canon is `["cad","sig"]`.

Using a canon, the **canonical form** of an object is generated by removing
fields not appearing in the canon, ordering remaining fields by appearance in
the canon, and eliding unnecessary whitespace. The canonical form is serialized
into UTF-8 for signing, verification, and hashing.

Canonical form generation steps:

- Omit fields not present in canon.
- Order fields by canon.
- Omit insignificant whitespace.

A **canonical digest** is generated by hashing the UTF-8 serialized canonical
form using the hashing algorithm specified by `alg`. For example,`"ES256"`'s
hashing algorithm is `"SHA-256"`.

The key thumbprint, `tmb`, is the canonical digest of `key` using the canon
`["alg","pub"]` and hashing algorithm specified by `key.alg`. For example, a key
`alg` of `ES256` corresponds to the hashing algorithm `SHA-256`. The canonical
form of the example key is:

```JSON
{"alg":"ES256","pub":"2nTOaFVm2QLxmUO_SjgyscVHBtvHEfo2rq65MvgNRjORojq39Haq9rXNxvXxwba_Xj0F5vZibJR3isBdOWbo5g"}
```

Hashing this canonical form results in the following digest, which is `tmb`:
`U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg`.

`czd` is the canonical digest of `coz` with the canon `["cad","sig"]`, which
results in the JSON `{"cad":"...","sig":"..."}`. `czd`'s hash must align with
`alg` in `pay`.

The canonical digest of

- `pay` is `cad`,
- `["alg","pub"]` is `tmb`,
- `["cad","sig"]` is `czd`.

Using the first example, the following canonical digests are calculated:

- `tmb` is `U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg`
- `cad` is `XzrXMGnY0QFwAKkr43Hh-Ku3yUS8NVE0BdzSlMLSuTU`.
- `czd` is `xrYMu87EXes58PnEACcDW1t0jF2ez4FCN-njTF0MHNo`.

Signing and verification functions must not mutate `pay`. Since `pay`'s canon is
the present fields, no fields are removed when canonicalizing `pay`.  Any
mutation of `pay` via `can` must occur by canon related functions.

### Coz and Binaries

The canonical digest of a binary file may simply be the digest of the file. The
hashing algorithm and any other metadata may be denoted by an accompanying coz.
For example, an image ("coz_logo_icon_256.png") may be referred to by its
digest.

```JSON
{
  "alg":"SHA-256",
  "file_name":"coz_logo_icon_256.png",
  "id":"oDBDAg4xplHQby6iQ2lZMS1Jz4Op0bNoD5LK3KxEUZo"
}
```

For example, a file's digest, denoted by `id`, may represent the authorization
to upload a file to a user's account. Note that Coz associates the signature
`alg` `ES256` to hashing `alg` `SHA-256`.

```JSON
{
  "pay": {
    "alg": "ES256",
    "file_name": "coz_logo_icon_256.png",
    "id": "oDBDAg4xplHQby6iQ2lZMS1Jz4Op0bNoD5LK3KxEUZo",
    "now": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/file/create"
  },
  "sig": "AV_gPaDCEd9OEyA1oZPo7LwpypzXkk2htmA-bEobpmcA4Vc7xNcaFPVaEBgU8DDCAZcQZcBHgRlOIjNk9g-Mkw"
}
```

## External Digest Serialization

When Coz digest values (such as `tmb`, `dig`, `cad`, or `czd`) are stored
outside of a coz and `alg` is not otherwise available, implementations should
use the following self-describing, non-JSON format in order to preserve the
cryptographic binding: the name of the algorithm, followed by the delimiter `:`,
followed by the b64ut value.

Examples:

```text
ES256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg
SHA-256:oDBDAg4xplHQby6iQ2lZMS1Jz4Op0bNoD5LK3KxEUZo
```

Optionally, for additional disambiguation, the prefix `coz:` may be prepended to
the serialized form:

```text
coz:ES256:U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg
```

## Revoke
A revoke is a self-signed declaration that a key is compromised. A Coz key may
revoke itself by signing a coz containing the field `rvk` with an integer value
greater than `0`. The integer value `1` is suitable to denote revocation and the
current Unix timestamp is the suggested value.

- `rvk` - Unix timestamp of key expiry.

`rvk` and `now` must be positive integers less than 2^53 – 1
(9,007,199,254,740,991), the maximum safe integer in IEEE 754 double-precision  
floating-point format. Implementations must error if either value is not an  
integer or is larger than 2^53 - 1.

Coz explicitly defines a self-revoke method so that third parties may revoke
leaked keys. Systems storing Coz keys must accept valid revoke cozies where pay
is under 2048 bytes and must immediately mark the associated key as revoked,
even if a future revocation time is specified.

Key expiration policies, key rotation, backdating, and alternative revocation
methods are outside the scope of Coz.

### Example Self Revoke

```json
{
  "pay": {
    "alg": "ES256",
    "msg": "Posted my private key online",
    "now": 1623132000,
    "rvk": 1623132000,
    "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
    "typ": "cyphr.me/key/revoke"
  },
  "sig": "EhAsIL_w51NbCtzxFUcJiRMb1KmlxFSD-g7M-9wgqH9nnVHaEHiNyecfvfkrNf--KnfZyrsDIyWuT86MLNozQg"
}
```

## Alg
`alg` specifies a parameter set and is a single source of truth for Coz
cryptographic operations.

Instead of a registry, supported algorithms and their exact parameters are
defined in the reference implementation (Go). Implementations must match these
parameters for interoperability and correctness.

For key algorithms, Coz assumes a **Deterministic Public-from-Private
Derivability** property: `pub` can be deterministically derived from `prv` and
not from any separate seed or intermediate value. Future algorithms must be
constructed to support this property.

Since the delimiter `:` is used for serialization, future Coz `alg` labels must
never use the character `:`.

### Example - "alg":"ES256"

- Name: ES256
- Genus: ECDSA
- Family: EC
- Use: sig
- Hash: SHA-256
- HashSize: 32
- HashSizeB64: 43
- PubSize: 64
- PubSizeB64: 86
- PrvSize: 32
- PrvSizeB64: 43
- Curve: P-256
- SigSize: 64
- SigSizeB64: 86

### Supported Algorithms

- ES224
- ES256
- ES384
- ES512
- Ed25519
- Ed25519ph
- ES256k

---
## End of Coz Specification

The above sections starting at [# Coz](#coz) constitute the Coz specification.
The following sections contain additional guidance, examples, philosophy, and
implementation notes that are informative but not normative.

---

## Coz Verifier
The Coz verifier is an in-browser tool for signing and verifying.

[Coz Verifier][Verifier]

![coz_verifier](docs/img/Hello_World!.gif)

There is also the [Simple Coz
Verifier][Verifier_simple] that has the minimal
amount of code needed for a basic Coz application.
Its [codebase is in the CozJS repo][CozeJSVerifier] and may be locally hosted.


## Current Coz Implementations
- [Coz Go][Coz] (this repo)
- [Coz Rust][CozRust] Official Rust implementation.
- [Coz JS (Javascript)][CozeJS] Official Javascript implementation.
- [Coz CLI repository][CozeCLI]. Coz command line interface application using Go Coz.

See [`docs/development.md`](docs/development.md) for the development guide.


## Coz Core and Coz X
The sections above are defined as the main Coz specification, Coz core. There
are no plans to increase Coz's scope or features in core other than additional
algorithm support. This will be especially true after Coz is out of Alpha/Beta.
(At the moment, we would like more time for feedback before casting the
specification into stone.)

Coz X (Coz extended) includes additional documentation, extra features,
drafts, proposals, early new algorithms support that's not yet adopted in Coz
core, and extended algorithm support.

See [Coz_go_x/normal][Normal] for an example of a Coz X feature not included in
Coz core.

Repository structure:

- [Coz][Coz] Main specification, Go reference implementation, and Go Coz core implementation.
- [CozRust][CozRust] Rust core implementation.
- [CozJS][CozeJS] Javascript core implementation.
- [CozX][CozeX] Coz extended. Additional documents, discussion, and new algorithms (Not a code repository).
- [CozGoX][CozeGoX] Go implementation of extended features.
- [CozJSX][CozeJSX] Javascript implementation of extended.
- etc...


# FAQ
#### Pronunciation? What does "Coz" mean? "Coz" vs "coz"?
We say "Co-zee" like a comfy cozy couch. Jared suggested Coz because it's funny.
The English word coze (pronounced "kohz") and means "a friendly talk; a chat"
which is the perfect name for a messaging specification. Upper case "Coz" refers
to the specification and lower case "coz"/"cozies" to refer to messages.  Coz
was formerly spelled "Coze", but to avoid conflict with a large corporation's AI
chat bot, Coze was respelled to Coz.


### What is Coz useful for?
Coz's applications are endless as Coz is useful for anything needing
cryptographic signing. Coz is deployed in various applications such as user
authentication, authorization, product tracking, user comments, user votes,
chain of custody, Internet of things (IoT), password replacement, user login,
passwordless login, sessions, bearer tokens, "stateless tokens", and cookies.

As a timely example the CEO of Reddit, spez, [edited people's
comments.](https://www.theverge.com/2016/11/23/13739026/reddit-ceo-steve-huffman-edit-comments)
Messages signed by Coz prevents such tampering by third parties.


## The Coz Philosophy of Abstraction
Providing a cryptographic abstraction layer is a key feature of Coz. Coz
provides gentle standardization that increases compatibility across various
systems. In this way, Coz is like a simple cryptographic programming language,
allowing projects to "speak the same language". A much larger strategic benefit
is that Coz decouples projects from underlying cryptographic primitives. If
problems are discovered with particular primitives, decoupled architecture is
simple to change while tightly coupled architecture can be extremely difficult
to alter.

A prevalent limitation many cryptographic projects face is that they are
rigidly tied to single primitives. It's hard to overstate the significance of
this problem.

Coz takes [Bruce Schneier's](https://www.schneier.com/blog/archives/2022/08/nists-post-quantum-cryptography-standards.html) advice seriously:

> It's not enough to implement a single standard; it's vital that our systems be
> able to easily swap in new algorithms when required. We've learned the hard way
> how algorithms can get so entrenched in systems that it can take many years to
> update them: in the transition from DES to AES, and the transition from MD4 and
> MD5 to SHA, SHA-1, and then SHA-3.

The consequences of rigidly tying primitives for cryptographic projects are:

- **Compatibility** - Projects are frequently incompatible because they use
  different primitives.
- **Standardization** - Even when projects use the same primitives,
  implementations vary widely across the industry, leading to incompatibility
  between systems.
- **Implementation** - Projects frequently implement primitives directly
  resulting in redundant codebases.
- **Decoupling** - It is very difficult, if not impossible, for projects to
  replace broken or problematic primitives.

Coz provides a standardized abstraction layer, eliminating significant
redundant effort of implementation, resolving compatibility conflicts,
establishing implementation standards, and providing the flexibility to use
various primitives as needed.

##### The Debt of Inflexibility
The cost of tight coupling to cryptographic primitives has been demonstrated
repeatedly throughout the industry.

**Git** - Git was tightly coupled to the questionably secure SHA1 in 2005.
Upgrading to SHA2 has been a herculean effort requiring many years to implement,
which is still ongoing in 2025, 20 years later.

**SSL/TLS** prior to TLS 1.2 - When MD5 and SHA1 weaknesses were discovered, it
required major protocol revisions rather than simple primitive substitution.

**Bitcoin** - Bitcoin is tightly coupled to SHA256, ES256k, and RIPEMD for its
proof-of-work and transaction verification. While ES256k remains secure, if
quantum computers eventually threaten it, transitioning would be extremely
challenging.

**PGP/GPG** - When MD5 was broken, transitioning to newer algorithms required
significant protocol changes and caused compatibility issues between versions.

**DNSSEC** - Transitioning from RSA and SHA1 to newer algorithms like ECDSA and
SHA2 required protocol extensions and complex transition mechanisms.

**WPA2** - WPA2 was tightly coupled to RC4 and AES in specific modes. When
vulnerabilities were found (like KRACK), updating the protocol was complex.

Tight coupling to cryptographic primitives creates significant technical debt
that becomes increasingly expensive to address over time. Quantum computing and
other security threats require the ability to adapt cryptographic systems
quickly. Coz aims to, as an intentional byproduct of standardization, prevent
projects from accumulating this kind of debt, ensuring they remain adaptable to
future cryptographic needs.


#### Binary? Why not support binary payloads?
JSON isn't well designed for large binary payloads. Instead, Coz suggests
including the digest of a binary file in a coz message while transporting the
binary separately. There's nothing stopping an application from base 64 encoding
a binary for transport, although it's not recommended.


#### How Should I Handle Large Text Messages?
JSON is not ideal for arbitrary text due to escaping, which increases the
size of arbitrary text and makes human readability difficult. Instead of signing
text embedded in a JSON field like `msg`, consider hashing the text, signing its
digest, and transporting the message separately. We consider signing digests
instead of large messages a best practice, although it may add some complexity
to services.

The following example, which signs a portion of this README, isn't ergonomic.

```JSON
{
  "alg": "ES256",
  "now": 1623132000,
  "msg": "# Coz \n**Coz** is a cryptographic JSON messaging specification.\n\n[Try Coz out!](https://cyphr.me/coz)",
  "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
  "typ": "cyphr.me/msg/create"
}
```

The SHA-256 digest (which aligns with an `alg` of ES256) of the message gives
`4FO2pB9yGxo8BBW2whULqbL5m7eAfUWOkvgQu7-9h08`, which is then signed.

```JSON
{
  "alg": "ES256",
  "now": 1623132000,
  "dig": "4FO2pB9yGxo8BBW2whULqbL5m7eAfUWOkvgQu7-9h08",
  "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
  "typ": "cyphr.me/msg/dig/create"
}
```

Like binary, the text is transported independently of the JSON Coz payload.

```md
# Coz

**Coz** is a cryptographic JSON messaging specification.

[Try Coz out!](https://cyphr.me/coz)
```

The coz not only digitally signs the message, but also the digest integrity
protects its value. An additional benefit of this method is that coz
signatures are guaranteed to remain a small, constant size regardless of the
size of the input text.


#### Why is Coz's scope so limited?
Coz is intentionally scope limited. It is easier to extend a limited standard
than to fix a large standard. Coz can be extended and customized for individual
applications.


#### Why does Coz have a revoke size limit?
Revoke coz messages, simply "revokes" or "revoke cozies", are limited to protect
services from DoS/DDoS attacks using excessively large payloads. Services may
safely ignore any revoke where `pay` exceeds 2048 bytes (2 KiB). The revoke
example in the README is only 172 bytes, leaving ample room for metadata. Since
revokes reference keys via `tmb`, not `pub`, this is suitable for even
post-quantum. We also assume that future hash sizes used by Coz for addressing
will not be much larger than 512 bits. The Go Coz library enforces this limit by
default, with a configurable global variable available for custom needs (though
increasing it is discouraged). Services may set stricter limits but must still
handle valid revokes up to 2048 bytes. Services are not required to store the
revoke message itself and are only required to mark the referenced key as
revoked. The requirement applies only to keys the service already hosts, not
unknown keys.


#### Is Coz versioned?
`alg` refers to a specific set of parameters for all operations and Coz Core
"versioning" is accomplished by noting specific algorithm support. If an
operation needs a different parameter set, `alg` itself must denote the
difference. `alg` permits Coz implementations to support a subset of features
while remaining Coz compliant. The specification hopes to stay simple and
stable enough to preclude versioning, however we suspect further tweaks are
probably warranted, so a long alpha and beta time is planned. Extension to Coz
are defined by [CozX][Cozex] so implementations avoid feature bloat.
Implementation releases themselves are versioned.


#### Why does `pay` have cryptographic components?
Coz's `pay` includes all payload information, a design we've dubbed a "fat
payload". We consider single pass hashing critical for Coz's simple design.

Alternative schemes require a larger canon, `{"head":{...},"pay":{...}}`, or
concatenation like `digest(head) || digest(pay)`. By hashing only `pay`, the
"head" label and encapsulating braces are dropped, `pay:{...}`, and the label
`"pay"` may then be inferred, `{...}`. `{...}` is better than
`{"head":{...},"pay":{...}}`.

Verifying a coz already requires hashing `pay`. Parsing `alg` from `pay` is a
small additional cost.


#### JSON APIs? Can my API do versioning?
Coz is well suited for JSON APIs. API versioning may be handled by applications
however desired. A suggested way of incorporating API versioning in Coz is to
use `typ`, e.g. `"typ":"cyphr.me/v1/msg/create"`, where "v1" is the api version.


#### Can my application use Canon/Canonicalization?
Yes, canon is suitable for general purpose application. Applications may
specify canon expectations in API documentation, if using Coz denoted by "typ"
or explicitly specified by `can`, or implicitly known and pre-established. Coz
Core contains simple canonicalization functions, or for more expressive
capabilities see [Normal][Normal].


#### `pay.typ` vs `key.typ`.
For applications, `pay.typ` may denote a canon. For example, a `typ` with value
`cyphr.me/msg/create` has a canon, as defined by the service, of ["alg", "now",
"msg", "tmb", "typ"]. The service may reject a coz that's not canonicalized as
expected. For example, the service might reject cozies missing `now`.

Like `typ` in `pay`, applications may use `key.typ` to specify custom fields
(e.g., "first_seen" or "account_id") and field order.

`Key.tmb` ignores `key.typ` because `alg` serves as the key's `typ` so the
static canon, `["alg","pub"]`, is sufficient. Using `alg` in the generation of
`tmb` ensures the impossibility of algorithms producing colliding thumbprints
(where one algorithm could produce `pub` values colliding with other algorithms).


#### ECDSA `pub` and `sig` Bytes.
For ECDSA , (X and Y) and (R and S) are concatenated for `pub` and `sig`
respectively. For ES512, which unlike the other ECDSA algorithms uses the odd
numbered P-521, X, Y, R, and S are padded before concatenation.


#### Why use `tmb` and not `pub` for references in messages?
Coz places no limit on public key size, which can be very large. For example,
GeMSS128 public keys are 352,188 bytes, compared to Ed25519's 32 bytes. Using
`tmb` instead of `pub` generalizes Coz for present and future algorithm use.
Additionally, `pub` may be cryptographically significant for key security while
`tmb` is not.


#### Required Coz Fields, Contextual Cozies, and the Empty Coz.
The standard fields provide Coz and applications fields with known types since
JSON has limited type identifiers. Coz has no required fields, however omitting
standard fields limits interoperability among applications, so it is suggested
to include standard fields appropriately.

Cozies that are missing the fields `pay.alg` and/or `pay.tmb` are **contextual
cozies**, denoting that additional information is needed for verification.
Caution is urged when deploying contextual cozies as including the standard
fields `pay.alg` and `pay.tmb` is preferred.

An **empty coz**, which has an empty `pay` and populated `sig`, is legitimate.
It may be verified if `key` is known. The following empty coz was signed with
the example key "cLj8vs".

```json
{
  "pay": {},
  "sig": "9iesKUSV7L1-xz5yd3A94vCkKLmdOAnrcPXTU3_qeKSuk4RMG7Qz0KyubpATy0XA_fXrcdaxJTvXg6saaQQcVQ"
}
```


#### UTF-8 and b64ut (RFC base 64 URI canonical truncated) Encoding
[Canonical base 64][RFC6468Canonical] (sometimes called "strict") encoding is
required and non-strict encoding of both b64ut and UTF-8 must error. For the
initial reason for why Coz uses b64ut see [base64.md][base64.md].


#### Why not PGP/OpenSSL/LibreSSL/SSHSIG/libsodium/JOSE(JWT)/COSE/etc...? How does Coz compare with prior arts?
We respect the various projects in the space. Other projects have noble goals
and we're thankful they exist. Coz is influenced by ideas from many others.
However existing solutions were not meeting our particular needs so we created
Coz.

See [coz_vs.md][coze_vs] and the [introduction
presentation](https://docs.google.com/presentation/d/1bVojfkDs7K9hRwjr8zMW-AoHv5yAZjKL9Z3Bicz5Too/edit#slide=id.g1367bc4eb0f_0_6)
for more.


#### Does Coz have checksums?
`pub`, `tmb`,`cad`, `czd`, and `sig` may be used for integrity checking.

Systems may use `sig` as an integrity check via cryptographic verification. If
`cad` and/or `czd` are included they may be recalculated and error on mismatch.

For keys, `pub` and/or `tmb` may be recalculated and error on mismatch. Coz keys
cannot be integrity checked when `prv`, `pub`, or `tmb` are presented alone. In
situations needing integrity checking, we recommend including at least two
components. See [checksums.md][checksums] for more.


#### Performance hacks?
Coz is not optimized for long messages, but if early knowledge of Coz standard
fields is critical for application performance, put the Coz standard fields
first, e.g. `{"alg", "tmb", ...}`


#### I need to keep my JSON separate but inside a coz.
If appending custom fields after the standard Coz fields isn't sufficient, we
suggest encapsulating custom JSON in "~", the last ASCII character. We've
dubbed this a "tilde encapsulated payload". For example:

```json
{
  "alg": "ES256",
  "now": 1623132000,
  "tmb": "U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg",
  "typ": "cyphr.me/msg/create",
  "~": {
    "msg": "tilde encapsulated payload"
  }
}
```


#### ASCII/Unicode/UTF-8/UTF-16 and Ordering?
Even though Javascript uses UTF-16 and JSON was designed in a Javascript
context, JSON implementations rejected the problematic UTF-16, which has some
code points out of order, in favor of UTF-8. Requiring JSON UTF-8 encoding was
formalized by the [JSON RFC 8259 section 8.1][RFC8259-8.1]. Unicode, ASCII, and
UTF-8 all share sorting order.

Although JSON arrays are defined as ordered, JSON objects are defined as
unordered. How is `pay`, an unordered JSON object, signed when signing requires
a static representation? [UTF-8 is the explicitly defined serialization for
JSON][RFC8259-8.1]. Coz's signing and verification operations are not over
abstract JSON, but rather the concrete UTF-8. Coz marshals JSON into UTF-8
before signing, and Coz verifies UTF-8 before unmarshalling into JSON.

Additionally, object field order may be denoted by `can`, [chaining
normals][Normal], or communicate via other means.


#### Does Coz support multisig?
No. At the protocol level, Coz only supports atomic signing (each key signs
independently) and does not include built-in multisig aggregation.

Adding multisig would significantly complicate Coz implementations so it is
omitted from the core specification. Systems can achieve multisignature
functionality at the application layer by composing multiple cozies.
Applications must verify each signature independently and enforce thresholds
(e.g., 2-of-3 or otherwise M-of-N). For true cryptographic multisig aggregation
(e.g., Schnorr or BLS primitives), a different scheme is required.

1. **Use an array of cozies**: Each coz signs the same payload (or a shared
   digest). This is verbose but provides full auditability.  Use this when you
   need per-signature metadata (different now, alg, explicit tmb, etc.)

  For example, a transaction adding a key to an account with two signing keys:

```json5
{
  "cozies": [
    {
      "pay": {
        "alg": "ES256",
        "now": 1628181264,
        "tmb": "<first-signing-key-tmb>",  
        "typ": "cyphr.me/cyphrpass/key/add",
        "id": "<new-key-tmb>"
      },
      "sig": "<signature-0>"
    },
    {
      "pay": {
        "alg": "ES256",
        "now": 1628181264,
        "tmb": "<second-signing-key-tmb>", 
        "typ": "cyphr.me/cyphrpass/key/add",
        "id": "<new-key-tmb>"
      },
      "sig": "<signature-1>"
    }
  ],
  "key": {
    /* new key details */
  }
}
```

2. **Sign a shared digest**: Each coz references the same content via `dig`.
   Optionally include standard fields like `now`, `tmb`, in each `pay`. This is
   good for signing external or large payloads without duplicating content:

```json5
{
  "cozies": [
    {
      "pay": {
        "alg": "ES256",
        "dig": "<shared-content-digest>"
      },
      "sig": "<signature-0>"
    },
    {
      "pay": {
        "alg": "ES384",
        "dig": "<shared-content-digest>"
      },
      "sig": "<signature-1>"
    }
  ]
}
```

3. **Compact map of signatures**: If all keys use the same `alg` and `now` is
   implicit/shared, and `tmb` is implicit or known out-of-band, use a single
   `cad` (canonical digest) with a map of thumbprints to signatures.   This is
   the most compact option and ideal for bandwidth-constrained apps, but
   requires app-level logic to verify all `sig`s against `cad`.

```json5
{
  "cad": "<canonical-digest-of-shared-payload>",
  "sigs": {
    "<tmb0>": "<signature-0>",
    "<tmb1>": "<signature-1>"
  }
}
```


#### Where does the cryptography come from?
Much of this comes from [NIST FIPS][FIPS].

For example, FIPS PUB 186-3 defines P-224, P-256, P-384, and P-521.

To learn more see this [walkthrough of ECDSA](https://learnmeabitcoin.com/technical/ecdsa).


#### Unsupported Things?
The following are out of scope or redundant.

- `ES192`, `P-192` - Not implemented anywhere and dropped from later FIPS.
- `SHA1`, `MD5` - Not considered secure for a long time.
- `kty` - "Key type". Redundant by `alg`.
- `iss` - `tmb` fulfills this role. Systems that need something like an issuer,
  associating messages with people/systems, can look up "issuer" based on
  thumbprint. Associating thumbprints to issuers is the design we recommend.
- `exp` - "Expiration". Outside the scope of Coz.
- `nbf` - "Not before". Outside the scope of Coz.
- `aud` - "Audience". Outside the scope of Coz, but consider denoting this with
  `typ`.
- `sub` - "Subject". Outside the scope of Coz, but consider denoting this with
  `typ`.
- `jti` - "Token ID/JWT ID". Redundant by `czd`, `cad`, or an application
  specified field.


#### Encryption?
Coz does not currently support encryption. If or when it ever does it would be
similar to or simply complement [age](https://github.com/FiloSottile/age).


#### Why define algorithms?
Coz's design is generalized and not overly coupled to any single primitive.
Because of this, applications that use Coz can easy upgrade cryptographic
primitives. Using a single primitive is perfectly fine, but tightly coupling
systems to a single primitive is not. Simultaneous support for multiple
primitives is a secondary, and optional, perk.


#### JSON "Name", "Key", "Field Name", "Member Name"?
They're all synonyms. A JSON name is a JSON key is a JSON field name is a JSON
member name. In this document we use "field name" to avoid confusion with Coz
key.


#### Why are duplicate field names prohibited?
Coz explicitly requires that implementations disallow duplicate field names in
`coz`, `pay`, and `key`. Existing JSON implementations have varying behavior.
Douglas Crockford, JSON's inventor, [tried to fix this but it was decided it
was too late](https://esdiscuss.org/topic/json-duplicate-keys).

Although Douglas Crockford couldn't change the spec forcing all implementations
to error on duplicate, his Java JSON implementation errors on duplicate names.
Others use `last-value-wins`, support duplicate keys, or other non-standard
behavior. The [JSON
RFC](https://datatracker.ietf.org/doc/html/rfc8259#section-4) states that
implementations should not allow duplicate keys, notes the varying behavior
of existing implementations, and states that when names are not unique, "the
behavior of software that receives such an object is unpredictable." Also note
that Javascript objects (ES6) and Go structs already require unique names.

Duplicate fields are a security issue, a source of bugs, and a surprising
behavior to users. See the article, "[An Exploration of JSON Interoperability
Vulnerabilities](https://bishopfox.com/blog/json-interoperability-vulnerabilities)"

Disallowing duplicates conforms to the small I-JSON RFC. The author of I-JSON,
Tim Bray, is also the author of current JSON specification ([RFC
8259][RFC8259]). See also https://github.com/json5/json5-spec/issues/38.


#### Why is human readability a goal?
Although humans cannot verify a signature without the assistance of tools,
readability allows humans to visually verify what a message does.

We saw the need for JSON-centric cryptography and idiomatic JSON is human
readable. JSON is not a binary format; it is a human readable format and any
framwork built on JSON should embrace its human readability. If human
readability is unneeded, JSON is entirely the wrong message format to employ.
All else being equal, human readability is better than non-human readability.


#### JSON?
- [RFC 8259 (2017, Bray)][RFC8259]
- [RFC 7159 (2014, Bray)][RFC7159]
- [RFC 7158 (2013, Bray)][RFC7158]
- [RFC 4627 (2006, Crockford)][RFC4627]

See also I-JSON and JSON5

- [RFC 7493 (2015, Bray)][RFC7493]
- [JSON5][JSON5]


#### HTTP? HTTP Cookies? HTTP Headers?
When using Coz with HTTP cookies, Coz messages should be JSON minified. For
example, we've encountered no issues using the first example as a cookie:

```
token={"pay":{"msg":"Coz is a cryptographic JSON messaging specification.","alg":"ES256","now":1623132000,"tmb":"U5XUZots-WmQYcQWmsO751Xk0yeVi9XUKWQ2mGz6Aqg","typ":"cyphr.me/msg/create"},"sig":"OJ4_timgp-wxpLF3hllrbe55wdjhzGOLgRYsGO1BmIMYbo4VKAdgZHnYyIU907ZTJkVr8B81A2K8U4nQA6ONEg"}; Path=/;  Secure; Max-Age=999999999; SameSite=None
```

For more considerations see [http_headers.md][http_headers]


#### Why release pre-alpha on 2021/06/08?
Coz was released on 2021/06/08 (1623132000) since it's 30 years and one day
after the initial release of PGP 1.0. We wrote a blog with more [details of
Coz's
genesis](https://cyphr.me/md/xlA-MSFwPxmWED4ZcNdxUy8OA22UPiLWlGQUQik8DwY).


#### Signature Malleability?
Coz prohibits signature malleability. See
[malleability_low_s.md][low_s].


#### Who created Coz?
Coz was created by [Cyphr.me](https://cyphr.me).


#### Discussion? Social Media?
- We have a bridged Matrix and Telegram chat room. (This is where we are the most active)
  - Matrix: https://app.element.io/#/room/#cyphrmepub:matrix.org
  - PM zamicol for our bridged Telegram group.
- We also hang out in the Go rooms:
  - https://app.element.io/#/room/#go-lang:matrix.org
  - https://t.me/+TgkdqZw0Q-jAkGWS
- https://twitter.com/CozeJSON
- https://old.reddit.com/r/CozeJson


#### Other Resources
- This README as a page: https://cyphrme.github.io/Coz
- [Coz go.pkg.dev](https://pkg.go.dev/github.com/cyphrme/coz#section-readme)
- CozJSON.com (which is currently pointed to the [Coz verifier](https://cyphr.me/coz))
- Coz Table links: https://docs.google.com/document/d/15_1R7qwfCf-Y3rTamtYS_QXuoTSNrOwbIRopwmv4KOc


#### Keywords
Coz JSON alg now tmb typ rvk tag prv pub coz pay key can cad czd sig cryptography crypto authentication auth login hash digest signature Cypherpunk Cyphrme Ed25519 Ed25519ph ES224 ES256 ES384 ES512 SHA-224 SHA-256 SHA-384 SHA512 JOSE JWS JWE JWK JWT PASETO PASERK signify ssh SSHSIG PGP Bitcoin Ethereum base64 b64ut SQRL

---

# Attribution, Trademark Notice, and License
Coz is released under The 3-Clause BSD License.

"Cyphr.me" is a trademark of Cypherpunk, LLC. The Cyphr.me logo is all rights
reserved Cypherpunk, LLC and may not be used without permission.

[GoBadge]: https://pkg.go.dev/badge/github.com/github.com/cyphrme/coz
[GoDoc]: https://pkg.go.dev/github.com/cyphrme/coz
[CozLogo]: docs/img/coz_logo_zami_white_450x273.png
[Presentation]: https://docs.google.com/presentation/d/1bVojfkDs7K9hRwjr8zMW-AoHv5yAZjKL9Z3Bicz5Too
[Verifier]: https://cyphr.me/coze
[Verifier_simple]: https://cyphr.me/coze_verifier_simple/coze.html
[CozeJSVerifier]: https://github.com/Cyphrme/Cozejs/tree/master/verifier
[GithubCozeVerifier]: https://cyphrme.github.io/Cozejs/verifier/coze.html
[Coz]: https://github.com/Cyphrme/Coz
[CozRust]: https://github.com/Cyphrme/coz-rust
[CozeCLI]: https://github.com/Cyphrme/CozeCLI
[CozeX]: https://github.com/Cyphrme/CozeX
[CozeGoX]: https://github.com/Cyphrme/CozeGoX
[CozeJS]: https://github.com/Cyphrme/CozeJS
[CozeJSX]: https://github.com/Cyphrme/CozeJS
[Normal]: https://github.com/Cyphrme/Coze_go_x/tree/master/normal
[checksums]: https://github.com/Cyphrme/Coze_x/blob/master/proposal/checksum.md
[coze_vs]: https://github.com/Cyphrme/Coze_x/blob/master/coze_vs.md
[http_headers]: https://github.com/Cyphrme/Coze_x/blob/master/http_headers.md
[low_s]: https://github.com/Cyphrme/Coze_x/blob/master/implemented/malleability_low_s.md
[base64.md]: https://github.com/Cyphrme/Coze_x/blob/master/implemented/base64.md
[RFC6468Canonical]: https://datatracker.ietf.org/doc/html/rfc4648#section-3.5
[RFC4648]: https://datatracker.ietf.org/doc/html/rfc4648
[RFC8259]: https://datatracker.ietf.org/doc/html/rfc8259
[RFC8259-8.1]: https://datatracker.ietf.org/doc/html/rfc8259#section-8.1
[RFC7159]: https://datatracker.ietf.org/doc/html/rfc7159
[RFC7158]: https://datatracker.ietf.org/doc/html/rfc7158
[RFC4627]: https://datatracker.ietf.org/doc/html/rfc4627
[RFC7493]: https://datatracker.ietf.org/doc/html/rfc7493
[JSON5]: https://github.com/json5/json5-spec
[FIPS]: https://csrc.nist.gov/publications/fips

Coz is released as open source software. Use at your own risk.
