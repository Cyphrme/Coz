# Coz Algorithm Registry

This registry defines the normative parameters for each `alg` in Coz.

## Signing

| Name      | Genus | Family | Use | Curve      | Hash     | HashSize | HashSizeB64 | PubSize | PubSizeB64 | PrvSize | PrvSizeB64 | SigSize | SigSizeB64 |
| --------- | ----- | ------ | --- | ---------- | -------- | -------- | ----------- | ------- | ---------- | ------- | ---------- | ------- | ---------- |
| ES224     | ECDSA | EC     | sig | P-224      | SHA-224  | 28       | 38          | 56      | 75         | 28      | 38         | 56      | 75         |
| ES256     | ECDSA | EC     | sig | P-256      | SHA-256  | 32       | 43          | 64      | 86         | 32      | 43         | 64      | 86         |
| ES384     | ECDSA | EC     | sig | P-384      | SHA-384  | 48       | 64          | 96      | 128        | 48      | 64         | 96      | 128        |
| ES512     | ECDSA | EC     | sig | P-521      | SHA-512  | 64       | 86          | 132     | 176        | 66      | 88         | 132     | 176        |
| ES256k    | ECDSA | EC     | sig | secp256k1  | SHA-256  | 32       | 43          | 64      | 86         | 32      | 43         | 64      | 86         |
| Ed25519   | EdDSA | EC     | sig | Curve25519 | SHA-512  | 64       | 86          | 32      | 43         | 32      | 43         | 64      | 86         |
| Ed25519ph | EdDSA | EC     | sig | Curve25519 | SHA-512  | 64       | 86          | 32      | 43         | 32      | 43         | 64      | 86         |
| Ed448     | EdDSA | EC     | sig | Curve448   | SHAKE256 | 64       | 86          | 57      | 76         | 57      | 76         | 114     | 152        |

## Hashing

| Name     | Genus | Family | Use | HashSize | HashSizeB64 |
| -------- | ----- | ------ | --- | -------- | ----------- |
| SHA-224  | SHA2  | SHA    | hsh | 28       | 38          |
| SHA-256  | SHA2  | SHA    | hsh | 32       | 43          |
| SHA-384  | SHA2  | SHA    | hsh | 48       | 64          |
| SHA-512  | SHA2  | SHA    | hsh | 64       | 86          |
| SHA3-224 | SHA3  | SHA    | hsh | 28       | 38          |
| SHA3-256 | SHA3  | SHA    | hsh | 32       | 43          |
| SHA3-384 | SHA3  | SHA    | hsh | 48       | 64          |
| SHA3-512 | SHA3  | SHA    | hsh | 64       | 86          |
| SHAKE128 | SHA3  | SHA    | hsh | 32       | 43          |
| SHAKE256 | SHA3  | SHA    | hsh | 64       | 86          |

## Notes

- Sizes are in bytes. B64 columns are b64ut and sizes are `ceil(4*n/3)`.
- Hex size is simply double of the byte size.  Omitted from the tables for
  brevity.
- Variable length hashes, like SHAKE128/SHAKE256, have defined fixed defaults;
  both permit arbitrary output length.