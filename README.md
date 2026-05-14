# Turnkey Unity SDK

Unofficial Unity implementation of Turnkey SDK for cryptographic operations and API client functionality.

## File Structure

This package was ported from the upstream Turnkey TypeScript SDKs at
fixed versions. The C# layout consolidates several TS source files
into fewer `.cs` files using nested `static` classes; the table below
records the original TS provenance for each piece of functionality.

| Node.js Package | Version | Node.js Source | Unity File | Description |
|-----------------|---------|----------------|------------|-------------|
| @turnkey/crypto | 2.8.9 | `crypto.ts` | `Crypto.cs` | Main cryptographic operations (HPKE, key generation, bundle encryption/decryption) |
| @turnkey/crypto | 2.8.9 | `math.ts` | `Crypto.cs` (nested `Crypto.Math`) | Mathematical utilities (modular square root) |
| @turnkey/crypto | 2.8.9 | `constants.ts` | `Crypto.cs` (nested `Crypto.Constants`) | HPKE suite IDs, signer public keys |
| @turnkey/crypto | 2.8.9 | (HKDF impl in `crypto.ts`; uses `@noble/hashes/hkdf` in Node.js) | `Crypto.cs` (nested `Crypto.Hkdf`) | HKDF Extract / Expand |
| @turnkey/http | 3.16.1 | `index.ts` | `Http.cs` | Signed Turnkey request builder (API key stamping; partial port — no error handling / polling / WebAuthn) |
| @turnkey/api-key-stamper | 0.6.0 | `index.ts` | `ApiKeyStamper.cs` | ECDSA signature generation for API authentication |
| @turnkey/encoding | 0.6.0 | `hex.ts` | `Encoding.cs` (`Uint8ArrayToHexString`, `Uint8ArrayFromHexString`) | Hex encoding / decoding |
| @turnkey/encoding | 0.6.0 | `bs58.ts`, `bs58check.ts` | `Encoding.cs` (`Base58Encode`, `Base58Decode`, `Base58CheckDecode`) | Base58 / Base58Check |
| @turnkey/encoding | 0.6.0 | (internal `BASE58_ALPHABET` in `bs58.ts`) | `Encoding.cs` (nested `Encoding.Constants`) | BASE58_ALPHABET constant |
| (Unity-specific) | - | - | `UnityConstants.cs` | BouncyCastle-specific constants (CURVE_NAME, P256 parameters) |

The upstream `@turnkey/encoding/base64.ts` is **not** ported: C# uses
`System.Convert.ToBase64String` / `FromBase64String` directly. Other
unported pieces are noted in the corresponding `.cs` file headers
(for example `hpkeAuthEncrypt`, `quorumKeyEncrypt`, and DER signature
helpers in `Crypto.cs`).

### Internal Dependencies

```
Level 0 (no internal dependencies):
  - UnityConstants.cs

Level 1:
  - Encoding.cs (uses its own nested Constants)

Level 2:
  - ApiKeyStamper.cs → Encoding, UnityConstants
  - Crypto.cs       → Encoding, UnityConstants (Math, Hkdf, Constants nested)

Level 3:
  - Http.cs → Crypto, Encoding, ApiKeyStamper
```

## Features

- **Signed request builder** (`Turnkey.Http`): build Turnkey API requests with API key stamping. Higher-level features such as response polling, WebAuthn, and error retries are out of scope.
- **API Key Stamper** (`Turnkey.ApiKeyStamper`): ECDSA signature generation for API authentication.
- **Cryptography** (`Turnkey.Crypto`): P-256 key pair generation, HPKE encryption / decryption, bundle encryption / decryption (`EncryptPrivateKeyToBundle`, `DecryptExportBundle`), and encrypted credential bundle decryption.
- **Encoding utilities** (`Turnkey.Encoding`): Hex / Base58 / UTF-8 conversions.
- **Signature verification**: ECDSA signature verification for bundle integrity.

## Installation

Add the package to your Unity project's `Packages/manifest.json` as a
UPM Git dependency, pinning a tag for stability:

```json
{
  "dependencies": {
    "com.kyuzan.turnkey-sdk-unity": "https://github.com/KyuzanInc/turnkey-sdk-unity.git#v0.1.0"
  }
}
```

Or via the Unity Package Manager UI:

1. Open **Window ▸ Package Manager**.
2. Click **+ ▸ Add package from git URL...**
3. Enter `https://github.com/KyuzanInc/turnkey-sdk-unity.git`.

### Local file path (contributors only)

When contributing to this package from a checkout that already has it
on disk, you can point Unity at the local copy with a `file:` URL
instead of pulling from Git:

```json
{
  "dependencies": {
    "com.kyuzan.turnkey-sdk-unity": "file:../turnkey-sdk-unity"
  }
}
```

## Usage

```csharp
using Turnkey;

// Generate P256 key pair
var keyPair = Crypto.GenerateP256KeyPair();

// Create HTTP client for Turnkey API
var httpClient = Http.FromTargetPrivateKey(privateKey);

// Create API key stamper
var stamper = new ApiKeyStamper(publicKey, privateKey);
var stampedRequest = stamper.Stamp(jsonPayload);

// Encrypt private key for Turnkey import
var encrypted = Crypto.EncryptPrivateKeyToBundle(new Crypto.EncryptPrivateKeyToBundleParams
{
    privateKey = "0x1234...",
    importBundle = importBundle,
    organizationId = "org_123",
    userId = "user_456",
    keyFormat = "HEXADECIMAL"
});

// Decrypt export bundle
var decrypted = Crypto.DecryptExportBundle(new Crypto.DecryptExportBundleParams
{
    exportBundle = exportBundle,
    embeddedKey = "0x5678...",
    organizationId = "org_123",
    returnMnemonic = false,
    keyFormat = "HEXADECIMAL"
});

// Decrypt credential bundle
var apiPrivateKey = Crypto.DecryptCredentialBundle(bundle, targetPrivateKey);

// Encoding utilities
var hex = Encoding.Uint8ArrayToHexString(bytes);
var bytes = Encoding.Uint8ArrayFromHexString(hex);
```

## Dependencies

- Unity 6000.0.5f1 or later
- BouncyCastle Cryptography (via Plugins)
- Newtonsoft.Json 3.2.1

## Usage Context

This package is a low-level cryptographic and signed-request library
that provides Turnkey-compatible operations for Unity projects.
Higher-level wallet SDKs (e.g.
[`peak-sdk-unity`](https://github.com/KyuzanInc/peak-sdk-unity)) can
build on top of it.

## Architecture

This package follows the same structure as Node.js Turnkey packages:

```
Node.js:  @turnkey/crypto → utils/turnkey.ts → wallet-service.ts
Unity:    Turnkey.Crypto  → Utils/Turnkey.cs → WalletService.cs
```

The main entry point is `Turnkey.Crypto` class, which provides all cryptographic operations needed for Turnkey integration.

## License

Released under the MIT License. A standalone `LICENSE` file is not
distributed at the package root; the BouncyCastle plugin retains its
own license at `Plugins/BouncyCastle/LICENSE.md`.

## Status

⚠️ **Unofficial Implementation**: This is not an official Turnkey SDK. When an official Unity SDK becomes available, projects should migrate to the official version.

This package is designed to eventually be moved to a separate repository when it becomes stable and feature-complete.

## Contributing

This package is designed to be replaced by an official Turnkey Unity SDK when available. Until then, bug fixes and compatibility updates are welcome.