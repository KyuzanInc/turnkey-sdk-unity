# Turnkey Unity SDK

Unofficial Unity implementation of Turnkey SDK for cryptographic operations and API client functionality.

## File Structure

| Node.js Package | Version | Node.js Source | Unity File | Description |
|-----------------|---------|----------------|------------|-------------|
| @turnkey/crypto | 2.8.9 | `crypto.ts` | `Crypto.cs` | Main cryptographic operations (HPKE, key generation, bundle encryption/decryption) |
| @turnkey/crypto | 2.8.9 | `math.ts` | `CryptoMath.cs` | Mathematical utilities (modular square root) |
| @turnkey/crypto | 2.8.9 | `constants.ts` | `CryptoConstants.cs` | HPKE suite IDs, signer public keys |
| @turnkey/crypto | 2.8.9 | (in crypto.ts) | `CryptoHkdf.cs` | HKDF implementation (uses @noble/hashes/hkdf in Node.js) |
| @turnkey/http | 3.16.1 | `index.ts` | `Http.cs` | HTTP client with Turnkey stamping |
| @turnkey/api-key-stamper | 0.6.0 | `index.ts` | `ApiKeyStamper.cs` | ECDSA signature generation for API authentication |
| @turnkey/encoding | 0.6.0 | `index.ts` | `Encoding.cs` | Hex/Base58/UTF-8 encoding and decoding |
| @turnkey/encoding | 0.6.0 | (internal) | `EncodingConstants.cs` | BASE58_ALPHABET constant |
| (Unity-specific) | - | - | `UnityConstants.cs` | BouncyCastle-specific constants (CURVE_NAME, P256 parameters) |

### Internal Dependencies

```
Level 0 (no internal dependencies):
  - CryptoConstants.cs
  - CryptoMath.cs
  - EncodingConstants.cs
  - UnityConstants.cs
  - CryptoHkdf.cs

Level 1:
  - Encoding.cs → EncodingConstants

Level 2:
  - ApiKeyStamper.cs → Encoding, UnityConstants
  - Crypto.cs → CryptoConstants, CryptoMath, Encoding, UnityConstants, Hkdf

Level 3:
  - Http.cs → Crypto, Encoding, ApiKeyStamper
```

## Features

- **HTTP Client**: API request signing with Turnkey stamping (`Turnkey.Http`)
- **API Key Stamper**: ECDSA signature generation for API authentication (`Turnkey.ApiKeyStamper`)
- **Cryptography**: P256 key pair generation and HPKE encryption/decryption (`Turnkey.Crypto`)
- **Private Key Operations**: Bundle encryption/decryption (`EncryptPrivateKeyToBundle`, `DecryptExportBundle`)
- **Credential Handling**: Encrypted credential bundle decryption
- **Encoding Utilities**: Base58/Base64/Hex encoding and decoding (`Turnkey.Encoding`)
- **Signature Verification**: ECDSA signature verification for bundle integrity

## Installation

### As local dependency (recommended)

This package is designed to be used as a local dependency within the Peak monorepo:

```json
{
  "dependencies": {
    "com.kyuzan.turnkey-sdk-unity": "file:../turnkey-sdk-unity"
  }
}
```

### Future: As Git dependency

When moved to a separate repository:
```json
{
  "dependencies": {
    "com.kyuzan.turnkey-sdk-unity": "https://github.com/KyuzanInc/turnkey-sdk-unity.git#v0.1.0"
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

This package is primarily used by:
- **@packages/peak-sdk-unity/** - Peak's embedded wallet SDK for Unity
- **@examples/peak-sdk-unity-example/** - Unity example project demonstrating usage

It is designed as a low-level cryptographic library that provides Turnkey-compatible operations for Unity projects.

## Architecture

This package follows the same structure as Node.js Turnkey packages:

```
Node.js:  @turnkey/crypto → utils/turnkey.ts → wallet-service.ts
Unity:    Turnkey.Crypto  → Utils/Turnkey.cs → WalletService.cs
```

The main entry point is `Turnkey.Crypto` class, which provides all cryptographic operations needed for Turnkey integration.

## License

MIT License - See LICENSE file for details

## Status

⚠️ **Unofficial Implementation**: This is not an official Turnkey SDK. When an official Unity SDK becomes available, projects should migrate to the official version.

This package is designed to eventually be moved to a separate repository when it becomes stable and feature-complete.

## Contributing

This package is designed to be replaced by an official Turnkey Unity SDK when available. Until then, bug fixes and compatibility updates are welcome.