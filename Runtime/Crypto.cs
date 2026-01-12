using System;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;

namespace Turnkey
{
    /// <summary>
    /// Core cryptographic operations for Turnkey.
    /// Ported from @turnkey/crypto v2.8.9.
    /// Note: hpkeAuthEncrypt, quorumKeyEncrypt, fromDerSignature, toDerSignature,
    /// and extractPrivateKeyFromPKCS8Bytes are not implemented.
    /// </summary>
    public static class Crypto
    {
        #region Nested Classes

        /// <summary>
        /// Constants used by the Turnkey crypto library.
        /// Ported from @turnkey/crypto v2.8.9 constants.ts.
        /// </summary>
        public static class Constants
        {
            // HPKE Suite constants
            public static readonly byte[] SUITE_ID_1 = new byte[] { 75, 69, 77, 0, 16 }; // KEM suite ID
            public static readonly byte[] SUITE_ID_2 = new byte[] { 72, 80, 75, 69, 0, 16, 0, 1, 0, 2 }; // HPKE suite ID
            public static readonly byte[] HPKE_VERSION = new byte[] { 72, 80, 75, 69, 45, 118, 49 }; // HPKE-v1

            // HPKE Labels
            public static readonly byte[] LABEL_SECRET = new byte[] { 115, 101, 99, 114, 101, 116 }; // secret
            public static readonly byte[] LABEL_EAE_PRK = new byte[] { 101, 97, 101, 95, 112, 114, 107 }; // eae_prk
            public static readonly byte[] LABEL_SHARED_SECRET = new byte[] { 115, 104, 97, 114, 101, 100, 95, 115, 101, 99, 114, 101, 116 }; // shared_secret

            // AES_KEY_INFO and IV_INFO constants
            public static readonly byte[] AES_KEY_INFO = new byte[] {
                0, 32, 72, 80, 75, 69, 45, 118, 49, 72, 80, 75, 69, 0, 16, 0, 1, 0, 2, 107,
                101, 121, 0, 143, 195, 174, 184, 50, 73, 10, 75, 90, 179, 228, 32, 35, 40,
                125, 178, 154, 31, 75, 199, 194, 34, 192, 223, 34, 135, 39, 183, 10, 64, 33,
                18, 47, 63, 4, 233, 32, 108, 209, 36, 19, 80, 53, 41, 180, 122, 198, 166, 48,
                185, 46, 196, 207, 125, 35, 69, 8, 208, 175, 151, 113, 201, 158, 80
            };

            public static readonly byte[] IV_INFO = new byte[] {
                0, 12, 72, 80, 75, 69, 45, 118, 49, 72, 80, 75, 69, 0, 16, 0, 1, 0, 2, 98, 97,
                115, 101, 95, 110, 111, 110, 99, 101, 0, 143, 195, 174, 184, 50, 73, 10, 75,
                90, 179, 228, 32, 35, 40, 125, 178, 154, 31, 75, 199, 194, 34, 192, 223, 34,
                135, 39, 183, 10, 64, 33, 18, 47, 63, 4, 233, 32, 108, 209, 36, 19, 80, 53,
                41, 180, 122, 198, 166, 48, 185, 46, 196, 207, 125, 35, 69, 8, 208, 175, 151,
                113, 201, 158, 80
            };

            // Key size constants
            public const int UNCOMPRESSED_PUB_KEY_LENGTH_BYTES = 65;

            // Production signer public key for bundle signature verification
            public const string PRODUCTION_SIGNER_SIGN_PUBLIC_KEY = "04cf288fe433cc4e1aa0ce1632feac4ea26bf2f5a09dcfe5a42c398e06898710330f0572882f4dbdf0f5304b8fc8703acd69adca9a4bbf7f5d00d20a5e364b2569";

            // Notarizer public key for session JWT verification
            public const string PRODUCTION_NOTARIZER_SIGN_PUBLIC_KEY = "04d498aa87ac3bf982ac2b5dd9604d0074905cfbda5d62727c5a237b895e6749205e9f7cd566909c4387f6ca25c308445c60884b788560b785f4a96ac33702a469";
        }

        /// <summary>
        /// Mathematical operations for Turnkey crypto.
        /// Ported from @turnkey/crypto v2.8.9 math.ts.
        /// </summary>
        public static class Math
        {
            /// <summary>
            /// Compute modular square root using Tonelli-Shanks algorithm.
            /// </summary>
            /// <param name="x">The value to compute square root of</param>
            /// <param name="p">The prime modulus</param>
            /// <returns>The modular square root</returns>
            /// <exception cref="ArgumentException">If p is not positive</exception>
            /// <exception cref="InvalidOperationException">If no modular square root exists or unsupported modulus</exception>
            public static BigInteger ModSqrt(BigInteger x, BigInteger p)
            {
                if (p.CompareTo(BigInteger.Zero) <= 0)
                {
                    throw new ArgumentException("p must be positive");
                }

                var baseVal = x.Mod(p);

                // Check if p % 4 == 3 (applies to NIST curves P-256, P-384, and P-521)
                // This is true when both bit 0 and bit 1 are set
                if (p.TestBit(0) && p.TestBit(1))
                {
                    // q = (p + 1) / 4
                    var q = p.Add(BigInteger.One).ShiftRight(2);
                    var squareRoot = baseVal.ModPow(q, p);

                    // Verify the result
                    if (!squareRoot.Multiply(squareRoot).Mod(p).Equals(baseVal))
                    {
                        throw new InvalidOperationException("could not find a modular square root");
                    }

                    return squareRoot;
                }

                // Other elliptic curve types not supported
                throw new InvalidOperationException("unsupported modulus value");
            }
        }

        /// <summary>
        /// HMAC-based Key Derivation Function (HKDF) implementation.
        /// Equivalent to @noble/hashes/hkdf used by @turnkey/crypto v2.8.9.
        /// Based on RFC 5869: https://tools.ietf.org/html/rfc5869
        /// </summary>
        public static class Hkdf
        {
            private const int HashLen = 32; // SHA-256 output length

            /// <summary>
            /// HKDF Extract step - Extract a pseudorandom key from input keying material
            /// </summary>
            /// <param name="salt">Optional salt value (if not provided, a string of HashLen zeros is used)</param>
            /// <param name="ikm">Input keying material</param>
            /// <returns>Pseudorandom key (PRK)</returns>
            public static byte[] Extract(byte[] salt, byte[] ikm)
            {
                if (salt == null || salt.Length == 0)
                {
                    salt = new byte[HashLen]; // Use HashLen zeros
                }

                using (var hmac = new System.Security.Cryptography.HMACSHA256(salt))
                {
                    return hmac.ComputeHash(ikm);
                }
            }

            /// <summary>
            /// HKDF Expand step - Expand the pseudorandom key to the desired length
            /// </summary>
            /// <param name="prk">Pseudorandom key from Extract step</param>
            /// <param name="info">Optional context and application specific information</param>
            /// <param name="length">Length of output keying material in bytes</param>
            /// <returns>Output keying material (OKM)</returns>
            public static byte[] Expand(byte[] prk, byte[] info, int length)
            {
                if (prk == null || prk.Length < HashLen)
                {
                    throw new ArgumentException("PRK must be at least HashLen bytes");
                }

                if (length > 255 * HashLen)
                {
                    throw new ArgumentException($"Output length cannot exceed 255 * HashLen ({255 * HashLen} bytes)");
                }

                if (info == null)
                {
                    info = new byte[0];
                }

                var n = (int)System.Math.Ceiling((double)length / HashLen);
                var okm = new byte[n * HashLen];
                var tPrev = new byte[0];

                using (var hmac = new System.Security.Cryptography.HMACSHA256(prk))
                {
                    for (int i = 1; i <= n; i++)
                    {
                        var input = new byte[tPrev.Length + info.Length + 1];
                        Array.Copy(tPrev, 0, input, 0, tPrev.Length);
                        Array.Copy(info, 0, input, tPrev.Length, info.Length);
                        input[input.Length - 1] = (byte)i;

                        var t = hmac.ComputeHash(input);
                        Array.Copy(t, 0, okm, (i - 1) * HashLen, HashLen);
                        tPrev = t;
                    }
                }

                // Return only the requested length
                var result = new byte[length];
                Array.Copy(okm, 0, result, 0, length);
                return result;
            }
        }

        #endregion
        /// <summary>
        /// HPKE Decrypt parameters
        /// </summary>
        public class HpkeDecryptParams
        {
            public byte[] CiphertextBuf { get; set; }
            public byte[] EncappedKeyBuf { get; set; }
            public string ReceiverPriv { get; set; }
        }

        /// <summary>
        /// HPKE Encrypt parameters
        /// </summary>
        public class HpkeEncryptParams
        {
            public byte[] PlainTextBuf { get; set; }
            public byte[] TargetKeyBuf { get; set; }
        }

        /// <summary>
        /// Key pair structure
        /// </summary>
        public class KeyPair
        {
            public string PrivateKey { get; set; }
            public string PublicKey { get; set; }
            public string PublicKeyUncompressed { get; set; }
        }

        /// <summary>
        /// Get public key from private key
        /// </summary>
        /// <param name="privateKey">Private key as byte array or hex string</param>
        /// <param name="isCompressed">Whether to return compressed format (default: true)</param>
        /// <returns>Public key as byte array</returns>
        public static byte[] GetPublicKey(byte[] privateKey, bool isCompressed = true)
        {
            var curve = ECNamedCurveTable.GetByName(UnityConstants.CURVE_NAME);
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

            var d = new BigInteger(1, privateKey);
            var privateKeyParams = new ECPrivateKeyParameters(d, domainParams);
            var publicKeyParams = new ECPublicKeyParameters(privateKeyParams.Parameters.G.Multiply(d), domainParams);

            return publicKeyParams.Q.GetEncoded(isCompressed);
        }

        /// <summary>
        /// Get public key from private key (hex string overload)
        /// </summary>
        public static byte[] GetPublicKey(string privateKeyHex, bool isCompressed = true)
        {
            var privateKey = Encoding.Uint8ArrayFromHexString(privateKeyHex);
            return GetPublicKey(privateKey, isCompressed);
        }

        /// <summary>
        /// Generate a P-256 key pair
        /// </summary>
        /// <returns>Key pair with hex-encoded keys</returns>
        public static KeyPair GenerateP256KeyPair()
        {
            var curve = ECNamedCurveTable.GetByName(UnityConstants.CURVE_NAME);
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

            var keyGen = new ECKeyPairGenerator();
            var random = new SecureRandom();
            var keyGenParams = new ECKeyGenerationParameters(domainParams, random);
            keyGen.Init(keyGenParams);

            var keyPair = keyGen.GenerateKeyPair();
            var privateKey = ((ECPrivateKeyParameters)keyPair.Private).D.ToByteArrayUnsigned();
            var publicKeyCompressed = ((ECPublicKeyParameters)keyPair.Public).Q.GetEncoded(true);
            var publicKeyUncompressed = ((ECPublicKeyParameters)keyPair.Public).Q.GetEncoded(false);

            // Ensure private key is 32 bytes
            if (privateKey.Length < 32)
            {
                var padded = new byte[32];
                Array.Copy(privateKey, 0, padded, 32 - privateKey.Length, privateKey.Length);
                privateKey = padded;
            }

            return new KeyPair
            {
                PrivateKey = Encoding.Uint8ArrayToHexString(privateKey),
                PublicKey = Encoding.Uint8ArrayToHexString(publicKeyCompressed),
                PublicKeyUncompressed = Encoding.Uint8ArrayToHexString(publicKeyUncompressed)
            };
        }

        /// <summary>
        /// HPKE decryption implementation matching @turnkey/crypto v2.8.9
        /// </summary>
        public static byte[] HpkeDecrypt(HpkeDecryptParams parameters)
        {
            var ciphertextBuf = parameters.CiphertextBuf;
            var encappedKeyBuf = parameters.EncappedKeyBuf;
            var receiverPriv = parameters.ReceiverPriv;

            // Get receiver public key (uncompressed)
            var receiverPrivBytes = Encoding.Uint8ArrayFromHexString(receiverPriv);
            var receiverPubBuf = GetPublicKey(receiverPrivBytes, false);

            // Build AAD
            var aad = BuildAdditionalAssociatedData(encappedKeyBuf, receiverPubBuf);

            // Step 1: Generate Shared Secret
            var ss = DeriveSS(encappedKeyBuf, receiverPriv);

            // Step 2: Generate the KEM context
            var kemContext = GetKemContext(encappedKeyBuf, Encoding.Uint8ArrayToHexString(receiverPubBuf));

            // Step 3: Build the HKDF inputs for key derivation
            var ikm = BuildLabeledIkm(Constants.LABEL_EAE_PRK, ss, Constants.SUITE_ID_1);
            var info = BuildLabeledInfo(Constants.LABEL_SHARED_SECRET, kemContext, Constants.SUITE_ID_1, 32);
            var sharedSecret = ExtractAndExpand(new byte[0], ikm, info, 32);

            // Step 4: Derive the AES key
            ikm = BuildLabeledIkm(Constants.LABEL_SECRET, new byte[0], Constants.SUITE_ID_2);
            info = Constants.AES_KEY_INFO;
            var key = ExtractAndExpand(sharedSecret, ikm, info, 32);

            // Step 5: Derive the initialization vector
            info = Constants.IV_INFO;
            var iv = ExtractAndExpand(sharedSecret, ikm, info, 12);

            // Step 6: Decrypt the data using AES-GCM
            return AesGcmDecrypt(ciphertextBuf, key, iv, aad);
        }

        /// <summary>
        /// HPKE encryption implementation matching @turnkey/crypto v2.8.9
        /// </summary>
        public static byte[] HpkeEncrypt(HpkeEncryptParams parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            var plainTextBuf = parameters.PlainTextBuf ?? Array.Empty<byte>();
            var targetKeyBuf = parameters.TargetKeyBuf ?? throw new ArgumentNullException(nameof(parameters.TargetKeyBuf));

            // Generate ephemeral key pair
            var ephemeralKeyPair = GenerateP256KeyPair();
            var senderPrivBuf = Encoding.Uint8ArrayFromHexString(ephemeralKeyPair.PrivateKey);
            var senderPubBuf = Encoding.Uint8ArrayFromHexString(ephemeralKeyPair.PublicKeyUncompressed);

            // Build associated data (sender public key + receiver public key)
            var aad = BuildAdditionalAssociatedData(senderPubBuf, targetKeyBuf);

            // Derive shared secret via ECDH
            var ss = DeriveSS(targetKeyBuf, Encoding.Uint8ArrayToHexString(senderPrivBuf));

            // Generate the KEM context
            var kemContext = GetKemContext(senderPubBuf, Encoding.Uint8ArrayToHexString(targetKeyBuf));

            // HKDF derive shared secret
            var ikm = BuildLabeledIkm(Constants.LABEL_EAE_PRK, ss, Constants.SUITE_ID_1);
            var info = BuildLabeledInfo(Constants.LABEL_SHARED_SECRET, kemContext, Constants.SUITE_ID_1, 32);
            var sharedSecret = ExtractAndExpand(Array.Empty<byte>(), ikm, info, 32);

            // Derive AES key and IV
            ikm = BuildLabeledIkm(Constants.LABEL_SECRET, Array.Empty<byte>(), Constants.SUITE_ID_2);
            info = Constants.AES_KEY_INFO;
            var key = ExtractAndExpand(sharedSecret, ikm, info, 32);

            info = Constants.IV_INFO;
            var iv = ExtractAndExpand(sharedSecret, ikm, info, 12);

            // Encrypt using AES-GCM
            var encryptedData = AesGcmEncrypt(plainTextBuf, key, iv, aad);

            // Concatenate compressed sender public key with ciphertext
            var compressedSenderBuf = CompressRawPublicKey(senderPubBuf);
            return Encoding.ConcatUint8Arrays(compressedSenderBuf, encryptedData);
        }

        /// <summary>
        /// Build additional associated data (AAD) for AES-GCM
        /// </summary>
        public static byte[] BuildAdditionalAssociatedData(byte[] senderPubBuf, byte[] receiverPubBuf)
        {
            return Encoding.ConcatUint8Arrays(senderPubBuf, receiverPubBuf);
        }

        /// <summary>
        /// Compress a raw public key
        /// </summary>
        public static byte[] CompressRawPublicKey(byte[] rawPublicKey)
        {
            if (rawPublicKey.Length != Constants.UNCOMPRESSED_PUB_KEY_LENGTH_BYTES || rawPublicKey[0] != 0x04)
            {
                throw new ArgumentException("Invalid uncompressed public key");
            }

            var x = new byte[32];
            Array.Copy(rawPublicKey, 1, x, 0, 32);

            // Check the last bit of Y to determine prefix
            var lastByte = rawPublicKey[64];
            var prefix = (byte)((lastByte & 1) == 0 ? 0x02 : 0x03);

            var compressed = new byte[33];
            compressed[0] = prefix;
            Array.Copy(x, 0, compressed, 1, 32);

            return compressed;
        }

        /// <summary>
        /// Uncompress a compressed public key
        /// </summary>
        public static byte[] UncompressRawPublicKey(byte[] rawPublicKey)
        {
            if (rawPublicKey.Length != UnityConstants.COMPRESSED_PUBLIC_KEY_SIZE)
            {
                throw new ArgumentException($"Invalid compressed public key size: {rawPublicKey.Length}");
            }

            // Validate prefix byte (must be 0x02 or 0x03)
            if (rawPublicKey[0] != 0x02 && rawPublicKey[0] != 0x03)
            {
                throw new ArgumentException("failed to uncompress raw public key: invalid prefix");
            }

            // point[0] == 3 indicates odd y-coordinate
            var lsb = rawPublicKey[0] == 0x03;

            // Extract X coordinate (skip the prefix byte) - matching JS: BigInt("0x" + hexString)
            var xBytes = new byte[32];
            Array.Copy(rawPublicKey, 1, xBytes, 0, 32);
            // Create hex string from bytes to match JS behavior
            var xHex = Encoding.Uint8ArrayToHexString(xBytes);
            var x = new BigInteger(xHex, 16); // Create from hex string like JS

            // NIST P-256 curve parameters
            // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf (Appendix D).
            var p = new BigInteger(UnityConstants.P256_P);
            var b = new BigInteger(UnityConstants.P256_B, 16);
            var a = p.Subtract(new BigInteger(UnityConstants.P256_A_OFFSET));

            // Now compute y based on x
            // y^2 = x^3 + ax + b (mod p)
            // Match JS: ((x * x + a) * x + b) % p
            var x2 = x.Multiply(x).Mod(p);
            var x2PlusA = x2.Add(a).Mod(p);
            var rhs = x2PlusA.Multiply(x).Add(b).Mod(p);

            // Compute y = sqrt(rhs) mod p
            var y = Math.ModSqrt(rhs, p);

            // Adjust y based on the LSB (least significant bit)
            if (lsb != y.TestBit(0))
            {
                y = p.Subtract(y).Mod(p);
            }

            // Validate x and y are in range
            if (x.SignValue < 0 || x.CompareTo(p) >= 0)
            {
                throw new Exception("x is out of range");
            }
            if (y.SignValue < 0 || y.CompareTo(p) >= 0)
            {
                throw new Exception("y is out of range");
            }

            // Construct uncompressed public key (0x04 + X + Y)
            // Match JS: "04" + bigIntToHex(x, 64) + bigIntToHex(y, 64)
            var uncompressed = new byte[65];
            uncompressed[0] = 0x04;

            // Convert to hex and ensure proper padding (32 bytes = 64 hex chars)
            var xHexOutput = x.ToString(16).ToLower().PadLeft(64, '0');
            var yHexOutput = y.ToString(16).ToLower().PadLeft(64, '0');

            // Convert hex strings back to bytes
            var xOutputBytes = Encoding.Uint8ArrayFromHexString(xHexOutput);
            var yOutputBytes = Encoding.Uint8ArrayFromHexString(yHexOutput);

            // Copy to final array
            Array.Copy(xOutputBytes, 0, uncompressed, 1, 32);
            Array.Copy(yOutputBytes, 0, uncompressed, 33, 32);

            return uncompressed;
        }

        // Private helper methods

        private static byte[] DeriveSS(byte[] encappedKeyBuf, string priv)
        {
            var curve = ECNamedCurveTable.GetByName(UnityConstants.CURVE_NAME);
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

            // Create private key
            var privBytes = Encoding.Uint8ArrayFromHexString(priv);
            var d = new BigInteger(1, privBytes);
            var privateKeyParams = new ECPrivateKeyParameters(d, domainParams);

            // Create public key from encapsulated key
            var point = curve.Curve.DecodePoint(encappedKeyBuf);
            var publicKeyParams = new ECPublicKeyParameters(point, domainParams);

            // Perform ECDH
            var agreement = new ECDHBasicAgreement();
            agreement.Init(privateKeyParams);
            var sharedSecretBig = agreement.CalculateAgreement(publicKeyParams);
            var ss = sharedSecretBig.ToByteArrayUnsigned();

            // Ensure 32 bytes (pad if necessary)
            if (ss.Length < 32)
            {
                var padded = new byte[32];
                Array.Copy(ss, 0, padded, 32 - ss.Length, ss.Length);
                ss = padded;
            }

            return ss;
        }

        private static byte[] GetKemContext(byte[] encappedKeyBuf, string publicKey)
        {
            var publicKeyArray = Encoding.Uint8ArrayFromHexString(publicKey);
            return Encoding.ConcatUint8Arrays(encappedKeyBuf, publicKeyArray);
        }

        private static byte[] BuildLabeledIkm(byte[] label, byte[] ikm, byte[] suiteId)
        {
            return Encoding.ConcatUint8Arrays(
                Constants.HPKE_VERSION,
                suiteId,
                label,
                ikm
            );
        }

        private static byte[] BuildLabeledInfo(byte[] label, byte[] info, byte[] suiteId, int len)
        {
            const int suiteIdStartIndex = 9; // first two are reserved for length bytes, the next 7 are for HPKE_VERSION
            var ret = new byte[suiteIdStartIndex + suiteId.Length + label.Length + info.Length];

            // Set length bytes (big-endian)
            ret[0] = 0;
            ret[1] = (byte)len;

            // Copy HPKE_VERSION starting at index 2
            Array.Copy(Constants.HPKE_VERSION, 0, ret, 2, Constants.HPKE_VERSION.Length);

            // Copy suite ID
            Array.Copy(suiteId, 0, ret, suiteIdStartIndex, suiteId.Length);

            // Copy label
            Array.Copy(label, 0, ret, suiteIdStartIndex + suiteId.Length, label.Length);

            // Copy info
            Array.Copy(info, 0, ret, suiteIdStartIndex + suiteId.Length + label.Length, info.Length);

            return ret;
        }

        private static byte[] ExtractAndExpand(byte[] sharedSecret, byte[] ikm, byte[] info, int len)
        {
            // Use the Hkdf class for extract and expand
            var prk = Hkdf.Extract(sharedSecret, ikm);
            var resp = Hkdf.Expand(prk, info, len);
            return resp;
        }

        private static byte[] AesGcmDecrypt(byte[] encryptedData, byte[] key, byte[] iv, byte[] aad)
        {
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), 128, iv, aad);
            cipher.Init(false, parameters);

            var decrypted = new byte[cipher.GetOutputSize(encryptedData.Length)];
            var len = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, decrypted, 0);
            cipher.DoFinal(decrypted, len);

            return decrypted;
        }

        private static byte[] AesGcmEncrypt(byte[] plainData, byte[] key, byte[] iv, byte[] aad)
        {
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), 128, iv, aad);
            cipher.Init(true, parameters);

            var encrypted = new byte[cipher.GetOutputSize(plainData.Length)];
            var len = cipher.ProcessBytes(plainData, 0, plainData.Length, encrypted, 0);
            cipher.DoFinal(encrypted, len);

            return encrypted;
        }

        /// <summary>
        /// Decrypt an encrypted credential bundle
        /// </summary>
        /// <param name="encryptedCredentialBundle">Base58 or Base58Check encoded bundle</param>
        /// <param name="targetPrivateKey">Target private key in hex format</param>
        /// <returns>Decrypted credential as hex string</returns>
        public static string DecryptCredentialBundle(string encryptedCredentialBundle, string targetPrivateKey)
        {
            // Decode bundle bytes - try Base58Check first, fall back to plain Base58
            byte[] bundleBytes;
            try
            {
                bundleBytes = Encoding.Base58CheckDecode(encryptedCredentialBundle);
            }
            catch
            {
                bundleBytes = Encoding.Base58Decode(encryptedCredentialBundle);
            }

            const int COMPRESSED_PUBLIC_KEY_SIZE = 33;
            if (bundleBytes.Length <= COMPRESSED_PUBLIC_KEY_SIZE)
            {
                throw new Exception($"Bundle size {bundleBytes.Length} is too low. Expecting a compressed public key (33 bytes) and an encrypted credential.");
            }

            // Standard format: compressed public key + ciphertext
            var compressedKey = new byte[COMPRESSED_PUBLIC_KEY_SIZE];
            Array.Copy(bundleBytes, 0, compressedKey, 0, COMPRESSED_PUBLIC_KEY_SIZE);

            var ciphertext = new byte[bundleBytes.Length - COMPRESSED_PUBLIC_KEY_SIZE];
            Array.Copy(bundleBytes, COMPRESSED_PUBLIC_KEY_SIZE, ciphertext, 0, ciphertext.Length);

            // Uncompress the encapsulated public key
            var encappedKey = UncompressRawPublicKey(compressedKey);

            // Perform HPKE decryption
            var decryptedData = HpkeDecrypt(new HpkeDecryptParams
            {
                CiphertextBuf = ciphertext,
                EncappedKeyBuf = encappedKey,
                ReceiverPriv = targetPrivateKey
            });

            return Encoding.Uint8ArrayToHexString(decryptedData);
        }

        /// <summary>
        /// Parameter structure for EncryptPrivateKeyToBundle
        /// Equivalent to @turnkey/crypto encryptPrivateKeyToBundle parameters
        /// </summary>
        [Serializable]
        public class EncryptPrivateKeyToBundleParams
        {
            public string privateKey;
            public string importBundle;
            public string organizationId;
            public string userId;
            public string keyFormat;
        }

        /// <summary>
        /// Parameter structure for DecryptExportBundle
        /// Equivalent to @turnkey/crypto decryptExportBundle parameters
        /// </summary>
        [Serializable]
        public class DecryptExportBundleParams
        {
            public string exportBundle;
            public string embeddedKey;
            public string organizationId;
            public bool returnMnemonic;
            public string keyFormat;
        }

        /// <summary>
        /// Encrypt private key to bundle for Turnkey import
        /// Equivalent to @turnkey/crypto encryptPrivateKeyToBundle
        /// </summary>
        public static string EncryptPrivateKeyToBundle(EncryptPrivateKeyToBundleParams parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            if (string.IsNullOrWhiteSpace(parameters.privateKey))
            {
                throw new ArgumentException("Private key is required", nameof(parameters.privateKey));
            }

            if (string.IsNullOrWhiteSpace(parameters.importBundle))
            {
                throw new ArgumentException("Import bundle is required", nameof(parameters.importBundle));
            }

            if (string.IsNullOrWhiteSpace(parameters.organizationId))
            {
                throw new ArgumentException("Organization ID is required", nameof(parameters.organizationId));
            }

            if (string.IsNullOrWhiteSpace(parameters.userId))
            {
                throw new ArgumentException("User ID is required", nameof(parameters.userId));
            }

            try
            {
                var bundle = Newtonsoft.Json.Linq.JObject.Parse(parameters.importBundle);

                var enclaveQuorumPublic = bundle["enclaveQuorumPublic"]?.ToString();
                var dataSignature = bundle["dataSignature"]?.ToString();
                var signedDataHex = bundle["data"]?.ToString();

                if (string.IsNullOrEmpty(enclaveQuorumPublic) || string.IsNullOrEmpty(dataSignature) || string.IsNullOrEmpty(signedDataHex))
                {
                    throw new Exception("Invalid import bundle format - missing required fields");
                }

                VerifyEnclaveSignature(enclaveQuorumPublic, dataSignature, signedDataHex);

                var signedDataBytes = Encoding.Uint8ArrayFromHexString(signedDataHex);
                var signedDataJson = Newtonsoft.Json.Linq.JObject.Parse(System.Text.Encoding.UTF8.GetString(signedDataBytes));

                var orgId = signedDataJson["organizationId"]?.ToString();
                if (!string.Equals(orgId, parameters.organizationId, StringComparison.Ordinal))
                {
                    throw new Exception($"Organization ID mismatch. Expected: {parameters.organizationId}, got: {orgId}");
                }

                var userId = signedDataJson["userId"]?.ToString();
                if (!string.Equals(userId, parameters.userId, StringComparison.Ordinal))
                {
                    throw new Exception($"User ID mismatch. Expected: {parameters.userId}, got: {userId}");
                }

                var targetPublic = signedDataJson["targetPublic"]?.ToString();
                if (string.IsNullOrEmpty(targetPublic))
                {
                    throw new Exception("Import bundle missing targetPublic value");
                }

                var targetKeyBuf = Encoding.Uint8ArrayFromHexString(targetPublic);
                var plainTextBuf = DecodeKey(parameters.privateKey, parameters.keyFormat);

                var encryptedBuf = HpkeEncrypt(new HpkeEncryptParams
                {
                    PlainTextBuf = plainTextBuf,
                    TargetKeyBuf = targetKeyBuf
                });

                return FormatHpkeBuf(encryptedBuf);
            }
            catch (Exception error)
            {
                throw new Exception($"Error encrypting private key bundle: {error.Message}", error);
            }
        }

        /// <summary>
        /// Decrypt export bundle from Turnkey
        /// Equivalent to @turnkey/crypto decryptExportBundle
        /// </summary>
        public static string DecryptExportBundle(DecryptExportBundleParams parameters)
        {
            try
            {
                var bundleData = Newtonsoft.Json.Linq.JObject.Parse(parameters.exportBundle);

                // Handle both legacy (signedData/signature) and current (data/dataSignature) envelopes.
                var encappedPublic = bundleData["encappedPublic"]?.ToString();
                var ciphertext = bundleData["ciphertext"]?.ToString();
                var signature = bundleData["signature"]?.ToString();
                var signedData = bundleData["signedData"]?.ToString();
                Newtonsoft.Json.Linq.JObject signedDataObj = null;

                if (!string.IsNullOrEmpty(signature) && !string.IsNullOrEmpty(signedData))
                {
                    if (!VerifySignature(Constants.PRODUCTION_SIGNER_SIGN_PUBLIC_KEY, signature, signedData))
                    {
                        throw new Exception("Invalid signature on export bundle");
                    }

                    signedDataObj = Newtonsoft.Json.Linq.JObject.Parse(signedData);
                    encappedPublic ??= signedDataObj["encappedPublic"]?.ToString();
                    ciphertext ??= signedDataObj["ciphertext"]?.ToString();
                }
                else
                {
                    var dataHex = bundleData["data"]?.ToString();
                    var dataSignature = bundleData["dataSignature"]?.ToString();
                    var enclaveQuorumPublic = bundleData["enclaveQuorumPublic"]?.ToString();

                    if (string.IsNullOrEmpty(dataHex) || string.IsNullOrEmpty(dataSignature) || string.IsNullOrEmpty(enclaveQuorumPublic))
                    {
                        throw new Exception("Invalid export bundle format - missing required fields");
                    }

                    VerifyEnclaveSignature(enclaveQuorumPublic, dataSignature, dataHex);

                    var signedDataBytes = Encoding.Uint8ArrayFromHexString(dataHex);
                    var signedDataJson = System.Text.Encoding.UTF8.GetString(signedDataBytes);
                    signedDataObj = Newtonsoft.Json.Linq.JObject.Parse(signedDataJson);

                    encappedPublic = signedDataObj["encappedPublic"]?.ToString();
                    ciphertext = signedDataObj["ciphertext"]?.ToString();
                }

                if (signedDataObj != null)
                {
                    var bundleOrgId = signedDataObj["organizationId"]?.ToString();
                    if (!string.IsNullOrEmpty(bundleOrgId) && bundleOrgId != parameters.organizationId)
                    {
                        throw new Exception($"Organization ID mismatch. Expected: {parameters.organizationId}, got: {bundleOrgId}");
                    }
                }

                if (string.IsNullOrEmpty(encappedPublic) || string.IsNullOrEmpty(ciphertext))
                {
                    throw new Exception("Invalid export bundle format - missing HPKE payload");
                }

                var encappedKeyBuf = Encoding.Uint8ArrayFromHexString(encappedPublic);
                var ciphertextBuf = Encoding.Uint8ArrayFromHexString(ciphertext);

                var decryptedData = HpkeDecrypt(new HpkeDecryptParams
                {
                    CiphertextBuf = ciphertextBuf,
                    EncappedKeyBuf = encappedKeyBuf,
                    ReceiverPriv = parameters.embeddedKey
                });

                if (parameters.returnMnemonic)
                {
                    return Encoding.Uint8ArrayToString(decryptedData);
                }

                if (parameters.keyFormat == "SOLANA")
                {
                    return Encoding.Base58Encode(decryptedData);
                }

                return Encoding.Uint8ArrayToHexString(decryptedData);
            }
            catch (Exception error)
            {
                throw new Exception($"Error decrypting export bundle: {error.Message}", error);
            }
        }

        /// <summary>
        /// Verifies the signature of a Turnkey session JWT.
        /// Equivalent to verifySessionJwtSignature() in @turnkey/crypto.
        /// </summary>
        /// <param name="jwt">The JWT token to verify</param>
        /// <returns>True if the signature is valid, false otherwise</returns>
        public static bool VerifySessionJwtSignature(string jwt)
        {
            try
            {
                // 1. Split JWT into parts
                var parts = jwt.Split('.');
                if (parts.Length != 3)
                {
                    throw new Exception("Invalid JWT: need 3 parts");
                }

                var headerB64 = parts[0];
                var payloadB64 = parts[1];
                var signatureB64 = parts[2];
                var signingInput = $"{headerB64}.{payloadB64}";

                // 2. Calculate sha256(sha256(header.payload)) - double SHA256
                byte[] msgDigest;
                using (var sha256 = SHA256.Create())
                {
                    var h1 = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(signingInput));
                    msgDigest = sha256.ComputeHash(h1);
                }

                // 3. Base64URL decode the signature
                var signature = Base64UrlDecode(signatureB64);
                if (signature.Length != 64)
                {
                    throw new Exception($"Invalid signature length: expected 64 bytes, got {signature.Length}");
                }

                // 4. Load the notarizer public key
                var publicKey = Encoding.Uint8ArrayFromHexString(Constants.PRODUCTION_NOTARIZER_SIGN_PUBLIC_KEY);

                // 5. Verify using P256
                return VerifyP256Signature(publicKey, signature, msgDigest);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Decodes a base64url encoded string.
        /// </summary>
        private static byte[] Base64UrlDecode(string input)
        {
            // Replace URL-safe characters
            var output = input.Replace('-', '+').Replace('_', '/');
            // Add padding
            switch (output.Length % 4)
            {
                case 2: output += "=="; break;
                case 3: output += "="; break;
            }
            return Convert.FromBase64String(output);
        }

        /// <summary>
        /// Verifies a P256 signature with raw r||s format (64 bytes).
        /// </summary>
        private static bool VerifyP256Signature(byte[] publicKeyBytes, byte[] signatureRaw, byte[] messageDigest)
        {
            try
            {
                // Get the curve
                var curve = ECNamedCurveTable.GetByName(UnityConstants.CURVE_NAME);
                var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

                // Decode public key
                var point = curve.Curve.DecodePoint(publicKeyBytes);
                var publicKeyParams = new ECPublicKeyParameters(point, domainParams);

                // Convert raw signature (r || s, 64 bytes) to DER format for BouncyCastle
                var r = new BigInteger(1, signatureRaw, 0, 32);
                var s = new BigInteger(1, signatureRaw, 32, 32);
                var derSignature = new DerSequence(
                    new DerInteger(r),
                    new DerInteger(s)
                ).GetDerEncoded();

                // Use NONEwithECDSA since we already have the message digest
                var signer = SignerUtilities.GetSigner("NONEwithECDSA");
                signer.Init(false, publicKeyParams);
                signer.BlockUpdate(messageDigest, 0, messageDigest.Length);

                return signer.VerifySignature(derSignature);
            }
            catch
            {
                return false;
            }
        }

        // Helper methods for bundle operations
        private static void VerifyEnclaveSignature(string enclaveQuorumPublic, string signatureHex, string signedDataHex)
        {
            if (!string.Equals(enclaveQuorumPublic, Constants.PRODUCTION_SIGNER_SIGN_PUBLIC_KEY, StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception($"Signer key {enclaveQuorumPublic} is not recognized. Expected: {Constants.PRODUCTION_SIGNER_SIGN_PUBLIC_KEY}");
            }

            var publicKeyBytes = Encoding.Uint8ArrayFromHexString(Constants.PRODUCTION_SIGNER_SIGN_PUBLIC_KEY);
            var signatureBytes = Encoding.Uint8ArrayFromHexString(signatureHex);
            var messageBytes = Encoding.Uint8ArrayFromHexString(signedDataHex);

            var curve = ECNamedCurveTable.GetByName(UnityConstants.CURVE_NAME);
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
            var point = curve.Curve.DecodePoint(publicKeyBytes);
            var publicKeyParams = new ECPublicKeyParameters(point, domainParams);

            var signer = SignerUtilities.GetSigner("SHA-256withECDSA");
            signer.Init(false, publicKeyParams);
            signer.BlockUpdate(messageBytes, 0, messageBytes.Length);

            if (!signer.VerifySignature(signatureBytes))
            {
                throw new Exception("Failed to verify enclave signature");
            }
        }

        private static bool VerifySignature(string publicKeyHex, string signatureHex, string message)
        {
            try
            {
                var publicKeyBytes = Encoding.Uint8ArrayFromHexString(publicKeyHex);
                var signatureBytes = Encoding.Uint8ArrayFromHexString(signatureHex);
                var messageBytes = System.Text.Encoding.UTF8.GetBytes(message);

                // Create hash of the message
                using (var sha256 = SHA256.Create())
                {
                    var hash = sha256.ComputeHash(messageBytes);

                    // Verify using BouncyCastle
                    var curve = ECNamedCurveTable.GetByName(UnityConstants.CURVE_NAME);
                    var domainParams = new ECDomainParameters(
                        curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

                    var point = curve.Curve.DecodePoint(publicKeyBytes);
                    var publicKeyParams = new ECPublicKeyParameters(point, domainParams);

                    var signer = SignerUtilities.GetSigner("SHA-256withECDSA");
                    signer.Init(false, publicKeyParams);
                    signer.BlockUpdate(messageBytes, 0, messageBytes.Length);

                    return signer.VerifySignature(signatureBytes);
                }
            }
            catch
            {
                return false;
            }
        }

        private static byte[] DecodeKey(string privateKey, string keyFormat)
        {
            if (string.Equals(keyFormat, "SOLANA", StringComparison.OrdinalIgnoreCase))
            {
                var decoded = Encoding.Base58Decode(privateKey);
                if (decoded.Length != 64)
                {
                    throw new Exception($"Invalid Solana private key length. Expected 64 bytes, got {decoded.Length}.");
                }

                var privateKeyBytes = new byte[32];
                Array.Copy(decoded, 0, privateKeyBytes, 0, 32);
                return privateKeyBytes;
            }

            var normalized = privateKey.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                ? privateKey.Substring(2)
                : privateKey;

            return Encoding.Uint8ArrayFromHexString(normalized);
        }

        /// <summary>
        /// Format HPKE buffer into JSON format
        /// </summary>
        public static string FormatHpkeBuf(byte[] encryptedBuf)
        {
            if (encryptedBuf.Length <= UnityConstants.COMPRESSED_PUBLIC_KEY_SIZE)
            {
                throw new ArgumentException("Encrypted buffer too small");
            }

            var compressedEncappedPublic = new byte[UnityConstants.COMPRESSED_PUBLIC_KEY_SIZE];
            Array.Copy(encryptedBuf, 0, compressedEncappedPublic, 0, UnityConstants.COMPRESSED_PUBLIC_KEY_SIZE);

            var encappedPublicUncompressed = UncompressRawPublicKey(compressedEncappedPublic);

            var ciphertext = new byte[encryptedBuf.Length - UnityConstants.COMPRESSED_PUBLIC_KEY_SIZE];
            Array.Copy(encryptedBuf, UnityConstants.COMPRESSED_PUBLIC_KEY_SIZE, ciphertext, 0, ciphertext.Length);

            var result = new
            {
                encappedPublic = Encoding.Uint8ArrayToHexString(encappedPublicUncompressed),
                ciphertext = Encoding.Uint8ArrayToHexString(ciphertext)
            };

            return Newtonsoft.Json.JsonConvert.SerializeObject(result);
        }
    }
}
