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
using UnityEngine;

namespace Turnkey
{
    /// <summary>
    /// Core cryptographic operations for Turnkey, aligned with @turnkey/crypto
    /// </summary>
    public static class Crypto
    {
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
            var curve = ECNamedCurveTable.GetByName(Constants.CURVE_NAME);
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
            var curve = ECNamedCurveTable.GetByName(Constants.CURVE_NAME);
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
        /// HPKE decryption implementation matching Turnkey v2.3.1
        /// </summary>
        public static byte[] HpkeDecrypt(HpkeDecryptParams parameters)
        {
            try
            {
                var ciphertextBuf = parameters.CiphertextBuf;
                var encappedKeyBuf = parameters.EncappedKeyBuf;
                var receiverPriv = parameters.ReceiverPriv;

                Debug.Log($"HPKE Decrypt - Ciphertext length: {ciphertextBuf.Length}");
                Debug.Log($"HPKE Decrypt - Encapped key length: {encappedKeyBuf.Length}");
                Debug.Log($"HPKE Decrypt - Receiver private key: {receiverPriv.Substring(0, System.Math.Min(8, receiverPriv.Length))}...");

                // Get receiver public key (uncompressed)
                var receiverPrivBytes = Encoding.Uint8ArrayFromHexString(receiverPriv);
                var receiverPubBuf = GetPublicKey(receiverPrivBytes, false);
                Debug.Log($"HPKE Decrypt - Derived receiver public key: {Encoding.Uint8ArrayToHexString(receiverPubBuf)}");

                // Build AAD
                var aad = BuildAdditionalAssociatedData(encappedKeyBuf, receiverPubBuf);
                Debug.Log($"HPKE Decrypt - AAD length: {aad.Length}");

                // Step 1: Generate Shared Secret
                Debug.Log("HPKE Decrypt - Deriving shared secret...");
                var ss = DeriveSS(encappedKeyBuf, receiverPriv);
                Debug.Log($"HPKE Decrypt - Shared secret length: {ss.Length}");

                // Step 2: Generate the KEM context
                var kemContext = GetKemContext(encappedKeyBuf, Encoding.Uint8ArrayToHexString(receiverPubBuf));
                Debug.Log($"HPKE Decrypt - KEM context length: {kemContext.Length}");

                // Step 3: Build the HKDF inputs for key derivation
                var ikm = BuildLabeledIkm(Constants.LABEL_EAE_PRK, ss, Constants.SUITE_ID_1);
                var info = BuildLabeledInfo(Constants.LABEL_SHARED_SECRET, kemContext, Constants.SUITE_ID_1, 32);
                var sharedSecret = ExtractAndExpand(new byte[0], ikm, info, 32);
                Debug.Log($"HPKE Decrypt - Shared secret after HKDF: {Encoding.Uint8ArrayToHexString(sharedSecret)}");

                // Step 4: Derive the AES key
                ikm = BuildLabeledIkm(Constants.LABEL_SECRET, new byte[0], Constants.SUITE_ID_2);
                info = Constants.AES_KEY_INFO;
                var key = ExtractAndExpand(sharedSecret, ikm, info, 32);
                Debug.Log($"HPKE Decrypt - Derived AES key: {Encoding.Uint8ArrayToHexString(key)}");

                // Step 5: Derive the initialization vector
                info = Constants.IV_INFO;
                var iv = ExtractAndExpand(sharedSecret, ikm, info, 12);
                Debug.Log($"HPKE Decrypt - Derived IV: {Encoding.Uint8ArrayToHexString(iv)}");

                // Step 6: Decrypt the data using AES-GCM
                Debug.Log("HPKE Decrypt - Starting AES-GCM decryption...");
                var decryptedData = AesGcmDecrypt(ciphertextBuf, key, iv, aad);
                Debug.Log($"HPKE Decrypt - Decryption successful, result length: {decryptedData.Length}");

                return decryptedData;
            }
            catch (Exception error)
            {
                Debug.LogError($"HPKE Decrypt - Error: {error.Message}");
                Debug.LogException(error);
                throw new Exception($"Unable to perform hpkeDecrypt: {error.Message}", error);
            }
        }

        /// <summary>
        /// HPKE encryption implementation matching Turnkey SDK v2.6.0
        /// </summary>
        public static byte[] HpkeEncrypt(HpkeEncryptParams parameters)
        {
            try
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
            catch (Exception error)
            {
                Debug.LogError($"HPKE Encrypt - Error: {error.Message}");
                Debug.LogException(error);
                throw new Exception($"Unable to perform hpkeEncrypt: {error.Message}", error);
            }
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
            if (rawPublicKey.Length != Constants.UNCOMPRESSED_PUBLIC_KEY_SIZE || rawPublicKey[0] != 0x04)
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
        /// Uncompress a compressed public key (aligned with Turnkey v2.3.1)
        /// </summary>
        public static byte[] UncompressRawPublicKey(byte[] rawPublicKey)
        {
            if (rawPublicKey.Length != Constants.COMPRESSED_PUBLIC_KEY_SIZE)
            {
                throw new ArgumentException($"Invalid compressed public key size: {rawPublicKey.Length}");
            }

            // point[0] must be 2 (false) or 3 (true).
            // this maps to the initial "02" or "03" prefix
            var lsb = rawPublicKey[0] == 3;

            // Extract X coordinate (skip the prefix byte) - matching JS: BigInt("0x" + hexString)
            var xBytes = new byte[32];
            Array.Copy(rawPublicKey, 1, xBytes, 0, 32);
            // Create hex string from bytes to match JS behavior
            var xHex = Encoding.Uint8ArrayToHexString(xBytes);
            var x = new BigInteger(xHex, 16); // Create from hex string like JS

            // NIST P-256 curve parameters
            // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf (Appendix D).
            var p = new BigInteger(Constants.P256_P);
            var b = new BigInteger(Constants.P256_B, 16);
            var a = p.Subtract(new BigInteger(Constants.P256_A_OFFSET));

            // Now compute y based on x
            // y^2 = x^3 + ax + b (mod p)
            // Match JS: ((x * x + a) * x + b) % p
            var x2 = x.Multiply(x).Mod(p);
            var x2PlusA = x2.Add(a).Mod(p);
            var rhs = x2PlusA.Multiply(x).Add(b).Mod(p);

            // Compute y = sqrt(rhs) mod p
            var y = TurnkeyMath.ModSqrt(rhs, p);

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
            var curve = ECNamedCurveTable.GetByName(Constants.CURVE_NAME);
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
            try
            {
                Debug.Log($"AES-GCM Decrypt - Encrypted data length: {encryptedData.Length}");
                Debug.Log($"AES-GCM Decrypt - Key length: {key.Length}, IV length: {iv.Length}, AAD length: {aad.Length}");

                var cipher = new GcmBlockCipher(new AesEngine());
                var parameters = new AeadParameters(new KeyParameter(key), 128, iv, aad);
                cipher.Init(false, parameters);

                Debug.Log($"AES-GCM Decrypt - Cipher initialized with tag length: 128 bits");

                var decrypted = new byte[cipher.GetOutputSize(encryptedData.Length)];
                Debug.Log($"AES-GCM Decrypt - Output buffer size: {decrypted.Length}");

                var len = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, decrypted, 0);
                Debug.Log($"AES-GCM Decrypt - Processed {len} bytes");

                try
                {
                    cipher.DoFinal(decrypted, len);
                    Debug.Log("AES-GCM Decrypt - DoFinal completed successfully");
                }
                catch (Exception ex)
                {
                    Debug.LogError($"AES-GCM Decrypt - DoFinal failed: {ex.Message}");
                    Debug.LogError($"AES-GCM Decrypt - First few bytes of encrypted data: {BitConverter.ToString(encryptedData, 0, System.Math.Min(16, encryptedData.Length))}");
                    throw;
                }

                return decrypted;
            }
            catch (Exception ex)
            {
                Debug.LogError($"AES-GCM Decrypt - Exception: {ex.Message}");
                throw;
            }
        }

        private static byte[] AesGcmEncrypt(byte[] plainData, byte[] key, byte[] iv, byte[] aad)
        {
            try
            {
                Debug.Log($"AES-GCM Encrypt - Plain data length: {plainData.Length}");
                Debug.Log($"AES-GCM Encrypt - Key length: {key.Length}, IV length: {iv.Length}, AAD length: {aad.Length}");

                var cipher = new GcmBlockCipher(new AesEngine());
                var parameters = new AeadParameters(new KeyParameter(key), 128, iv, aad);
                cipher.Init(true, parameters);

                var encrypted = new byte[cipher.GetOutputSize(plainData.Length)];
                var len = cipher.ProcessBytes(plainData, 0, plainData.Length, encrypted, 0);
                cipher.DoFinal(encrypted, len);

                return encrypted;
            }
            catch (Exception ex)
            {
                Debug.LogError($"AES-GCM Encrypt - Error: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Decrypt an encrypted credential bundle
        /// </summary>
        /// <param name="encryptedCredentialBundle">Base58 or Base58Check encoded bundle</param>
        /// <param name="targetPrivateKey">Target private key in hex format</param>
        /// <returns>Decrypted credential as hex string</returns>
        public static string DecryptCredentialBundle(string encryptedCredentialBundle, string targetPrivateKey)
        {
            try
            {
                Debug.Log($"Starting decryption of bundle: {encryptedCredentialBundle.Substring(0, System.Math.Min(20, encryptedCredentialBundle.Length))}...");

                // Decode bundle bytes
                byte[] bundleBytes;
                try
                {
                    Debug.Log("Attempting Base58Check decode...");
                    bundleBytes = Encoding.Base58CheckDecode(encryptedCredentialBundle);
                    Debug.Log($"Base58Check decode successful, got {bundleBytes.Length} bytes");
                }
                catch (Exception ex)
                {
                    // Fall back to plain Base58 for test data
                    Debug.Log($"Base58Check decode failed: {ex.Message}, falling back to plain Base58");
                    bundleBytes = Encoding.Base58Decode(encryptedCredentialBundle);
                    Debug.Log($"Base58 decode successful, got {bundleBytes.Length} bytes");
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

                var result = Encoding.Uint8ArrayToHexString(decryptedData);
                Debug.Log($"Decryption successful, result length: {result.Length}");
                return result;
            }
            catch (Exception error)
            {
                Debug.LogError($"Error decrypting bundle: {error.Message}");
                throw new Exception($"Error decrypting bundle: {error.Message}", error);
            }
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
                    var signerPublicKey = Constants.TURNKEY_SIGNER_PUBLIC_KEYS.FirstOrDefault(candidate =>
                        VerifySignature(candidate, signature, signedData));

                    if (signerPublicKey == null)
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

        // Helper methods for bundle operations
        private static void VerifyEnclaveSignature(string enclaveQuorumPublic, string signatureHex, string signedDataHex)
        {
            var matchedKey = Constants.TURNKEY_SIGNER_PUBLIC_KEYS.FirstOrDefault(key =>
                string.Equals(enclaveQuorumPublic, key, StringComparison.OrdinalIgnoreCase));

            if (matchedKey == null)
            {
                var expectedKeys = string.Join(", ", Constants.TURNKEY_SIGNER_PUBLIC_KEYS);
                throw new Exception($"Signer key {enclaveQuorumPublic} is not recognized. Expected one of: {expectedKeys}");
            }

            var publicKeyBytes = Encoding.Uint8ArrayFromHexString(matchedKey);
            var signatureBytes = Encoding.Uint8ArrayFromHexString(signatureHex);
            var messageBytes = Encoding.Uint8ArrayFromHexString(signedDataHex);

            var curve = ECNamedCurveTable.GetByName(Constants.CURVE_NAME);
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
                    var curve = ECNamedCurveTable.GetByName(Constants.CURVE_NAME);
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
            if (encryptedBuf.Length <= Constants.COMPRESSED_PUBLIC_KEY_SIZE)
            {
                throw new ArgumentException("Encrypted buffer too small");
            }

            var compressedEncappedPublic = new byte[Constants.COMPRESSED_PUBLIC_KEY_SIZE];
            Array.Copy(encryptedBuf, 0, compressedEncappedPublic, 0, Constants.COMPRESSED_PUBLIC_KEY_SIZE);

            var encappedPublicUncompressed = UncompressRawPublicKey(compressedEncappedPublic);

            var ciphertext = new byte[encryptedBuf.Length - Constants.COMPRESSED_PUBLIC_KEY_SIZE];
            Array.Copy(encryptedBuf, Constants.COMPRESSED_PUBLIC_KEY_SIZE, ciphertext, 0, ciphertext.Length);

            var result = new
            {
                encappedPublic = Encoding.Uint8ArrayToHexString(encappedPublicUncompressed),
                ciphertext = Encoding.Uint8ArrayToHexString(ciphertext)
            };

            return Newtonsoft.Json.JsonConvert.SerializeObject(result);
        }
    }
}
