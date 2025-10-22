using System;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using UnityEngine;

namespace Turnkey
{
    /// <summary>
    /// Signs API requests with Turnkey API keys
    /// </summary>
    public class ApiKeyStamper
    {
        private const string CURVE_NAME = "secp256r1";
        private const string SIGNATURE_SCHEME = "SIGNATURE_SCHEME_TK_API_P256";

        private readonly string apiPublicKey;
        private readonly string apiPrivateKey;
        private readonly ECPrivateKeyParameters privateKeyParams;

        /// <summary>
        /// Initialize API key stamper
        /// </summary>
        /// <param name="apiPublicKey">API public key in hex format</param>
        /// <param name="apiPrivateKey">API private key in hex format</param>
        public ApiKeyStamper(string apiPublicKey, string apiPrivateKey)
        {
            this.apiPublicKey = apiPublicKey;
            this.apiPrivateKey = apiPrivateKey;

            // Initialize private key parameters
            var curve = ECNamedCurveTable.GetByName(CURVE_NAME);
            var domainParams = new ECDomainParameters(
                curve.Curve,
                curve.G,
                curve.N,
                curve.H,
                curve.GetSeed());

            var privateKeyBytes = Encoding.Uint8ArrayFromHexString(apiPrivateKey);

            // Ensure private key is exactly 32 bytes (pad with leading zeros if necessary)
            if (privateKeyBytes.Length < 32)
            {
                var paddedBytes = new byte[32];
                Array.Copy(privateKeyBytes, 0, paddedBytes, 32 - privateKeyBytes.Length, privateKeyBytes.Length);
                privateKeyBytes = paddedBytes;
            }
            else if (privateKeyBytes.Length > 32)
            {
                // If longer than 32 bytes, take only the last 32 bytes
                var truncatedBytes = new byte[32];
                Array.Copy(privateKeyBytes, privateKeyBytes.Length - 32, truncatedBytes, 0, 32);
                privateKeyBytes = truncatedBytes;
            }

            var d = new BigInteger(1, privateKeyBytes);

            // Validate that the private key is in valid range [1, n-1]
            if (d.CompareTo(BigInteger.One) < 0 || d.CompareTo(domainParams.N) >= 0)
            {
                throw new ArgumentException("Private key is out of valid range");
            }

            this.privateKeyParams = new ECPrivateKeyParameters(d, domainParams);
        }

        /// <summary>
        /// Stamp structure for API requests
        /// </summary>
        [System.Serializable]
        public class TurnkeyStamp
        {
            public string publicKey;
            public string scheme;
            public string signature;
        }

        /// <summary>
        /// Create a signature stamp for the given payload
        /// </summary>
        /// <param name="payload">Payload to sign</param>
        /// <returns>Base64URL-encoded stamp</returns>
        public string Stamp(string payload)
        {
            try
            {
                // Sign the payload
                var signature = SignPayload(payload);

                // Create stamp object
                var stamp = new TurnkeyStamp
                {
                    publicKey = apiPublicKey,
                    scheme = SIGNATURE_SCHEME,
                    signature = signature
                };

                // Convert to JSON
                var stampJson = JsonUtility.ToJson(stamp);

                // Encode as base64url
                return Base64UrlEncode(stampJson);
            }
            catch (Exception e)
            {
                Debug.LogError($"[ApiKeyStamper] Failed to stamp payload: {e.Message}");
                throw;
            }
        }

        /// <summary>
        /// Sign payload using P256 ECDSA
        /// </summary>
        public string SignPayload(string payload)
        {
            try
            {
                // Convert payload to bytes
                var payloadBytes = System.Text.Encoding.UTF8.GetBytes(payload);

                // Create signer using HMacDsaKCalculator for deterministic signatures (RFC 6979)
                // Try different approaches to match noble/curves implementation
                var hmacCalculator = new HMacDsaKCalculator(DigestUtilities.GetDigest("SHA-256"));
                var signer = new ECDsaSigner(hmacCalculator);
                signer.Init(true, privateKeyParams);

                // Hash the payload using SHA256
                var digest = DigestUtilities.GetDigest("SHA-256");
                digest.BlockUpdate(payloadBytes, 0, payloadBytes.Length);
                var hash = new byte[digest.GetDigestSize()];
                digest.DoFinal(hash, 0);

                // Sign the hash
                var signature = signer.GenerateSignature(hash);

                // Get r and s values
                var r = signature[0];
                var s = signature[1];

                // Ensure low s value (BIP 62) - noble/curves uses lowS: true by default
                var curve = ECNamedCurveTable.GetByName(CURVE_NAME);
                var n = curve.N;
                var halfN = n.ShiftRight(1);

                if (s.CompareTo(halfN) > 0)
                {
                    s = n.Subtract(s);
                }

                // Convert to byte arrays
                var rBytes = r.ToByteArrayUnsigned();
                var sBytes = s.ToByteArrayUnsigned();

                // DER encoding: SEQUENCE { INTEGER r, INTEGER s }
                using (var ms = new System.IO.MemoryStream())
                {
                    // Write SEQUENCE tag
                    ms.WriteByte(0x30);

                    // Calculate lengths
                    int rLength = rBytes.Length;
                    int sLength = sBytes.Length;

                    // Add padding byte if high bit is set (to maintain positive sign)
                    bool rNeedsPadding = rBytes.Length > 0 && (rBytes[0] & 0x80) != 0;
                    bool sNeedsPadding = sBytes.Length > 0 && (sBytes[0] & 0x80) != 0;

                    if (rNeedsPadding) rLength++;
                    if (sNeedsPadding) sLength++;

                    int totalLength = 2 + rLength + 2 + sLength; // 2 bytes for each INTEGER header
                    ms.WriteByte((byte)totalLength);

                    // Write R as INTEGER
                    ms.WriteByte(0x02); // INTEGER tag
                    ms.WriteByte((byte)rLength);
                    if (rNeedsPadding) ms.WriteByte(0x00);
                    ms.Write(rBytes, 0, rBytes.Length);

                    // Write S as INTEGER
                    ms.WriteByte(0x02); // INTEGER tag
                    ms.WriteByte((byte)sLength);
                    if (sNeedsPadding) ms.WriteByte(0x00);
                    ms.Write(sBytes, 0, sBytes.Length);

                    return Encoding.Uint8ArrayToHexString(ms.ToArray());
                }
            }
            catch (Exception e)
            {
                Debug.LogError($"[ApiKeyStamper] Failed to sign payload: {e.Message}");
                throw;
            }
        }

        /// <summary>
        /// Base64URL encode a string
        /// </summary>
        private static string Base64UrlEncode(string input)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(input);
            var base64 = Convert.ToBase64String(bytes);

            // Convert to base64url
            return base64
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");
        }
    }
}
