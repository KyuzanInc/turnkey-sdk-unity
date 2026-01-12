using System;
using System.Security.Cryptography;

namespace Turnkey
{
    /// <summary>
    /// HMAC-based Key Derivation Function (HKDF) implementation
    /// Based on RFC 5869: https://tools.ietf.org/html/rfc5869
    /// </summary>
    public static class CryptoHkdf
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

            using (var hmac = new HMACSHA256(salt))
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

            using (var hmac = new HMACSHA256(prk))
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

        /// <summary>
        /// Convenience method that performs both Extract and Expand steps
        /// </summary>
        /// <param name="salt">Optional salt value</param>
        /// <param name="ikm">Input keying material</param>
        /// <param name="info">Optional context information</param>
        /// <param name="length">Length of output keying material</param>
        /// <returns>Output keying material (OKM)</returns>
        public static byte[] DeriveKey(byte[] salt, byte[] ikm, byte[] info, int length)
        {
            var prk = Extract(salt, ikm);
            return Expand(prk, info, length);
        }
    }
}