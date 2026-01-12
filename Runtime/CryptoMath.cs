using Org.BouncyCastle.Math;

namespace Turnkey
{
    /// <summary>
    /// Mathematical operations for Turnkey crypto.
    /// Ported from @turnkey/crypto math.js.
    /// </summary>
    public static class CryptoMath
    {
        /// <summary>
        /// Compute modular square root using Tonelli-Shanks algorithm
        /// For P-256, p ≡ 3 (mod 4), so we can use the simpler formula: sqrt(a) = a^((p+1)/4) mod p
        /// </summary>
        /// <param name="a">The value to compute square root of</param>
        /// <param name="p">The prime modulus</param>
        /// <returns>The modular square root</returns>
        public static BigInteger ModSqrt(BigInteger a, BigInteger p)
        {
            // For p ≡ 3 (mod 4), sqrt(a) = a^((p+1)/4) mod p
            var exponent = p.Add(BigInteger.One).ShiftRight(2); // (p + 1) / 4
            return a.ModPow(exponent, p);
        }

        /// <summary>
        /// Test if a specific bit is set in a BigInteger
        /// </summary>
        /// <param name="n">The BigInteger to test</param>
        /// <param name="bitIndex">The bit index (0-based from least significant bit)</param>
        /// <returns>True if the bit is set, false otherwise</returns>
        public static bool TestBit(BigInteger n, int bitIndex)
        {
            return n.TestBit(bitIndex);
        }

        /// <summary>
        /// Convert BigInteger to hex string with specified padding
        /// </summary>
        /// <param name="value">The BigInteger value</param>
        /// <param name="padLength">The desired hex string length (will pad with leading zeros)</param>
        /// <returns>Hex string representation</returns>
        public static string BigIntToHex(BigInteger value, int padLength)
        {
            var hex = value.ToString(16).ToLower();
            return hex.PadLeft(padLength, '0');
        }

        /// <summary>
        /// Create a positive BigInteger from hex string
        /// </summary>
        /// <param name="hex">Hex string (with or without 0x prefix)</param>
        /// <returns>Positive BigInteger</returns>
        public static BigInteger BigIntFromHex(string hex)
        {
            if (hex.StartsWith("0x") || hex.StartsWith("0X"))
            {
                hex = hex.Substring(2);
            }
            return new BigInteger(hex, 16);
        }

        /// <summary>
        /// Create a positive BigInteger from byte array
        /// </summary>
        /// <param name="bytes">Byte array</param>
        /// <returns>Positive BigInteger</returns>
        public static BigInteger BigIntFromBytes(byte[] bytes)
        {
            return new BigInteger(1, bytes);
        }
    }
}