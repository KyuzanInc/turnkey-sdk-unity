using System;
using Org.BouncyCastle.Math;

namespace Turnkey
{
    /// <summary>
    /// Mathematical operations for Turnkey crypto.
    /// Ported from @turnkey/crypto v2.8.9 math.ts.
    /// </summary>
    public static class CryptoMath
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
}