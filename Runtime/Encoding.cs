using System;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Math;

namespace Turnkey
{
    /// <summary>
    /// Encoding utilities for Turnkey crypto.
    /// Ported from @turnkey/encoding v0.6.0.
    /// </summary>
    public static class Encoding
    {
        private static readonly Regex HexRegex = new Regex("^[0-9A-Fa-f]+$");

        /// <summary>
        /// Convert a byte array to hex string.
        /// </summary>
        public static string Uint8ArrayToHexString(byte[] input)
        {
            if (input == null || input.Length == 0) return string.Empty;
            return BitConverter.ToString(input).Replace("-", "").ToLower();
        }

        /// <summary>
        /// Convert a hex string to byte array.
        /// </summary>
        /// <param name="hexString">Hex string (must be valid hex characters only, no 0x prefix)</param>
        /// <param name="length">Optional target length for leading-zero padding</param>
        /// <returns>Byte array</returns>
        public static byte[] Uint8ArrayFromHexString(string hexString, int? length = null)
        {
            if (string.IsNullOrEmpty(hexString) || hexString.Length % 2 != 0 || !HexRegex.IsMatch(hexString))
            {
                throw new ArgumentException($"cannot create uint8array from invalid hex string: \"{hexString}\"");
            }

            byte[] buffer = new byte[hexString.Length / 2];
            for (int i = 0; i < buffer.Length; i++)
            {
                buffer[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }

            if (!length.HasValue)
            {
                return buffer;
            }

            if (hexString.Length / 2 > length.Value)
            {
                throw new ArgumentException($"hex value cannot fit in a buffer of {length.Value} byte(s)");
            }

            byte[] paddedBuffer = new byte[length.Value];
            Array.Copy(buffer, 0, paddedBuffer, length.Value - buffer.Length, buffer.Length);
            return paddedBuffer;
        }

        /// <summary>
        /// Base58 encode a byte array (without checksum)
        /// </summary>
        public static string Base58Encode(byte[] data)
        {
            if (data == null || data.Length == 0) return string.Empty;

            var intData = new BigInteger(1, data);
            var result = new StringBuilder();

            while (intData.CompareTo(BigInteger.Zero) > 0)
            {
                var remainder = intData.Mod(new BigInteger("58"));
                intData = intData.Divide(new BigInteger("58"));
                result.Insert(0, EncodingConstants.BASE58_ALPHABET[remainder.IntValue]);
            }

            // Add leading zeros
            foreach (var b in data)
            {
                if (b == 0)
                    result.Insert(0, '1');
                else
                    break;
            }

            return result.ToString();
        }

        /// <summary>
        /// Base58 decode a string (without checksum)
        /// </summary>
        public static byte[] Base58Decode(string encoded)
        {
            if (string.IsNullOrEmpty(encoded)) return new byte[0];

            var decoded = new BigInteger("0");
            var multi = new BigInteger("1");

            for (int i = encoded.Length - 1; i >= 0; i--)
            {
                int digit = EncodingConstants.BASE58_ALPHABET.IndexOf(encoded[i]);
                if (digit < 0)
                {
                    throw new ArgumentException($"Invalid character '{encoded[i]}' in base58 string");
                }
                decoded = decoded.Add(multi.Multiply(new BigInteger(digit.ToString())));
                multi = multi.Multiply(new BigInteger("58"));
            }

            // Use ToByteArrayUnsigned to get the bytes in big-endian order without sign byte
            var bytes = decoded.ToByteArrayUnsigned();

            // Handle leading zeros
            int leadingZeros = 0;
            for (int i = 0; i < encoded.Length && encoded[i] == '1'; i++)
            {
                leadingZeros++;
            }

            // Add leading zeros back if needed
            if (leadingZeros > 0)
            {
                var result = new byte[leadingZeros + bytes.Length];
                // Leading zeros are already zeros, just copy the bytes
                Array.Copy(bytes, 0, result, leadingZeros, bytes.Length);
                return result;
            }

            return bytes;
        }

        /// <summary>
        /// Base58 decode with checksum verification (Base58Check)
        /// </summary>
        public static byte[] Base58CheckDecode(string encoded)
        {
            var decoded = Base58Decode(encoded);
            if (decoded.Length < 4)
            {
                throw new ArgumentException("Invalid Base58Check string - too short");
            }

            var data = decoded.Take(decoded.Length - 4).ToArray();
            var checksum = decoded.Skip(decoded.Length - 4).ToArray();

            var hash = System.Security.Cryptography.SHA256.Create();
            var computedChecksum = hash.ComputeHash(hash.ComputeHash(data)).Take(4).ToArray();

            if (!checksum.SequenceEqual(computedChecksum))
            {
                throw new ArgumentException("Invalid Base58Check checksum");
            }

            return data;
        }

        // Unity-specific helpers (not in official @turnkey/encoding)

        /// <summary>
        /// Convert UTF-8 bytes to string.
        /// Unity-specific helper (equivalent to TextDecoder in JS).
        /// </summary>
        public static string Uint8ArrayToString(byte[] bytes)
        {
            return System.Text.Encoding.UTF8.GetString(bytes);
        }

        /// <summary>
        /// Concatenate multiple byte arrays.
        /// Unity-specific helper.
        /// </summary>
        public static byte[] ConcatUint8Arrays(params byte[][] arrays)
        {
            var totalLength = arrays.Sum(a => a?.Length ?? 0);
            var result = new byte[totalLength];
            var offset = 0;

            foreach (var array in arrays)
            {
                if (array != null)
                {
                    Array.Copy(array, 0, result, offset, array.Length);
                    offset += array.Length;
                }
            }

            return result;
        }
    }
}