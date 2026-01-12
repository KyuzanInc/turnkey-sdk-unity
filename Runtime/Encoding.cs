using System;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Math;

namespace Turnkey
{
    /// <summary>
    /// Encoding utilities for Turnkey crypto, aligned with @turnkey/encoding
    /// </summary>
    public static class Encoding
    {
        /// <summary>
        /// Convert a byte array to hex string
        /// </summary>
        public static string Uint8ArrayToHexString(byte[] bytes)
        {
            if (bytes == null) return string.Empty;
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }

        /// <summary>
        /// Convert a hex string to byte array
        /// </summary>
        public static byte[] Uint8ArrayFromHexString(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return new byte[0];

            hex = hex.Replace(" ", "").Replace("-", "");
            if (hex.StartsWith("0x") || hex.StartsWith("0X"))
            {
                hex = hex.Substring(2);
            }

            if (hex.Length % 2 != 0)
            {
                throw new ArgumentException("Hex string must have even length");
            }

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
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
                result.Insert(0, CryptoConstants.BASE58_ALPHABET[remainder.IntValue]);
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
                int digit = CryptoConstants.BASE58_ALPHABET.IndexOf(encoded[i]);
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
        /// Base58 encode with checksum (Base58Check)
        /// </summary>
        public static string Base58CheckEncode(byte[] data)
        {
            var hash = System.Security.Cryptography.SHA256.Create();
            var checksum = hash.ComputeHash(hash.ComputeHash(data)).Take(4).ToArray();
            var dataWithChecksum = data.Concat(checksum).ToArray();
            return Base58Encode(dataWithChecksum);
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

        /// <summary>
        /// Convert string to UTF-8 bytes
        /// </summary>
        public static byte[] StringToUint8Array(string str)
        {
            return System.Text.Encoding.UTF8.GetBytes(str);
        }

        /// <summary>
        /// Convert UTF-8 bytes to string
        /// </summary>
        public static string Uint8ArrayToString(byte[] bytes)
        {
            return System.Text.Encoding.UTF8.GetString(bytes);
        }

        /// <summary>
        /// Concatenate multiple byte arrays
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