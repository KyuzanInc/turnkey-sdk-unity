namespace Turnkey
{
    /// <summary>
    /// Constants used by the Turnkey crypto library
    /// </summary>
    public static class Constants
    {
        // HPKE Suite constants from @turnkey/crypto v2.3.1
        public static readonly byte[] SUITE_ID_1 = new byte[] { 75, 69, 77, 0, 16 }; // KEM suite ID
        public static readonly byte[] SUITE_ID_2 = new byte[] { 72, 80, 75, 69, 0, 16, 0, 1, 0, 2 }; // HPKE suite ID
        public static readonly byte[] HPKE_VERSION = new byte[] { 72, 80, 75, 69, 45, 118, 49 }; // HPKE-v1

        // HPKE Labels
        public static readonly byte[] LABEL_SECRET = new byte[] { 115, 101, 99, 114, 101, 116 }; // secret
        public static readonly byte[] LABEL_EAE_PRK = new byte[] { 101, 97, 101, 95, 112, 114, 107 }; // eae_prk
        public static readonly byte[] LABEL_SHARED_SECRET = new byte[] { 115, 104, 97, 114, 101, 100, 95, 115, 101, 99, 114, 101, 116 }; // shared_secret

        // AES_KEY_INFO and IV_INFO constants from v2.3.1
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

        // Curve constants
        public const string CURVE_NAME = "secp256r1";
        public const int COMPRESSED_PUBLIC_KEY_SIZE = 33;
        public const int UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;
        public const int PRIVATE_KEY_SIZE = 32;
        public const int TAG_SIZE = 16; // GCM tag size in bytes

        // P-256 curve parameters
        public const string P256_P = "115792089210356248762697446949407573530086143415290314195533631308867097853951";
        public const string P256_B = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
        public const string P256_A_OFFSET = "3"; // p - 3

        // Turnkey signer public keys (production allowlist)
        public const string TURNKEY_SIGNER_PUBLIC_KEY = "04a6b134bb0c7c89e14e80515ee6b0e36b345df7b08d0af9c2615d59f982c2c16c0e8fdb436185cff63491114d61285bb6db8bda6a507e143507478b10e6186cc8";

        public static readonly string[] TURNKEY_SIGNER_PUBLIC_KEYS =
        {
            TURNKEY_SIGNER_PUBLIC_KEY,
            // Added September 2025: new signer published by Turnkey for export responses
            "04cf288fe433cc4e1aa0ce1632feac4ea26bf2f5a09dcfe5a42c398e06898710330f0572882f4dbdf0f5304b8fc8703acd69adca9a4bbf7f5d00d20a5e364b2569"
        };

        // Notarizer public key for session JWT verification (from @turnkey/crypto v2.8.8)
        public const string PRODUCTION_NOTARIZER_SIGN_PUBLIC_KEY = "04d498aa87ac3bf982ac2b5dd9604d0074905cfbda5d62727c5a237b895e6749205e9f7cd566909c4387f6ca25c308445c60884b788560b785f4a96ac33702a469";

        // Base58 alphabet
        public const string BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    }
}
