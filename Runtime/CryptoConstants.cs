namespace Turnkey
{
    /// <summary>
    /// Constants used by the Turnkey crypto library.
    /// Ported from @turnkey/crypto v2.8.9 constants.ts.
    /// </summary>
    public static class CryptoConstants
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
}
