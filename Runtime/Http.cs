using System;
using UnityEngine;

namespace Turnkey
{
    /// <summary>
    /// Creates signed Turnkey requests using API key stamping.
    /// Equivalent to @turnkey/http in the Node.js SDK
    /// </summary>
    public class Http
    {
        private const string BaseUrl = "https://api.turnkey.com";
        private const string StampHeaderName = "X-Stamp";

        private readonly ApiKeyStamper stamper;

        private Http(ApiKeyStamper stamper)
        {
            this.stamper = stamper ?? throw new ArgumentNullException(nameof(stamper));
        }

        /// <summary>
        /// Create client from encrypted credential bundle (legacy flow).
        /// </summary>
        public static Http GetHttpClient(string encryptedCredentialBundle, string targetPrivateKey)
        {
            if (string.IsNullOrEmpty(encryptedCredentialBundle))
            {
                throw new ArgumentException("Encrypted credential bundle is required", nameof(encryptedCredentialBundle));
            }

            if (string.IsNullOrEmpty(targetPrivateKey))
            {
                throw new ArgumentException("Target private key is required", nameof(targetPrivateKey));
            }

            try
            {
                var apiPrivateKey = Crypto.DecryptCredentialBundle(encryptedCredentialBundle, targetPrivateKey);
                var apiPrivateKeyBytes = Encoding.Uint8ArrayFromHexString(apiPrivateKey);
                var apiPublicKeyBytes = Crypto.GetPublicKey(apiPrivateKeyBytes, true);

                var normalizedPrivateKey = Encoding.Uint8ArrayToHexString(apiPrivateKeyBytes);
                var apiPublicKey = Encoding.Uint8ArrayToHexString(apiPublicKeyBytes);

                Debug.Log($"[Http] Initialized from credential bundle. Public key: {apiPublicKey}");

                return new Http(new ApiKeyStamper(apiPublicKey, normalizedPrivateKey));
            }
            catch (Exception e)
            {
                Debug.LogError($"[Http] Failed to create client: {e.Message}");
                throw;
            }
        }

        /// <summary>
        /// Create client directly from a target private key (OTP session flow).
        /// </summary>
        public static Http FromTargetPrivateKey(string targetPrivateKey)
        {
            if (string.IsNullOrWhiteSpace(targetPrivateKey))
            {
                throw new ArgumentException("Target private key is required", nameof(targetPrivateKey));
            }

            var privateKeyBytes = Encoding.Uint8ArrayFromHexString(targetPrivateKey);
            if (privateKeyBytes.Length == 0)
            {
                throw new ArgumentException("Target private key was not valid hex", nameof(targetPrivateKey));
            }

            var normalizedPrivateKey = Encoding.Uint8ArrayToHexString(privateKeyBytes);
            var publicKeyBytes = Crypto.GetPublicKey(privateKeyBytes, true);
            var publicKeyHex = Encoding.Uint8ArrayToHexString(publicKeyBytes);

            Debug.Log($"[Http] Derived API key. Public key: {publicKeyHex}");

            return new Http(new ApiKeyStamper(publicKeyHex, normalizedPrivateKey));
        }

        public SignedRequest StampGetWhoami(string organizationId)
        {
            if (string.IsNullOrEmpty(organizationId))
            {
                throw new ArgumentException("Organization ID is required", nameof(organizationId));
            }

            var body = new WhoamiRequestBody { organizationId = organizationId };
            return CreateSignedRequest($"{BaseUrl}/public/v1/query/whoami", body);
        }

        public SignedRequest StampInitImportPrivateKey(InitImportPrivateKeyRequestBody body)
        {
            if (body == null)
            {
                throw new ArgumentNullException(nameof(body));
            }

            return CreateSignedRequest($"{BaseUrl}/public/v1/submit/init_import_private_key", body);
        }

        public SignedRequest StampImportPrivateKey(ImportPrivateKeyRequestBody body)
        {
            if (body == null)
            {
                throw new ArgumentNullException(nameof(body));
            }

            return CreateSignedRequest($"{BaseUrl}/public/v1/submit/import_private_key", body);
        }

        public SignedRequest StampExportPrivateKey(ExportPrivateKeyRequestBody body)
        {
            if (body == null)
            {
                throw new ArgumentNullException(nameof(body));
            }

            return CreateSignedRequest($"{BaseUrl}/public/v1/submit/export_private_key", body);
        }

        private SignedRequest CreateSignedRequest<TBody>(string url, TBody body)
        {
            var bodyJson = JsonUtility.ToJson(body);
            var stampValue = stamper.Stamp(bodyJson);

            return new SignedRequest
            {
                url = url,
                body = bodyJson,
                stamp = new Stamp
                {
                    stampHeaderName = StampHeaderName,
                    stampHeaderValue = stampValue
                }
            };
        }

        #region DTOs

        /// <summary>
        /// Signed request structure
        /// </summary>
        [Serializable]
        public class SignedRequest
        {
            public string url;
            public string body;
            public Stamp stamp;
        }

        /// <summary>
        /// Stamp structure for signed requests
        /// </summary>
        [Serializable]
        public class Stamp
        {
            public string stampHeaderName;
            public string stampHeaderValue;
        }

        [Serializable]
        private class WhoamiRequestBody
        {
            public string organizationId;
        }

        [Serializable]
        public class InitImportPrivateKeyRequestBody
        {
            public string organizationId;
            public string type;
            public string timestampMs;
            public InitImportPrivateKeyParameters parameters;
        }

        [Serializable]
        public class InitImportPrivateKeyParameters
        {
            public string userId;
        }

        [Serializable]
        public class ImportPrivateKeyRequestBody
        {
            public string organizationId;
            public string type;
            public string timestampMs;
            public ImportPrivateKeyParameters parameters;
        }

        [Serializable]
        public class ImportPrivateKeyParameters
        {
            public string userId;
            public string[] addressFormats;
            public string curve;
            public string encryptedBundle;
            public string privateKeyName;
        }

        [Serializable]
        public class ExportPrivateKeyRequestBody
        {
            public string organizationId;
            public string type;
            public string timestampMs;
            public ExportPrivateKeyParameters parameters;
        }

        [Serializable]
        public class ExportPrivateKeyParameters
        {
            public string privateKeyId;
            public string targetPublicKey;
        }

        #endregion
    }
}
