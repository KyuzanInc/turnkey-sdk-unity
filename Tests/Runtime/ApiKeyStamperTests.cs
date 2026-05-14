using System;
using System.Collections;
using NUnit.Framework;
using UnityEngine;
using UnityEngine.TestTools;

namespace Turnkey.Tests
{
    /// <summary>
    /// Unit tests for <see cref="Turnkey.ApiKeyStamper"/>.
    /// </summary>
    public class ApiKeyStamperTests
    {
        [UnityTest]
        public IEnumerator Stamp_CreatesValidStamp()
        {
            yield return null; // Unity test requirement

            // Arrange: fresh P256 keypair from the same package under test
            var keyPair = Crypto.GenerateP256KeyPair();
            var stamper = new ApiKeyStamper(keyPair.PublicKey, keyPair.PrivateKey);
            var payload = "{\"test\":\"data\"}";

            // Act
            var stamp = stamper.Stamp(payload);

            // Assert
            Assert.IsNotNull(stamp);
            Assert.AreEqual("X-Stamp", stamp.stampHeaderName);
            Assert.IsTrue(stamp.stampHeaderValue.Length > 0);

            // Base64URL output must avoid the URL-unsafe and padding characters.
            Assert.IsFalse(stamp.stampHeaderValue.Contains("=", StringComparison.Ordinal));
            Assert.IsFalse(stamp.stampHeaderValue.Contains("+", StringComparison.Ordinal));
            Assert.IsFalse(stamp.stampHeaderValue.Contains("/", StringComparison.Ordinal));

            // Log stamp preview safely
            var stampPreview = stamp.stampHeaderValue.Length > 50
                ? stamp.stampHeaderValue.Substring(0, 50) + "..."
                : stamp.stampHeaderValue;
            Debug.Log($"Created stamp (length: {stamp.stampHeaderValue.Length}): {stampPreview}");
        }

        [Test]
        public void Constructor_InvalidKeys_ThrowsException()
        {
            // Ignore any unrelated log messages that might appear during test execution
            LogAssert.ignoreFailingMessages = true;

            try
            {
                // Encoding.Uint8ArrayFromHexString rejects non-hex strings with ArgumentException.
                Assert.Throws<ArgumentException>(() =>
                    new ApiKeyStamper("invalid-hex", "valid-hex"));

                Assert.Throws<ArgumentException>(() =>
                    new ApiKeyStamper("0123456789abcdef", "invalid-hex"));
            }
            finally
            {
                LogAssert.ignoreFailingMessages = false;
            }
        }

        [UnityTest]
        public IEnumerator Stamp_DifferentPayloads_ProducesDifferentStamps()
        {
            yield return null;

            // Arrange
            var keyPair = Crypto.GenerateP256KeyPair();
            var stamper = new ApiKeyStamper(keyPair.PublicKey, keyPair.PrivateKey);

            // Act
            var stamp1 = stamper.Stamp("{\"data\":\"test1\"}");
            var stamp2 = stamper.Stamp("{\"data\":\"test2\"}");
            var stamp3 = stamper.Stamp("{\"data\":\"test1\"}"); // Same payload as stamp1

            // Debug output to investigate stamp generation
            Debug.Log($"Stamp1: {stamp1.stampHeaderValue}");
            Debug.Log($"Stamp2: {stamp2.stampHeaderValue}");
            Debug.Log($"Stamp3: {stamp3.stampHeaderValue}");

            // Assert
            Assert.IsFalse(
                string.Equals(stamp1.stampHeaderValue, stamp2.stampHeaderValue, StringComparison.Ordinal),
                "Different payloads should produce different stamps");
            Assert.IsTrue(
                stamp1.stampHeaderValue.Length > 0 && stamp2.stampHeaderValue.Length > 0,
                "Stamps should not be empty");
            // Note: ECDSA signatures are non-deterministic, so stamp1 may differ from stamp3
            // even though the payload is identical. We only assert different-payload divergence here.
        }

        [Test]
        public void SignPayload_ProducesDerEncodedSignature()
        {
            // Arrange: fresh keypair, payload
            var keyPair = Crypto.GenerateP256KeyPair();
            var stamper = new ApiKeyStamper(keyPair.PublicKey, keyPair.PrivateKey);
            var payload = "{\"test\":\"data\"}";

            // Act
            var signature = stamper.SignPayload(payload);

            // Assert: signature is a valid DER-encoded ECDSA signature in hex
            Assert.IsNotNull(signature);
            // DER ECDSA signatures start with 0x30 (SEQUENCE tag). In hex that's "30".
            Assert.IsTrue(signature.StartsWith("30", StringComparison.Ordinal),
                $"Expected DER signature to start with 0x30, got: {signature.Substring(0, Math.Min(8, signature.Length))}");
            // Total signature length is typically 70-72 bytes = 140-144 hex chars for P-256.
            Assert.IsTrue(signature.Length >= 140 && signature.Length <= 144,
                $"Expected DER signature length 140-144 (hex), got {signature.Length}");
            // Hex-only characters
            Assert.IsTrue(System.Text.RegularExpressions.Regex.IsMatch(signature, "^[0-9a-fA-F]+$"),
                "Signature should be hex-encoded");
        }
    }
}
