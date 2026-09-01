package com.example.keycloak.deviceauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class SignatureVerificationTest {

    private SignatureService signatureService;
    private CanonicalPayloadService canonicalPayloadService;

    @BeforeEach
    void setUp() {
        signatureService = new SignatureService();
        canonicalPayloadService = new CanonicalPayloadService();
    }

    @Test
    void testValidSignature() throws Exception {
        KeyPair keyPair = SignatureService.generateKeyPair();
        String jwk = SignatureService.publicKeyToJwk(keyPair.getPublic(), "test-key");

        String challengeId = "challenge-123";
        String challenge = "abc123def456";
        String deviceId = "device-123";
        String clientId = "client-123";
        Instant timestamp = Instant.now();

        byte[] payload = canonicalPayloadService.createCanonicalPayloadBytes(
                challengeId, challenge, deviceId, clientId, ChallengeService.PURPOSE_SIGNIN, timestamp);

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(payload);
        byte[] derSignature = signer.sign();

        byte[] rawSignature = derToRaw(derSignature);
        String signatureBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(rawSignature);

        boolean valid = signatureService.verifySignature(signatureBase64, payload, jwk, "ES256");
        assertTrue(valid);
    }

    @Test
    void testInvalidSignature() throws Exception {
        KeyPair keyPair = SignatureService.generateKeyPair();
        String jwk = SignatureService.publicKeyToJwk(keyPair.getPublic(), "test-key");

        byte[] payload = "test payload".getBytes(StandardCharsets.UTF_8);

        byte[] randomSignature = new byte[64];
        new java.security.SecureRandom().nextBytes(randomSignature);
        String signatureBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(randomSignature);

        boolean valid = signatureService.verifySignature(signatureBase64, payload, jwk, "ES256");
        assertFalse(valid);
    }

    @Test
    void testWrongPublicKey() throws Exception {
        KeyPair keyPair1 = SignatureService.generateKeyPair();
        KeyPair keyPair2 = SignatureService.generateKeyPair();

        String jwk2 = SignatureService.publicKeyToJwk(keyPair2.getPublic(), "test-key");

        byte[] payload = "test payload".getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keyPair1.getPrivate());
        signer.update(payload);
        byte[] derSignature = signer.sign();

        byte[] rawSignature = derToRaw(derSignature);
        String signatureBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(rawSignature);

        boolean valid = signatureService.verifySignature(signatureBase64, payload, jwk2, "ES256");
        assertFalse(valid);
    }

    @Test
    void testModifiedPayload() throws Exception {
        KeyPair keyPair = SignatureService.generateKeyPair();
        String jwk = SignatureService.publicKeyToJwk(keyPair.getPublic(), "test-key");

        byte[] payload = "original payload".getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(payload);
        byte[] derSignature = signer.sign();

        byte[] rawSignature = derToRaw(derSignature);
        String signatureBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(rawSignature);

        byte[] modifiedPayload = "modified payload".getBytes(StandardCharsets.UTF_8);
        boolean valid = signatureService.verifySignature(signatureBase64, modifiedPayload, jwk, "ES256");
        assertFalse(valid);
    }

    @Test
    void testDerSignatureFormat() throws Exception {
        KeyPair keyPair = SignatureService.generateKeyPair();
        String jwk = SignatureService.publicKeyToJwk(keyPair.getPublic(), "test-key");

        byte[] payload = "test payload".getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(payload);
        byte[] derSignature = signer.sign();

        String signatureBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(derSignature);

        boolean valid = signatureService.verifySignature(signatureBase64, payload, jwk, "ES256");
        assertTrue(valid);
    }

    @Test
    void testGenerateKeyPair() throws Exception {
        KeyPair keyPair = SignatureService.generateKeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("EC", keyPair.getPublic().getAlgorithm());
    }

    @Test
    void testPublicKeyToJwk() throws Exception {
        KeyPair keyPair = SignatureService.generateKeyPair();
        String jwk = SignatureService.publicKeyToJwk(keyPair.getPublic(), "my-key-id");

        assertNotNull(jwk);
        assertTrue(jwk.contains("\"kty\":\"EC\""));
        assertTrue(jwk.contains("\"crv\":\"P-256\""));
        assertTrue(jwk.contains("\"kid\":\"my-key-id\""));
        assertTrue(jwk.contains("\"x\""));
        assertTrue(jwk.contains("\"y\""));
    }

    @Test
    void testPublicKeyToJwkNullKeyId() throws Exception {
        KeyPair keyPair = SignatureService.generateKeyPair();
        String jwk = SignatureService.publicKeyToJwk(keyPair.getPublic(), null);

        assertNotNull(jwk);
        assertFalse(jwk.contains("kid"));
    }

    @Test
    void testCanonicalPayloadConsistency() {
        String challengeId = "c1";
        String challenge = "ch1";
        String deviceId = "d1";
        String clientId = "cl1";
        Instant timestamp = Instant.ofEpochMilli(1234567890L);

        byte[] payload1 = canonicalPayloadService.createCanonicalPayloadBytes(
                challengeId, challenge, deviceId, clientId, ChallengeService.PURPOSE_SIGNIN, timestamp);
        byte[] payload2 = canonicalPayloadService.createCanonicalPayloadBytes(
                challengeId, challenge, deviceId, clientId, ChallengeService.PURPOSE_SIGNIN, timestamp);

        assertArrayEquals(payload1, payload2);
    }

    @Test
    void testCanonicalPayloadDifferentInputs() {
        Instant timestamp = Instant.ofEpochMilli(1234567890L);

        byte[] payload1 = canonicalPayloadService.createCanonicalPayloadBytes(
                "c1", "ch1", "d1", "cl1", ChallengeService.PURPOSE_SIGNIN, timestamp);
        byte[] payload2 = canonicalPayloadService.createCanonicalPayloadBytes(
                "c2", "ch1", "d1", "cl1", ChallengeService.PURPOSE_SIGNIN, timestamp);

        assertFalse(java.util.Arrays.equals(payload1, payload2));
    }

    @Test
    void testCanonicalPayloadDifferentPurpose() {
        Instant timestamp = Instant.ofEpochMilli(1234567890L);

        byte[] signin = canonicalPayloadService.createCanonicalPayloadBytes(
                "c1", "ch1", "d1", "cl1", ChallengeService.PURPOSE_SIGNIN, timestamp);
        byte[] stepUp = canonicalPayloadService.createCanonicalPayloadBytes(
                "c1", "ch1", "d1", "cl1", ChallengeService.PURPOSE_STEP_UP, timestamp);

        assertFalse(java.util.Arrays.equals(signin, stepUp));
    }

    @Test
    void testCanonicalPayloadFormat() {
        Instant timestamp = Instant.ofEpochMilli(1234567890L);

        String payload = canonicalPayloadService.createCanonicalPayload(
                "c1", "ch1", "d1", "cl1", ChallengeService.PURPOSE_SIGNIN, timestamp);

        String expected = "c1\nch1\nd1\ncl1\nsignin\n1234567890";
        assertEquals(expected, payload);
    }

    private byte[] derToRaw(byte[] derSignature) throws Exception {
        int offset = 2;
        if ((derSignature[offset] & 0x80) != 0) {
            int length = derSignature[offset] & 0xFF;
            offset += 1;
        }
        offset += 1;

        int rLength = derSignature[offset] & 0xFF;
        offset += 1;
        byte[] r = new byte[32];
        int rStart = Math.max(0, rLength - 32);
        System.arraycopy(derSignature, offset + rStart, r, 32 - (rLength - rStart), rLength - rStart);
        offset += rLength;

        offset += 1;
        int sLength = derSignature[offset] & 0xFF;
        offset += 1;
        byte[] s = new byte[32];
        int sStart = Math.max(0, sLength - 32);
        System.arraycopy(derSignature, offset + sStart, s, 32 - (sLength - sStart), sLength - sStart);

        byte[] raw = new byte[64];
        System.arraycopy(r, 0, raw, 0, 32);
        System.arraycopy(s, 0, raw, 32, 32);
        return raw;
    }
}
