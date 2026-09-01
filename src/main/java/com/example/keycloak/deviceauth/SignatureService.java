package com.example.keycloak.deviceauth;

import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

public class SignatureService {

    private static final Logger logger = Logger.getLogger(SignatureService.class);

    private static final String ALGORITHM = "SHA256withECDSA";
    private static final String EC_CURVE = "secp256r1";
    private static final int P256_KEY_SIZE = 32;
    private static final int ECDSA_SIG_SIZE = 64;

    public boolean verifySignature(String signatureBase64, byte[] payload, String publicKeyJwk, String algorithm) {
        try {
            PublicKey publicKey = parsePublicKey(publicKeyJwk);
            byte[] signatureBytes = Base64.getUrlDecoder().decode(signatureBase64);

            Signature signature = Signature.getInstance(ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(payload);

            byte[] derSignature = convertRawToDer(signatureBytes);

            return signature.verify(derSignature);
        } catch (Exception e) {
            logger.warn("Signature verification failed: " + e.getMessage());
            return false;
        }
    }

    private byte[] convertRawToDer(byte[] rawSignature) throws Exception {
        if (rawSignature.length == ECDSA_SIG_SIZE) {
            byte[] r = new byte[P256_KEY_SIZE];
            byte[] s = new byte[P256_KEY_SIZE];
            System.arraycopy(rawSignature, 0, r, 0, P256_KEY_SIZE);
            System.arraycopy(rawSignature, P256_KEY_SIZE, s, 0, P256_KEY_SIZE);
            return createDerSignature(r, s);
        } else if (rawSignature.length > 0 && rawSignature[0] == 0x30) {
            return rawSignature;
        } else {
            throw new InvalidKeyException("Unsupported signature format, length: " + rawSignature.length);
        }
    }

    private byte[] createDerSignature(byte[] r, byte[] s) throws Exception {
        byte[] rTrimmed = trimLeadingZeros(r);
        byte[] sTrimmed = trimLeadingZeros(s);

        int rLen = rTrimmed.length;
        int sLen = sTrimmed.length;

        boolean rNeedPad = (rTrimmed[0] & 0x80) != 0;
        boolean sNeedPad = (sTrimmed[0] & 0x80) != 0;

        int rFinalLen = rNeedPad ? rLen + 1 : rLen;
        int sFinalLen = sNeedPad ? sLen + 1 : sLen;

        int totalLen = 2 + rFinalLen + 2 + sFinalLen;
        byte[] der = new byte[2 + totalLen];

        der[0] = 0x30;
        der[1] = (byte) totalLen;
        der[2] = 0x02;
        der[3] = (byte) rFinalLen;

        int offset = 4;
        if (rNeedPad) {
            der[offset++] = 0x00;
        }
        System.arraycopy(rTrimmed, 0, der, offset, rLen);
        offset += rLen;

        der[offset++] = 0x02;
        der[offset++] = (byte) sFinalLen;
        if (sNeedPad) {
            der[offset++] = 0x00;
        }
        System.arraycopy(sTrimmed, 0, der, offset, sLen);

        return der;
    }

    private byte[] trimLeadingZeros(byte[] value) {
        int start = 0;
        while (start < value.length - 1 && value[start] == 0) {
            start++;
        }
        if (start == 0) {
            return value;
        }
        byte[] trimmed = new byte[value.length - start];
        System.arraycopy(value, start, trimmed, 0, trimmed.length);
        return trimmed;
    }

    @SuppressWarnings("unchecked")
    private PublicKey parsePublicKey(String publicKeyJwk) throws Exception {
        Map<String, Object> jwk = new com.fasterxml.jackson.databind.ObjectMapper()
                .readValue(publicKeyJwk, Map.class);

        String kty = (String) jwk.get("kty");
        if (!"EC".equals(kty)) {
            throw new InvalidKeyException("Only EC keys are supported, got: " + kty);
        }

        String crv = (String) jwk.get("crv");
        if (!"P-256".equals(crv)) {
            throw new InvalidKeyException("Only P-256 curve is supported, got: " + crv);
        }

        byte[] xBytes = Base64.getUrlDecoder().decode((String) jwk.get("x"));
        byte[] yBytes = Base64.getUrlDecoder().decode((String) jwk.get("y"));

        java.math.BigInteger x = new java.math.BigInteger(1, xBytes);
        java.math.BigInteger y = new java.math.BigInteger(1, yBytes);

        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(EC_CURVE));
        java.security.spec.ECParameterSpec ecSpec = parameters.getParameterSpec(java.security.spec.ECParameterSpec.class);
        java.security.spec.ECPoint ecPoint = new java.security.spec.ECPoint(x, y);
        ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, ecSpec);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec(EC_CURVE), new SecureRandom());
        return keyGen.generateKeyPair();
    }

    public static String publicKeyToJwk(PublicKey publicKey, String keyId) {
        if (!(publicKey instanceof ECPublicKey ecPublicKey)) {
            throw new IllegalArgumentException("Not an EC public key");
        }

        java.math.BigInteger x = ecPublicKey.getW().getAffineX();
        java.math.BigInteger y = ecPublicKey.getW().getAffineY();

        String xBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(x.toByteArray());
        String yBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(y.toByteArray());

        StringBuilder sb = new StringBuilder();
        sb.append("{\"kty\":\"EC\",\"crv\":\"P-256\"");
        sb.append(",\"x\":\"").append(xBase64).append("\"");
        sb.append(",\"y\":\"").append(yBase64).append("\"");
        if (keyId != null) {
            sb.append(",\"kid\":\"").append(keyId).append("\"");
        }
        sb.append("}");
        return sb.toString();
    }
}
