package com.example.keycloak.deviceauth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DeviceServiceValidationTest {

    @Test
    void testValidateDeviceIdValid() {
        assertDoesNotThrow(() -> DeviceService.validateDeviceId("550e8400-e29b-41d4-a716-446655440000"));
    }

    @Test
    void testValidateDeviceIdNull() {
        assertThrows(IllegalArgumentException.class, () -> DeviceService.validateDeviceId(null));
    }

    @Test
    void testValidateDeviceIdBlank() {
        assertThrows(IllegalArgumentException.class, () -> DeviceService.validateDeviceId("  "));
    }

    @Test
    void testValidateDeviceIdInvalidFormat() {
        assertThrows(IllegalArgumentException.class, () -> DeviceService.validateDeviceId("not-a-uuid"));
    }

    @Test
    void testValidateJwkValid() {
        String jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"dGVzdA==\",\"y\":\"dGVzdA==\",\"kid\":\"key-1\"}";
        assertThrows(IllegalArgumentException.class, () -> DeviceService.validateJwk(jwk, "ES256"));
    }

    @Test
    void testValidateJwkNull() {
        assertThrows(IllegalArgumentException.class, () -> DeviceService.validateJwk(null, "ES256"));
    }

    @Test
    void testValidateJwkBlank() {
        assertThrows(IllegalArgumentException.class, () -> DeviceService.validateJwk("  ", "ES256"));
    }

    @Test
    void testValidateJwkWrongKty() {
        String jwk = "{\"kty\":\"RSA\",\"crv\":\"P-256\",\"x\":\"dGVzdA==\",\"y\":\"dGVzdA==\",\"kid\":\"key-1\"}";
        assertThrows(IllegalArgumentException.class, () -> DeviceService.validateJwk(jwk, "ES256"));
    }

    @Test
    void testValidateJwkWrongCrv() {
        String jwk = "{\"kty\":\"EC\",\"crv\":\"P-384\",\"x\":\"dGVzdA==\",\"y\":\"dGVzdA==\",\"kid\":\"key-1\"}";
        assertThrows(IllegalArgumentException.class, () -> DeviceService.validateJwk(jwk, "ES256"));
    }

    @Test
    void testValidateJwkMissingKid() {
        String jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"dGVzdA==\",\"y\":\"dGVzdA==\"}";
        assertThrows(IllegalArgumentException.class, () -> DeviceService.validateJwk(jwk, "ES256"));
    }

    @Test
    void testValidateJwkUnsupportedAlgorithm() {
        String jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"dGVzdA==\",\"y\":\"dGVzdA==\",\"kid\":\"key-1\"}";
        assertThrows(IllegalArgumentException.class, () -> DeviceService.validateJwk(jwk, "RS256"));
    }

    @Test
    void testValidateJwkInvalidJson() {
        assertThrows(IllegalArgumentException.class, () -> DeviceService.validateJwk("not-json", "ES256"));
    }

    @Test
    void testValidateJwkEmptyX() {
        String jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"\",\"y\":\"dGVzdA==\",\"kid\":\"key-1\"}";
        assertThrows(IllegalArgumentException.class, () -> DeviceService.validateJwk(jwk, "ES256"));
    }

    @Test
    void testValidateJwkMissingX() {
        String jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"y\":\"dGVzdA==\",\"kid\":\"key-1\"}";
        assertThrows(IllegalArgumentException.class, () -> DeviceService.validateJwk(jwk, "ES256"));
    }

    @Test
    void testDeviceStatusTransitions() {
        Device device = new Device();
        device.setStatus(Device.Status.ACTIVE);
        assertTrue(device.isActive());

        device.setStatus(Device.Status.REVOKED);
        assertFalse(device.isActive());
    }
}
