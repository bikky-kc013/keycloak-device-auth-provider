package com.example.keycloak.deviceauth;

/**
 * Attested security level of the hardware backing a device's private key.
 * Recorded on every binding, never blocking registration - a software-backed
 * key is still accepted so citizens on cheaper handsets aren't excluded.
 */
public enum AttestationLevel {
    HARDWARE,
    SOFTWARE,
    UNKNOWN;

    public static AttestationLevel fromString(String value) {
        if (value == null || value.isBlank()) {
            return UNKNOWN;
        }
        try {
            return AttestationLevel.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return UNKNOWN;
        }
    }
}
