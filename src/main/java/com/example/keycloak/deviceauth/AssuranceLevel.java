package com.example.keycloak.deviceauth;

/**
 * The Sewa identity-assurance tier (T0-T3, per "Sewa Authentication and Identity
 * Assurance" doc section 2.1) a device was registered under. Recorded, never
 * blocking registration - mirrors AttestationLevel's lenient pattern. Only T1
 * is actually reachable via the current Flow A (OTP-verified) enrollment path;
 * T2/T3 verification isn't implemented yet (see T2VerificationRequiredAction).
 */
public enum AssuranceLevel {
    T0,
    T1,
    T2,
    T3,
    UNKNOWN;

    public static AssuranceLevel fromString(String value) {
        if (value == null || value.isBlank()) {
            return UNKNOWN;
        }
        try {
            return AssuranceLevel.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return UNKNOWN;
        }
    }
}
