package com.example.keycloak.deviceauth;

/**
 * Constants for user attributes used to track Sewa-specific identity-assurance
 * state (see "Sewa Authentication and Identity Assurance" architecture doc, section 6).
 */
public final class SewaAttributes {

    /** Stores a {@link VerificationLevel} name. Defaulted to CLAIMED at account creation. */
    public static final String VERIFICATION_LEVEL_ATTRIBUTE = "sewa.verificationLevel";

    private SewaAttributes() {
    }
}
