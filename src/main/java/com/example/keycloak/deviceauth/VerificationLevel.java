package com.example.keycloak.deviceauth;

/**
 * IAL-equivalent verification level for an account (doc section 2.1/6). CLAIMED
 * corresponds to Sewa's T1 (identity claimed, not validated); VERIFIED corresponds
 * to T2 (validated against the DRP record). Only the CLAIMED default is wired up
 * here - the T2 verification step itself is an explicitly open decision (SLUDI/eSignet
 * vs. an interim path) and is intentionally not implemented, see T2VerificationRequiredAction.
 */
public enum VerificationLevel {
    CLAIMED,
    VERIFIED
}
