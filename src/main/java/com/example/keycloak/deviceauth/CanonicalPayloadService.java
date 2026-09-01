package com.example.keycloak.deviceauth;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * Service for creating canonical payloads for device signature verification.
 *
 * The canonical format is:
 *   challengeId + "\n" + challenge + "\n" + deviceId + "\n" + clientId + "\n" + purpose + "\n" + timestamp
 *
 * This ensures deterministic byte sequences for signing and verification. "purpose"
 * (e.g. "signin" or "step-up") scopes a signature to what it was actually authorizing,
 * so a routine sign-in signature can't be replayed as a step-up authorization.
 *
 * IMPORTANT: "timestamp" must be the timestamp the *client* embedded when it signed
 * the payload, not a fresh server-side value - the server must reconstruct the exact
 * bytes the client signed. See DeviceAuthenticationService for the clock-skew check
 * that's applied to the client-supplied timestamp before it's trusted.
 */
public class CanonicalPayloadService {

    /**
     * Create a canonical payload string from the given parameters.
     */
    public String createCanonicalPayload(String challengeId, String challenge, String deviceId,
                                         String clientId, String purpose, Instant timestamp) {
        StringBuilder sb = new StringBuilder();
        sb.append(challengeId).append("\n");
        sb.append(challenge).append("\n");
        sb.append(deviceId).append("\n");
        sb.append(clientId).append("\n");
        sb.append(purpose).append("\n");
        sb.append(timestamp.toEpochMilli());
        return sb.toString();
    }

    /**
     * Get the canonical payload as bytes (UTF-8 encoded).
     */
    public byte[] createCanonicalPayloadBytes(String challengeId, String challenge, String deviceId,
                                              String clientId, String purpose, Instant timestamp) {
        return createCanonicalPayload(challengeId, challenge, deviceId, clientId, purpose, timestamp)
                .getBytes(StandardCharsets.UTF_8);
    }
}
