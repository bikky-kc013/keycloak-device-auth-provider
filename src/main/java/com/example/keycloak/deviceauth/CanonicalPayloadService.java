package com.example.keycloak.deviceauth;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * Service for creating canonical payloads for device signature verification.
 *
 * The canonical format is:
 *   challengeId + "\n" + challenge + "\n" + deviceId + "\n" + clientId + "\n" + timestamp
 *
 * This ensures deterministic byte sequences for signing and verification.
 */
public class CanonicalPayloadService {

    /**
     * Create a canonical payload string from the given parameters.
     */
    public String createCanonicalPayload(String challengeId, String challenge, String deviceId,
                                         String clientId, Instant timestamp) {
        StringBuilder sb = new StringBuilder();
        sb.append(challengeId).append("\n");
        sb.append(challenge).append("\n");
        sb.append(deviceId).append("\n");
        sb.append(clientId).append("\n");
        sb.append(timestamp.toEpochMilli());
        return sb.toString();
    }

    /**
     * Get the canonical payload as bytes (UTF-8 encoded).
     */
    public byte[] createCanonicalPayloadBytes(String challengeId, String challenge, String deviceId,
                                              String clientId, Instant timestamp) {
        return createCanonicalPayload(challengeId, challenge, deviceId, clientId, timestamp)
                .getBytes(StandardCharsets.UTF_8);
    }
}
