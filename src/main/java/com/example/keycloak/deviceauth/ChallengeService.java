package com.example.keycloak.deviceauth;

import org.jboss.logging.Logger;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class ChallengeService {

    private static final Logger logger = Logger.getLogger(ChallengeService.class);

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int CHALLENGE_BYTES = 32;

    /** Default purpose for a routine sign-in challenge, as opposed to a step-up challenge. */
    public static final String PURPOSE_SIGNIN = "signin";
    /** Purpose for a fresh, action-scoped step-up challenge (doc section 4.2/5). */
    public static final String PURPOSE_STEP_UP = "step-up";

    // Deliberately static: a new ChallengeService instance is created on every
    // authenticator/resource-provider invocation (each HTTP request gets its own
    // KeycloakSession-scoped provider instances), but a challenge created in one
    // request (POST /challenge) must be consumable by a later, separate request
    // (POST /token with the signed response). This map is the actual shared store,
    // scoped to this Keycloak node's JVM - see "Known Limitations" in the README
    // for the distributed-deployment caveat (use Redis/database there).
    private static final Map<String, Challenge> challenges = new ConcurrentHashMap<>();
    private final long challengeExpirySeconds;

    public ChallengeService(long challengeExpirySeconds) {
        this.challengeExpirySeconds = challengeExpirySeconds;
    }

    public Challenge createChallenge(String userId, String deviceId, String clientId,
                                     String authenticationSessionId, String purpose) {
        byte[] challengeBytes = new byte[CHALLENGE_BYTES];
        SECURE_RANDOM.nextBytes(challengeBytes);
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes);

        String challengeId = UUID.randomUUID().toString();
        String challengeHash = hashChallenge(challenge);
        String resolvedPurpose = (purpose == null || purpose.isBlank()) ? PURPOSE_SIGNIN : purpose;

        Instant expiresAt = Instant.now().plus(challengeExpirySeconds, ChronoUnit.SECONDS);

        Challenge challengeObj = new Challenge(
                challengeId,
                challenge,
                challengeHash,
                userId,
                deviceId,
                clientId,
                resolvedPurpose,
                authenticationSessionId,
                expiresAt
        );

        challenges.put(challengeId, challengeObj);

        logger.infov("Challenge created, purpose={0}", resolvedPurpose);

        return challengeObj;
    }

    public Challenge getChallenge(String challengeId) {
        return challenges.get(challengeId);
    }

    public String getChallengeValue(String challengeId) {
        Challenge challenge = challenges.get(challengeId);
        return challenge != null ? challenge.getChallenge() : null;
    }

    public Challenge consumeChallenge(String challengeId) {
        Challenge challenge = challenges.get(challengeId);
        if (challenge == null) {
            return null;
        }

        synchronized (challenge) {
            if (challenge.isUsed()) {
                logger.warnv("Challenge already used");
                return null;
            }

            if (challenge.isExpired()) {
                logger.warnv("Challenge expired");
                return null;
            }

            challenge.setUsedAt(Instant.now());
            return challenge;
        }
    }

    public void cleanupExpiredChallenges() {
        Instant now = Instant.now();
        challenges.entrySet().removeIf(entry -> entry.getValue().getExpiresAt().isBefore(now));
    }

    private String hashChallenge(String challenge) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(challenge.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash challenge", e);
        }
    }
}
