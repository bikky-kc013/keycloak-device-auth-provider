package com.example.keycloak.deviceauth;

import org.jboss.logging.Logger;

import java.time.Instant;

/**
 * Shared challenge+signature verification logic, used by both the browser-flow
 * {@link DeviceChallengeAuthenticator} and the silent {@link DeviceKeyGrantType}
 * (Flow B), so the security-critical check exists in exactly one place.
 *
 * NOTE on timestamp: the canonical payload's timestamp must be the value the
 * *client* embedded when it signed (see README "Signature Format"), not a
 * fresh server-side Instant.now() - otherwise the server would never
 * reconstruct the exact bytes the client signed and verification would always
 * fail. The client-supplied timestamp is only trusted within a small clock-skew
 * window to prevent stale signatures being replayed indefinitely.
 */
public class DeviceAuthenticationService {

    private static final Logger logger = Logger.getLogger(DeviceAuthenticationService.class);

    /** Maximum allowed difference between the client-supplied timestamp and server time. */
    public static final long ALLOWED_CLOCK_SKEW_MILLIS = 60_000L;

    private final DeviceStorageProvider deviceStorage;
    private final ChallengeService challengeService;
    private final SignatureService signatureService;
    private final CanonicalPayloadService canonicalPayloadService;

    public DeviceAuthenticationService(DeviceStorageProvider deviceStorage, ChallengeService challengeService,
                                        SignatureService signatureService, CanonicalPayloadService canonicalPayloadService) {
        this.deviceStorage = deviceStorage;
        this.challengeService = challengeService;
        this.signatureService = signatureService;
        this.canonicalPayloadService = canonicalPayloadService;
    }

    public enum FailureReason {
        INVALID_OR_EXPIRED_CHALLENGE,
        DEVICE_MISMATCH,
        PURPOSE_MISMATCH,
        SESSION_MISMATCH,
        DEVICE_NOT_ACTIVE,
        DEVICE_USER_MISMATCH,
        TIMESTAMP_OUT_OF_RANGE,
        INVALID_SIGNATURE
    }

    public static final class Result {
        private final boolean success;
        private final Device device;
        private final Challenge challenge;
        private final FailureReason failureReason;

        private Result(boolean success, Device device, Challenge challenge, FailureReason failureReason) {
            this.success = success;
            this.device = device;
            this.challenge = challenge;
            this.failureReason = failureReason;
        }

        static Result success(Device device, Challenge challenge) {
            return new Result(true, device, challenge, null);
        }

        static Result failure(FailureReason reason) {
            return new Result(false, null, null, reason);
        }

        public boolean isSuccess() { return success; }
        public Device getDevice() { return device; }
        public Challenge getChallenge() { return challenge; }
        public FailureReason getFailureReason() { return failureReason; }
    }

    /**
     * Verifies a challenge-response. Consumes the challenge (single use) as a side effect,
     * regardless of outcome, so a failed attempt can't be retried against the same challenge.
     *
     * @param expectedPurpose        required purpose the challenge must have been created for
     *                                (e.g. {@link ChallengeService#PURPOSE_SIGNIN}); pass null to accept any purpose
     * @param expectedSessionId      required authenticationSessionId, only relevant for the browser-flow
     *                                caller; pass null when there is no browser session (Flow B)
     * @param clientTimestampMillis  the timestamp the client embedded in the payload it signed (epoch millis)
     */
    public Result verify(String deviceId, String challengeId, String signatureBase64,
                          String expectedPurpose, String expectedSessionId, long clientTimestampMillis) {
        Challenge challenge = challengeService.consumeChallenge(challengeId);
        if (challenge == null) {
            logger.warnv("Challenge verification failed: invalid or expired challengeId");
            return Result.failure(FailureReason.INVALID_OR_EXPIRED_CHALLENGE);
        }

        if (!challenge.getDeviceId().equals(deviceId)) {
            logger.warnv("Challenge verification failed: device mismatch");
            return Result.failure(FailureReason.DEVICE_MISMATCH);
        }

        if (expectedPurpose != null && !expectedPurpose.equals(challenge.getPurpose())) {
            logger.warnv("Challenge verification failed: purpose mismatch, expected={0} actual={1}",
                    expectedPurpose, challenge.getPurpose());
            return Result.failure(FailureReason.PURPOSE_MISMATCH);
        }

        if (expectedSessionId != null && !expectedSessionId.equals(challenge.getAuthenticationSessionId())) {
            logger.warnv("Challenge verification failed: session mismatch");
            return Result.failure(FailureReason.SESSION_MISMATCH);
        }

        Device device = deviceStorage.getDeviceById(deviceId);
        if (device == null || !device.isActive()) {
            logger.warnv("Challenge verification failed: device not found or not active");
            return Result.failure(FailureReason.DEVICE_NOT_ACTIVE);
        }

        if (!device.getUserId().equals(challenge.getUserId())) {
            logger.warnv("Challenge verification failed: device does not belong to challenge's user");
            return Result.failure(FailureReason.DEVICE_USER_MISMATCH);
        }

        long skew = Math.abs(Instant.now().toEpochMilli() - clientTimestampMillis);
        if (skew > ALLOWED_CLOCK_SKEW_MILLIS) {
            logger.warnv("Challenge verification failed: timestamp out of range, skewMillis={0}", skew);
            return Result.failure(FailureReason.TIMESTAMP_OUT_OF_RANGE);
        }

        byte[] canonicalPayload = canonicalPayloadService.createCanonicalPayloadBytes(
                challenge.getChallengeId(), challenge.getChallenge(), deviceId,
                challenge.getClientId(), challenge.getPurpose(), Instant.ofEpochMilli(clientTimestampMillis));

        boolean valid = signatureService.verifySignature(
                signatureBase64, canonicalPayload, device.getPublicKeyJwk(), device.getAlgorithm());

        if (!valid) {
            logger.warnv("Challenge verification failed: invalid signature");
            return Result.failure(FailureReason.INVALID_SIGNATURE);
        }

        device.setLastUsedAt(Instant.now());
        deviceStorage.updateDevice(device);

        logger.infov("Challenge verification succeeded, purpose={0}", challenge.getPurpose());
        return Result.success(device, challenge);
    }
}
