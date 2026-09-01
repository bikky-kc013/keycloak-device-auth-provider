package com.example.keycloak.deviceauth;

import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public class DeviceChallengeAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(DeviceChallengeAuthenticator.class);

    public static final String CHALLENGE_EXPIRY_SECONDS = "challengeExpirySeconds";

    private ChallengeService challengeService;
    private DeviceStorageProvider deviceStorage;
    private SignatureService signatureService;
    private CanonicalPayloadService canonicalPayloadService;

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String userId = context.getUser().getId();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String authSessionId = authSession.getParentSession() != null
                ? authSession.getParentSession().getId() : "unknown";

        List<Device> devices = deviceStorage.getDevicesByUserId(userId);
        List<Device> activeDevices = devices.stream()
                .filter(Device::isActive)
                .toList();

        if (activeDevices.isEmpty()) {
            logger.infov("No active devices found for user");
            context.forceChallenge(context.form().createForm("device-challenge-form.ftl"));
            return;
        }

        Device device = activeDevices.getFirst();

        Challenge challenge = challengeService.createChallenge(
                userId, device.getDeviceId(), "unknown", authSessionId);

        context.getAuthenticationSession().setAuthNote("deviceId", device.getDeviceId());
        context.getAuthenticationSession().setAuthNote("challengeId", challenge.getChallengeId());
        context.getAuthenticationSession().setAuthNote("challenge", challenge.getChallenge());

        Map<String, Object> formData = Map.of(
                "challengeId", challenge.getChallengeId(),
                "challenge", challenge.getChallenge(),
                "deviceId", device.getDeviceId(),
                "deviceName", device.getDeviceName() != null ? device.getDeviceName() : "Unknown Device"
        );

        context.challenge(context.form()
                .setAttribute("challengeData", formData)
                .createForm("device-challenge-form.ftl"));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String submittedChallengeId = formData.getFirst("challengeId");
        String submittedSignature = formData.getFirst("signature");
        String submittedDeviceId = formData.getFirst("deviceId");

        if (submittedChallengeId == null || submittedSignature == null || submittedDeviceId == null) {
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        Challenge challenge = challengeService.consumeChallenge(submittedChallengeId);
        if (challenge == null) {
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        if (!challenge.getUserId().equals(context.getUser().getId())) {
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        if (!challenge.getDeviceId().equals(submittedDeviceId)) {
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        AuthenticationSessionModel authSession2 = context.getAuthenticationSession();
        String authSessionId = authSession2.getParentSession() != null
                ? authSession2.getParentSession().getId() : "unknown";
        if (!challenge.getAuthenticationSessionId().equals(authSessionId)) {
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        Device device = deviceStorage.getDeviceById(submittedDeviceId);
        if (device == null || !device.isActive()) {
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        if (!device.getUserId().equals(context.getUser().getId())) {
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        Instant timestamp = Instant.now();
        byte[] canonicalPayload = canonicalPayloadService.createCanonicalPayloadBytes(
                challenge.getChallengeId(),
                challenge.getChallenge(),
                submittedDeviceId,
                challenge.getClientId(),
                timestamp
        );

        boolean valid = signatureService.verifySignature(
                submittedSignature, canonicalPayload, device.getPublicKeyJwk(), device.getAlgorithm());

        if (valid) {
            device.setLastUsedAt(Instant.now());
            deviceStorage.updateDevice(device);

            logger.infov("Device authentication successful");
            context.success();
        } else {
            logger.warnv("Invalid signature");
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

    public void setChallengeService(ChallengeService challengeService) {
        this.challengeService = challengeService;
    }

    public void setDeviceStorage(DeviceStorageProvider deviceStorage) {
        this.deviceStorage = deviceStorage;
    }

    public void setSignatureService(SignatureService signatureService) {
        this.signatureService = signatureService;
    }

    public void setCanonicalPayloadService(CanonicalPayloadService canonicalPayloadService) {
        this.canonicalPayloadService = canonicalPayloadService;
    }
}
