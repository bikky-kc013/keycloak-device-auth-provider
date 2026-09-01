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

import java.util.List;
import java.util.Map;

/**
 * Browser-flow, form-rendered device challenge step. NOT part of the default
 * realm configuration (see README "Realm Configuration") - Flow B's silent
 * grant type (DeviceKeyGrantType) is the primary sign-in/step-up path for a
 * mobile app with no browser involved. This authenticator remains available,
 * bug-fixed and functional, for a pure-browser edge case, but submitting a
 * signature from this FTL-rendered form still requires the client to bridge a
 * native Keystore/Secure Enclave signing operation into the browser page,
 * which is not implemented here - see device-challenge-form.ftl.
 */
public class DeviceChallengeAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(DeviceChallengeAuthenticator.class);

    public static final String CHALLENGE_EXPIRY_SECONDS = "challengeExpirySeconds";

    private ChallengeService challengeService;
    private DeviceStorageProvider deviceStorage;
    private SignatureService signatureService;
    private CanonicalPayloadService canonicalPayloadService;
    private DeviceAuthenticationService deviceAuthenticationService;

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

        if (activeDevices.size() > 1) {
            logger.warnv("User has {0} active devices, expected exactly one (single-active-device policy) - using the first",
                    activeDevices.size());
        }

        Device device = activeDevices.getFirst();

        Challenge challenge = challengeService.createChallenge(
                userId, device.getDeviceId(), context.getAuthenticationSession().getClient().getClientId(),
                authSessionId, ChallengeService.PURPOSE_SIGNIN);

        context.getAuthenticationSession().setAuthNote("deviceId", device.getDeviceId());
        context.getAuthenticationSession().setAuthNote("challengeId", challenge.getChallengeId());
        context.getAuthenticationSession().setAuthNote("challenge", challenge.getChallenge());

        Map<String, Object> formData = Map.of(
                "challengeId", challenge.getChallengeId(),
                "challenge", challenge.getChallenge(),
                "deviceId", device.getDeviceId(),
                "purpose", challenge.getPurpose(),
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
        String submittedTimestamp = formData.getFirst("timestamp");

        if (submittedChallengeId == null || submittedSignature == null || submittedDeviceId == null
                || submittedTimestamp == null) {
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        long timestampMillis;
        try {
            timestampMillis = Long.parseLong(submittedTimestamp);
        } catch (NumberFormatException e) {
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String authSessionId = authSession.getParentSession() != null
                ? authSession.getParentSession().getId() : "unknown";

        DeviceAuthenticationService.Result result = deviceAuthenticationService.verify(
                submittedDeviceId, submittedChallengeId, submittedSignature,
                ChallengeService.PURPOSE_SIGNIN, authSessionId, timestampMillis);

        if (!result.isSuccess()) {
            logger.warnv("Device authentication failed: {0}", result.getFailureReason());
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        if (!result.getChallenge().getUserId().equals(context.getUser().getId())
                || !result.getDevice().getUserId().equals(context.getUser().getId())) {
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        logger.infov("Device authentication successful");
        context.success();
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
        rebuildDeviceAuthenticationService();
    }

    public void setDeviceStorage(DeviceStorageProvider deviceStorage) {
        this.deviceStorage = deviceStorage;
        rebuildDeviceAuthenticationService();
    }

    public void setSignatureService(SignatureService signatureService) {
        this.signatureService = signatureService;
        rebuildDeviceAuthenticationService();
    }

    public void setCanonicalPayloadService(CanonicalPayloadService canonicalPayloadService) {
        this.canonicalPayloadService = canonicalPayloadService;
        rebuildDeviceAuthenticationService();
    }

    private void rebuildDeviceAuthenticationService() {
        if (deviceStorage != null && challengeService != null && signatureService != null && canonicalPayloadService != null) {
            this.deviceAuthenticationService = new DeviceAuthenticationService(
                    deviceStorage, challengeService, signatureService, canonicalPayloadService);
        }
    }
}
