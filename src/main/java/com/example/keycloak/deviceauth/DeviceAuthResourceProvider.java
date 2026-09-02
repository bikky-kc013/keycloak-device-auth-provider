package com.example.keycloak.deviceauth;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;

import java.util.Map;

public class DeviceAuthResourceProvider implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(DeviceAuthResourceProvider.class);

    /** Must match DeviceChallengeAuthenticatorFactory's default so /challenge and the browser flow agree. */
    private static final long CHALLENGE_EXPIRY_SECONDS = 60;

    private final KeycloakSession session;
    private final DeviceStorageProvider deviceStorage;
    private final ChallengeService challengeService;

    public DeviceAuthResourceProvider(KeycloakSession session, DeviceStorageProvider deviceStorage) {
        this.session = session;
        this.deviceStorage = deviceStorage;
        // ChallengeService's backing store is static/shared (see ChallengeService), so a new
        // instance here still consumes challenges created by other request-scoped instances
        // (e.g. DeviceChallengeAuthenticator, DeviceKeyGrantType).
        this.challengeService = new ChallengeService(CHALLENGE_EXPIRY_SECONDS);
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
    }

    @POST
    @Path("/register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response registerDevice(RegisterDeviceRequest request) {
        try {
            if (request == null) {
                return errorResponse(Response.Status.BAD_REQUEST, "Invalid request body");
            }

            if (request.deviceId == null || request.deviceId.isBlank()) {
                return errorResponse(Response.Status.BAD_REQUEST, "Device ID is required");
            }

            try {
                java.util.UUID.fromString(request.deviceId);
            } catch (IllegalArgumentException e) {
                return errorResponse(Response.Status.BAD_REQUEST, "Device ID must be a valid UUID");
            }

            if (request.deviceName == null || request.deviceName.isBlank()) {
                return errorResponse(Response.Status.BAD_REQUEST, "Device name is required");
            }

            if (request.platform == null || request.platform.isBlank()) {
                return errorResponse(Response.Status.BAD_REQUEST, "Platform is required");
            }

            if (request.publicKey == null) {
                return errorResponse(Response.Status.BAD_REQUEST, "Public key is required");
            }

            if (request.algorithm == null || request.algorithm.isBlank()) {
                return errorResponse(Response.Status.BAD_REQUEST, "Algorithm is required");
            }

            if (!"ES256".equals(request.algorithm) && !"ECDSA".equals(request.algorithm)) {
                return errorResponse(Response.Status.BAD_REQUEST, "Only ES256/ECDSA algorithms are supported");
            }

            String publicKeyJwk;
            try {
                com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                publicKeyJwk = mapper.writeValueAsString(request.publicKey);
                DeviceService.validateJwk(publicKeyJwk, request.algorithm);
            } catch (IllegalArgumentException e) {
                return errorResponse(Response.Status.BAD_REQUEST, "Invalid public key: " + e.getMessage());
            } catch (Exception e) {
                return errorResponse(Response.Status.BAD_REQUEST, "Invalid public key format");
            }

            UserModel authenticatedUser = authenticateBearer();
            if (authenticatedUser == null) {
                return errorResponse(Response.Status.UNAUTHORIZED, "Not authenticated");
            }

            if (deviceStorage.hasDeviceWithId(request.deviceId)) {
                return errorResponse(Response.Status.CONFLICT, "Device with this ID already exists");
            }

            AttestationLevel attestationLevel = AttestationLevel.UNKNOWN;
            String attestationStatement = null;
            if (request.attestation != null) {
                attestationLevel = AttestationLevel.fromString(request.attestation.level);
                attestationStatement = request.attestation.statement;
            }
            AssuranceLevel assuranceLevel = AssuranceLevel.fromString(request.acr);

            DeviceService deviceService = new DeviceService(deviceStorage, session);
            Device device = deviceService.registerDevice(
                    authenticatedUser.getId(),
                    request.deviceId,
                    request.deviceName,
                    request.platform,
                    publicKeyJwk,
                    request.algorithm,
                    request.publicKey.kid,
                    attestationLevel,
                    attestationStatement,
                    assuranceLevel
            );

            logger.infov("Device registered via REST, attestationLevel={0}, assuranceLevel={1}",
                    attestationLevel, assuranceLevel);

            return Response.ok(Map.of(
                    "deviceId", device.getDeviceId(),
                    "status", device.getStatus().name(),
                    "attestationLevel", device.getAttestationLevel().name(),
                    "acr", device.getAssuranceLevel().name()
            )).build();

        } catch (Exception e) {
            logger.error("Error registering device", e);
            return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Internal server error");
        }
    }

    @POST
    @Path("/revoke")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response revokeDevice(RevokeDeviceRequest request) {
        try {
            if (request == null || request.deviceId == null || request.deviceId.isBlank()) {
                return errorResponse(Response.Status.BAD_REQUEST, "Device ID is required");
            }

            UserModel authenticatedUser = authenticateBearer();
            if (authenticatedUser == null) {
                return errorResponse(Response.Status.UNAUTHORIZED, "Not authenticated");
            }

            DeviceService deviceService = new DeviceService(deviceStorage, session);
            Device device = deviceService.revokeDevice(
                    authenticatedUser.getId(), request.deviceId);

            logger.infov("Device revoked via REST");

            return Response.ok(Map.of(
                    "deviceId", device.getDeviceId(),
                    "status", device.getStatus().name()
            )).build();

        } catch (IllegalArgumentException e) {
            return errorResponse(Response.Status.NOT_FOUND, "Device not found");
        } catch (IllegalStateException e) {
            return errorResponse(Response.Status.CONFLICT, e.getMessage());
        } catch (Exception e) {
            logger.error("Error revoking device", e);
            return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Internal server error");
        }
    }

    /**
     * Flow B (silent sign-in / step-up), leg 1 of 2: issue a challenge for an already-registered,
     * active device. Deliberately unauthenticated (no Bearer token) - the device itself is the
     * credential being tested, and the account it belongs to is only revealed after a valid
     * signature is presented to the token endpoint (leg 2, DeviceKeyGrantType). Purpose defaults
     * to "signin"; pass "step-up" for an action-scoped, fresh authorization (doc section 4.2/5).
     */
    @POST
    @Path("/challenge")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createChallenge(ChallengeRequest request) {
        try {
            if (request == null || request.deviceId == null || request.deviceId.isBlank()) {
                return errorResponse(Response.Status.BAD_REQUEST, "Device ID is required");
            }

            Device device = deviceStorage.getDeviceById(request.deviceId);
            if (device == null || !device.isActive()) {
                // Deliberately vague - do not reveal whether a deviceId exists at all.
                return errorResponse(Response.Status.NOT_FOUND, "Device not found or not active");
            }

            String purpose = (request.purpose == null || request.purpose.isBlank())
                    ? ChallengeService.PURPOSE_SIGNIN : request.purpose;
            if (!ChallengeService.PURPOSE_SIGNIN.equals(purpose) && !ChallengeService.PURPOSE_STEP_UP.equals(purpose)) {
                return errorResponse(Response.Status.BAD_REQUEST, "purpose must be 'signin' or 'step-up'");
            }

            if (request.clientId == null || request.clientId.isBlank()) {
                return errorResponse(Response.Status.BAD_REQUEST, "clientId is required");
            }
            // No Bearer token/client auth context exists on this unauthenticated endpoint, so the
            // caller-supplied clientId is trusted at challenge-creation time; it only becomes a real
            // binding once DeviceKeyGrantType's token exchange authenticates as that same OAuth client.
            String clientId = request.clientId;

            Challenge challenge = challengeService.createChallenge(
                    device.getUserId(), device.getDeviceId(), clientId, null, purpose);

            return Response.ok(Map.of(
                    "challengeId", challenge.getChallengeId(),
                    "challenge", challenge.getChallenge(),
                    "purpose", challenge.getPurpose(),
                    "expiresIn", CHALLENGE_EXPIRY_SECONDS
            )).build();
        } catch (Exception e) {
            logger.error("Error creating challenge", e);
            return errorResponse(Response.Status.INTERNAL_SERVER_ERROR, "Internal server error");
        }
    }

    /**
     * RealmResourceProvider endpoints are NOT automatically Bearer-authenticated by
     * Keycloak (unlike protocol/protected endpoints) - the original /register and
     * /revoke here relied on session.getContext().getUser(), which nothing ever
     * populates for a custom realm resource, so those endpoints always returned
     * "Not authenticated" regardless of a valid token. This explicitly validates
     * the Authorization: Bearer header against the realm.
     */
    private UserModel authenticateBearer() {
        AuthenticationManager.AuthResult authResult = new AppAuthManager.BearerTokenAuthenticator(session)
                .setRealm(session.getContext().getRealm())
                .setUriInfo(session.getContext().getUri())
                .setConnection(session.getContext().getConnection())
                .setHeaders(session.getContext().getRequestHeaders())
                .authenticate();
        return authResult != null ? authResult.getUser() : null;
    }

    private Response errorResponse(Response.Status status, String message) {
        return Response.status(status)
                .entity(Map.of("error", message))
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    public static class RegisterDeviceRequest {
        @JsonProperty("deviceId")
        public String deviceId;
        @JsonProperty("deviceName")
        public String deviceName;
        @JsonProperty("platform")
        public String platform;
        @JsonProperty("publicKey")
        public PublicKey publicKey;
        @JsonProperty("algorithm")
        public String algorithm;
        @JsonProperty("attestation")
        public Attestation attestation;
        /** Sewa assurance tier (T0/T1/T2/T3) the client believes it's registering under.
         *  Unrecognized/missing values are recorded as UNKNOWN, never rejected - same
         *  leniency as attestation.level. */
        @JsonProperty("acr")
        public String acr;
    }

    public static class Attestation {
        /** HARDWARE, SOFTWARE, or UNKNOWN - unrecognized/missing values are recorded as UNKNOWN, never rejected. */
        @JsonProperty("level")
        public String level;
        /** Opaque attestation statement (e.g. base64 cert chain). Recorded, not parsed or validated. */
        @JsonProperty("statement")
        public String statement;
    }

    public static class PublicKey {
        @JsonProperty("kty")
        public String kty;
        @JsonProperty("crv")
        public String crv;
        @JsonProperty("x")
        public String x;
        @JsonProperty("y")
        public String y;
        @JsonProperty("kid")
        public String kid;
    }

    public static class RevokeDeviceRequest {
        @JsonProperty("deviceId")
        public String deviceId;
    }

    public static class ChallengeRequest {
        @JsonProperty("deviceId")
        public String deviceId;
        @JsonProperty("purpose")
        public String purpose;
        @JsonProperty("clientId")
        public String clientId;
    }
}
