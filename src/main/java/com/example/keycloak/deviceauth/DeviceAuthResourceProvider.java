package com.example.keycloak.deviceauth;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import java.util.Map;

public class DeviceAuthResourceProvider implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(DeviceAuthResourceProvider.class);

    private final KeycloakSession session;
    private final DeviceStorageProvider deviceStorage;

    public DeviceAuthResourceProvider(KeycloakSession session, DeviceStorageProvider deviceStorage) {
        this.session = session;
        this.deviceStorage = deviceStorage;
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

            if (session.getContext().getUser() == null) {
                return errorResponse(Response.Status.UNAUTHORIZED, "Not authenticated");
            }

            if (deviceStorage.hasDeviceWithId(request.deviceId)) {
                return errorResponse(Response.Status.CONFLICT, "Device with this ID already exists");
            }

            DeviceService deviceService = new DeviceService(deviceStorage, session);
            Device device = deviceService.registerDevice(
                    session.getContext().getUser().getId(),
                    request.deviceId,
                    request.deviceName,
                    request.platform,
                    publicKeyJwk,
                    request.algorithm,
                    request.publicKey.kid
            );

            logger.infov("Device registered via REST");

            return Response.ok(Map.of(
                    "deviceId", device.getDeviceId(),
                    "status", device.getStatus().name()
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

            if (session.getContext().getUser() == null) {
                return errorResponse(Response.Status.UNAUTHORIZED, "Not authenticated");
            }

            DeviceService deviceService = new DeviceService(deviceStorage, session);
            Device device = deviceService.revokeDevice(
                    session.getContext().getUser().getId(), request.deviceId);

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
}
