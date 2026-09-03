package com.example.keycloak.deviceauth;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class DeviceService {

    private static final Logger logger = Logger.getLogger(DeviceService.class);

    private final DeviceStorageProvider deviceStorage;
    private final KeycloakSession session;
    private final DeviceRebindingNotifier rebindingNotifier;

    public DeviceService(DeviceStorageProvider deviceStorage, KeycloakSession session) {
        this(deviceStorage, session, new LoggingDeviceRebindingNotifier());
    }

    public DeviceService(DeviceStorageProvider deviceStorage, KeycloakSession session, DeviceRebindingNotifier rebindingNotifier) {
        this.deviceStorage = deviceStorage;
        this.session = session;
        this.rebindingNotifier = rebindingNotifier;
    }

    public Device registerDevice(String userId, String deviceId, String deviceName, String platform,
                                 String publicKeyJwk, String algorithm, String keyId) {
        return registerDevice(userId, deviceId, deviceName, platform, publicKeyJwk, algorithm, keyId,
                AttestationLevel.UNKNOWN, null);
    }

    public Device registerDevice(String userId, String deviceId, String deviceName, String platform,
                                 String publicKeyJwk, String algorithm, String keyId,
                                 AttestationLevel attestationLevel, String attestationStatement) {
        return registerDevice(userId, deviceId, deviceName, platform, publicKeyJwk, algorithm, keyId,
                attestationLevel, attestationStatement, AssuranceLevel.UNKNOWN);
    }

    public Device registerDevice(String userId, String deviceId, String deviceName, String platform,
                                 String publicKeyJwk, String algorithm, String keyId,
                                 AttestationLevel attestationLevel, String attestationStatement,
                                 AssuranceLevel assuranceLevel) {
        if (deviceStorage.hasDeviceWithId(deviceId)) {
            throw new IllegalArgumentException("Device with id " + deviceId + " already exists");
        }

        UserModel user = session.users().getUserById(session.getContext().getRealm(), userId);
        if (user == null) {
            throw new IllegalArgumentException("User not found: " + userId);
        }

        return bindDevice(userId, deviceId, deviceName, platform, publicKeyJwk, algorithm, keyId,
                attestationLevel, attestationStatement, assuranceLevel);
    }

    /**
     * The actual single-active-device-per-account enforcement (doc section 4.3: "One active
     * key per account. Registering a new key invalidates the previous one.") plus attestation
     * recording and the re-binding notification hook. Deliberately session-free so it's directly
     * unit-testable without mocking KeycloakSession.
     */
    Device bindDevice(String userId, String deviceId, String deviceName, String platform,
                      String publicKeyJwk, String algorithm, String keyId,
                      AttestationLevel attestationLevel, String attestationStatement) {
        return bindDevice(userId, deviceId, deviceName, platform, publicKeyJwk, algorithm, keyId,
                attestationLevel, attestationStatement, AssuranceLevel.UNKNOWN);
    }

    Device bindDevice(String userId, String deviceId, String deviceName, String platform,
                      String publicKeyJwk, String algorithm, String keyId,
                      AttestationLevel attestationLevel, String attestationStatement,
                      AssuranceLevel assuranceLevel) {
        List<Device> existingActiveDevices = deviceStorage.getDevicesByUserId(userId).stream()
                .filter(Device::isActive)
                .toList();

        Device previousDevice = existingActiveDevices.isEmpty() ? null : existingActiveDevices.get(0);
        if (previousDevice != null) {
            previousDevice.setStatus(Device.Status.REVOKED);
            previousDevice.setRevokedAt(Instant.now());
            deviceStorage.updateDevice(previousDevice);
            logger.infov("Revoked previous active device {0} for userId={1} as part of re-binding",
                    previousDevice.getDeviceId(), userId);
        }

        Device device = new Device();
        device.setId(UUID.randomUUID().toString());
        device.setUserId(userId);
        device.setDeviceId(deviceId);
        device.setDeviceName(deviceName);
        device.setPlatform(platform);
        device.setPublicKeyJwk(publicKeyJwk);
        device.setAlgorithm(algorithm);
        device.setStatus(Device.Status.ACTIVE);
        device.setKeyId(keyId);
        device.setAttestationLevel(attestationLevel);
        device.setAttestationStatement(attestationStatement);
        device.setAssuranceLevel(assuranceLevel);
        device.setCreatedAt(Instant.now());

        device = deviceStorage.createDevice(device);

        logger.infov("Device registered: userId={0}, deviceId={1}, platform={2}, attestationLevel={3}, assuranceLevel={4}",
                userId, deviceId, platform, device.getAttestationLevel(), device.getAssuranceLevel());

        if (previousDevice != null) {
            rebindingNotifier.notifyRebinding(userId, previousDevice, device);
        }

        return device;
    }

    public Device getDevice(String userId, String deviceId) {
        return deviceStorage.getDeviceByUserIdAndDeviceId(userId, deviceId);
    }

    public Device getDeviceById(String deviceId) {
        return deviceStorage.getDeviceById(deviceId);
    }

    public boolean hasActiveDevice(String userId) {
        return deviceStorage.hasActiveDevice(userId);
    }

    public Device revokeDevice(String userId, String deviceId) {
        Device device = deviceStorage.getDeviceByUserIdAndDeviceId(userId, deviceId);
        if (device == null) {
            throw new IllegalArgumentException("Device not found or does not belong to user");
        }

        if (!device.isActive()) {
            throw new IllegalStateException("Device is already revoked");
        }

        device.setStatus(Device.Status.REVOKED);
        device.setRevokedAt(Instant.now());
        deviceStorage.updateDevice(device);

        logger.infov("Device revoked: userId={0}, deviceId={1}", userId, deviceId);

        return device;
    }

    public void updateLastUsed(String deviceId) {
        Device device = deviceStorage.getDeviceById(deviceId);
        if (device != null) {
            device.setLastUsedAt(Instant.now());
            deviceStorage.updateDevice(device);
        }
    }

    @SuppressWarnings("unchecked")
    public static void validateJwk(String publicKeyJwk, String algorithm) {
        if (publicKeyJwk == null || publicKeyJwk.isBlank()) {
            throw new IllegalArgumentException("Public key JWK is required");
        }

        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            Map<String, Object> jwk = mapper.readValue(publicKeyJwk, Map.class);

            String kty = (String) jwk.get("kty");
            if (!"EC".equals(kty)) {
                throw new IllegalArgumentException("Only EC keys are supported, got: " + kty);
            }

            String crv = (String) jwk.get("crv");
            if (!"P-256".equals(crv)) {
                throw new IllegalArgumentException("Only P-256 curve is supported, got: " + crv);
            }

            String x = (String) jwk.get("x");
            String y = (String) jwk.get("y");
            if (x == null || x.isBlank() || y == null || y.isBlank()) {
                throw new IllegalArgumentException("JWK must contain x and y coordinates");
            }

            byte[] xBytes = Base64.getUrlDecoder().decode(x);
            byte[] yBytes = Base64.getUrlDecoder().decode(y);
            if (xBytes.length != 32 || yBytes.length != 32) {
                throw new IllegalArgumentException("Invalid EC P-256 key coordinates length");
            }

            if (algorithm != null && !algorithm.isEmpty()) {
                if (!"ES256".equals(algorithm) && !"ECDSA".equals(algorithm)) {
                    throw new IllegalArgumentException("Only ES256/ECDSA algorithms are supported, got: " + algorithm);
                }
            }

            String kid = (String) jwk.get("kid");
            if (kid == null || kid.isBlank()) {
                throw new IllegalArgumentException("JWK must contain a kid (key ID) field");
            }

        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid JWK format: " + e.getMessage());
        }
    }

    public static void validateDeviceId(String deviceId) {
        if (deviceId == null || deviceId.isBlank()) {
            throw new IllegalArgumentException("Device ID is required");
        }
        try {
            UUID.fromString(deviceId);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Device ID must be a valid UUID");
        }
    }
}
