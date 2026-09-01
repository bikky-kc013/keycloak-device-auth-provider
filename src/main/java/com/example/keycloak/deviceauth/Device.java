package com.example.keycloak.deviceauth;

import java.time.Instant;
import java.util.Objects;

public class Device {

    public enum Status {
        ACTIVE,
        REVOKED
    }

    private String id;
    private String userId;
    private String deviceId;
    private String deviceName;
    private String platform;
    private String publicKeyJwk;
    private String algorithm;
    private Status status;
    private String keyId;
    private Instant createdAt;
    private Instant lastUsedAt;
    private Instant revokedAt;

    public Device() {
    }

    public Device(String id, String userId, String deviceId, String deviceName, String platform,
                  String publicKeyJwk, String algorithm, Status status, String keyId,
                  Instant createdAt) {
        this.id = id;
        this.userId = userId;
        this.deviceId = deviceId;
        this.deviceName = deviceName;
        this.platform = platform;
        this.publicKeyJwk = publicKeyJwk;
        this.algorithm = algorithm;
        this.status = status;
        this.keyId = keyId;
        this.createdAt = createdAt;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }

    public String getDeviceName() { return deviceName; }
    public void setDeviceName(String deviceName) { this.deviceName = deviceName; }

    public String getPlatform() { return platform; }
    public void setPlatform(String platform) { this.platform = platform; }

    public String getPublicKeyJwk() { return publicKeyJwk; }
    public void setPublicKeyJwk(String publicKeyJwk) { this.publicKeyJwk = publicKeyJwk; }

    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }

    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }

    public String getKeyId() { return keyId; }
    public void setKeyId(String keyId) { this.keyId = keyId; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getLastUsedAt() { return lastUsedAt; }
    public void setLastUsedAt(Instant lastUsedAt) { this.lastUsedAt = lastUsedAt; }

    public Instant getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Instant revokedAt) { this.revokedAt = revokedAt; }

    public boolean isActive() {
        return status == Status.ACTIVE;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Device device = (Device) o;
        return Objects.equals(id, device.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
