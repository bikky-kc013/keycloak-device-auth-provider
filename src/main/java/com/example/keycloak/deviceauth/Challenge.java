package com.example.keycloak.deviceauth;

import java.time.Instant;
import java.util.Objects;

public class Challenge {

    private String challengeId;
    private String challengeHash;
    private String challenge;
    private String userId;
    private String deviceId;
    private String clientId;
    private String purpose;
    private String authenticationSessionId;
    private Instant expiresAt;
    private Instant usedAt;

    public Challenge() {
    }

    public Challenge(String challengeId, String challenge, String challengeHash,
                     String userId, String deviceId, String clientId, String purpose,
                     String authenticationSessionId, Instant expiresAt) {
        this.challengeId = challengeId;
        this.challenge = challenge;
        this.challengeHash = challengeHash;
        this.userId = userId;
        this.deviceId = deviceId;
        this.clientId = clientId;
        this.purpose = purpose;
        this.authenticationSessionId = authenticationSessionId;
        this.expiresAt = expiresAt;
    }

    public String getChallengeId() { return challengeId; }
    public void setChallengeId(String challengeId) { this.challengeId = challengeId; }

    public String getChallengeHash() { return challengeHash; }
    public void setChallengeHash(String challengeHash) { this.challengeHash = challengeHash; }

    public String getChallenge() { return challenge; }
    public void setChallenge(String challenge) { this.challenge = challenge; }

    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getPurpose() { return purpose; }
    public void setPurpose(String purpose) { this.purpose = purpose; }

    public String getAuthenticationSessionId() { return authenticationSessionId; }
    public void setAuthenticationSessionId(String authenticationSessionId) { this.authenticationSessionId = authenticationSessionId; }

    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }

    public Instant getUsedAt() { return usedAt; }
    public void setUsedAt(Instant usedAt) { this.usedAt = usedAt; }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isUsed() {
        return usedAt != null;
    }

    public boolean isValid() {
        return !isExpired() && !isUsed();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Challenge challenge1 = (Challenge) o;
        return Objects.equals(challengeId, challenge1.challengeId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(challengeId);
    }
}
