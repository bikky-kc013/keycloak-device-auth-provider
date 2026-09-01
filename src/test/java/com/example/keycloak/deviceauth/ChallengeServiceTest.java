package com.example.keycloak.deviceauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.*;

class ChallengeServiceTest {

    private ChallengeService challengeService;

    @BeforeEach
    void setUp() {
        challengeService = new ChallengeService(60);
    }

    @Test
    void testCreateChallenge() {
        Challenge challenge = challengeService.createChallenge("user1", "device-1", "client1", "session1");

        assertNotNull(challenge.getChallengeId());
        assertNotNull(challenge.getChallenge());
        assertNotNull(challenge.getChallengeHash());
        assertEquals("user1", challenge.getUserId());
        assertEquals("device-1", challenge.getDeviceId());
        assertEquals("client1", challenge.getClientId());
        assertEquals("session1", challenge.getAuthenticationSessionId());
        assertFalse(challenge.isExpired());
        assertFalse(challenge.isUsed());
        assertTrue(challenge.isValid());
    }

    @Test
    void testGetChallenge() {
        Challenge created = challengeService.createChallenge("user1", "device-1", "client1", "session1");
        Challenge retrieved = challengeService.getChallenge(created.getChallengeId());

        assertNotNull(retrieved);
        assertEquals(created.getChallengeId(), retrieved.getChallengeId());
    }

    @Test
    void testGetNonexistentChallenge() {
        assertNull(challengeService.getChallenge("nonexistent"));
    }

    @Test
    void testConsumeChallenge() {
        Challenge created = challengeService.createChallenge("user1", "device-1", "client1", "session1");
        Challenge consumed = challengeService.consumeChallenge(created.getChallengeId());

        assertNotNull(consumed);
        assertNotNull(consumed.getUsedAt());
        assertFalse(consumed.isValid());
    }

    @Test
    void testConsumeChallengeTwiceFails() {
        Challenge created = challengeService.createChallenge("user1", "device-1", "client1", "session1");
        Challenge first = challengeService.consumeChallenge(created.getChallengeId());
        Challenge second = challengeService.consumeChallenge(created.getChallengeId());

        assertNotNull(first);
        assertNull(second);
    }

    @Test
    void testConsumeExpiredChallenge() {
        ChallengeService shortLived = new ChallengeService(0);
        Challenge created = shortLived.createChallenge("user1", "device-1", "client1", "session1");

        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        Challenge consumed = shortLived.consumeChallenge(created.getChallengeId());
        assertNull(consumed);
    }

    @Test
    void testChallengeExpiration() {
        ChallengeService shortLived = new ChallengeService(0);
        Challenge created = shortLived.createChallenge("user1", "device-1", "client1", "session1");

        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        assertTrue(created.isExpired());
        assertFalse(created.isValid());
    }

    @Test
    void testChallengeIsSingleUse() {
        Challenge created = challengeService.createChallenge("user1", "device-1", "client1", "session1");
        challengeService.consumeChallenge(created.getChallengeId());

        assertTrue(created.isUsed());
        assertFalse(created.isValid());
    }

    @Test
    void testCleanupExpiredChallenges() {
        ChallengeService shortLived = new ChallengeService(0);
        Challenge created = shortLived.createChallenge("user1", "device-1", "client1", "session1");

        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        shortLived.cleanupExpiredChallenges();
        assertNull(shortLived.getChallenge(created.getChallengeId()));
    }

    @Test
    void testGetChallengeValue() {
        Challenge created = challengeService.createChallenge("user1", "device-1", "client1", "session1");
        String value = challengeService.getChallengeValue(created.getChallengeId());

        assertNotNull(value);
        assertEquals(created.getChallenge(), value);
    }

    @Test
    void testMultipleChallengesUnique() {
        Challenge c1 = challengeService.createChallenge("user1", "device-1", "client1", "session1");
        Challenge c2 = challengeService.createChallenge("user1", "device-1", "client1", "session1");

        assertNotEquals(c1.getChallengeId(), c2.getChallengeId());
        assertNotEquals(c1.getChallenge(), c2.getChallenge());
    }
}
