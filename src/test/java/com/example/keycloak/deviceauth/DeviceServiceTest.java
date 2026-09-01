package com.example.keycloak.deviceauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exercises DeviceService.bindDevice directly (session-free) to prove the
 * single-active-device-per-account policy (doc section 4.3) without needing
 * to mock KeycloakSession.
 */
class DeviceServiceTest {

    private InMemoryDeviceStorageProvider storage;
    private RecordingNotifier notifier;
    private DeviceService deviceService;

    @BeforeEach
    void setUp() {
        storage = new InMemoryDeviceStorageProvider();
        notifier = new RecordingNotifier();
        deviceService = new DeviceService(storage, null, notifier);
    }

    @Test
    void testFirstDeviceRegistrationDoesNotNotify() {
        Device device = deviceService.bindDevice("user1", "device-1", "Phone", "android",
                testJwk(), "ES256", "key-1", AttestationLevel.HARDWARE, "stmt-1");

        assertEquals(Device.Status.ACTIVE, device.getStatus());
        assertTrue(notifier.calls.isEmpty());
    }

    @Test
    void testRegisteringSecondDeviceRevokesFirst() {
        Device first = deviceService.bindDevice("user1", "device-1", "Phone A", "android",
                testJwk(), "ES256", "key-1", AttestationLevel.HARDWARE, null);

        Device second = deviceService.bindDevice("user1", "device-2", "Phone B", "ios",
                testJwk(), "ES256", "key-2", AttestationLevel.SOFTWARE, null);

        Device firstReloaded = storage.getDeviceById("device-1");
        assertEquals(Device.Status.REVOKED, firstReloaded.getStatus());
        assertNotNull(firstReloaded.getRevokedAt());

        assertEquals(Device.Status.ACTIVE, second.getStatus());

        List<Device> active = storage.getDevicesByUserId("user1").stream().filter(Device::isActive).toList();
        assertEquals(1, active.size());
        assertEquals("device-2", active.get(0).getDeviceId());
    }

    @Test
    void testRegisteringSecondDeviceFiresRebindingNotification() {
        deviceService.bindDevice("user1", "device-1", "Phone A", "android",
                testJwk(), "ES256", "key-1", AttestationLevel.HARDWARE, null);
        deviceService.bindDevice("user1", "device-2", "Phone B", "ios",
                testJwk(), "ES256", "key-2", AttestationLevel.SOFTWARE, null);

        assertEquals(1, notifier.calls.size());
        assertEquals("user1", notifier.calls.get(0).userId());
        assertEquals("device-1", notifier.calls.get(0).previous().getDeviceId());
        assertEquals("device-2", notifier.calls.get(0).replacement().getDeviceId());
    }

    @Test
    void testOtherUsersDeviceUnaffected() {
        deviceService.bindDevice("user1", "device-1", "Phone", "android",
                testJwk(), "ES256", "key-1", AttestationLevel.HARDWARE, null);
        deviceService.bindDevice("user2", "device-2", "Phone", "android",
                testJwk(), "ES256", "key-2", AttestationLevel.HARDWARE, null);

        assertTrue(storage.getDeviceById("device-1").isActive());
        assertTrue(storage.getDeviceById("device-2").isActive());
        assertTrue(notifier.calls.isEmpty());
    }

    @Test
    void testAttestationRoundTripsThroughRegistration() {
        Device device = deviceService.bindDevice("user1", "device-1", "Phone", "android",
                testJwk(), "ES256", "key-1", AttestationLevel.HARDWARE, "base64-attestation-blob");

        Device reloaded = storage.getDeviceById("device-1");
        assertEquals(AttestationLevel.HARDWARE, reloaded.getAttestationLevel());
        assertEquals("base64-attestation-blob", reloaded.getAttestationStatement());
    }

    @Test
    void testMissingAttestationDefaultsToUnknownAndDoesNotBlock() {
        Device device = deviceService.bindDevice("user1", "device-1", "Phone", "android",
                testJwk(), "ES256", "key-1", null, null);

        assertEquals(Device.Status.ACTIVE, device.getStatus());
        assertEquals(AttestationLevel.UNKNOWN, device.getAttestationLevel());
    }

    private String testJwk() {
        return "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"test\",\"y\":\"test\",\"kid\":\"key-1\"}";
    }

    private static final class RecordingNotifier implements DeviceRebindingNotifier {
        final List<Call> calls = new ArrayList<>();

        @Override
        public void notifyRebinding(String userId, Device previousDevice, Device newDevice) {
            calls.add(new Call(userId, previousDevice, newDevice));
        }

        record Call(String userId, Device previous, Device replacement) {
        }
    }
}
