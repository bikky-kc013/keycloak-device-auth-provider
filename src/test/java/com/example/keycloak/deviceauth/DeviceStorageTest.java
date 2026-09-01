package com.example.keycloak.deviceauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DeviceStorageTest {

    private InMemoryDeviceStorageProvider storage;

    @BeforeEach
    void setUp() {
        storage = new InMemoryDeviceStorageProvider();
    }

    @Test
    void testCreateAndRetrieveDevice() {
        Device device = createTestDevice("user1", "device-1");
        storage.createDevice(device);

        Device retrieved = storage.getDeviceById("device-1");
        assertNotNull(retrieved);
        assertEquals("user1", retrieved.getUserId());
        assertEquals("device-1", retrieved.getDeviceId());
        assertEquals(Device.Status.ACTIVE, retrieved.getStatus());
    }

    @Test
    void testCreateDuplicateDeviceThrows() {
        Device device = createTestDevice("user1", "device-1");
        storage.createDevice(device);

        assertThrows(IllegalArgumentException.class, () -> {
            storage.createDevice(createTestDevice("user1", "device-1"));
        });
    }

    @Test
    void testGetDevicesByUserId() {
        storage.createDevice(createTestDevice("user1", "device-1"));
        storage.createDevice(createTestDevice("user1", "device-2"));
        storage.createDevice(createTestDevice("user2", "device-3"));

        var devices = storage.getDevicesByUserId("user1");
        assertEquals(2, devices.size());
    }

    @Test
    void testGetDeviceByUserIdAndDeviceId() {
        storage.createDevice(createTestDevice("user1", "device-1"));
        storage.createDevice(createTestDevice("user2", "device-2"));

        Device found = storage.getDeviceByUserIdAndDeviceId("user1", "device-1");
        assertNotNull(found);

        Device notFound = storage.getDeviceByUserIdAndDeviceId("user2", "device-1");
        assertNull(notFound);
    }

    @Test
    void testUpdateDevice() {
        Device device = createTestDevice("user1", "device-1");
        storage.createDevice(device);

        device.setDeviceName("Updated Name");
        assertTrue(storage.updateDevice(device));

        Device updated = storage.getDeviceById("device-1");
        assertEquals("Updated Name", updated.getDeviceName());
    }

    @Test
    void testDeleteDevice() {
        Device device = createTestDevice("user1", "device-1");
        storage.createDevice(device);

        assertTrue(storage.deleteDevice("device-1"));
        assertNull(storage.getDeviceById("device-1"));
        assertFalse(storage.hasDeviceWithId("device-1"));
    }

    @Test
    void testDeleteNonexistentDevice() {
        assertFalse(storage.deleteDevice("nonexistent"));
    }

    @Test
    void testHasActiveDevice() {
        assertFalse(storage.hasActiveDevice("user1"));

        Device device = createTestDevice("user1", "device-1");
        storage.createDevice(device);
        assertTrue(storage.hasActiveDevice("user1"));

        device.setStatus(Device.Status.REVOKED);
        storage.updateDevice(device);
        assertFalse(storage.hasActiveDevice("user1"));
    }

    @Test
    void testMultipleDevicesPerUser() {
        storage.createDevice(createTestDevice("user1", "device-1"));
        storage.createDevice(createTestDevice("user1", "device-2"));
        storage.createDevice(createTestDevice("user1", "device-3"));

        assertEquals(3, storage.getDevicesByUserId("user1").size());
        assertTrue(storage.hasDeviceWithId("device-1"));
        assertTrue(storage.hasDeviceWithId("device-2"));
        assertTrue(storage.hasDeviceWithId("device-3"));
    }

    private Device createTestDevice(String userId, String deviceId) {
        Device device = new Device();
        device.setId(java.util.UUID.randomUUID().toString());
        device.setUserId(userId);
        device.setDeviceId(deviceId);
        device.setDeviceName("Test Device");
        device.setPlatform("android");
        device.setPublicKeyJwk("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"test\",\"y\":\"test\",\"kid\":\"key-1\"}");
        device.setAlgorithm("ES256");
        device.setStatus(Device.Status.ACTIVE);
        device.setKeyId("key-1");
        device.setCreatedAt(java.time.Instant.now());
        return device;
    }
}
