package com.example.keycloak.deviceauth;

import org.keycloak.provider.Provider;

import java.util.List;

public interface DeviceStorageProvider extends Provider {

    Device createDevice(Device device);

    Device getDeviceById(String deviceId);

    List<Device> getDevicesByUserId(String userId);

    Device getDeviceByUserIdAndDeviceId(String userId, String deviceId);

    boolean updateDevice(Device device);

    boolean deleteDevice(String deviceId);

    boolean hasActiveDevice(String userId);

    boolean hasDeviceWithId(String deviceId);
}
