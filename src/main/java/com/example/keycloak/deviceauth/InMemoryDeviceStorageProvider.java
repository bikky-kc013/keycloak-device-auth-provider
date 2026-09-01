package com.example.keycloak.deviceauth;

import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryDeviceStorageProvider implements DeviceStorageProvider {

    private static final Logger logger = Logger.getLogger(InMemoryDeviceStorageProvider.class);

    // Instance fields are fine here ONLY because InMemoryDeviceStorageProviderFactory hands out
    // a single shared instance (see its Javadoc) rather than a fresh one per
    // session.getProvider(DeviceStorageProvider.class) call - a fresh instance per request
    // would silently lose every device between requests (a device "successfully" registered
    // in one HTTP request would be invisible to the very next). Tests construct this class
    // directly and rely on getting an isolated, empty store per instance.
    private final Map<String, Device> devicesById = new ConcurrentHashMap<>();
    private final Map<String, List<String>> devicesByUserId = new ConcurrentHashMap<>();

    @Override
    public Device createDevice(Device device) {
        if (devicesById.containsKey(device.getDeviceId())) {
            throw new IllegalArgumentException("Device with id " + device.getDeviceId() + " already exists");
        }

        devicesById.put(device.getDeviceId(), device);
        devicesByUserId.computeIfAbsent(device.getUserId(), k -> new ArrayList<>()).add(device.getDeviceId());

        logger.infov("Device created: userId={0}, deviceId={1}, platform={2}",
                device.getUserId(), device.getDeviceId(), device.getPlatform());

        return device;
    }

    @Override
    public Device getDeviceById(String deviceId) {
        return devicesById.get(deviceId);
    }

    @Override
    public List<Device> getDevicesByUserId(String userId) {
        List<String> deviceIds = devicesByUserId.getOrDefault(userId, List.of());
        List<Device> result = new ArrayList<>();
        for (String deviceId : deviceIds) {
            Device device = devicesById.get(deviceId);
            if (device != null) {
                result.add(device);
            }
        }
        return result;
    }

    @Override
    public Device getDeviceByUserIdAndDeviceId(String userId, String deviceId) {
        Device device = devicesById.get(deviceId);
        if (device != null && device.getUserId().equals(userId)) {
            return device;
        }
        return null;
    }

    @Override
    public boolean updateDevice(Device device) {
        if (!devicesById.containsKey(device.getDeviceId())) {
            return false;
        }
        devicesById.put(device.getDeviceId(), device);
        return true;
    }

    @Override
    public boolean deleteDevice(String deviceId) {
        Device removed = devicesById.remove(deviceId);
        if (removed != null) {
            List<String> userDevices = devicesByUserId.get(removed.getUserId());
            if (userDevices != null) {
                userDevices.remove(deviceId);
            }
            logger.infov("Device deleted: deviceId={0}", deviceId);
            return true;
        }
        return false;
    }

    @Override
    public boolean hasActiveDevice(String userId) {
        List<String> deviceIds = devicesByUserId.getOrDefault(userId, List.of());
        for (String deviceId : deviceIds) {
            Device device = devicesById.get(deviceId);
            if (device != null && device.isActive()) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean hasDeviceWithId(String deviceId) {
        return devicesById.containsKey(deviceId);
    }

    @Override
    public void close() {
        logger.debug("Closing InMemoryDeviceStorageProvider");
    }
}
