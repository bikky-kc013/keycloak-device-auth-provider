package com.example.keycloak.deviceauth;

import org.jboss.logging.Logger;

/**
 * Stub {@link DeviceRebindingNotifier} - logs the event instead of sending SMS/push.
 * Replace with a real implementation once a notification channel is available.
 */
public class LoggingDeviceRebindingNotifier implements DeviceRebindingNotifier {

    private static final Logger logger = Logger.getLogger(LoggingDeviceRebindingNotifier.class);

    @Override
    public void notifyRebinding(String userId, Device previousDevice, Device newDevice) {
        logger.warnv(
                "Re-binding event for userId={0}: previousDeviceId={1} (platform={2}) revoked, " +
                        "newDeviceId={3} (platform={4}) now active. " +
                        "NOTE: no real notification delivered (stub notifier) - registered mobile number and " +
                        "previous device must be notified per policy once a real channel is wired in.",
                userId, previousDevice.getDeviceId(), previousDevice.getPlatform(),
                newDevice.getDeviceId(), newDevice.getPlatform());
    }
}
