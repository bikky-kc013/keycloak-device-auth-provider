package com.example.keycloak.deviceauth;

/**
 * Notifies relevant parties when a device replaces a previously active device for
 * an account (a re-binding event, doc section 4.3): "Every re-binding is notified
 * to the registered mobile number and, where reachable, to the previous device,
 * with a path to report an unrecognised attempt."
 *
 * No concrete delivery (SMS/push) is implemented yet - {@link LoggingDeviceRebindingNotifier}
 * is a stub that only logs, matching the pattern already used for OTP delivery
 * (real gateway integration pending). Swap in a real implementation once a
 * notification channel is available.
 */
public interface DeviceRebindingNotifier {

    void notifyRebinding(String userId, Device previousDevice, Device newDevice);
}
