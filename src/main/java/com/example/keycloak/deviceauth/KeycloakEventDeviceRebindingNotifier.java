package com.example.keycloak.deviceauth;

import org.jboss.logging.Logger;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Records a re-binding event (doc section 4.3) into Keycloak's own event store, in
 * addition to logging, so it's queryable/auditable (Admin Console > Events, or the
 * Admin REST API) rather than only visible in application logs.
 *
 * This is NOT the SMS/push notification to the citizen's registered number and previous
 * device that the doc asks for - no delivery gateway exists yet (same gap as OTP
 * delivery, see DevelopmentOtpAuthenticator). It's the nearest real, zero-new-dependency
 * substitute available today, and gives a concrete hook - an EventListenerProvider
 * reacting to EventType.CUSTOM_REQUIRED_ACTION with detail sewa_event=device_rebinding -
 * to wire a real notification off of once a gateway exists. Replace/supplement once one
 * is available.
 */
public class KeycloakEventDeviceRebindingNotifier implements DeviceRebindingNotifier {

    private static final Logger logger = Logger.getLogger(KeycloakEventDeviceRebindingNotifier.class);

    private final KeycloakSession session;

    public KeycloakEventDeviceRebindingNotifier(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void notifyRebinding(String userId, Device previousDevice, Device newDevice) {
        logger.warnv(
                "Re-binding event for userId={0}: previousDeviceId={1} (platform={2}) revoked, " +
                        "newDeviceId={3} (platform={4}) now active.",
                userId, previousDevice.getDeviceId(), previousDevice.getPlatform(),
                newDevice.getDeviceId(), newDevice.getPlatform());

        try {
            RealmModel realm = session.getContext().getRealm();
            new EventBuilder(realm, session, session.getContext().getConnection())
                    .event(EventType.CUSTOM_REQUIRED_ACTION)
                    .user(userId)
                    .detail("sewa_event", "device_rebinding")
                    .detail("previous_device_id", previousDevice.getDeviceId())
                    .detail("previous_device_platform", previousDevice.getPlatform())
                    .detail("new_device_id", newDevice.getDeviceId())
                    .detail("new_device_platform", newDevice.getPlatform())
                    .success();
        } catch (Exception e) {
            // Never let event-store trouble block the re-bind itself - the device swap
            // (and the session revocation next to it) has already happened by the time
            // this notifier runs.
            logger.error("Failed to record device re-binding event", e);
        }
    }
}
