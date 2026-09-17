package com.example.keycloak.deviceauth;

import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;

/**
 * Reacts to the device re-binding event KeycloakEventDeviceRebindingNotifier records
 * (EventType.CUSTOM_REQUIRED_ACTION, detail sewa_event=device_rebinding) and forwards it
 * via the configured RebindingWebhookSender - doc section 4.3's "every re-binding is
 * notified to the registered mobile number and, where reachable, to the previous
 * device". Ignores every other event type/detail shape, including this provider's own
 * REGISTER/LOGIN events and Keycloak's built-in ones.
 */
public class DeviceRebindingEventListener implements EventListenerProvider {

    private static final Logger logger = Logger.getLogger(DeviceRebindingEventListener.class);

    static final String SEWA_EVENT_DETAIL = "sewa_event";
    static final String DEVICE_REBINDING_EVENT = "device_rebinding";

    private final RebindingWebhookSender sender;

    DeviceRebindingEventListener(RebindingWebhookSender sender) {
        this.sender = sender;
    }

    @Override
    public void onEvent(Event event) {
        if (event.getType() != EventType.CUSTOM_REQUIRED_ACTION) return;
        if (event.getDetails() == null) return;
        if (!DEVICE_REBINDING_EVENT.equals(event.getDetails().get(SEWA_EVENT_DETAIL))) return;

        try {
            sender.send(event);
        } catch (Exception e) {
            logger.error("Failed to forward device re-binding event", e);
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        // Not interested in admin events.
    }

    @Override
    public void close() {
    }
}
