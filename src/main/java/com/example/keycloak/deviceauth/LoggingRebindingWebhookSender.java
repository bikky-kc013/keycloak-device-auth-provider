package com.example.keycloak.deviceauth;

import org.jboss.logging.Logger;
import org.keycloak.events.Event;

/**
 * Default RebindingWebhookSender when no webhook URL is configured - logs instead of
 * calling out. Lets DeviceRebindingEventListenerFactory be enabled safely before the
 * Sewa backend's receiving endpoint exists.
 */
public class LoggingRebindingWebhookSender implements RebindingWebhookSender {

    private static final Logger logger = Logger.getLogger(LoggingRebindingWebhookSender.class);

    @Override
    public void send(Event event) {
        logger.infov(
                "[dev] No webhook URL configured - would forward device re-binding event: "
                        + "userId={0}, details={1}",
                event.getUserId(), event.getDetails());
    }
}
