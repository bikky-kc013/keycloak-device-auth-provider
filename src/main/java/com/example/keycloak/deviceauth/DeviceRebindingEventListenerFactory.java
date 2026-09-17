package com.example.keycloak.deviceauth;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Registers as a realm event listener under provider id "sewa-device-rebinding" -
 * enable it via the Admin Console (Realm settings > Events > Event listeners) or the
 * realm's eventsListeners list. Forwards device re-binding events (see
 * DeviceRebindingEventListener) to the URL configured via the "webhookUrl" SPI config
 * property:
 *
 *   keycloak.conf:  spi-events-listener-sewa-device-rebinding-webhook-url=https://...
 *   env var:        KC_SPI_EVENTS_LISTENER_SEWA_DEVICE_REBINDING_WEBHOOK_URL=https://...
 *
 * Falls back to a logging-only sender when unset, so this is safe to enable before the
 * backend's receiving endpoint exists.
 */
public class DeviceRebindingEventListenerFactory implements EventListenerProviderFactory {

    private static final Logger logger = Logger.getLogger(DeviceRebindingEventListenerFactory.class);

    public static final String PROVIDER_ID = "sewa-device-rebinding";

    private RebindingWebhookSender sender = new LoggingRebindingWebhookSender();

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new DeviceRebindingEventListener(sender);
    }

    @Override
    public void init(Config.Scope config) {
        String webhookUrl = config.get("webhookUrl");
        if (webhookUrl != null && !webhookUrl.isBlank()) {
            sender = new HttpRebindingWebhookSender(webhookUrl);
            logger.infov("Device re-binding webhook configured: {0}", webhookUrl);
        } else {
            logger.warnv(
                    "No device re-binding webhook URL configured (spi-events-listener-{0}-webhook-url) "
                            + "- re-binding events will only be logged, not forwarded",
                    PROVIDER_ID);
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
