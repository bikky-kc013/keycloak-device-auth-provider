package com.example.keycloak.deviceauth;

import org.keycloak.events.Event;

/**
 * Swappable delivery for forwarding a device re-binding event to the Sewa backend.
 * Mirrors the pattern already used for OTP delivery (DevelopmentOtpAuthenticator) - a
 * logging stub until a real destination exists, a real implementation once it does.
 */
public interface RebindingWebhookSender {
    void send(Event event);
}
