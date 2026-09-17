package com.example.keycloak.deviceauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * POSTs the device re-binding event to the Sewa backend as JSON, so it can push-notify
 * the previous device (it already owns the FCM token registry - see
 * citizen/v1/devices/tokens in the container app) and, once a gateway exists, SMS the
 * registered number (doc section 4.3). SMS delivery itself is out of scope here - this
 * only forwards the event; the backend decides what to do with it.
 *
 * Delivery failures are logged and swallowed, never thrown - by the time this fires, the
 * device re-bind and session revocation it's reporting on have already completed, so a
 * failed webhook call must not affect the auth flow.
 */
public class HttpRebindingWebhookSender implements RebindingWebhookSender {

    private static final Logger logger = Logger.getLogger(HttpRebindingWebhookSender.class);

    private final String webhookUrl;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private final ObjectMapper mapper = new ObjectMapper();

    public HttpRebindingWebhookSender(String webhookUrl) {
        this.webhookUrl = webhookUrl;
    }

    @Override
    public void send(Event event) {
        try {
            String body = toJson(event);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(webhookUrl))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 300) {
                logger.warnv("Rebinding webhook call to {0} returned status {1}",
                        webhookUrl, response.statusCode());
            }
        } catch (Exception e) {
            logger.error("Rebinding webhook call failed: " + webhookUrl, e);
        }
    }

    private String toJson(Event event) throws com.fasterxml.jackson.core.JsonProcessingException {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("userId", event.getUserId());
        payload.put("time", event.getTime());
        payload.put("details", event.getDetails());
        return mapper.writeValueAsString(payload);
    }
}
