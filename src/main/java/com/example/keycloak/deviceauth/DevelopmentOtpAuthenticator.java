package com.example.keycloak.deviceauth;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class DevelopmentOtpAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(DevelopmentOtpAuthenticator.class);

    public static final String DEV_OTP_ENABLED = "devOtpEnabled";
    public static final String DEV_OTP_VALUE = "devOtpValue";
    public static final String OTP_LENGTH = "otpLength";
    public static final String OTP_MAX_ATTEMPTS = "otpMaxAttempts";

    private static final Map<String, AtomicInteger> attemptCounters = new ConcurrentHashMap<>();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Map<String, String> config = getConfig(context);
        boolean devOtpEnabled = Boolean.parseBoolean(config.getOrDefault(DEV_OTP_ENABLED, "true"));
        String devOtpValue = config.getOrDefault(DEV_OTP_VALUE, "123456");

        var form = context.form();
        if (devOtpEnabled) {
            form.setAttribute("devOtpHint", devOtpValue);
        }
        context.challenge(form.createForm("otp-form.ftl"));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String submittedOtp = formData.getFirst("otp");

        Map<String, String> config = getConfig(context);
        boolean devOtpEnabled = Boolean.parseBoolean(config.getOrDefault(DEV_OTP_ENABLED, "true"));
        String devOtpValue = config.getOrDefault(DEV_OTP_VALUE, "123456");
        int otpLength = Integer.parseInt(config.getOrDefault(OTP_LENGTH, "6"));
        int maxAttempts = Integer.parseInt(config.getOrDefault(OTP_MAX_ATTEMPTS, "5"));

        // A blank/missing submission (e.g. the JS-driven boxes never combined into
        // the hidden field) is not a wrong guess - let the user just retry instead
        // of terminating the flow and without counting it as a failed attempt.
        if (submittedOtp == null || submittedOtp.isBlank()) {
            context.challenge(challengeForm(context, devOtpEnabled ? devOtpValue : null, "otp_required"));
            return;
        }

        String userId = context.getUser() != null ? context.getUser().getId() : "unknown";
        AtomicInteger attempts = attemptCounters.computeIfAbsent(userId, k -> new AtomicInteger(0));

        if (attempts.get() >= maxAttempts) {
            logger.warnv("OTP max attempts reached for user");
            attemptCounters.remove(userId);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        attempts.incrementAndGet();

        if (!devOtpEnabled) {
            logger.warn("Development OTP is disabled");
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        if (submittedOtp.length() != otpLength || !submittedOtp.equals(devOtpValue)) {
            logger.warnv("OTP verification failed");
            context.challenge(challengeForm(context, devOtpValue, "otp_invalid"));
            return;
        }

        logger.infov("OTP verification successful");
        attemptCounters.remove(userId);
        context.success();
    }

    private Response challengeForm(AuthenticationFlowContext context, String devOtpValue, String errorKey) {
        var form = context.form();
        if (devOtpValue != null) {
            form.setAttribute("devOtpHint", devOtpValue);
        }
        return form.setError(errorKey).createForm("otp-form.ftl");
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

    private Map<String, String> getConfig(AuthenticationFlowContext context) {
        if (context.getAuthenticatorConfig() != null) {
            return context.getAuthenticatorConfig().getConfig();
        }
        return Map.of();
    }
}
