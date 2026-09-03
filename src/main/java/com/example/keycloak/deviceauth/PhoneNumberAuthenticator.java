package com.example.keycloak.deviceauth;

import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.Map;

public class PhoneNumberAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(PhoneNumberAuthenticator.class);

    public static final String AUTO_CREATE_USERS = "autoCreateUsers";
    public static final String PHONE_ATTRIBUTE = "phoneAttribute";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.challenge(context.form().createForm("phone-number-form.ftl"));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String phoneNumber = formData.getFirst("phoneNumber");
        if (phoneNumber == null || phoneNumber.isBlank()) {
            context.challenge(context.form()
                    .setError("phone_number_required")
                    .createForm("phone-number-form.ftl"));
            return;
        }

        String normalizedPhone = normalizePhoneNumber(phoneNumber);
        String phoneAttribute = getConfigValue(context, PHONE_ATTRIBUTE, "phoneNumber");

        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();

        UserModel user = session.users().searchForUserByUserAttributeStream(realm, phoneAttribute, normalizedPhone)
                .findFirst()
                .orElse(null);

        if (user == null) {
            boolean autoCreate = Boolean.parseBoolean(getConfigValue(context, AUTO_CREATE_USERS, "false"));
            if (!autoCreate) {
                context.challenge(context.form()
                        .setAttribute("submittedPhoneDigits", localDigits(normalizedPhone))
                        .setError("user_not_found")
                        .createForm("phone-number-form.ftl"));
                return;
            }

            user = session.users().addUser(realm, normalizedPhone);
            user.setEnabled(true);
            user.setSingleAttribute(phoneAttribute, normalizedPhone);
            user.setSingleAttribute(SewaAttributes.VERIFICATION_LEVEL_ATTRIBUTE, VerificationLevel.CLAIMED.name());
            logger.infov("Auto-created user for phone number");
        }

        context.setUser(user);
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
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

    private static String localDigits(String normalizedPhone) {
        String digits = normalizedPhone == null ? "" : normalizedPhone.replaceAll("\\D", "");
        return digits.length() > 9 ? digits.substring(digits.length() - 9) : digits;
    }

    public static String normalizePhoneNumber(String phoneNumber) {
        if (phoneNumber == null) {
            return null;
        }
        String normalized = phoneNumber.replaceAll("[\\s\\-\\(\\)\\.]", "");
        if (!normalized.startsWith("+") && normalized.length() >= 10) {
            normalized = "+" + normalized;
        }
        return normalized;
    }

    private String getConfigValue(AuthenticationFlowContext context, String key, String defaultValue) {
        Map<String, String> config = context.getAuthenticatorConfig() != null
                ? context.getAuthenticatorConfig().getConfig()
                : null;
        if (config != null && config.containsKey(key)) {
            return config.get(key);
        }
        return defaultValue;
    }
}
