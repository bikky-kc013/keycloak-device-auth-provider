package com.example.keycloak.deviceauth;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class DevelopmentOtpAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(DevelopmentOtpAuthenticator.class);

    public static final String DEV_OTP_ENABLED = "devOtpEnabled";
    public static final String DEV_OTP_VALUE = "devOtpValue";
    public static final String OTP_LENGTH = "otpLength";
    /** Soft per-flow-attempt block threshold - see class doc. */
    public static final String OTP_MAX_ATTEMPTS = "otpMaxAttempts";

    // Auth-session notes (per browser flow attempt, cleared with the session)
    // holding the code actually in effect right now - starts as devOtpValue,
    // replaced with a fresh random one on every resend, so a resend genuinely
    // invalidates the old code (lets the invalid/expired-OTP path be exercised)
    // instead of just being a cosmetic timer.
    private static final String AUTH_NOTE_OTP_VALUE = "sewaDevOtpValue";
    private static final String AUTH_NOTE_RESEND_COUNT = "sewaDevOtpResendCount";

    private static final SecureRandom RANDOM = new SecureRandom();

    // Soft, per-flow-attempt block ("block the registration flow after 3 failed OTP
    // attempts and display guidance to retry"). Resets whenever a flow ends (success,
    // this block, or the user abandoning it), which is exactly why it CANNOT be what
    // enforces the 5th-consecutive-failure account lock below - that has to survive
    // across separate flow restarts, which only Keycloak's own persistent
    // BruteForceProtector (see getProtector() below, realm-configured in
    // realm-setup.sh) can do. The two are deliberately separate mechanisms.
    private static final Map<String, AtomicInteger> attemptCounters = new ConcurrentHashMap<>();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (isLockedOut(context, user)) {
            context.failureChallenge(AuthenticationFlowError.USER_TEMPORARILY_DISABLED, lockedForm(context));
            return;
        }

        Map<String, String> config = getConfig(context);
        boolean devOtpEnabled = Boolean.parseBoolean(config.getOrDefault(DEV_OTP_ENABLED, "true"));
        String devOtpValue = config.getOrDefault(DEV_OTP_VALUE, "123456");

        var authSession = context.getAuthenticationSession();
        if (authSession.getAuthNote(AUTH_NOTE_OTP_VALUE) == null) {
            authSession.setAuthNote(AUTH_NOTE_OTP_VALUE, devOtpValue);
        }

        var form = context.form();
        if (devOtpEnabled) {
            form.setAttribute("devOtpHint", authSession.getAuthNote(AUTH_NOTE_OTP_VALUE));
        }
        form.setAttribute("resendCount", parseIntOrZero(authSession.getAuthNote(AUTH_NOTE_RESEND_COUNT)));
        setPhoneNumberAttribute(context, form);
        context.challenge(form.createForm("otp-form.ftl"));
    }

    private boolean isLockedOut(AuthenticationFlowContext context, UserModel user) {
        return user != null
                && context.getProtector().isTemporarilyDisabled(context.getSession(), context.getRealm(), user);
    }

    private Response lockedForm(AuthenticationFlowContext context) {
        return context.form().setError("account_locked").createForm("otp-form.ftl");
    }

    // Lets otp-form.ftl show "we sent a code to <number>", matching the SuperApp OTP
    // screen. PhoneNumberAuthenticator runs first in this flow and either binds an
    // existing user (found by the phoneAttribute) or auto-creates one with the
    // normalized number as its username - falling back to username covers both.
    private void setPhoneNumberAttribute(AuthenticationFlowContext context, LoginFormsProvider form) {
        UserModel user = context.getUser();
        if (user == null) {
            return;
        }
        String phone = user.getFirstAttribute("phoneNumber");
        if (phone == null || phone.isBlank()) {
            phone = user.getUsername();
        }
        if (phone != null && !phone.isBlank()) {
            form.setAttribute("phoneNumber", phone);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (isLockedOut(context, user)) {
            context.failureChallenge(AuthenticationFlowError.USER_TEMPORARILY_DISABLED, lockedForm(context));
            return;
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();

        // Resend is its own submission of the same form (see device-auth.js), not
        // an OTP guess - handle and return before touching attempt/lockout state.
        if ("true".equals(formData.getFirst("resendOtp"))) {
            handleResend(context);
            return;
        }

        String submittedOtp = formData.getFirst("otp");

        Map<String, String> config = getConfig(context);
        boolean devOtpEnabled = Boolean.parseBoolean(config.getOrDefault(DEV_OTP_ENABLED, "true"));
        int otpLength = Integer.parseInt(config.getOrDefault(OTP_LENGTH, "6"));
        int softBlockAttempts = Integer.parseInt(config.getOrDefault(OTP_MAX_ATTEMPTS, "3"));
        String expectedOtp = currentExpectedOtp(context, config);

        // A blank/missing submission (e.g. the JS-driven boxes never combined into
        // the hidden field) is not a wrong guess - let the user just retry instead
        // of terminating the flow and without counting it as a failed attempt.
        if (submittedOtp == null || submittedOtp.isBlank()) {
            context.challenge(challengeForm(context, "otp_required"));
            return;
        }

        String userId = user != null ? user.getId() : "unknown";
        AtomicInteger attempts = attemptCounters.computeIfAbsent(userId, k -> new AtomicInteger(0));

        if (attempts.get() >= softBlockAttempts) {
            logger.warnv("OTP soft-block reached ({0} attempts) for this flow attempt", softBlockAttempts);
            attemptCounters.remove(userId);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeForm(context, "otp_blocked"));
            return;
        }

        if (!devOtpEnabled) {
            logger.warn("Development OTP is disabled");
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            return;
        }

        boolean matches = submittedOtp.length() == otpLength && submittedOtp.equals(expectedOtp);

        if (!matches) {
            attempts.incrementAndGet();
            // Feeds Keycloak's own persistent brute-force counter (realm-configured
            // failureFactor/waitIncrement - see realm-setup.sh) - this is what
            // survives across separate flow restarts to enforce the 5th-consecutive-
            // failure lock, independent of the soft-block counter above.
            if (user != null) {
                context.getProtector().failedLogin(
                        context.getRealm(), user, context.getConnection(), context.getUriInfo(), Collections.emptySet());
            }
            logger.warnv("OTP verification failed");
            context.challenge(challengeForm(context, "otp_invalid"));
            return;
        }

        logger.infov("OTP verification successful");
        attemptCounters.remove(userId);
        context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_OTP_VALUE);
        context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_RESEND_COUNT);
        if (user != null) {
            context.getProtector().successfulLogin(
                    context.getRealm(), user, context.getConnection(), context.getUriInfo(), Collections.emptySet());
        }
        context.success();
    }

    // Dev-mode only: generates a genuinely different random code and swaps it in as
    // the one now expected, so re-submitting a previously-shown code correctly
    // fails as "invalid" - this is what makes resend exercise the invalid/expired
    // path, unlike the old fixed-devOtpValue comparison. No real delivery (no SMS
    // gateway exists yet, same gap as elsewhere) - the new code is only shown via
    // devOtpHint, same as the initial one.
    private void handleResend(AuthenticationFlowContext context) {
        Map<String, String> config = getConfig(context);
        boolean devOtpEnabled = Boolean.parseBoolean(config.getOrDefault(DEV_OTP_ENABLED, "true"));
        int otpLength = Integer.parseInt(config.getOrDefault(OTP_LENGTH, "6"));

        var authSession = context.getAuthenticationSession();
        String newOtp = generateRandomOtp(otpLength);
        authSession.setAuthNote(AUTH_NOTE_OTP_VALUE, newOtp);
        int resendCount = parseIntOrZero(authSession.getAuthNote(AUTH_NOTE_RESEND_COUNT)) + 1;
        authSession.setAuthNote(AUTH_NOTE_RESEND_COUNT, String.valueOf(resendCount));

        logger.infov("OTP resent (dev mode, not actually delivered) - resendCount={0}", resendCount);

        var form = context.form();
        if (devOtpEnabled) {
            form.setAttribute("devOtpHint", newOtp);
        }
        form.setAttribute("resendCount", resendCount);
        setPhoneNumberAttribute(context, form);
        context.challenge(form.createForm("otp-form.ftl"));
    }

    private String currentExpectedOtp(AuthenticationFlowContext context, Map<String, String> config) {
        String stored = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_OTP_VALUE);
        return stored != null ? stored : config.getOrDefault(DEV_OTP_VALUE, "123456");
    }

    private static String generateRandomOtp(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(RANDOM.nextInt(10));
        }
        return sb.toString();
    }

    private static int parseIntOrZero(String value) {
        if (value == null) {
            return 0;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private Response challengeForm(AuthenticationFlowContext context, String errorKey) {
        Map<String, String> config = getConfig(context);
        boolean devOtpEnabled = Boolean.parseBoolean(config.getOrDefault(DEV_OTP_ENABLED, "true"));
        var form = context.form();
        if (devOtpEnabled) {
            form.setAttribute("devOtpHint", currentExpectedOtp(context, config));
        }
        form.setAttribute("resendCount", parseIntOrZero(context.getAuthenticationSession().getAuthNote(AUTH_NOTE_RESEND_COUNT)));
        setPhoneNumberAttribute(context, form);
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
