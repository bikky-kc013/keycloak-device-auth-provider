package com.example.keycloak.deviceauth;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class DevelopmentOtpAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "dev-otp-auth";

    @Override
    public String getDisplayType() {
        return "Development OTP Authentication";
    }

    @Override
    public String getReferenceCategory() {
        return "otp";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Development OTP authenticator for testing. WARNING: Do not use in production.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty devEnabled = new ProviderConfigProperty();
        devEnabled.setName(DevelopmentOtpAuthenticator.DEV_OTP_ENABLED);
        devEnabled.setLabel("Enable Development OTP");
        devEnabled.setHelpText("Enable development OTP for testing (MUST NOT be enabled in production)");
        devEnabled.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        devEnabled.setDefaultValue("true");

        ProviderConfigProperty devValue = new ProviderConfigProperty();
        devValue.setName(DevelopmentOtpAuthenticator.DEV_OTP_VALUE);
        devValue.setLabel("Development OTP Value");
        devValue.setHelpText("The fixed OTP value for development testing");
        devValue.setType(ProviderConfigProperty.STRING_TYPE);
        devValue.setDefaultValue("123456");

        ProviderConfigProperty otpLength = new ProviderConfigProperty();
        otpLength.setName(DevelopmentOtpAuthenticator.OTP_LENGTH);
        otpLength.setLabel("OTP Length");
        otpLength.setHelpText("Expected length of the OTP code");
        otpLength.setType(ProviderConfigProperty.STRING_TYPE);
        otpLength.setDefaultValue("6");

        ProviderConfigProperty maxAttempts = new ProviderConfigProperty();
        maxAttempts.setName(DevelopmentOtpAuthenticator.OTP_MAX_ATTEMPTS);
        maxAttempts.setLabel("Soft-block attempts (this flow only)");
        maxAttempts.setHelpText("Failed attempts within a single flow before blocking it with retry "
                + "guidance. The 5th CONSECUTIVE failure across separate flow attempts triggers a "
                + "temporary account lock instead, via the realm's Brute Force Detection setting - "
                + "not this value.");
        maxAttempts.setType(ProviderConfigProperty.STRING_TYPE);
        maxAttempts.setDefaultValue("3");

        return List.of(devEnabled, devValue, otpLength, maxAttempts);
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new DevelopmentOtpAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {
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
