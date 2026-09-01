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

public class DeviceChallengeAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "device-challenge-auth";

    @Override
    public String getDisplayType() {
        return "Device Challenge Authentication";
    }

    @Override
    public String getReferenceCategory() {
        return "device";
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
        return "Authenticates using device challenge-response with public-key cryptography.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty expiry = new ProviderConfigProperty();
        expiry.setName(DeviceChallengeAuthenticator.CHALLENGE_EXPIRY_SECONDS);
        expiry.setLabel("Challenge Expiry Seconds");
        expiry.setHelpText("Number of seconds until a challenge expires");
        expiry.setType(ProviderConfigProperty.STRING_TYPE);
        expiry.setDefaultValue("60");

        return List.of(expiry);
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        DeviceChallengeAuthenticator authenticator = new DeviceChallengeAuthenticator();

        DeviceStorageProvider deviceStorage = session.getProvider(DeviceStorageProvider.class);
        authenticator.setDeviceStorage(deviceStorage);

        authenticator.setChallengeService(new ChallengeService(60));
        authenticator.setSignatureService(new SignatureService());
        authenticator.setCanonicalPayloadService(new CanonicalPayloadService());

        return authenticator;
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
