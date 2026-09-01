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

public class PhoneNumberAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "phone-number-auth";

    @Override
    public String getDisplayType() {
        return "Phone Number Identification";
    }

    @Override
    public String getReferenceCategory() {
        return "phone";
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
        return "Identifies a user by their phone number. The phone number is used as an identifier until OTP/device authentication succeeds.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty autoCreate = new ProviderConfigProperty();
        autoCreate.setName(PhoneNumberAuthenticator.AUTO_CREATE_USERS);
        autoCreate.setLabel("Auto Create Users");
        autoCreate.setHelpText("Automatically create a user if the phone number is not found");
        autoCreate.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        autoCreate.setDefaultValue("false");

        ProviderConfigProperty phoneAttr = new ProviderConfigProperty();
        phoneAttr.setName(PhoneNumberAuthenticator.PHONE_ATTRIBUTE);
        phoneAttr.setLabel("Phone Attribute");
        phoneAttr.setHelpText("The user attribute name that stores the phone number");
        phoneAttr.setType(ProviderConfigProperty.STRING_TYPE);
        phoneAttr.setDefaultValue("phoneNumber");

        return List.of(autoCreate, phoneAttr);
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new PhoneNumberAuthenticator();
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
