package com.example.keycloak.deviceauth;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class DeviceRegistrationRequiredActionFactory implements RequiredActionFactory {

    public static final String PROVIDER_ID = "device-registration";

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        DeviceRegistrationRequiredAction action = new DeviceRegistrationRequiredAction();
        DeviceStorageProvider deviceStorage = session.getProvider(DeviceStorageProvider.class);
        action.setDeviceStorage(deviceStorage);
        return action;
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

    @Override
    public String getDisplayText() {
        return "Device Registration";
    }
}
