package com.example.keycloak.deviceauth;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class DeviceAuthResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "device-auth";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        DeviceStorageProvider deviceStorage = session.getProvider(DeviceStorageProvider.class);
        return new DeviceAuthResourceProvider(session, deviceStorage);
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
