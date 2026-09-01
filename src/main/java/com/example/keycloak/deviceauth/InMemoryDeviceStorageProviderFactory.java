package com.example.keycloak.deviceauth;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class InMemoryDeviceStorageProviderFactory implements DeviceStorageProviderFactory {

    private static final Logger logger = Logger.getLogger(InMemoryDeviceStorageProviderFactory.class);

    public static final String PROVIDER_ID = "in-memory";

    @Override
    public DeviceStorageProvider create(KeycloakSession session) {
        logger.debug("Creating InMemoryDeviceStorageProvider");
        return new InMemoryDeviceStorageProvider();
    }

    @Override
    public void init(Config.Scope config) {
        logger.debug("Initializing InMemoryDeviceStorageProviderFactory");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
        logger.debug("Closing InMemoryDeviceStorageProviderFactory");
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
