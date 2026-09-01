package com.example.keycloak.deviceauth;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class InMemoryDeviceStorageProviderFactory implements DeviceStorageProviderFactory {

    private static final Logger logger = Logger.getLogger(InMemoryDeviceStorageProviderFactory.class);

    public static final String PROVIDER_ID = "in-memory";

    // A fresh KeycloakSession (and hence a fresh call to create()) happens on every single
    // request. Handing back a new InMemoryDeviceStorageProvider each time would mean every
    // request sees an empty device store - a device registered in one request would be
    // invisible in the next. All callers must see the same store, so this factory hands out
    // one shared instance for the JVM's lifetime instead (InMemoryDeviceStorageProvider.close()
    // is a no-op, so this is safe - nothing tears the shared state down between requests).
    // Single-node only, per the README's "Known Limitations" - a real deployment needs a
    // JPA/Redis-backed DeviceStorageProvider.
    private static final DeviceStorageProvider SHARED_INSTANCE = new InMemoryDeviceStorageProvider();

    @Override
    public DeviceStorageProvider create(KeycloakSession session) {
        return SHARED_INSTANCE;
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
