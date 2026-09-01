package com.example.keycloak.deviceauth;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

public class DeviceStorageSpi implements Spi {

    public static final String SPI_ID = "device-storage";

    @Override
    public String getName() {
        return SPI_ID;
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return DeviceStorageProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return DeviceStorageProviderFactory.class;
    }

    @Override
    public boolean isInternal() {
        return false;
    }
}
