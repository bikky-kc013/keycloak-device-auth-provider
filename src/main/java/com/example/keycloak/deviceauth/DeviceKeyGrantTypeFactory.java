package com.example.keycloak.deviceauth;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory;

/** Registers DeviceKeyGrantType with Keycloak's token endpoint under grant_type=urn:sewa:params:oauth:grant-type:device-key. */
public class DeviceKeyGrantTypeFactory implements OAuth2GrantTypeFactory {

    /** Same expiry as DeviceAuthResourceProvider's /challenge endpoint - see CHALLENGE_EXPIRY_SECONDS there. */
    private static final long CHALLENGE_EXPIRY_SECONDS = 60;

    @Override
    public String getId() {
        return DeviceKeyGrantType.GRANT_TYPE;
    }

    @Override
    public String getShortcut() {
        return "dk";
    }

    @Override
    public OAuth2GrantType create(KeycloakSession session) {
        DeviceStorageProvider deviceStorage = session.getProvider(DeviceStorageProvider.class);
        return new DeviceKeyGrantType(deviceStorage, new ChallengeService(CHALLENGE_EXPIRY_SECONDS),
                new SignatureService(), new CanonicalPayloadService());
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
}
