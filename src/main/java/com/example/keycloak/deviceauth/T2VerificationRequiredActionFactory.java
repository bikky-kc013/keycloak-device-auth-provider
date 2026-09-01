package com.example.keycloak.deviceauth;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/** SCAFFOLD ONLY - deliberately NOT registered in META-INF/services. See T2VerificationRequiredAction. */
public class T2VerificationRequiredActionFactory implements RequiredActionFactory {

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return new T2VerificationRequiredAction();
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
        return T2VerificationRequiredAction.PROVIDER_ID;
    }

    @Override
    public String getDisplayText() {
        return "Sewa T2 Verification (not implemented - scaffold only)";
    }
}
