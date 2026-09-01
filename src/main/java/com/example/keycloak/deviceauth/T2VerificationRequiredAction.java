package com.example.keycloak.deviceauth;

import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;

/**
 * SCAFFOLD ONLY - not registered in META-INF/services, so this has no effect on any
 * flow until deliberately wired in.
 *
 * Extension point for the T2 (verified-identity) check described in the "Sewa
 * Authentication and Identity Assurance" doc, section 5: "a verification step
 * invoked at the point of a T2 action, returning an assurance assertion to the
 * container, with the provider behind it replaceable." The concrete verification
 * method (SLUDI-via-eSignet vs. an interim bank-grade path) is an explicitly open
 * decision per that doc and must not be built against yet - this class exists only
 * to mark where that decision plugs in once made, keyed off
 * {@link SewaAttributes#VERIFICATION_LEVEL_ATTRIBUTE}.
 */
public class T2VerificationRequiredAction implements RequiredActionProvider {

    public static final String PROVIDER_ID = "sewa-t2-verification";

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        // Intentionally does nothing - wiring this to actually trigger per doc section 5
        // ("plugged in at the first T2 action the citizen attempts, not at onboarding")
        // requires the concrete verification provider decision first.
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        throw new UnsupportedOperationException(
                "T2 verification is not implemented - concrete provider (SLUDI/eSignet vs. interim) is still an open decision");
    }

    @Override
    public void processAction(RequiredActionContext context) {
        throw new UnsupportedOperationException("T2 verification is not implemented");
    }

    @Override
    public void close() {
    }
}
