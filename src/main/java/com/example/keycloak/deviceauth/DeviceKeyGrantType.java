package com.example.keycloak.deviceauth;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.Constants;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType.Context;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.TokenUtil;

import java.util.Collections;
import java.util.Set;

/**
 * OAuth 2.0 grant type for Flow B: silent sign-in / step-up via a signed device
 * challenge, with no browser round trip. Grant type identifier:
 * urn:sewa:params:oauth:grant-type:device-key
 *
 * Request params: deviceId, challengeId, signature, timestamp (epoch millis - must be
 * the exact value the client embedded in the signed canonical payload, see
 * DeviceAuthenticationService). purpose is NOT a client-supplied param here - it comes
 * from whatever purpose was set when the challenge was created via POST /challenge,
 * so a client can't claim step-up authorization for a signin-purposed challenge.
 *
 * Modeled directly on Keycloak's own ResourceOwnerPasswordCredentialsGrantType (see
 * org.keycloak.protocol.oidc.grants in keycloak-services): we don't run this through
 * Keycloak's Authenticator/flow-execution SPI (our "authentication decision" is the
 * signature verification, not a chain of authenticator steps) - instead we verify the
 * challenge/signature ourselves via DeviceAuthenticationService, then use the same
 * AuthenticationSessionModel + AuthenticationProcessor.attachSession() + TokenManager
 * plumbing Keycloak's own grant types use, so tokens are minted through Keycloak's
 * normal pipeline (real session, refresh token rotation) rather than hand-rolled.
 */
public class DeviceKeyGrantType extends OAuth2GrantTypeBase {

    private static final Logger logger = Logger.getLogger(DeviceKeyGrantType.class);

    public static final String GRANT_TYPE = "urn:sewa:params:oauth:grant-type:device-key";

    static final String PARAM_DEVICE_ID = "deviceId";
    static final String PARAM_CHALLENGE_ID = "challengeId";
    static final String PARAM_SIGNATURE = "signature";
    static final String PARAM_TIMESTAMP = "timestamp";

    private final DeviceAuthenticationService deviceAuthenticationService;

    public DeviceKeyGrantType(DeviceStorageProvider deviceStorage, ChallengeService challengeService,
                               SignatureService signatureService, CanonicalPayloadService canonicalPayloadService) {
        this.deviceAuthenticationService = new DeviceAuthenticationService(
                deviceStorage, challengeService, signatureService, canonicalPayloadService);
    }

    @Override
    public Response process(Context context) {
        setContext(context);

        event.detail(Details.AUTH_METHOD, "device_key");

        MultivaluedMap<String, String> params = context.getFormParams();
        String deviceId = params.getFirst(PARAM_DEVICE_ID);
        String challengeId = params.getFirst(PARAM_CHALLENGE_ID);
        String signature = params.getFirst(PARAM_SIGNATURE);
        String timestampParam = params.getFirst(PARAM_TIMESTAMP);

        if (isBlank(deviceId) || isBlank(challengeId) || isBlank(signature) || isBlank(timestampParam)) {
            return invalidGrant("Missing required parameter(s): deviceId, challengeId, signature, timestamp");
        }

        long timestampMillis;
        try {
            timestampMillis = Long.parseLong(timestampParam);
        } catch (NumberFormatException e) {
            return invalidGrant("timestamp must be epoch milliseconds");
        }

        DeviceAuthenticationService.Result result = deviceAuthenticationService.verify(
                deviceId, challengeId, signature, /* expectedPurpose */ null, /* expectedSessionId */ null, timestampMillis);

        if (!result.isSuccess()) {
            logger.warnv("Device key grant failed: {0}", result.getFailureReason());
            return invalidGrant("Device authentication failed");
        }

        Device device = result.getDevice();
        UserModel user = session.users().getUserById(realm, device.getUserId());
        if (user == null || !user.isEnabled()) {
            return invalidGrant("Account not available");
        }

        String scope = getRequestedScopes();

        RootAuthenticationSessionModel rootAuthSession = new AuthenticationSessionManager(session).createAuthenticationSession(realm, false);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);

        authSession.setAuthenticatedUser(user);
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setAction(AuthenticatedClientSessionModel.Action.AUTHENTICATE.name());
        authSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scope);

        if (user.getRequiredActionsStream().count() > 0) {
            new AuthenticationSessionManager(session).removeAuthenticationSession(realm, authSession, false);
            return invalidGrant("Account is not fully set up");
        }

        AuthenticationManager.setClientScopesInSession(session, authSession);

        ClientSessionContext clientSessionCtx = AuthenticationProcessor.attachSession(
                authSession, null, session, realm, clientConnection, event);
        clientSessionCtx.setAttribute(Constants.GRANT_TYPE, context.getGrantType());
        clientSessionCtx.setAttribute(OAuth2Constants.RESOURCE, formParams.getFirst(OAuth2Constants.RESOURCE));
        UserSessionModel userSession = session.sessions().getUserSession(realm, authSession.getParentSession().getId());
        if (userSession == null) {
            userSession = clientSessionCtx.getClientSession().getUserSession();
        }
        updateUserSessionFromClientAuth(userSession);

        TokenManager.AccessTokenResponseBuilder responseBuilder = tokenManager
                .responseBuilder(realm, client, event, session, userSession, clientSessionCtx).generateAccessToken();
        boolean useRefreshToken = useRefreshToken();
        if (useRefreshToken) {
            responseBuilder.generateRefreshToken();
            if (TokenUtil.TOKEN_TYPE_OFFLINE.equals(responseBuilder.getRefreshToken().getType())) {
                session.sessions().removeUserSession(realm, userSession);
            }
        }

        // Unlike a standard grant, this endpoint's documented request params (see
        // auth_developer_guide.md SS6.4) never include `scope` - the client has no reason to
        // send one, since this grant exists solely to silently mint a real OIDC sign-in
        // session. Gating on TokenUtil.isOIDCRequest(scopeParam) here would mean it's always
        // false (no `scope` form param -> OAuth2GrantTypeBase.getRequestedScopes() returns
        // null) and an id_token would never be generated, despite the response contract in
        // SS6.4 promising one unconditionally - so always generate it rather than requiring
        // callers to know to pass scope=openid.
        responseBuilder.generateIDToken().generateAccessTokenHash();

        checkAndBindMtlsHoKToken(responseBuilder, useRefreshToken);

        AccessTokenResponse res = responseBuilder.build();

        event.detail(Details.USERNAME, user.getUsername());
        event.user(user);
        event.success();
        AuthenticationManager.logSuccess(session, authSession);

        return cors.add(Response.ok(res, MediaType.APPLICATION_JSON_TYPE));
    }

    private Response invalidGrant(String message) {
        event.detail(Details.REASON, message);
        event.error(Errors.INVALID_REQUEST);
        throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT, message, Response.Status.BAD_REQUEST);
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    @Override
    public EventType getEventType() {
        return EventType.LOGIN;
    }

    @Override
    public Set<String> getTokenParameterNames() {
        return Set.of(PARAM_DEVICE_ID, PARAM_CHALLENGE_ID, PARAM_SIGNATURE, PARAM_TIMESTAMP);
    }
}
