# keycloak-device-auth

Custom Keycloak authentication provider for device-based authentication using EC P-256 public-key cryptography, built against the "Sewa Authentication and Identity Assurance" architecture doc's assurance model (phone+OTP for enrollment/re-binding only, a device keypair as the actual multi-factor mechanism for everything else).

## Architecture - two flows

**Flow A (enrollment / re-binding, browser-based, rare)**: a citizen with no registered device (first install, or after losing their key - uninstall, factory reset, biometric re-enrollment) goes through Keycloak's hosted phone+OTP UI in the system browser (Custom Tabs / SFSafariViewController), gets a real Authorization Code + PKCE token, and uses that token to register a device keypair via a plain REST call - no browser involvement for the registration step itself.

**Flow B (routine sign-in / step-up, silent, the common case)**: the app never opens a browser. It requests a challenge, signs it locally with the device's private key (released by app lock/biometric), and exchanges the signature for real tokens via a custom OAuth grant type on Keycloak's standard token endpoint.

```
Flow A (rare - enrollment/re-binding)          Flow B (routine - every sign-in/step-up)
--------------------------------------          -----------------------------------------
Mobile App                                      Mobile App
    |                                               |
    | Authorization Code + PKCE (Custom Tabs)        | POST /device-auth/challenge
    v                                               v
Keycloak hosted UI                              Keycloak (unauthenticated, by deviceId)
    +--> Phone Number (identification)              |
    +--> OTP (verification)                          | sign challenge locally (device key)
    |                                                v
    v                                          POST /protocol/openid-connect/token
Authorization Code --> Token Endpoint --> Tokens    grant_type=urn:sewa:params:oauth:
    |                                                grant-type:device-key
    v                                               |
App calls POST /device-auth/register                v
(Bearer token from above, generates &               Real Keycloak tokens (access/refresh/id)
 registers an EC P-256 keypair - no browser)          (DeviceKeyGrantType, no browser at all)
```

Device registration (`/register`) auto-revokes any previously active device for that account - **only one active device per account is supported**; registering a new one is what a re-binding event *is*.

The provider integrates with Keycloak's standard OAuth 2.0 / OpenID Connect flow throughout - it never issues tokens itself outside Keycloak's own `TokenManager`/token endpoint pipeline (real sessions, refresh token rotation).

## Requirements

- Java 21+
- Keycloak 26.7.3
- Maven 3.9+ (a Maven Docker image works fine if Maven isn't installed locally: `docker run --rm -v "$PWD":/app -w /app maven:3.9-eclipse-temurin-21 mvn clean package`)

## Build

```bash
export JAVA_HOME=/path/to/jdk-21
mvn clean package
```

## Deployment

### Docker

```bash
docker build -t keycloak-device-auth:1.0.0 .
docker run -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  keycloak-device-auth:1.0.0 start-dev
```

### Provider Installation

Copy `target/keycloak-device-auth-1.0.0.jar` to `/opt/keycloak/providers/` and run:

```bash
/opt/keycloak/bin/kc.sh build
```

## Realm Configuration

**Use `deploy/realm-setup.sh` instead of clicking through Admin Console** - it scripts every step below via the Admin REST API and is exactly what was used to verify this provider end-to-end (see "Verification" below). Set `KC_URL`/`KC_ADMIN_USER`/`KC_ADMIN_PASSWORD`/`REALM`/`CLIENT_ID`/`REDIRECT_URIS` as needed and run it.

If configuring by hand instead:

### 1. Create Realm

```
Admin Console > Create Realm > Name: sewa-device-auth
```

### 2. Disable VERIFY_PROFILE

Keycloak's default `VERIFY_PROFILE` required action fires for auto-created users missing standard profile fields and will block Flow A's token issuance. Disable it: `Authentication > Required Actions > Verify Profile > OFF`.

### 3. Create Client

```
Admin Console > Clients > Create Client
  Client Type: OpenID Connect
  Client ID: sewa-mobile

  Settings:
    Access Type: public
    Valid Redirect URIs: your app's custom-scheme redirect (e.g. com.example.app://oauth2redirect)
    Web Origins: +
    Standard Flow Enabled: ON
    Direct Access Grants Enabled: OFF

  Advanced Settings:
    Proof Key Code Exchange (PKCE): S256 required
```

### 4. Browser Authentication Flow (Flow A only)

Create a new flow bound as the realm's **Browser Flow**:

```
Flow Name: device-auth-browser
  1. Phone Number Identification    [REQUIRED]  (config: autoCreateUsers=true)
  2. Development OTP                 [REQUIRED]
```

**Deliberately do NOT add Device Challenge or Device Registration to this flow**, and do not enable `DeviceRegistrationRequiredAction` realm-wide. Two reasons:

- `DeviceRegistrationRequiredAction` would run as a Required Action *before* Keycloak issues the authorization code - but `/register` requires a Bearer access token, which doesn't exist yet at that point. Gating token issuance on it would deadlock the flow. Device registration is deliberately a plain, unblocked REST call the app makes *after* Flow A's token exchange.
- `DeviceChallengeAuthenticator` (the form-rendered, browser-based challenge step) is not the primary sign-in path - `DeviceKeyGrantType` (Flow B, see below) is, and it never touches the browser at all. `DeviceChallengeAuthenticator`/`device-challenge-form.ftl` remain in the codebase, bug-fixed and functional, only as an unbound fallback for a pure-browser edge case; producing a valid `signature` from that form still requires bridging a native Keystore/Secure-Enclave signing operation into the page, which is not implemented.

### 5. Login Theme

```
Realm Settings > Themes > Login theme: device-auth
```

## Authentication Flows

### Flow A: Enrollment / re-binding

```
Phone Number Input --> OTP Verification --> Authorization Code --> Token Exchange
    --> App generates device keypair --> POST /device-auth/register (Bearer token)
```

### Flow B: Silent sign-in / step-up (no browser)

```
POST /device-auth/challenge (deviceId, clientId, purpose)
    --> App signs canonical payload with device private key
    --> POST /protocol/openid-connect/token (grant_type=urn:sewa:params:oauth:grant-type:device-key)
    --> Real access/refresh/id tokens
```

`purpose` is `"signin"` (default) or `"step-up"` - it's baked into the signed payload server-side from whatever the challenge was created with, so a client can't present a signin-purposed signature as step-up authorization for a sensitive action. Step-up is otherwise identical to sign-in: a fresh challenge, requested at the point of the action.

## Configuration

Configure via `Authentication > Flows > device-auth-browser > Actions > Config`:

| Key | Default | Description |
|-----|---------|-------------|
| `autoCreateUsers` | `false` | Auto-create users on unknown phone numbers |
| `phoneAttribute` | `phoneNumber` | User attribute storing phone number |
| `devOtpEnabled` | `true` | Enable development OTP (disable in production) |
| `devOtpValue` | `123456` | Fixed OTP value for testing |
| `otpLength` | `6` | Expected OTP length |
| `otpMaxAttempts` | `5` | Max OTP verification attempts |
| `challengeExpirySeconds` | `60` | Challenge validity period (browser-flow `DeviceChallengeAuthenticatorFactory` only - `/device-auth/challenge` and `DeviceKeyGrantTypeFactory` currently hardcode the same 60s value rather than reading this config property; keep them in sync if you change it) |

**WARNING**: `devOtpEnabled=true` with `devOtpValue=123456` MUST NEVER be used in production - no real SMS OTP delivery is implemented yet, see Known Limitations.

## REST API

### Register Device

Requires a Bearer access token from Flow A's token exchange (or any prior valid session). **Auto-revokes any existing active device for the account** - registering a new device is a re-binding event.

```bash
curl -X POST "https://keycloak.example.com/realms/sewa-device-auth/device-auth/register" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "deviceId": "550e8400-e29b-41d4-a716-446655440000",
    "deviceName": "Android Phone",
    "platform": "android",
    "publicKey": {
      "kty": "EC",
      "crv": "P-256",
      "x": "base64url-encoded-x-coordinate",
      "y": "base64url-encoded-y-coordinate",
      "kid": "device-key-1"
    },
    "algorithm": "ES256",
    "attestation": {
      "level": "HARDWARE",
      "statement": "opaque-attestation-blob-or-cert-chain"
    }
  }'
```

`attestation` is optional. `level` is `HARDWARE`, `SOFTWARE`, or `UNKNOWN` (unrecognized/missing values are recorded as `UNKNOWN`) - it is **recorded, never blocking**: a software-backed key is still accepted, so citizens on cheaper handsets aren't excluded. `statement` is stored opaquely (not parsed or cryptographically validated in this phase).

Response:

```json
{
  "deviceId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "ACTIVE",
  "attestationLevel": "HARDWARE"
}
```

### Revoke Device

```bash
curl -X POST "https://keycloak.example.com/realms/sewa-device-auth/device-auth/revoke" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"deviceId": "550e8400-e29b-41d4-a716-446655440000"}'
```

### Create Challenge (Flow B, leg 1 of 2)

**Unauthenticated** - the device itself is the credential under test; the account it belongs to is only revealed after a valid signature reaches the token endpoint.

```bash
curl -X POST "https://keycloak.example.com/realms/sewa-device-auth/device-auth/challenge" \
  -H "Content-Type: application/json" \
  -d '{"deviceId": "550e8400-e29b-41d4-a716-446655440000", "clientId": "sewa-mobile", "purpose": "signin"}'
```

`purpose` defaults to `"signin"`; pass `"step-up"` for an action-scoped authorization. `clientId` is required - there's no authenticated client context on this endpoint to derive it from, so the caller states it explicitly; it only becomes a real binding once the signed response is exchanged as that same OAuth client at the token endpoint.

Response:

```json
{
  "challengeId": "a1b2c3d4-...",
  "challenge": "AbCdEf...",
  "purpose": "signin",
  "expiresIn": 60
}
```

### Exchange Challenge for Tokens (Flow B, leg 2 of 2)

Standard Keycloak token endpoint, custom grant type - this is what actually issues real access/refresh/id tokens.

```bash
curl -X POST "https://keycloak.example.com/realms/sewa-device-auth/protocol/openid-connect/token" \
  --data-urlencode "grant_type=urn:sewa:params:oauth:grant-type:device-key" \
  --data-urlencode "client_id=sewa-mobile" \
  --data-urlencode "deviceId=550e8400-e29b-41d4-a716-446655440000" \
  --data-urlencode "challengeId=a1b2c3d4-..." \
  --data-urlencode "signature=<base64url signature>" \
  --data-urlencode "timestamp=<epoch millis embedded in the signed payload>"
```

Returns a normal Keycloak `AccessTokenResponse` (access_token, refresh_token, id_token, ...), minted through Keycloak's regular `TokenManager` pipeline - a real session is created, not a hand-rolled token.

## Signature Format

### Canonical Payload

The device signs a canonical byte sequence:

```
challengeId\nchallenge\ndeviceId\nclientId\npurpose\ntimestamp
```

Where `timestamp` is epoch milliseconds - **it must be the exact value the client embeds when signing**, not a value the server invents. The server reconstructs this exact payload using the client-supplied timestamp (checked against server time with a 60-second allowed clock skew, `DeviceAuthenticationService.ALLOWED_CLOCK_SKEW_MILLIS`) to verify the signature; it cannot use its own `Instant.now()`, since that would essentially never match the byte sequence the client actually signed.

Example:

```
a1b2c3d4-e5f6-7890-abcd-ef1234567890
AbCdEf1234567890AbCdEf1234567890AbCdEf=
550e8400-e29b-41d4-a716-446655440000
sewa-mobile
signin
1725168000000
```

### Signature Encoding

Signatures use **Raw R||S format** (64 bytes, JOSE-compatible):

```
Base64URL(R[0:32] || S[0:32])
```

The provider accepts both:
- Raw R||S format (recommended)
- ASN.1 DER format (automatic detection)

### Algorithm

- **ES256** - ECDSA with P-256 (secp256r1) and SHA-256

## Mobile Integration

### Android Keystore

```java
// Generate key pair in Android Keystore
KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
kpg.initialize(new ECGenParameterSpec("secp256r1"));
KeyPair keyPair = kpg.generateKeyPair();

// Extract JWK from public key
PublicKey publicKey = keyPair.getPublic();
ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
String x = Base64Url.encode(ecPublicKey.getW().getAffineX().toByteArray());
String y = Base64Url.encode(ecPublicKey.getW().getAffineY().toByteArray());

// Register device
registerDevice(publicKey.getEncoded(), "ES256", "android");
```

### iOS Secure Enclave

```swift
// Generate key pair in Secure Enclave
let accessControl = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage],
    nil
)!

let attributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecAttrAccessControl as String: accessControl
]

var error: Unmanaged<CFError>?
guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
    throw error!.takeRetainedValue() as Error
}

let publicKey = SecKeyCopyPublicKey(privateKey)!
```

### Sign Challenge (Flow B)

```java
long timestampMillis = System.currentTimeMillis();
String canonicalPayload = challengeId + "\n" + challenge + "\n" + deviceId + "\n" + clientId + "\n" + purpose + "\n" + timestampMillis;

Signature signer = Signature.getInstance("SHA256withECDSA");
signer.initSign(privateKey);
signer.update(canonicalPayload.getBytes(StandardCharsets.UTF_8));
byte[] derSignature = signer.sign();

// Convert DER to Raw R||S
byte[] rawSignature = derToRaw(derSignature);
String signature = Base64Url.encode(rawSignature);

// POST timestampMillis (as "timestamp") alongside deviceId/challengeId/signature to the token endpoint
```

## Security Considerations

- HTTPS required in production
- Development OTP (`123456`) must never be enabled in production
- Challenges expire after 60 seconds, are single-use (atomic consumption prevents replay - verified: replaying a consumed challenge is rejected)
- Signed payload timestamp is checked against a 60-second clock-skew window
- Only one device may be active per account - registering a new one revokes the previous one (verified: the previously active device can no longer obtain a challenge once superseded)
- Device ownership is validated per-user; purpose (signin vs. step-up) is bound into the signed payload
- Revoked devices cannot authenticate
- Public keys only (private keys never leave the device)
- SecureRandom for challenge generation (32+ bytes)
- REST endpoints (`/register`, `/revoke`) explicitly Bearer-authenticate the caller via `AppAuthManager.BearerTokenAuthenticator` - a custom `RealmResourceProvider` is **not** automatically Bearer-authenticated by Keycloak the way protocol endpoints are; relying on `session.getContext().getUser()` alone (as this provider originally did) silently never authenticates anyone

## Known Limitations

- In-memory device and challenge storage, deliberately shared as a JVM-wide singleton so state survives across requests within one node (a fresh instance per request would lose everything immediately - see the comments on `InMemoryDeviceStorageProviderFactory` and `ChallengeService`) - **still not safe for a distributed/multi-node deployment**; implement a JPA/Redis-backed `DeviceStorageProvider` and a shared challenge store for that
- No SMS/Email OTP - development OTP only
- Phone number is not verified (trust-based)
- No cryptographic validation of the attestation statement (recorded opaquely only, per design - see doc section 4.1, "recorded, not blocking")
- Re-binding notification (`DeviceRebindingNotifier`) is a logging-only stub - no real SMS/push is sent to the registered number or previous device yet
- T2 (verified-identity) check is an unwired scaffold only (`T2VerificationRequiredAction`) - the concrete verification method (SLUDI/eSignet vs. an interim path) is an explicitly open decision per the source doc and must not be built against yet
- `challengeExpirySeconds` admin config property is defined but not actually read when constructing `ChallengeService` in `DeviceChallengeAuthenticatorFactory`/`DeviceKeyGrantTypeFactory` - both hardcode 60s

## Verification

This branch (`feature/sewa-flow-a-flow-b-compliance`) was verified locally, end-to-end, against a real Keycloak 26.7.3 instance (Docker) with `deploy/realm-setup.sh`, including:
- Flow A through the actual rendered login theme (phone form -> OTP form -> real authorization code -> PKCE token exchange)
- Device registration with attestation, correctly Bearer-authenticated
- Flow B: challenge issuance -> local ECDSA signing (openssl) -> custom grant type -> real Keycloak-issued tokens, with zero browser involvement
- Replay protection (a consumed challenge cannot be reused)
- Single-active-device enforcement (registering a second device revokes the first; the first device's challenge request then fails)
- `deploy/realm-setup.sh` itself, run against a second, independent instance from a clean state

Not exercised live: the browser-fallback `device-challenge-form.ftl` path (unbound by default, see "Realm Configuration") and `device-registration-form.ftl` (only rendered if `DeviceRegistrationRequiredAction` is deliberately enabled, which is not recommended - see above); both render from the same theme macro system already proven working for the phone/OTP forms, but weren't independently exercised.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run `mvn clean package` to verify the build
4. Submit a pull request

## License

Apache 2.0 - see [LICENSE](LICENSE)
