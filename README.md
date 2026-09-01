# keycloak-device-auth

Custom Keycloak authentication provider for device-based authentication using EC P-256 public-key cryptography.

## Architecture

This provider extends Keycloak's Authentication SPI with:

1. **Phone Number Identification** - Identifies users by phone number
2. **Development OTP** - Fixed OTP for testing (not for production)
3. **Device Challenge-Response** - Cryptographic authentication via signed challenges
4. **Device Registration** - Public-key enrollment via REST API
5. **Device Revocation** - Disable compromised devices

The provider integrates with Keycloak's standard OAuth 2.0 / OpenID Connect flow. It does not issue tokens directly.

```
Mobile App
    |
    | Authorization Code + PKCE
    v
Keycloak
    |
    | Custom Authentication Flow
    |
    +--> Phone Number (identification)
    +--> OTP (verification)
    +--> Device Challenge (registered device)
    |
    v
Authorization Code --> Token Endpoint --> Tokens
```

## Requirements

- Java 21+
- Keycloak 26.7.3
- Maven 3.9+

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

### 1. Create Realm

```
Admin Console > Create Realm > Name: device-auth
```

### 2. Create Client

```
Admin Console > Clients > Create Client
  Client Type: OpenID Connect
  Client ID: mobile-app
  Name: Mobile Application
  Root URL: https://your-app.example.com

  Settings:
    Access Type: public
    Valid Redirect URIs: https://your-app.example.com/*
    Web Origins: https://your-app.example.com
    Standard Flow Enabled: ON
    Direct Access Grants Enabled: OFF

  Advanced Settings:
    Proof Key Code Exchange (PKCE): S256 required
```

### 3. Authentication Flow

Create a new flow in `Authentication > Flows`:

```
Flow Name: Device Auth Flow
  1. Phone Number Identification    [REQUIRED]
  2. Development OTP                 [REQUIRED]
  3. Device Challenge                [ALTERNATIVE]
```

Then bind the flow:

```
Authentication > Bind Flow > Device Auth Flow
```

## Authentication Flows

### Flow 1: First-Time Device (Enrollment)

```
Phone Number Input --> OTP Verification --> Device Registration Required Action --> Auth Success
```

### Flow 2: Registered Device (Challenge-Response)

```
Phone Number Identification --> Device Challenge --> Mobile Signs Challenge --> Signature Verification --> Auth Success
```

## Configuration

Configure via `Authentication > Flows > Device Auth Flow > Actions > Config`:

| Key | Default | Description |
|-----|---------|-------------|
| `autoCreateUsers` | `false` | Auto-create users on unknown phone numbers |
| `phoneAttribute` | `phoneNumber` | User attribute storing phone number |
| `devOtpEnabled` | `true` | Enable development OTP (disable in production) |
| `devOtpValue` | `123456` | Fixed OTP value for testing |
| `otpLength` | `6` | Expected OTP length |
| `otpMaxAttempts` | `5` | Max OTP verification attempts |
| `challengeExpirySeconds` | `60` | Challenge validity period |

**WARNING**: `devOtpEnabled=true` with `devOtpValue=123456` MUST NEVER be used in production.

## REST API

### Register Device

```bash
curl -X POST "https://keycloak.example.com/realms/device-auth/device-auth/register" \
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
    "algorithm": "ES256"
  }'
```

Response:

```json
{
  "deviceId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "ACTIVE"
}
```

### Revoke Device

```bash
curl -X POST "https://keycloak.example.com/realms/device-auth/device-auth/revoke" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "deviceId": "550e8400-e29b-41d4-a716-446655440000"
  }'
```

Response:

```json
{
  "deviceId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "REVOKED"
}
```

## Signature Format

### Canonical Payload

The device signs a canonical byte sequence:

```
challengeId\nchallenge\ndeviceId\nclientId\ntimestamp
```

Where `timestamp` is epoch milliseconds.

Example:

```
a1b2c3d4-e5f6-7890-abcd-ef1234567890
AbCdEf1234567890AbCdEf1234567890AbCdEf=
550e8400-e29b-41d4-a716-446655440000
mobile-app
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

### Sign Challenge

```java
Signature signer = Signature.getInstance("SHA256withECDSA");
signer.initSign(privateKey);
signer.update(canonicalPayloadBytes);
byte[] derSignature = signer.sign();

// Convert DER to Raw R||S
byte[] rawSignature = derToRaw(derSignature);
String signature = Base64Url.encode(rawSignature);
```

## Security Considerations

- HTTPS required in production
- Development OTP (`123456`) must never be enabled in production
- Challenges expire after 60 seconds
- Challenges are single-use
- Device ownership is validated per-user
- Revoked devices cannot authenticate
- Public keys only (private keys never leave the device)
- SecureRandom for challenge generation (32+ bytes)
- Atomic challenge consumption prevents replay attacks

## Known Limitations

- In-memory device storage (no JPA persistence) - for production, implement JPA storage provider
- In-memory challenge storage - for distributed deployments, use Redis/database
- No SMS/Email OTP - development OTP only
- Phone number is not verified (trust-based)
- No device attestation (WebAuthn/FIDO2)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run `mvn clean package` to verify the build
4. Submit a pull request

## License

Apache 2.0 - see [LICENSE](LICENSE)
# keycloak-device-auth-provider
