#!/bin/bash
# Configures a Keycloak realm/client/authentication-flow for the Sewa device-auth
# provider (Flow A: browser phone+OTP enrollment/re-binding; Flow B: silent
# device-key sign-in/step-up via the token endpoint). Idempotent-ish: re-running
# will fail on "already exists" for the realm/client/flow - delete them first if
# you need to re-apply from scratch.
#
# This is exactly what was used to stand up and verify the provider locally
# (see the branch's verification notes) - only the target host/credentials and
# client redirect URIs need to change for a real deployment.
#
# Usage: KC_URL=https://iam.example.com KC_ADMIN_PASSWORD=... ./realm-setup.sh
set -euo pipefail

KC_URL="${KC_URL:-http://localhost:8080}"
KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
KC_ADMIN_PASSWORD="${KC_ADMIN_PASSWORD:?Set KC_ADMIN_PASSWORD}"
REALM="${REALM:-sewa-device-auth}"
CLIENT_ID="${CLIENT_ID:-sewa-mobile}"
LOGIN_THEME="${LOGIN_THEME:-device-auth}"

# Space-separated list of valid redirect URIs for the mobile client's custom-scheme
# OAuth redirect. Include both prod and dev flavor schemes.
REDIRECT_URIS="${REDIRECT_URIS:-com.innovationnxt.srilankasuperapp://oauth2redirect com.innovationnxt.srilankasuperapp.dev://oauth2redirect}"
export REDIRECT_URIS

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

echo "== Authenticating to $KC_URL as $KC_ADMIN_USER =="
ADMIN_TOKEN=$(curl -sf -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=admin-cli&username=$KC_ADMIN_USER&password=$KC_ADMIN_PASSWORD" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

api() {
  # api METHOD PATH [JSON_BODY]
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sf -X "$method" "$KC_URL$path" \
      -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" -d "$body"
  else
    curl -sf -X "$method" "$KC_URL$path" -H "Authorization: Bearer $ADMIN_TOKEN"
  fi
}

echo "== Creating realm '$REALM' =="
api POST /admin/realms "{\"realm\":\"$REALM\",\"enabled\":true}"

echo "== Setting login theme to '$LOGIN_THEME' =="
api PUT "/admin/realms/$REALM" "{\"loginTheme\":\"$LOGIN_THEME\"}"

echo "== Disabling VERIFY_PROFILE required action =="
# Keycloak's default VERIFY_PROFILE required action fires for auto-created users missing
# standard profile fields (email etc.) and would block token issuance in Flow A - see
# README "Realm Configuration" for why this must stay disabled, same reasoning as
# DeviceRegistrationRequiredAction.
api PUT "/admin/realms/$REALM/authentication/required-actions/VERIFY_PROFILE" \
  '{"alias":"VERIFY_PROFILE","name":"Verify Profile","providerId":"VERIFY_PROFILE","enabled":false,"defaultAction":false,"priority":90,"config":{}}'

echo "== Creating public client '$CLIENT_ID' (PKCE S256, standard flow) =="
REDIRECT_JSON=$(python3 -c "import json,os; print(json.dumps(os.environ['REDIRECT_URIS'].split()))" )
api POST "/admin/realms/$REALM/clients" "$(cat <<JSON
{
  "clientId": "$CLIENT_ID",
  "name": "Citizen Mobile",
  "enabled": true,
  "publicClient": true,
  "protocol": "openid-connect",
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": false,
  "serviceAccountsEnabled": false,
  "redirectUris": $REDIRECT_JSON,
  "webOrigins": ["+"],
  "attributes": { "pkce.code.challenge.method": "S256" }
}
JSON
)"

echo "== Creating 'phone-number' client scope (phone_number claim, ID token + userinfo only) =="
# Deliberately its own client scope, not the built-in 'profile' - this realm is auth-only by
# design (sewa-mobile doesn't get 'profile'; see auth_developer_guide.md SS4.1) and the enrolled
# phone number is an exception carved out because it's the authentication identifier itself, not
# general profile data. Marked DEFAULT (not optional) so it's always issued without the client
# needing to request an extra scope, and access.token.claim is deliberately "false" - the access
# token goes to resource servers on every API call and has no reason to carry this; only the ID
# token/userinfo, which the client itself consumes once at sign-in, should.
api POST "/admin/realms/$REALM/client-scopes" \
  '{"name":"phone-number","protocol":"openid-connect","attributes":{"include.in.token.scope":"false","display.on.consent.screen":"false"}}'

PHONE_SCOPE_ID=$(api GET "/admin/realms/$REALM/client-scopes" \
  | python3 -c "import sys,json; [print(s['id']) for s in json.load(sys.stdin) if s['name']=='phone-number']")

api POST "/admin/realms/$REALM/client-scopes/$PHONE_SCOPE_ID/protocol-mappers/models" "$(cat <<JSON
{
  "name": "phone-number",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-attribute-mapper",
  "config": {
    "user.attribute": "phoneNumber",
    "claim.name": "phone_number",
    "jsonType.label": "String",
    "id.token.claim": "true",
    "access.token.claim": "false",
    "userinfo.token.claim": "true",
    "lightweight.claim": "false",
    "multivalued": "false"
  }
}
JSON
)"

echo "== Assigning 'phone-number' as a DEFAULT scope on '$CLIENT_ID' =="
CLIENT_UUID=$(api GET "/admin/realms/$REALM/clients?clientId=$CLIENT_ID" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")
api PUT "/admin/realms/$REALM/clients/$CLIENT_UUID/default-client-scopes/$PHONE_SCOPE_ID"

echo "== Creating browser flow 'device-auth-browser' (Phone REQUIRED -> OTP REQUIRED) =="
api POST "/admin/realms/$REALM/authentication/flows" \
  '{"alias":"device-auth-browser","providerId":"basic-flow","topLevel":true,"builtIn":false}'

api POST "/admin/realms/$REALM/authentication/flows/device-auth-browser/executions/execution" \
  '{"provider":"phone-number-auth"}'
api POST "/admin/realms/$REALM/authentication/flows/device-auth-browser/executions/execution" \
  '{"provider":"dev-otp-auth"}'

EXECUTIONS=$(api GET "/admin/realms/$REALM/authentication/flows/device-auth-browser/executions")
PHONE_EXEC_ID=$(echo "$EXECUTIONS" | python3 -c "import sys,json; [print(e['id']) for e in json.load(sys.stdin) if e['providerId']=='phone-number-auth']")
OTP_EXEC_ID=$(echo "$EXECUTIONS" | python3 -c "import sys,json; [print(e['id']) for e in json.load(sys.stdin) if e['providerId']=='dev-otp-auth']")

api PUT "/admin/realms/$REALM/authentication/flows/device-auth-browser/executions" \
  "{\"id\":\"$PHONE_EXEC_ID\",\"requirement\":\"REQUIRED\",\"providerId\":\"phone-number-auth\"}"
api PUT "/admin/realms/$REALM/authentication/flows/device-auth-browser/executions" \
  "{\"id\":\"$OTP_EXEC_ID\",\"requirement\":\"REQUIRED\",\"providerId\":\"dev-otp-auth\"}"

# The executions PUT above has no "index"/"level"/ordering field - the Admin REST
# API silently ignores extra JSON properties, so a prior version of this script
# that set those had no effect. Execution order is instead whatever order
# POST .../executions/execution left them in, which is NOT guaranteed to match
# creation order (observed on Keycloak 26.7.3: dev-otp-auth ended up before
# phone-number-auth despite being created second) - explicitly fix it via
# raise-priority/lower-priority, the only reordering mechanism this API exposes.
# This matters: dev-otp-auth.requiresUser() is true, so if it ever runs before
# phone-number-auth resolves a user, Keycloak rejects it with a generic
# "Invalid username or password" error page instead of showing any form at all.
CURRENT_FIRST=$(api GET "/admin/realms/$REALM/authentication/flows/device-auth-browser/executions" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['providerId'])")
if [ "$CURRENT_FIRST" != "phone-number-auth" ]; then
  echo "== Reordering: phone-number-auth must run before dev-otp-auth =="
  api POST "/admin/realms/$REALM/authentication/executions/$PHONE_EXEC_ID/raise-priority"
fi

echo "== Configuring phone step (autoCreateUsers=true) =="
api POST "/admin/realms/$REALM/authentication/executions/$PHONE_EXEC_ID/config" \
  '{"alias":"phone-config","config":{"autoCreateUsers":"true","phoneAttribute":"phoneNumber"}}'

echo "== IMPORTANT: leave dev-otp-auth's devOtpEnabled=true default ONLY for non-production realms."
echo "   Set devOtpEnabled=false (via this step's authenticator config) before going to production -"
echo "   real OTP delivery is not implemented yet, see README Known Limitations."

echo "== Binding 'device-auth-browser' as the realm's browser flow =="
api PUT "/admin/realms/$REALM" "{\"browserFlow\":\"device-auth-browser\"}"

echo "== Done. =="
echo "Deliberately NOT bound: DeviceRegistrationRequiredAction and DeviceChallengeAuthenticator"
echo "are not part of this flow - see README 'Realm Configuration' for why (Flow A does not gate"
echo "token issuance on device registration; Flow B never uses a browser at all)."
echo "Custom grant type 'urn:sewa:params:oauth:grant-type:device-key' needs no separate realm"
echo "config - it's available automatically once the provider jar is deployed."
echo "Both flows now return the enrolled phone number as an id_token 'phone_number' claim"
echo "(and via /userinfo) - see README 'Claims' / auth_developer_guide.md SS4.1 for why this is"
echo "the one deliberate exception to this realm's otherwise auth-only, no-profile-data design."
