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
REALM="${REALM:-citizen}"
CLIENT_ID="${CLIENT_ID:-citizen-mobile}"
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
  "{\"id\":\"$PHONE_EXEC_ID\",\"requirement\":\"REQUIRED\",\"providerId\":\"phone-number-auth\",\"level\":0,\"index\":0}"
api PUT "/admin/realms/$REALM/authentication/flows/device-auth-browser/executions" \
  "{\"id\":\"$OTP_EXEC_ID\",\"requirement\":\"REQUIRED\",\"providerId\":\"dev-otp-auth\",\"level\":0,\"index\":1}"

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
