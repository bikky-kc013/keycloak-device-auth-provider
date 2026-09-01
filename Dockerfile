FROM quay.io/keycloak/keycloak:26.7.3

COPY target/keycloak-device-auth-1.0.0.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build
