package com.example.keycloak.deviceauth;

import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;

public class DeviceRegistrationRequiredAction implements RequiredActionProvider {

    private static final Logger logger = Logger.getLogger(DeviceRegistrationRequiredAction.class);

    private DeviceStorageProvider deviceStorage;

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        String userId = context.getUser().getId();
        boolean hasActiveDevice = deviceStorage.hasActiveDevice(userId);

        if (!hasActiveDevice) {
            logger.infov("User has no active devices, requiring registration");
            context.getUser().addRequiredAction("DEVICE_REGISTRATION");
        } else {
            context.getUser().removeRequiredAction("DEVICE_REGISTRATION");
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        context.challenge(context.form().createForm("device-registration-form.ftl"));
    }

    @Override
    public void processAction(RequiredActionContext context) {
        context.success();
    }

    @Override
    public void close() {
    }

    public void setDeviceStorage(DeviceStorageProvider deviceStorage) {
        this.deviceStorage = deviceStorage;
    }
}
