<#--
  Browser-flow fallback ONLY. Not part of the default realm configuration and not
  the primary sign-in path (that's Flow B / DeviceKeyGrantType, which never renders
  a page at all). Producing "signature" here requires bridging a native
  Keystore/Secure-Enclave signing operation into this page, which is not implemented -
  this template exists so the step renders (no template-not-found error) if an admin
  ever binds DeviceChallengeAuthenticator into a flow, not as a finished mobile UI.
-->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "form">
        <form id="kc-device-challenge-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <#if challengeData??>
                <input type="hidden" name="challengeId" value="${challengeData.challengeId}" />
                <input type="hidden" name="deviceId" value="${challengeData.deviceId}" />
                <div class="${properties.kcFormGroupClass!}">
                    <p>${msg("deviceChallengeInfo")!"Sign this challenge with your device to continue:"}</p>
                    <code>${challengeData.challenge}</code>
                </div>
                <div class="${properties.kcFormGroupClass!}">
                    <label for="signature" class="${properties.kcLabelClass!}">${msg("signatureLabel")!"Signature"}</label>
                    <input type="text" id="signature" name="signature" class="${properties.kcInputClass!}" />
                </div>
                <div class="${properties.kcFormGroupClass!}">
                    <label for="timestamp" class="${properties.kcLabelClass!}">${msg("timestampLabel")!"Timestamp (epoch millis)"}</label>
                    <input type="text" id="timestamp" name="timestamp" class="${properties.kcInputClass!}" />
                </div>
            </#if>

            <#if message?has_content>
                <div class="${properties.kcFormGroupClass!} ${properties.kcFeedbackErrorClass!}">
                    <span>${kcSanitize(message.summary)?no_esc}</span>
                </div>
            </#if>

            <div class="${properties.kcFormGroupClass!}">
                <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!}"
                       type="submit" value="${msg("doVerify")!"Verify"}" />
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
