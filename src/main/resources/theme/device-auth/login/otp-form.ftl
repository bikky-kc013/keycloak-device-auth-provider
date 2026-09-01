<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "form">
        <form id="kc-otp-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <label for="otp" class="${properties.kcLabelClass!}">${msg("otpLabel")!"Enter the code we sent you"}</label>
                <input type="text" id="otp" name="otp" class="${properties.kcInputClass!}" autofocus
                       autocomplete="one-time-code" inputmode="numeric" maxlength="6" />
            </div>

            <#if devOtpHint?has_content>
                <div class="${properties.kcFormGroupClass!}">
                    <span>Testing mode — OTP is ${devOtpHint}</span>
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
