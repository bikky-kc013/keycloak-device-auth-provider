<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "form">
        <form id="kc-phone-number-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <label for="phoneNumber" class="${properties.kcLabelClass!}">${msg("phoneNumberLabel")!"Phone number"}</label>
                <input type="tel" id="phoneNumber" name="phoneNumber" class="${properties.kcInputClass!}" autofocus
                       autocomplete="tel" placeholder="+94..." />
            </div>

            <#if message?has_content>
                <div class="${properties.kcFormGroupClass!} ${properties.kcFeedbackErrorClass!}">
                    <span>${kcSanitize(message.summary)?no_esc}</span>
                </div>
            </#if>

            <div class="${properties.kcFormGroupClass!}">
                <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!}"
                       type="submit" value="${msg("doContinue")!"Continue"}" />
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
