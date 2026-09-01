<#--
  Rendered only if DeviceRegistrationRequiredAction is deliberately enabled on the realm
  (it is NOT part of the default configuration - see README "Realm Configuration").
  Device registration normally happens as a plain POST /register call the app makes
  after Flow A's token exchange, with no browser involvement at all.
-->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "form">
        <form id="kc-device-registration-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <p>${msg("deviceRegistrationInfo")!"Finish setting up this device in the app to continue."}</p>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!}"
                       type="submit" value="${msg("doContinue")!"Continue"}" />
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
