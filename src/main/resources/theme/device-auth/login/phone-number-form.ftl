<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false displayMessage=false; section>
    <#if section = "form">
        <div class="sa-appbar">
            <span class="sa-appbar-spacer" aria-hidden="true"></span>
            <div class="sa-stepper" role="presentation">
                <span class="sa-stepper-seg is-active"></span>
                <span class="sa-stepper-seg"></span>
            </div>
            <span class="sa-appbar-help" aria-hidden="true">
                <svg width="18" height="18" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M10.875 14.625C10.875 14.8475 10.809 15.065 10.6854 15.25C10.5618 15.435 10.3861 15.5792 10.1805 15.6644C9.97496 15.7495 9.74876 15.7718 9.53053 15.7284C9.3123 15.685 9.11184 15.5778 8.95451 15.4205C8.79718 15.2632 8.69003 15.0627 8.64662 14.8445C8.60321 14.6262 8.62549 14.4 8.71064 14.1945C8.79579 13.9889 8.93998 13.8132 9.12499 13.6896C9.30999 13.566 9.5275 13.5 9.75 13.5C10.0484 13.5 10.3345 13.6185 10.5455 13.8295C10.7565 14.0405 10.875 14.3266 10.875 14.625ZM9.75 4.5C7.68188 4.5 6 6.01406 6 7.875V8.25C6 8.44891 6.07902 8.63968 6.21967 8.78033C6.36033 8.92098 6.55109 9 6.75 9C6.94892 9 7.13968 8.92098 7.28033 8.78033C7.42099 8.63968 7.5 8.44891 7.5 8.25V7.875C7.5 6.84375 8.50969 6 9.75 6C10.9903 6 12 6.84375 12 7.875C12 8.90625 10.9903 9.75 9.75 9.75C9.55109 9.75 9.36033 9.82902 9.21967 9.96967C9.07902 10.1103 9 10.3011 9 10.5V11.25C9 11.4489 9.07902 11.6397 9.21967 11.7803C9.36033 11.921 9.55109 12 9.75 12C9.94892 12 10.1397 11.921 10.2803 11.7803C10.421 11.6397 10.5 11.4489 10.5 11.25V11.1825C12.21 10.8684 13.5 9.50437 13.5 7.875C13.5 6.01406 11.8181 4.5 9.75 4.5ZM19.5 9.75C19.5 11.6784 18.9282 13.5634 17.8568 15.1668C16.7855 16.7702 15.2627 18.0199 13.4812 18.7578C11.6996 19.4958 9.73919 19.6889 7.84787 19.3127C5.95656 18.9365 4.21928 18.0079 2.85571 16.6443C1.49215 15.2807 0.563554 13.5434 0.187348 11.6521C-0.188858 9.76082 0.00422452 7.80042 0.742179 6.01884C1.48013 4.23726 2.72982 2.71451 4.33319 1.64317C5.93657 0.571828 7.82164 0 9.75 0C12.335 0.00272983 14.8134 1.03084 16.6413 2.85872C18.4692 4.68661 19.4973 7.16498 19.5 9.75ZM18 9.75C18 8.1183 17.5161 6.52325 16.6096 5.16655C15.7031 3.80984 14.4146 2.75242 12.9071 2.12799C11.3997 1.50357 9.74085 1.34019 8.14051 1.65852C6.54017 1.97685 5.07016 2.76259 3.91637 3.91637C2.76259 5.07015 1.97685 6.54016 1.65853 8.1405C1.3402 9.74085 1.50358 11.3996 2.128 12.9071C2.75242 14.4146 3.80984 15.7031 5.16655 16.6096C6.52326 17.5161 8.11831 18 9.75 18C11.9373 17.9975 14.0343 17.1275 15.5809 15.5809C17.1275 14.0343 17.9975 11.9373 18 9.75Z" fill="#222222"/>
                </svg>
            </span>
        </div>

        <div class="sa-body">
            <h1 class="sa-title">${msg("mobileNumberQuestion")!"What's your mobile number?"}</h1>
            <p class="sa-subtitle">${msg("mobileVerifyDesc")!"We'll send a one-time code to verify it's you."}</p>

            <form id="kc-phone-number-form" action="${url.loginAction}" method="post" novalidate>
                <div class="${properties.kcFormGroupClass!}">
                    <label for="phoneNumber" class="${properties.kcLabelClass!}">${msg("phoneNumberLabel")!"Mobile number"}</label>
                    <div class="sa-input-group<#if message?has_content> has-error</#if>">
                        <span class="sa-input-prefix">
                            <svg width="20" height="15" viewBox="0 0 24 18" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <g clip-path="url(#sa-lk-flag-clip)">
                                    <rect width="24" height="18" rx="2" fill="white"/>
                                    <path fill-rule="evenodd" clip-rule="evenodd" d="M0 0H24V18H0V0Z" fill="#FECA00"/>
                                    <rect x="1.5" y="1.5" width="4.5" height="15" fill="#1F8A6E"/>
                                    <rect x="6" y="1.5" width="4.5" height="15" fill="#F56800"/>
                                    <rect x="10.5" y="1.5" width="12" height="15" fill="#B01D00"/>
                                    <rect x="9" y="1.5" width="1.5" height="15" fill="#E8AA00"/>
                                </g>
                                <defs>
                                    <clipPath id="sa-lk-flag-clip">
                                        <rect width="24" height="18" rx="2" fill="white"/>
                                    </clipPath>
                                </defs>
                            </svg>
                            <span>+94</span>
                        </span>
                        <input type="tel" id="phoneNumber" name="phoneNumber" inputmode="numeric"
                               autocomplete="tel-national" maxlength="10" placeholder="77 123 4567"
                               value="${submittedPhoneDigits!""}" autofocus />
                        <button type="button" class="sa-input-clear" id="phoneNumberClear" aria-label="${msg("doClear")!"Clear"}">
                            <svg width="14" height="14" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <path d="M15 5L5 15M5 5L15 15" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
                            </svg>
                        </button>
                        <span class="sa-input-check" aria-hidden="true">
                            <svg width="18" height="18" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                                <path d="M10 0C4.486 0 0 4.486 0 10C0 15.514 4.486 20 10 20C15.514 20 20 15.514 20 10C20 4.486 15.514 0 10 0ZM14.844 7.594L9.28 13.594C9.187 13.694 9.075 13.774 8.951 13.829C8.827 13.884 8.693 13.912 8.558 13.912C8.423 13.912 8.289 13.884 8.165 13.829C8.041 13.774 7.929 13.694 7.836 13.594L5.156 10.719C4.966 10.514 4.966 10.181 5.156 9.977C5.346 9.772 5.654 9.772 5.844 9.977L8.558 12.891L14.156 6.883C14.346 6.678 14.654 6.678 14.844 6.883C15.034 7.087 15.034 7.39 14.844 7.594Z" fill="#1FAA63"/>
                            </svg>
                        </span>
                    </div>
                </div>

                <#if message?has_content>
                    <div class="sa-error-text">${kcSanitize(message.summary)?no_esc}</div>
                </#if>

                <div class="sa-footer">
                    <button type="submit" id="phoneNumberSubmit"
                            class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} sa-button">
                        ${msg("doSendOtp")!"Send OTP code"}
                    </button>
                </div>
            </form>
        </div>
    </#if>
</@layout.registrationLayout>
