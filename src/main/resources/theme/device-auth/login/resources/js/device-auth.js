(function () {
    "use strict";

    function digitsOnly(value) {
        return (value || "").replace(/\D/g, "");
    }

    // Sri Lankan mobile numbers are a 9-digit national number, optionally typed
    // with the domestic trunk prefix "0" in front (10 digits total) - both are
    // valid input here, matching the SuperApp number field's own validation.
    function isValidLkDigits(digits) {
        return digits.length === 9 || digits.length === 10;
    }

    // Strips a leading trunk "0" from a 10-digit entry so the result is always
    // the bare 9-digit national number to combine with the "94" country code.
    function toNationalDigits(digits) {
        if (digits.length === 10 && digits.charAt(0) === "0") {
            return digits.slice(1);
        }
        return digits;
    }

    function initPhoneForm() {
        var form = document.getElementById("kc-phone-number-form");
        var input = document.getElementById("phoneNumber");
        if (!form || !input) {
            return;
        }

        var group = input.closest(".sa-input-group");
        var clearBtn = document.getElementById("phoneNumberClear");
        var submitBtn = document.getElementById("phoneNumberSubmit");

        function syncState() {
            var digits = digitsOnly(input.value);
            var valid = isValidLkDigits(digits);
            if (group) {
                group.classList.toggle("has-value", digits.length > 0);
                group.classList.toggle("is-valid", valid);
            }
            if (submitBtn) {
                submitBtn.disabled = !valid;
            }
        }

        input.addEventListener("input", function () {
            var digits = digitsOnly(input.value).slice(0, 10);
            if (digits !== input.value) {
                input.value = digits;
            }
            if (group) {
                group.classList.remove("has-error");
            }
            syncState();
        });

        if (clearBtn) {
            clearBtn.addEventListener("click", function () {
                input.value = "";
                if (group) {
                    group.classList.remove("has-error");
                }
                syncState();
                input.focus();
            });
        }

        form.addEventListener("submit", function (event) {
            var digits = digitsOnly(input.value);
            if (!isValidLkDigits(digits)) {
                event.preventDefault();
                return;
            }
            input.value = "94" + toNationalDigits(digits);
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.classList.add("sa-loading");
            }
        });

        syncState();
    }

    function initOtpForm() {
        var form = document.getElementById("kc-otp-form");
        var boxGroup = document.getElementById("otpBoxes");
        if (!form || !boxGroup) {
            return;
        }

        var hidden = document.createElement("input");
        hidden.type = "hidden";
        hidden.name = "otp";
        hidden.id = "otp";
        form.appendChild(hidden);

        var boxes = Array.prototype.slice.call(boxGroup.querySelectorAll(".sa-otp-box"));
        var submitBtn = document.getElementById("otpSubmit");

        function syncSubmit() {
            hidden.value = boxes.map(function (box) {
                return box.value;
            }).join("");
            if (submitBtn) {
                submitBtn.disabled = hidden.value.length !== boxes.length;
            }
        }

        boxes.forEach(function (box, index) {
            box.addEventListener("input", function () {
                box.value = digitsOnly(box.value).slice(-1);
                boxGroup.classList.remove("has-error", "has-success");
                if (box.value && index < boxes.length - 1) {
                    boxes[index + 1].focus();
                }
                syncSubmit();
            });

            box.addEventListener("keydown", function (event) {
                if (event.key === "Backspace" && !box.value && index > 0) {
                    boxes[index - 1].focus();
                }
            });

            box.addEventListener("paste", function (event) {
                var clipboard = event.clipboardData || window.clipboardData;
                var pasted = digitsOnly(clipboard ? clipboard.getData("text") : "");
                if (!pasted) {
                    return;
                }
                event.preventDefault();
                for (var i = 0; i < boxes.length; i++) {
                    boxes[i].value = pasted[i] || "";
                }
                var lastIndex = Math.min(pasted.length, boxes.length) - 1;
                if (lastIndex >= 0) {
                    boxes[lastIndex].focus();
                }
                syncSubmit();
            });
        });

        var otpAbortController = typeof AbortController === "function" ? new AbortController() : null;

        form.addEventListener("submit", function () {
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.classList.add("sa-loading");
            }
            if (otpAbortController) {
                otpAbortController.abort();
            }
        });

        // Native SMS code autofill (Android Chrome and other WebOTP-capable
        // browsers) - without this, splitting the code into 6 boxes instead
        // of one input loses the OS's "use code from SMS" suggestion.
        if ("OTPCredential" in window && otpAbortController) {
            navigator.credentials.get({
                otp: { transport: ["sms"] },
                signal: otpAbortController.signal
            }).then(function (otpCredential) {
                var pasted = digitsOnly(otpCredential && otpCredential.code);
                if (!pasted) {
                    return;
                }
                for (var i = 0; i < boxes.length; i++) {
                    boxes[i].value = pasted[i] || "";
                }
                boxGroup.classList.remove("has-error", "has-success");
                syncSubmit();
            }).catch(function () {
                // Ignored - user cancelled, no SMS arrived, or the API/permission
                // isn't available; the boxes remain a fully functional fallback.
            });
        }

        // Resend actually regenerates the dev OTP server-side now
        // (DevelopmentOtpAuthenticator.handleResend) - clicking it submits this
        // same form with resendOtp=true, which is a full page reload, not AJAX.
        // Real delivery is still dev-only (see README known limitations); only
        // the on-page devOtpHint shows the new code.
        //
        // Incremental cooldown: 30s after the 1st resend, 60s after the 2nd, 90s
        // after the 3rd, and so on - mirrors the (otherwise unused) SuperApp
        // native OTP screen's _resendCooldownStepSeconds * _resendCount logic.
        // Since each resend reloads the page, resendCount is read from the
        // server-rendered data-resend-count attribute (backed by an auth-session
        // note, so it survives the reload) rather than kept in JS memory, and the
        // cooldown resumes immediately on load if a resend just happened.
        var resendBtn = document.getElementById("otpResend");
        var resendHiddenField = document.getElementById("resendOtp");
        if (resendBtn && resendHiddenField) {
            var baseLabel = resendBtn.textContent;
            var resendCooldownStepSeconds = 30;
            var resendCount = parseInt(resendBtn.getAttribute("data-resend-count"), 10) || 0;
            var secondsLeft = 0;
            var timer = null;

            function startCooldown() {
                secondsLeft = resendCooldownStepSeconds * resendCount;
                resendBtn.disabled = true;
                if (timer) {
                    window.clearInterval(timer);
                }
                timer = window.setInterval(function () {
                    secondsLeft -= 1;
                    if (secondsLeft <= 0) {
                        window.clearInterval(timer);
                        resendBtn.disabled = false;
                        resendBtn.textContent = baseLabel;
                    } else {
                        resendBtn.textContent = baseLabel + " (" + secondsLeft + "s)";
                    }
                }, 1000);
            }

            resendBtn.addEventListener("click", function () {
                if (secondsLeft > 0) {
                    return;
                }
                resendHiddenField.value = "true";
                resendBtn.disabled = true;
                form.requestSubmit ? form.requestSubmit() : form.submit();
            });

            if (resendCount > 0) {
                startCooldown();
            }
        }

        if (boxes[0]) {
            boxes[0].focus();
        }
        syncSubmit();
    }

    document.addEventListener("DOMContentLoaded", function () {
        initPhoneForm();
        initOtpForm();
    });
})();
