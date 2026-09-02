(function () {
    "use strict";

    function digitsOnly(value) {
        return (value || "").replace(/\D/g, "");
    }

    function initBackButtons() {
        var buttons = document.querySelectorAll(".sa-appbar-back");
        for (var i = 0; i < buttons.length; i++) {
            buttons[i].addEventListener("click", function () {
                window.history.back();
            });
        }
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
            if (group) {
                group.classList.toggle("has-value", input.value.length > 0);
            }
        }

        input.addEventListener("input", function () {
            var digits = digitsOnly(input.value).slice(0, 9);
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

        form.addEventListener("submit", function () {
            var digits = digitsOnly(input.value);
            if (digits.length > 0) {
                input.value = "94" + digits;
            }
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

        // Resend has no backend wiring yet (OTP delivery is dev-only, see
        // README known limitations) - this is a cosmetic cooldown only.
        var resendBtn = document.getElementById("otpResend");
        if (resendBtn) {
            var baseLabel = resendBtn.textContent;
            var secondsLeft = 0;
            var timer = null;

            resendBtn.addEventListener("click", function () {
                if (secondsLeft > 0) {
                    return;
                }
                secondsLeft = 30;
                resendBtn.disabled = true;
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
            });
        }

        if (boxes[0]) {
            boxes[0].focus();
        }
        syncSubmit();
    }

    document.addEventListener("DOMContentLoaded", function () {
        initBackButtons();
        initPhoneForm();
        initOtpForm();
    });
})();
