package com.example.keycloak.deviceauth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PhoneNumberNormalizationTest {

    @Test
    void testNormalizePhoneNumberNull() {
        assertNull(PhoneNumberAuthenticator.normalizePhoneNumber(null));
    }

    @Test
    void test9DigitNationalNumber() {
        assertEquals("+94771234567", PhoneNumberAuthenticator.normalizePhoneNumber("771234567"));
    }

    @Test
    void test10DigitWithTrunkPrefix() {
        assertEquals("+94771234567", PhoneNumberAuthenticator.normalizePhoneNumber("0771234567"));
    }

    @Test
    void testAlreadyCountryCodedNoPlus() {
        assertEquals("+94771234567", PhoneNumberAuthenticator.normalizePhoneNumber("94771234567"));
    }

    @Test
    void testAlreadyCountryCodedWithPlus() {
        assertEquals("+94771234567", PhoneNumberAuthenticator.normalizePhoneNumber("+94771234567"));
    }

    @Test
    void testWithSpaces() {
        assertEquals("+94771234567", PhoneNumberAuthenticator.normalizePhoneNumber("077 123 4567"));
    }

    @Test
    void testWithDashes() {
        assertEquals("+94771234567", PhoneNumberAuthenticator.normalizePhoneNumber("077-123-4567"));
    }

    @Test
    void testWithParensAndSpaces() {
        assertEquals("+94771234567", PhoneNumberAuthenticator.normalizePhoneNumber("+94 (77) 123 4567"));
    }

    @Test
    void testRejectsTooShort() {
        assertNull(PhoneNumberAuthenticator.normalizePhoneNumber("12345"));
    }

    @Test
    void testRejectsTooLong() {
        assertNull(PhoneNumberAuthenticator.normalizePhoneNumber("123456789012"));
    }

    @Test
    void testRejects10DigitWithoutTrunkPrefix() {
        // 10 digits but not starting with the local trunk "0" - not a recognized
        // Sri Lankan shape (would otherwise be ambiguous with a foreign number).
        assertNull(PhoneNumberAuthenticator.normalizePhoneNumber("4155551234"));
    }

    @Test
    void testRejects11DigitsWithoutSriLankaCountryCode() {
        // 11 digits but not "94..." - a different country's number, out of scope.
        assertNull(PhoneNumberAuthenticator.normalizePhoneNumber("14155551234"));
    }

    @Test
    void testRejectsEmptyString() {
        assertNull(PhoneNumberAuthenticator.normalizePhoneNumber(""));
    }
}
