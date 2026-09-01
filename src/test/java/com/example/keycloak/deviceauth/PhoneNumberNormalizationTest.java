package com.example.keycloak.deviceauth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PhoneNumberNormalizationTest {

    @Test
    void testNormalizePhoneNumberWithCountryCode() {
        assertEquals("+14155551234", PhoneNumberAuthenticator.normalizePhoneNumber("+14155551234"));
    }

    @Test
    void testNormalizePhoneNumberWithoutCountryCode() {
        assertEquals("+4155551234", PhoneNumberAuthenticator.normalizePhoneNumber("4155551234"));
    }

    @Test
    void testNormalizePhoneNumberWithSpaces() {
        assertEquals("+14155551234", PhoneNumberAuthenticator.normalizePhoneNumber("+1 415 555 1234"));
    }

    @Test
    void testNormalizePhoneNumberWithDashes() {
        assertEquals("+14155551234", PhoneNumberAuthenticator.normalizePhoneNumber("+1-415-555-1234"));
    }

    @Test
    void testNormalizePhoneNumberWithParens() {
        assertEquals("+14155551234", PhoneNumberAuthenticator.normalizePhoneNumber("+1 (415) 555-1234"));
    }

    @Test
    void testNormalizePhoneNumberWithDots() {
        assertEquals("+14155551234", PhoneNumberAuthenticator.normalizePhoneNumber("+1.415.555.1234"));
    }

    @Test
    void testNormalizePhoneNumberNull() {
        assertNull(PhoneNumberAuthenticator.normalizePhoneNumber(null));
    }

    @Test
    void testNormalizePhoneNumberInternationalFormat() {
        assertEquals("+447911123456", PhoneNumberAuthenticator.normalizePhoneNumber("447911123456"));
    }

    @Test
    void testNormalizePhoneNumberAlreadyNormalized() {
        assertEquals("+12025551234", PhoneNumberAuthenticator.normalizePhoneNumber("+12025551234"));
    }
}
