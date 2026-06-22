package za.co.securelogin.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PasswordValidatorTest {

    private final PasswordValidator validator = new PasswordValidator();

    @Test
    void strongPassword_passesValidation() {
        List<String> violations = validator.validate("Str0ngPass!");
        assertTrue(violations.isEmpty(), "A strong password should have no violations");
    }

    @Test
    void shortPassword_isRejected() {
        List<String> violations = validator.validate("Sh0rt");
        assertFalse(violations.isEmpty());
        assertTrue(violations.stream().anyMatch(v -> v.contains("8 characters")));
    }

    @Test
    void passwordWithoutUppercase_isRejected() {
        List<String> violations = validator.validate("lowercase123");
        assertTrue(violations.stream().anyMatch(v -> v.contains("uppercase")));
    }

    @Test
    void passwordWithoutLowercase_isRejected() {
        List<String> violations = validator.validate("UPPERCASE123");
        assertTrue(violations.stream().anyMatch(v -> v.contains("lowercase")));
    }

    @Test
    void passwordWithoutDigit_isRejected() {
        List<String> violations = validator.validate("NoDigitsHere");
        assertTrue(violations.stream().anyMatch(v -> v.contains("digit")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"password", "123456", "qwerty", "admin", "Password"})
    void commonPasswords_areRejected(String commonPassword) {
        List<String> violations = validator.validate(commonPassword);
        assertFalse(violations.isEmpty(), "Common password '" + commonPassword + "' should be rejected");
    }

    @Test
    void nullPassword_isRejectedGracefully() {
        List<String> violations = validator.validate(null);
        assertFalse(violations.isEmpty());
    }

    @Test
    void isValid_returnsTrueOnlyForFullyCompliantPassword() {
        assertTrue(validator.isValid("V3ryStrongP@ss"));
        assertFalse(validator.isValid("weak"));
    }
}
