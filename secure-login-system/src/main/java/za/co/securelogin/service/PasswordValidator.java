package za.co.securelogin.service;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

/**
 * Validates password strength against a set of rules BEFORE the password
 * is ever hashed or stored.
 *
 * Rules enforced:
 *  1. Minimum length of 8 characters.
 *  2. Must contain at least one uppercase letter.
 *  3. Must contain at least one lowercase letter.
 *  4. Must contain at least one digit.
 *  5. Must not be a commonly used / breached password (a small denylist here;
 *     a real system might check against the "Have I Been Pwned" API).
 *
 * Returning a list of violation messages (rather than throwing on the first
 * failure) gives the user clear, complete feedback in one response.
 */
@Component
public class PasswordValidator {

    private static final int MIN_LENGTH = 8;

    // A small sample of extremely common passwords. In a production system
    // this list would be much larger or backed by an external breach-check API.
    private static final Set<String> COMMON_PASSWORDS = Set.of(
            "password", "123456", "12345678", "qwerty", "abc123",
            "password1", "letmein", "admin", "welcome", "monkey"
    );

    /**
     * Validates the given plain-text password.
     *
     * @return a list of human-readable violation messages.
     *         An empty list means the password passed all checks.
     */
    public List<String> validate(String password) {
        List<String> violations = new java.util.ArrayList<>();

        if (password == null || password.length() < MIN_LENGTH) {
            violations.add("Password must be at least " + MIN_LENGTH + " characters long");
        }
        if (password != null) {
            if (!password.chars().anyMatch(Character::isUpperCase)) {
                violations.add("Password must contain at least one uppercase letter");
            }
            if (!password.chars().anyMatch(Character::isLowerCase)) {
                violations.add("Password must contain at least one lowercase letter");
            }
            if (!password.chars().anyMatch(Character::isDigit)) {
                violations.add("Password must contain at least one digit");
            }
            if (COMMON_PASSWORDS.contains(password.toLowerCase())) {
                violations.add("Password is too common and easily guessed");
            }
        }

        return violations;
    }

    public boolean isValid(String password) {
        return validate(password).isEmpty();
    }
}
