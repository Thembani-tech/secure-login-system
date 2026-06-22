package za.co.securelogin.security_tests;

import za.co.securelogin.security.LoginAttemptTracker;
import za.co.securelogin.security.PasswordHasher;
import za.co.securelogin.security.TokenService;
import za.co.securelogin.service.AuthService;
import za.co.securelogin.service.PasswordValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SECURITY TEST SUITE: Weak / breached password rejection.
 *
 * Verifies the system actively prevents users from setting passwords that
 * are trivially guessable, rather than relying purely on hashing + lockout
 * as the only lines of defence. This is "shifting security left" - stopping
 * a weak credential from ever being created in the first place.
 */
class WeakPasswordRejectionTest {

    private AuthService authService;

    @BeforeEach
    void setUp() {
        PasswordHasher passwordHasher = new PasswordHasher(new BCryptPasswordEncoder(4));
        PasswordValidator passwordValidator = new PasswordValidator();
        LoginAttemptTracker loginAttemptTracker = new LoginAttemptTracker();
        TokenService tokenService = new TokenService();
        authService = new AuthService(passwordHasher, passwordValidator, loginAttemptTracker, tokenService);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "password",      // common password
            "12345678",      // numeric only, no letters
            "abcdefgh",       // lowercase only, no digits/uppercase
            "short1A",        // too short
            "qwerty12"        // common keyboard pattern
    })
    void weakPasswords_areRejectedAtRegistration(String weakPassword) {
        assertThrows(IllegalArgumentException.class,
                () -> authService.register("testuser_" + weakPassword.hashCode(), weakPassword));
    }

    @Test
    void rejectedRegistration_doesNotCreateAccount() {
        String username = "shouldNotExist";
        try {
            authService.register(username, "weak");
        } catch (IllegalArgumentException ignored) {
            // expected
        }
        assertFalse(authService.userExists(username),
                "An account must NOT be created when password validation fails");
    }

    @Test
    void strongPassword_isAcceptedAndAccountIsCreated() {
        String username = "strongPassUser";
        authService.register(username, "Tr0ub4dor&3");
        assertTrue(authService.userExists(username));
    }
}
