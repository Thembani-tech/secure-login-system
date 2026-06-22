package za.co.securelogin.security_tests;

import za.co.securelogin.exception.InvalidCredentialsException;
import za.co.securelogin.exception.UserAlreadyExistsException;
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
 * SECURITY TEST SUITE: Injection-style attacks.
 *
 * This system has no SQL database (storage is in-memory), so classical SQL
 * injection cannot literally execute here. However, these tests document
 * and verify the DEFENSIVE PRINCIPLE that matters regardless of storage
 * backend: user-supplied input is NEVER concatenated into a command/query
 * and is always treated as plain data, not executable code.
 *
 * If this project were extended to use a real database, these same test
 * cases would be the starting point for verifying that JPA/parameterised
 * queries (not string concatenation) are used everywhere.
 */
class SqlInjectionAttackTest {

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
            "' OR '1'='1",
            "admin'--",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --"
    })
    void classicSqlInjectionPayloads_areTreatedAsLiteralUsernames_notExecuted(String payload) {
        // Attempting to log in with a SQLi payload as the username should
        // simply fail like any other non-existent user - NOT throw a SQL
        // error, NOT bypass authentication, NOT return another user's data.
        assertThrows(InvalidCredentialsException.class,
                () -> authService.login(payload, "irrelevantPassword1"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "' OR '1'='1",
            "'; DROP TABLE users; --"
    })
    void sqlInjectionPayload_canBeUsedAsLiteralUsernameForRegistration(String payload) {
        // The system should happily accept these as plain strings during
        // registration (proving they're never interpreted as code), and
        // then behave completely normally for subsequent login.
        authService.register(payload, "StrongPass1");
        assertTrue(authService.userExists(payload));

        String token = authService.login(payload, "StrongPass1");
        assertNotNull(token);
    }

    @Test
    void duplicateRegistrationWithInjectionPayload_isStillBlockedNormally() {
        String payload = "' OR '1'='1";
        authService.register(payload, "StrongPass1");

        assertThrows(UserAlreadyExistsException.class,
                () -> authService.register(payload, "AnotherPass1"));
    }
}
