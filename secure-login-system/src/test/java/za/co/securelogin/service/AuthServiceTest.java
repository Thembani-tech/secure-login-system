package za.co.securelogin.service;

import za.co.securelogin.exception.AccountLockedException;
import za.co.securelogin.exception.InvalidCredentialsException;
import za.co.securelogin.exception.UserAlreadyExistsException;
import za.co.securelogin.security.LoginAttemptTracker;
import za.co.securelogin.security.PasswordHasher;
import za.co.securelogin.security.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

class AuthServiceTest {

    private AuthService authService;

    @BeforeEach
    void setUp() {
        // Using real collaborators (not mocks) here since they are fast,
        // deterministic-enough, and this gives more confidence the whole
        // flow works end-to-end at the service layer.
        PasswordHasher passwordHasher = new PasswordHasher(new BCryptPasswordEncoder(4)); // low cost for fast tests
        PasswordValidator passwordValidator = new PasswordValidator();
        LoginAttemptTracker loginAttemptTracker = new LoginAttemptTracker();
        TokenService tokenService = new TokenService();

        authService = new AuthService(passwordHasher, passwordValidator, loginAttemptTracker, tokenService);
    }

    @Test
    void register_succeedsWithValidUsernameAndStrongPassword() {
        authService.register("alice", "StrongPass1");
        assertTrue(authService.userExists("alice"));
    }

    @Test
    void register_throwsWhenUsernameAlreadyTaken() {
        authService.register("bob", "StrongPass1");
        assertThrows(UserAlreadyExistsException.class,
                () -> authService.register("bob", "AnotherPass1"));
    }

    @Test
    void register_throwsWhenPasswordIsWeak() {
        assertThrows(IllegalArgumentException.class,
                () -> authService.register("carol", "weak"));
    }

    @Test
    void login_succeedsWithCorrectCredentials() {
        authService.register("dave", "StrongPass1");
        String token = authService.login("dave", "StrongPass1");
        assertNotNull(token);
        assertFalse(token.isBlank());
    }

    @Test
    void login_throwsForWrongPassword() {
        authService.register("erin", "StrongPass1");
        assertThrows(InvalidCredentialsException.class,
                () -> authService.login("erin", "WrongPassword1"));
    }

    @Test
    void login_throwsForNonExistentUser() {
        assertThrows(InvalidCredentialsException.class,
                () -> authService.login("ghost", "AnyPassword1"));
    }

    @Test
    void login_locksAccountAfterTooManyFailedAttempts() {
        authService.register("frank", "StrongPass1");

        for (int i = 0; i < LoginAttemptTracker.getMaxAttempts(); i++) {
            try {
                authService.login("frank", "WrongPassword");
            } catch (InvalidCredentialsException ignored) {
                // expected on each failed attempt
            }
        }

        // Even with the CORRECT password now, the account should be locked.
        assertThrows(AccountLockedException.class,
                () -> authService.login("frank", "StrongPass1"));
    }
}
