package za.co.securelogin.security_tests;

import za.co.securelogin.exception.AccountLockedException;
import za.co.securelogin.exception.InvalidCredentialsException;
import za.co.securelogin.security.LoginAttemptTracker;
import za.co.securelogin.security.PasswordHasher;
import za.co.securelogin.security.TokenService;
import za.co.securelogin.service.AuthService;
import za.co.securelogin.service.PasswordValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SECURITY TEST SUITE: Brute-force / credential-guessing attacks.
 *
 * Simulates an attacker (or automated script) repeatedly guessing passwords
 * for a known username, and verifies the system's lockout defence kicks in
 * and HOLDS even when the attacker eventually guesses the correct password.
 */
class BruteForceAttackTest {

    private AuthService authService;
    private static final String VICTIM_USERNAME = "victim";
    private static final String VICTIM_REAL_PASSWORD = "RealPassword1";

    @BeforeEach
    void setUp() {
        PasswordHasher passwordHasher = new PasswordHasher(new BCryptPasswordEncoder(4));
        PasswordValidator passwordValidator = new PasswordValidator();
        LoginAttemptTracker loginAttemptTracker = new LoginAttemptTracker();
        TokenService tokenService = new TokenService();
        authService = new AuthService(passwordHasher, passwordValidator, loginAttemptTracker, tokenService);

        authService.register(VICTIM_USERNAME, VICTIM_REAL_PASSWORD);
    }

    @Test
    void simulatedBruteForceAttack_getsLockedOutBeforeExhaustingAttempts() {
        // A small "dictionary" of guesses an attacker script might try.
        List<String> attackerGuesses = List.of(
                "password1", "123456789", "qwerty123", "letmein123",
                "iloveyou1", "admin12345", "welcome123", "monkey1234",
                "dragon1234", "football12"
        );

        int blockedAttempts = 0;

        for (String guess : attackerGuesses) {
            try {
                authService.login(VICTIM_USERNAME, guess);
                fail("None of the attacker's guesses should be correct in this test");
            } catch (InvalidCredentialsException e) {
                // expected: wrong guess, attempt counted
            } catch (AccountLockedException e) {
                // expected once the threshold is crossed
                blockedAttempts++;
            }
        }

        // The attack had more guesses than MAX_ATTEMPTS, so at least some
        // of the later guesses must have been blocked by the lockout,
        // proving the attacker could NOT exhaustively try every guess.
        assertTrue(blockedAttempts > 0,
                "Brute-force attack should be interrupted by account lockout");
    }

    @Test
    void evenCorrectPassword_isRejectedWhileAccountIsLocked() {
        // Exhaust the allowed attempts with wrong guesses first.
        for (int i = 0; i < LoginAttemptTracker.getMaxAttempts(); i++) {
            try {
                authService.login(VICTIM_USERNAME, "wrongGuess" + i);
            } catch (InvalidCredentialsException ignored) {
            }
        }

        // This is the critical security property: lockout is based on
        // FAILED ATTEMPT COUNT, not on "have they found the right password
        // yet" - so even the legitimate owner must wait it out (a deliberate
        // trade-off between security and convenience).
        assertThrows(AccountLockedException.class,
                () -> authService.login(VICTIM_USERNAME, VICTIM_REAL_PASSWORD));
    }

    @Test
    void lockoutDoesNotLeakWhetherUsernameExists() {
        // An attacker should not be able to distinguish "this username
        // doesn't exist" from "wrong password for an existing username"
        // based on the exception type alone - both surface as
        // InvalidCredentialsException with the same generic message.
        Exception nonExistentUserException = assertThrows(InvalidCredentialsException.class,
                () -> authService.login("totallyMadeUpUser", "SomePassword1"));

        Exception wrongPasswordException = assertThrows(InvalidCredentialsException.class,
                () -> authService.login(VICTIM_USERNAME, "WrongPassword1"));

        assertEquals(nonExistentUserException.getMessage(), wrongPasswordException.getMessage(),
                "Error messages must not reveal whether the username exists");
    }
}
