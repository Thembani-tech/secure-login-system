package za.co.securelogin.security;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * Tracks failed login attempts per username and temporarily locks accounts
 * that exceed a maximum number of consecutive failures.
 *
 * WHY THIS MATTERS (brute-force attacks):
 * Without this, an attacker (or script) could try millions of password
 * guesses against one username with no consequence. By locking the account
 * after a small number of failures, we make automated guessing impractical.
 *
 * Design notes:
 *  - This is in-memory (ConcurrentHashMap) to match the project's in-memory
 *    storage choice. In a production system this would typically live in
 *    a database or distributed cache (e.g. Redis) so it survives restarts
 *    and works across multiple server instances.
 *  - ConcurrentHashMap is used (not HashMap) because multiple login requests
 *    could arrive at the same time on different threads; ConcurrentHashMap
 *    is thread-safe.
 */
@Component
public class LoginAttemptTracker {

    private static final int MAX_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION_SECONDS = 60; // 1 minute lockout

    private final Map<String, Integer> failedAttempts = new ConcurrentHashMap<>();
    private final Map<String, Instant> lockoutUntil = new ConcurrentHashMap<>();

    /**
     * Records a failed login attempt for the given username.
     * If this attempt pushes the user over the threshold, the account is locked.
     */
    public void recordFailedAttempt(String username) {
        int attempts = failedAttempts.merge(username, 1, Integer::sum);
        if (attempts >= MAX_ATTEMPTS) {
            lockoutUntil.put(username, Instant.now().plusSeconds(LOCKOUT_DURATION_SECONDS));
        }
    }

    /**
     * Clears failed-attempt tracking for a user, called after a successful login.
     */
    public void recordSuccessfulLogin(String username) {
        failedAttempts.remove(username);
        lockoutUntil.remove(username);
    }

    /**
     * Returns true if the given username is currently locked out.
     * Automatically clears the lockout once it has expired.
     */
    public boolean isLockedOut(String username) {
        Instant lockedUntil = lockoutUntil.get(username);
        if (lockedUntil == null) {
            return false;
        }
        if (Instant.now().isAfter(lockedUntil)) {
            // Lockout period has expired - reset state.
            lockoutUntil.remove(username);
            failedAttempts.remove(username);
            return false;
        }
        return true;
    }

    /**
     * Returns the current number of consecutive failed attempts for a user.
     * Exposed mainly for testing/inspection.
     */
    public int getFailedAttemptCount(String username) {
        return failedAttempts.getOrDefault(username, 0);
    }

    public static int getMaxAttempts() {
        return MAX_ATTEMPTS;
    }
}
