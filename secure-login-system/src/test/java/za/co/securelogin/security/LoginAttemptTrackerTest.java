package za.co.securelogin.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class LoginAttemptTrackerTest {

    private LoginAttemptTracker tracker;

    @BeforeEach
    void setUp() {
        tracker = new LoginAttemptTracker();
    }

    @Test
    void newUser_isNotLockedOut() {
        assertFalse(tracker.isLockedOut("newuser"));
    }

    @Test
    void recordFailedAttempt_incrementsCount() {
        tracker.recordFailedAttempt("alice");
        tracker.recordFailedAttempt("alice");
        assertEquals(2, tracker.getFailedAttemptCount("alice"));
    }

    @Test
    void accountLocksAfterMaxFailedAttempts() {
        String username = "bob";
        for (int i = 0; i < LoginAttemptTracker.getMaxAttempts(); i++) {
            tracker.recordFailedAttempt(username);
        }
        assertTrue(tracker.isLockedOut(username), "Account should be locked after reaching max attempts");
    }

    @Test
    void accountNotLockedBeforeMaxAttemptsReached() {
        String username = "carol";
        for (int i = 0; i < LoginAttemptTracker.getMaxAttempts() - 1; i++) {
            tracker.recordFailedAttempt(username);
        }
        assertFalse(tracker.isLockedOut(username), "Account should not be locked before reaching the threshold");
    }

    @Test
    void successfulLogin_resetsFailedAttemptCount() {
        String username = "dave";
        tracker.recordFailedAttempt(username);
        tracker.recordFailedAttempt(username);
        tracker.recordSuccessfulLogin(username);
        assertEquals(0, tracker.getFailedAttemptCount(username));
        assertFalse(tracker.isLockedOut(username));
    }

    @Test
    void differentUsernames_areTrackedIndependently() {
        for (int i = 0; i < LoginAttemptTracker.getMaxAttempts(); i++) {
            tracker.recordFailedAttempt("attacker");
        }
        assertTrue(tracker.isLockedOut("attacker"));
        assertFalse(tracker.isLockedOut("innocentUser"), "Locking one account must not affect another");
    }
}
