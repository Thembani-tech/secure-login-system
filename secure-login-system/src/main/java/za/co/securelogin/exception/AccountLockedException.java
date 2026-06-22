package za.co.securelogin.exception;

/**
 * Thrown when a login attempt is made against an account that has been
 * temporarily locked due to too many consecutive failed attempts.
 */
public class AccountLockedException extends RuntimeException {
    public AccountLockedException(String message) {
        super(message);
    }
}
