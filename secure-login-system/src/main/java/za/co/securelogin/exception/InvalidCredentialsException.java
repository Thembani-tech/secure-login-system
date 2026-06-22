package za.co.securelogin.exception;

/**
 * Thrown when a login attempt fails due to a wrong username or password.
 *
 * SECURITY NOTE: we deliberately use ONE generic exception/message for both
 * "username not found" and "wrong password" cases. If we told the client
 * specifically which one was wrong, an attacker could use that to enumerate
 * valid usernames (a real vulnerability called "user enumeration").
 */
public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException(String message) {
        super(message);
    }
}
