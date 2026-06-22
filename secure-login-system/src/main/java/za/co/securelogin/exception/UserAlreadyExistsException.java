package za.co.securelogin.exception;

/**
 * Thrown when attempting to register a username that is already taken.
 */
public class UserAlreadyExistsException extends RuntimeException {
    public UserAlreadyExistsException(String message) {
        super(message);
    }
}
