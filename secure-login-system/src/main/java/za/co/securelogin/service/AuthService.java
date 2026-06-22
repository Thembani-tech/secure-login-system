package za.co.securelogin.service;

import za.co.securelogin.exception.AccountLockedException;
import za.co.securelogin.exception.InvalidCredentialsException;
import za.co.securelogin.exception.UserAlreadyExistsException;
import za.co.securelogin.model.User;
import za.co.securelogin.security.LoginAttemptTracker;
import za.co.securelogin.security.PasswordHasher;
import za.co.securelogin.security.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Core authentication business logic: registration and login.
 *
 * Storage is in-memory (ConcurrentHashMap) by design for this project -
 * there is no database. This keeps the focus on the SECURITY logic rather
 * than persistence concerns. All data is lost when the application stops.
 */
@Service
public class AuthService {

    // username -> User. ConcurrentHashMap because multiple HTTP requests
    // (register/login) can run concurrently on different threads.
    private final Map<String, User> users = new ConcurrentHashMap<>();

    private final PasswordHasher passwordHasher;
    private final PasswordValidator passwordValidator;
    private final LoginAttemptTracker loginAttemptTracker;
    private final TokenService tokenService;

    @Autowired
    public AuthService(PasswordHasher passwordHasher,
                        PasswordValidator passwordValidator,
                        LoginAttemptTracker loginAttemptTracker,
                        TokenService tokenService) {
        this.passwordHasher = passwordHasher;
        this.passwordValidator = passwordValidator;
        this.loginAttemptTracker = loginAttemptTracker;
        this.tokenService = tokenService;
    }

    /**
     * Registers a new user.
     *
     * @throws UserAlreadyExistsException if the username is taken
     * @throws IllegalArgumentException   if the password fails strength validation
     */
    public User register(String username, String plainPassword) {
        if (users.containsKey(username)) {
            throw new UserAlreadyExistsException("Username '" + username + "' is already taken");
        }

        List<String> violations = passwordValidator.validate(plainPassword);
        if (!violations.isEmpty()) {
            throw new IllegalArgumentException(String.join("; ", violations));
        }

        String hashed = passwordHasher.hash(plainPassword);
        User user = new User(username, hashed);
        users.put(username, user);
        return user;
    }

    /**
     * Attempts to log a user in.
     *
     * @return a signed session token on success
     * @throws AccountLockedException      if the account is temporarily locked
     * @throws InvalidCredentialsException if username/password is wrong
     */
    public String login(String username, String plainPassword) {
        if (loginAttemptTracker.isLockedOut(username)) {
            throw new AccountLockedException(
                    "Account is temporarily locked due to too many failed login attempts. Try again later.");
        }

        User user = users.get(username);

        // SECURITY NOTE: even if the user doesn't exist, we still run a
        // password check against a dummy hash. This keeps the response
        // timing similar for "user not found" vs "wrong password", which
        // helps prevent timing-based user enumeration attacks.
        String hashToCheck = (user != null)
                ? user.getPasswordHash()
                : "$2a$12$invalidsaltinvalidsaltinvalidsaltinvalidsaltinvalidsa";

        boolean passwordMatches = passwordHasher.matches(plainPassword, hashToCheck);

        if (user == null || !passwordMatches) {
            loginAttemptTracker.recordFailedAttempt(username);
            throw new InvalidCredentialsException("Invalid username or password");
        }

        loginAttemptTracker.recordSuccessfulLogin(username);
        return tokenService.generateToken(username);
    }

    /**
     * Exposed for testing/inspection - not a security-sensitive operation.
     */
    public boolean userExists(String username) {
        return users.containsKey(username);
    }
}
