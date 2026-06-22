package za.co.securelogin.model;

/**
 * Represents a registered user.
 *
 * IMPORTANT: passwordHash stores a BCrypt hash, NEVER the plain-text password.
 * The raw password is never kept in memory longer than it takes to hash it.
 */
public class User {

    private final String username;
    private String passwordHash;

    public User(String username, String passwordHash) {
        this.username = username;
        this.passwordHash = passwordHash;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }
}
