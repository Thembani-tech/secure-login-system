package za.co.securelogin.security;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Wraps Spring Security's BCryptPasswordEncoder.
 *
 * WHY BCRYPT (and not MD5/SHA-256 alone)?
 *  - BCrypt is a "slow" hashing algorithm by design. Fast hashes like MD5/SHA-256
 *    let attackers try billions of password guesses per second on stolen hashes.
 *    BCrypt deliberately takes longer per hash, making brute-forcing impractical.
 *  - BCrypt automatically generates and stores a random "salt" with each hash,
 *    so two users with the same password get completely different hashes.
 *    This defeats precomputed "rainbow table" attacks.
 */
@Component
public class PasswordHasher {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public PasswordHasher(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Hashes a plain-text password. The result is safe to store.
     */
    public String hash(String plainPassword) {
        return passwordEncoder.encode(plainPassword);
    }

    /**
     * Checks a plain-text password against a previously stored hash.
     * Returns true only if they match.
     */
    public boolean matches(String plainPassword, String hashedPassword) {
        return passwordEncoder.matches(plainPassword, hashedPassword);
    }
}
