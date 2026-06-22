package za.co.securelogin.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

class PasswordHasherTest {

    private PasswordHasher passwordHasher;

    @BeforeEach
    void setUp() {
        passwordHasher = new PasswordHasher(new BCryptPasswordEncoder(12));
    }

    @Test
    void hash_neverReturnsThePlainTextPassword() {
        String plain = "MySecretPass1";
        String hashed = passwordHasher.hash(plain);
        assertNotEquals(plain, hashed, "Hashed password must not equal the plain-text password");
    }

    @Test
    void hash_producesDifferentHashesForSamePassword() {
        // This proves BCrypt is salting each hash - critical defence against
        // rainbow-table attacks and against spotting "users with same password".
        String plain = "MySecretPass1";
        String hash1 = passwordHasher.hash(plain);
        String hash2 = passwordHasher.hash(plain);
        assertNotEquals(hash1, hash2, "Same password hashed twice should produce different hashes (salting)");
    }

    @Test
    void matches_returnsTrueForCorrectPassword() {
        String plain = "MySecretPass1";
        String hashed = passwordHasher.hash(plain);
        assertTrue(passwordHasher.matches(plain, hashed));
    }

    @Test
    void matches_returnsFalseForIncorrectPassword() {
        String hashed = passwordHasher.hash("CorrectPassword1");
        assertFalse(passwordHasher.matches("WrongPassword1", hashed));
    }

    @Test
    void hashedPassword_looksLikeBCryptFormat() {
        String hashed = passwordHasher.hash("AnyPassword1");
        // BCrypt hashes start with $2a$, $2b$ or $2y$ followed by the cost factor
        assertTrue(hashed.matches("^\\$2[aby]\\$.*"), "Hash should be in BCrypt format");
    }
}
