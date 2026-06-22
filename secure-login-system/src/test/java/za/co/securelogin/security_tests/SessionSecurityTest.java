package za.co.securelogin.security_tests;

import za.co.securelogin.security.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * SECURITY TEST SUITE: Session/token security.
 *
 * Verifies properties of the JWT session tokens issued on successful login:
 * tokens must be tamper-evident (any modification invalidates them) and
 * must not be trivially forgeable.
 */
class SessionSecurityTest {

    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        tokenService = new TokenService();
    }

    @Test
    void validToken_isAccepted() {
        String token = tokenService.generateToken("alice");
        assertTrue(tokenService.isTokenValid(token));
        assertEquals("alice", tokenService.validateTokenAndGetUsername(token));
    }

    @Test
    void tamperedToken_isRejected() {
        String token = tokenService.generateToken("alice");

        // Simulate an attacker flipping a character in the token's payload
        // section, attempting to change the embedded username without
        // knowing the signing key.
        String tampered = tamperWithPayload(token);

        assertFalse(tokenService.isTokenValid(tampered),
                "A tampered token must be rejected - signature check should fail");
    }

    @Test
    void completelyForgedToken_isRejected() {
        String forgedToken = "this.is.not.a.real.jwt.token";
        assertFalse(tokenService.isTokenValid(forgedToken));
    }

    @Test
    void emptyOrNullToken_isRejectedGracefully() {
        assertFalse(tokenService.isTokenValid(""));
        assertFalse(tokenService.isTokenValid(null));
    }

    @Test
    void tokensForDifferentUsers_areDifferent() {
        String tokenAlice = tokenService.generateToken("alice");
        String tokenBob = tokenService.generateToken("bob");
        assertNotEquals(tokenAlice, tokenBob);
    }

    /**
     * Helper that mutates one character in the middle of the token string,
     * simulating naive tampering. JWTs are base64url-encoded and signed,
     * so even a single flipped character should break the signature check.
     */
    private String tamperWithPayload(String token) {
        int midPoint = token.length() / 2;
        char originalChar = token.charAt(midPoint);
        char replacement = (originalChar == 'A') ? 'B' : 'A';
        return token.substring(0, midPoint) + replacement + token.substring(midPoint + 1);
    }
}
