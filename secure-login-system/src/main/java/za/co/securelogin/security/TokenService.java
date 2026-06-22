package za.co.securelogin.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

/**
 * Issues and validates simple JWT tokens used to represent a logged-in session.
 *
 * WHY TOKENS INSTEAD OF SERVER-SIDE SESSIONS?
 * This is a stateless REST API (no server-side session storage). A signed
 * JWT lets the server verify a client's identity on each request WITHOUT
 * storing any session state in memory or a database - the token itself
 * carries the (signed, tamper-proof) claim of who the user is.
 *
 * SECURITY NOTE: the signing key below is generated fresh each time the
 * application starts, purely for demo purposes. In a real production system
 * the key would be a long-lived secret loaded from a secure config/vault,
 * NOT regenerated on every restart (otherwise all previously issued tokens
 * become invalid whenever the server restarts).
 */
@Component
public class TokenService {

    private final SecretKey signingKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_MS = 15 * 60 * 1000; // 15 minutes

    /**
     * Generates a signed token for the given username.
     */
    public String generateToken(String username) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + EXPIRATION_MS);

        return Jwts.builder()
                .subject(username)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(signingKey)
                .compact();
    }

    /**
     * Validates a token's signature and expiry.
     * Returns the username embedded in the token if valid.
     * Throws JwtException (or a subclass) if the token is invalid, tampered
     * with, or expired.
     */
    public String validateTokenAndGetUsername(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claims.getSubject();
    }

    public boolean isTokenValid(String token) {
        try {
            validateTokenAndGetUsername(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
