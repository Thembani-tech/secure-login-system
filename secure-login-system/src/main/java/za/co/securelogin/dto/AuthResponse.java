package za.co.securelogin.dto;

/**
 * Response body returned after a successful login.
 * Contains a token the client would attach to future requests
 * (e.g. as an "Authorization: Bearer <token>" header).
 */
public class AuthResponse {

    private String username;
    private String token;
    private String message;

    public AuthResponse(String username, String token, String message) {
        this.username = username;
        this.token = token;
        this.message = message;
    }

    public String getUsername() {
        return username;
    }

    public String getToken() {
        return token;
    }

    public String getMessage() {
        return message;
    }
}
