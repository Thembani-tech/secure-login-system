package za.co.securelogin.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import za.co.securelogin.dto.AuthResponse;
import za.co.securelogin.dto.LoginRequest;
import za.co.securelogin.dto.RegisterRequest;
import za.co.securelogin.exception.AccountLockedException;
import za.co.securelogin.exception.InvalidCredentialsException;
import za.co.securelogin.exception.UserAlreadyExistsException;
import za.co.securelogin.service.AuthService;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private AuthService authService;

    // Constructor
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // Register a new user
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(
            @Valid @RequestBody RegisterRequest request) {

        try {
            authService.register(
                    request.getUsername(),
                    request.getPassword()
            );

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(Map.of("message", "User registered successfully"));

        } catch (UserAlreadyExistsException e) {

            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("error", e.getMessage()));

        } catch (IllegalArgumentException e) {

            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    // Login existing user
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(
            @Valid @RequestBody LoginRequest request) {

        try {
            String token = authService.login(
                    request.getUsername(),
                    request.getPassword()
            );

            AuthResponse response = new AuthResponse(
                    request.getUsername(),
                    token,
                    "Login successful"
            );

            return ResponseEntity.ok(response);

        } catch (AccountLockedException e) {

            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("error", e.getMessage()));

        } catch (InvalidCredentialsException e) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", e.getMessage()));
        }
    }
}
