# Secure Login System

A REST API authentication system built in Java/Spring Boot, paired with a
dedicated **security test suite** that actively tries to attack the system
and verifies the defences hold.

This project demonstrates both:
- **Secure development practices** (password hashing, brute-force protection,
  password strength enforcement, tamper-proof session tokens)
- **QA / security testing mindset** (writing tests that simulate real attacks,
  not just "happy path" functionality tests)

## Tech Stack
- Java 17
- Spring Boot 3 (Web, Security, Validation)
- BCrypt password hashing
- JWT (JSON Web Tokens) for stateless session tokens
- JUnit 5 + Mockito for testing
- Maven

## Project Structure

```
src/main/java/za/co/securelogin/
├── SecureLoginApplication.java   - Spring Boot entry point
├── SecurityConfig.java           - Spring Security setup (BCrypt bean, endpoint rules)
├── controller/AuthController.java - REST endpoints
├── model/User.java                - User entity (stores hash, never plain password)
├── service/
│   ├── AuthService.java           - Core register/login business logic
│   └── PasswordValidator.java     - Password strength rules
├── security/
│   ├── PasswordHasher.java        - BCrypt wrapper
│   ├── LoginAttemptTracker.java    - Brute-force lockout logic
│   └── TokenService.java          - JWT issuing/validation
├── dto/                            - Request/response objects
└── exception/                      - Custom exceptions

src/test/java/za/co/securelogin/
├── service/        - Unit tests for business logic
├── security/        - Unit tests for security components
└── security_tests/  - ATTACK SIMULATION test suite:
    ├── SqlInjectionAttackTest.java
    ├── BruteForceAttackTest.java
    ├── WeakPasswordRejectionTest.java
    └── SessionSecurityTest.java
```

## Security Features

| Feature | Why it matters |
|---|---|
| BCrypt password hashing (cost factor 12) | Slow, salted hashing defeats brute-force and rainbow-table attacks |
| Account lockout after 5 failed attempts | Stops automated credential-guessing attacks |
| Password strength validation | Prevents weak/common passwords from ever being set |
| Generic error messages on login failure | Prevents username enumeration |
| Signed JWT session tokens | Tamper-evident; server can verify identity without storing session state |

## Running the Project

```bash
mvn spring-boot:run
```

The API will be available at `http://localhost:8080`.

### Endpoints

**Register**
```
POST /api/auth/register
Content-Type: application/json

{ "username": "alice", "password": "StrongPass1" }
```

**Login**
```
POST /api/auth/login
Content-Type: application/json

{ "username": "alice", "password": "StrongPass1" }
```

## Running the Tests

```bash
mvn test
```

This runs both the standard unit tests AND the security attack simulation
suite in `security_tests/`.

## Design Notes

- **Storage is in-memory** (a `ConcurrentHashMap`), by design, to keep the
  focus on security logic rather than database setup. Restarting the app
  clears all data.
- **JWT signing key** is regenerated on each application start (acceptable
  for a demo project; a production system would load a persistent secret
  from secure configuration).

## Possible Extensions

- Add persistent storage (PostgreSQL/H2) using parameterised queries
- Add rate limiting at the network layer (not just per-account lockout)
- Add multi-factor authentication (MFA)
- Add password reset flow with expiring tokens
- Integrate with the "Have I Been Pwned" breach-check API
