package za.co.securelogin;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security configuration for the application.
 *
 * By default, Spring Security locks down every endpoint and serves its own
 * login form. Since we are building our OWN authentication system (custom
 * register/login endpoints, our own password hashing, our own lockout logic),
 * we override that default behaviour here:
 *
 *  - permitAll() on /api/auth/** so our custom controller handles auth, not Spring's.
 *  - CSRF disabled because this is a stateless REST API using tokens, not cookies/forms.
 *  - A BCryptPasswordEncoder bean is exposed so it can be injected wherever we
 *    need to hash or verify passwords (see PasswordHasher).
 */
@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Strength 12 = good balance of security vs. performance for a learning project.
        // Higher = slower to compute = harder to brute force.
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .anyRequest().authenticated()
            );
        return http.build();
    }
}
