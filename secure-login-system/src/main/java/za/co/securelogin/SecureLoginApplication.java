package za.co.securelogin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the Secure Login System.
 *
 * Running this class starts an embedded web server (default port 8080)
 * and exposes the REST endpoints defined in AuthController.
 */
@SpringBootApplication
public class SecureLoginApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecureLoginApplication.class, args);
    }
}
