package com.app.api_gateway.security;

import com.app.api_gateway.authentication.User;
import com.app.api_gateway.authentication.UserRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    // Injected from application.yml or environment variables
    @Value("${jwt.secret}")
    private String SECRET_KEY;

    private final SecretKey key;  // Use a SecretKey for signing

    @Autowired
    private UserRepository userRepository;

    public JwtUtil(@Value("${jwt.secret}") String secretKey) {
        this.SECRET_KEY = secretKey;
        this.key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes()); // Initialize key in constructor
    }

    /**
     * Generates a JWT token for the given username.
     *
     * @param username The username for which the token is generated.
     * @return The generated JWT token.
     */
    public String generateToken(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", user.getRoles().stream().map(Enum::name).collect(Collectors.toList()));

        logger.info("Generating token for user: {}", username);
        logger.debug("Roles in token: {}", claims.get("roles"));

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24)) // 24 hours
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Extracts the username from the JWT token.
     *
     * @param token The JWT token.
     * @return The username extracted from the token.
     */
    public String getUsernameFromToken(String token) {
        return getAllClaimsFromToken(token).getSubject();
    }

    /**
     * Extracts all claims from the JWT token.
     *
     * @param token The JWT token.
     * @return The claims contained in the token.
     */
    public Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Validates the JWT token.
     *
     * @param authHeader The Authorization header containing the JWT token.
     * @return True if the token is valid, false otherwise.
     */
    public boolean validateToken(String authHeader) {
        if (authHeader == null) {
            logger.warn("Authorization header is null");
            return false;
        }

        String token = authHeader;
        // If it has the Bearer prefix, remove it
        if (authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        }

        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            boolean expired = isTokenExpired(token);
            if (expired) {
                logger.warn("Token is expired: {}", token);
            }
            return !expired;
        } catch (JwtException | IllegalArgumentException e) {
            logger.error("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Checks if the JWT token is expired.
     *
     * @param token The JWT token.
     * @return True if the token is expired, false otherwise.
     */
    private boolean isTokenExpired(String token) {
        Date expiration = getAllClaimsFromToken(token).getExpiration();
        return expiration.before(new Date());
    }

    /**
     * Returns the secret key used for signing the JWT tokens.
     *
     * @return The secret key.
     */
    public SecretKey getSecretKey() {
        return key;
    }
}


//package com.app.api_gateway.security;
//
//import com.app.api_gateway.authentication.User;
//import com.app.api_gateway.authentication.UserRepository;
//import io.jsonwebtoken.*;
//import io.jsonwebtoken.security.Keys;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Component;
//
//import javax.crypto.SecretKey;
//import java.util.Date;
//import java.util.HashMap;
//import java.util.Map;
//import java.util.stream.Collectors;
//
//@Component
//public class JwtUtil {
//
//    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);
//
//    // Injected from application.yml or environment variables
//    @Value("${jwt.secret}")
//    private String SECRET_KEY;
//
//    private final SecretKey key;  // Use a SecretKey for signing
//
//    @Autowired
//    private UserRepository userRepository;
//
//    public JwtUtil(@Value("${jwt.secret}") String secretKey) {
//        this.SECRET_KEY = secretKey;
//        this.key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes()); // Initialize key in constructor
//    }
//
//    /**
//     * Generates a JWT token for the given username.
//     *
//     * @param username The username for which the token is generated.
//     * @return The generated JWT token.
//     */
//    public String generateToken(String username) {
//        User user = userRepository.findByUsername(username)
//                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
//
//        Map<String, Object> claims = new HashMap<>();
//        claims.put("roles", user.getRoles().stream().map(Enum::name).collect(Collectors.toList()));
//
//        logger.info("Generating token for user: {}", username);
//        logger.debug("Roles in token: {}", claims.get("roles"));
//
//        return Jwts.builder()
//                .setClaims(claims)
//                .setSubject(username)
//                .setIssuedAt(new Date())
//                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24)) // 24 hours
//                .signWith(key, SignatureAlgorithm.HS256)
//                .compact();
//    }
//
//    /**
//     * Extracts the username from the JWT token.
//     *
//     * @param token The JWT token.
//     * @return The username extracted from the token.
//     */
//    public String getUsernameFromToken(String token) {
//        return getAllClaimsFromToken(token).getSubject();
//    }
//
//    /**
//     * Extracts all claims from the JWT token.
//     *
//     * @param token The JWT token.
//     * @return The claims contained in the token.
//     */
//    public Claims getAllClaimsFromToken(String token) {
//        return Jwts.parserBuilder()
//                .setSigningKey(key)
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//    }
//
//    /**
//     * Validates the JWT token.
//     *
//     * @param authHeader The Authorization header containing the JWT token.
//     * @return True if the token is valid, false otherwise.
//     */
//    public boolean validateToken(String authHeader) {
//        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
//            logger.warn("Invalid Authorization header: {}", authHeader);
//            return false;
//        }
//        try {
//            String token = authHeader.substring(7);
//            Jwts.parserBuilder()
//                    .setSigningKey(key)
//                    .build()
//                    .parseClaimsJws(token); // Check signature and expiry
//
//            boolean expired = isTokenExpired(token);
//            if (expired) {
//                logger.warn("Token is expired: {}", token);
//            }
//
//            return !expired;
//        } catch (JwtException | IllegalArgumentException e) {
//            logger.error("Token validation failed: {}", e.getMessage());
//            return false;
//        }
//    }
//
//    /**
//     * Checks if the JWT token is expired.
//     *
//     * @param token The JWT token.
//     * @return True if the token is expired, false otherwise.
//     */
//    private boolean isTokenExpired(String token) {
//        Date expiration = getAllClaimsFromToken(token).getExpiration();
//        return expiration.before(new Date());
//    }
//
//    /**
//     * Returns the secret key used for signing the JWT tokens.
//     *
//     * @return The secret key.
//     */
//    public SecretKey getSecretKey() {
//        return key;
//    }
//}