package com.app.api_gateway.security;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class CustomReactiveJwtAuthenticationManager implements ReactiveAuthenticationManager { // Renamed
    private final CustomReactiveUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public CustomReactiveJwtAuthenticationManager(CustomReactiveUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String username = authentication.getName();

        // For JWT auth, we've already validated the token in the converter
        // Just re-use the authorities from the token
        if (authentication.getCredentials() == null) {
            return Mono.just(authentication);
        }

        // This part would be used for username/password authentication
        return userDetailsService.findByUsername(username)
                .filter(userDetails ->
                        passwordEncoder.matches(authentication.getCredentials().toString(), userDetails.getPassword()))
                .map(userDetails ->
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities()));
    }
}