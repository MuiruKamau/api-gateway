package com.app.api_gateway.security;

import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class CustomJwtAuthenticationConverter implements ServerAuthenticationConverter {

    private final JwtUtil jwtUtil;

    public CustomJwtAuthenticationConverter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        return Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst("Authorization"))
                .filter(authHeader -> authHeader.startsWith("Bearer "))
                .map(authHeader -> authHeader.substring(7))
                .filter(token -> !token.isEmpty())
                .flatMap(token -> {
                    try {
                        if (!jwtUtil.validateToken(token)) {
                            System.out.println("Token validation failed");
                            return Mono.empty();
                        }

                        Claims claims = jwtUtil.getAllClaimsFromToken(token);
                        String username = claims.getSubject();
                        List<String> roles = claims.get("roles", List.class);

                        // Add user information to headers
                        exchange.getRequest().mutate()
                                .header("X-User-Username", username)
                                .header("X-User-Roles", String.join(",", roles))
                                .build();
                        System.out.println("Adding headers - Username: " + username + ", Roles: " + String.join(",", roles));

                        List<SimpleGrantedAuthority> authorities = roles.stream()
                                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                                .collect(Collectors.toList());

                        return Mono.just(new UsernamePasswordAuthenticationToken(username, null, authorities));
                    } catch (Exception e) {
                        System.out.println("Exception during token parsing: " + e.getMessage());
                        return Mono.empty();
                    }
                });
    }
}





