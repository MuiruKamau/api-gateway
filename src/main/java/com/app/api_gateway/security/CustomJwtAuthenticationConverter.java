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
                            return Mono.empty();
                        }

                        Claims claims = jwtUtil.getAllClaimsFromToken(token);
                        String username = claims.getSubject();
                        List<String> roles = claims.get("roles", List.class);

                        List<SimpleGrantedAuthority> authorities = roles.stream()
                                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                                .collect(Collectors.toList());

                        return Mono.just(new UsernamePasswordAuthenticationToken(username, null, authorities));
                    } catch (Exception e) {
                        return Mono.empty();
                    }
                });
    }
}

//package com.app.api_gateway.security;
//
//import org.springframework.security.authentication.ReactiveAuthenticationManager;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
//import org.springframework.stereotype.Component;
//import reactor.core.publisher.Mono;
//
//@Component
//public class CustomReactiveJwtAuthenticationManager implements ReactiveAuthenticationManager {
//    @Override
//    public Mono<Authentication> authenticate(Authentication authentication) {
//        // For JWT authentication, the token is already validated by the JwtAuthenticationConverter
//        // Just return the authentication object as-is
//        return Mono.just(authentication);
//    }
//}

//package com.app.api_gateway.security;
//
//import io.jsonwebtoken.Claims;
//import org.springframework.core.convert.converter.Converter;
//import org.springframework.security.authentication.AbstractAuthenticationToken;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.oauth2.jwt.Jwt;
//import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
//import org.springframework.stereotype.Component;
//import reactor.core.publisher.Mono;
//
//import java.util.Collection;
//import java.util.List;
//import java.util.stream.Collectors;
//
//@Component
//public class CustomJwtAuthenticationConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {
//    private final JwtUtil jwtUtil;
//
//    public CustomJwtAuthenticationConverter(JwtUtil jwtUtil) {
//        this.jwtUtil = jwtUtil;
//    }
//
//    @Override
//    public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
//        Claims claims = jwtUtil.getAllClaimsFromToken(jwt.getTokenValue());
//        List<String> roles = claims.get("roles", List.class);
//        Collection<GrantedAuthority> authorities = roles.stream()
//                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
//                .collect(Collectors.toList());
//
//        return Mono.just(new JwtAuthenticationToken(jwt, authorities));
//    }
//}
//

