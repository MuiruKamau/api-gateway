//package com.app.api_gateway.config;
//
//import com.app.api_gateway.security.CustomJwtAuthenticationConverter;
//import com.app.api_gateway.security.JwtUtil;
//import com.app.api_gateway.security.CustomReactiveJwtAuthenticationManager;
//import com.app.api_gateway.security.CustomReactiveUserDetailsService;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.Primary;
//import org.springframework.http.HttpMethod;
//import org.springframework.http.HttpStatus;
//import org.springframework.security.authentication.ReactiveAuthenticationManager;
//import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
//import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
//import org.springframework.security.config.web.server.ServerHttpSecurity;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.server.SecurityWebFilterChain;
//import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
//import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
//import reactor.core.publisher.Mono;
//
//@Configuration
//@EnableWebFluxSecurity
//public class SecurityConfig {
//
//    private final JwtUtil jwtUtil;
//    private final CustomReactiveUserDetailsService userDetailsService;
//
//    public SecurityConfig(JwtUtil jwtUtil, CustomReactiveUserDetailsService userDetailsService) {
//        this.jwtUtil = jwtUtil;
//        this.userDetailsService = userDetailsService;
//    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//    @Bean
//    @Primary
//    public ReactiveAuthenticationManager reactiveAuthenticationManager() {
//        return new CustomReactiveJwtAuthenticationManager(userDetailsService, passwordEncoder());
//    }
//
//    @Bean
//    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
//        // Create the JWT authentication filter
//        AuthenticationWebFilter jwtAuthenticationFilter = new AuthenticationWebFilter(reactiveAuthenticationManager());
//        jwtAuthenticationFilter.setServerAuthenticationConverter(new CustomJwtAuthenticationConverter(jwtUtil));
//        jwtAuthenticationFilter.setRequiresAuthenticationMatcher(ServerWebExchangeMatchers.pathMatchers("/**"));
//
//        // Configure security
//        return http
//                .csrf(csrf -> csrf.disable()) // Disable CSRF
//                .cors(cors -> cors.disable()) // Disable CORS
//                .httpBasic(httpBasic -> httpBasic.disable()) // Disable HTTP Basic Authentication
//                .formLogin(formLogin -> formLogin.disable()) // Disable Form-Based Login
//                .exceptionHandling(exceptionHandling -> exceptionHandling
//                        .authenticationEntryPoint((swe, e) -> Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED)))
//                        .accessDeniedHandler((swe, e) -> Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN)))
//                )
//                .authorizeExchange(authorize -> authorize
//                        .pathMatchers(HttpMethod.OPTIONS).permitAll() // Allow CORS preflight requests
//                        .pathMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/auth/register", "/auth/login", "/auth/public").permitAll()
//                        .pathMatchers("/config/**").authenticated() // Example: Protect config service
//                        .pathMatchers("/auth/admin/assign-role").hasRole("SUPER_ADMINISTRATOR")
//                        .pathMatchers("/auth/admin/**").hasRole("ADMINISTRATOR")
//                        .pathMatchers("/auth/teacher/**").hasAnyRole("TEACHER", "ADMINISTRATOR") // Example: Protect teacher endpoints
//                        .pathMatchers("/auth/student/**").hasRole("STUDENT") // Example: Protect student endpoints
//                        .anyExchange().authenticated() // All other endpoints require authentication
//                )
//                .oauth2ResourceServer(oauth2 -> oauth2
//                        .jwt(jwt -> jwt.jwtAuthenticationConverter(new CustomJwtAuthenticationConverter(jwtUtil)))
//                )
//                .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION) // Add JWT filter
//                .build();
//    }
//}

package com.app.api_gateway.config;

import com.app.api_gateway.security.CustomJwtAuthenticationConverter;
import com.app.api_gateway.security.JwtUtil;
import com.app.api_gateway.security.CustomReactiveJwtAuthenticationManager;
import com.app.api_gateway.security.CustomReactiveUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final JwtUtil jwtUtil;
    private final CustomReactiveUserDetailsService userDetailsService;

    public SecurityConfig(JwtUtil jwtUtil, CustomReactiveUserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Primary
    public ReactiveAuthenticationManager reactiveAuthenticationManager() {
        return new CustomReactiveJwtAuthenticationManager(userDetailsService, passwordEncoder());
    }

    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
        // Create the JWT authentication filter
        AuthenticationWebFilter jwtAuthenticationFilter = new AuthenticationWebFilter(reactiveAuthenticationManager());
        jwtAuthenticationFilter.setServerAuthenticationConverter(new CustomJwtAuthenticationConverter(jwtUtil));
        jwtAuthenticationFilter.setRequiresAuthenticationMatcher(ServerWebExchangeMatchers.pathMatchers("/**"));

        // Configure security
        return http
                .csrf(csrf -> csrf.disable()) // Disable CSRF
                .cors(cors -> cors.disable()) // Disable CORS
                .httpBasic(httpBasic -> httpBasic.disable()) // Disable HTTP Basic Authentication
                .formLogin(formLogin -> formLogin.disable()) // Disable Form-Based Login
//                .authorizeExchange(exchanges -> exchanges
//                        .pathMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
//                        .anyExchange().authenticated()
//                )
//                .build();
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint((swe, e) -> Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED)))
                        .accessDeniedHandler((swe, e) -> Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN)))
                )
                .authorizeExchange(authorize -> authorize
                        .pathMatchers(HttpMethod.OPTIONS).permitAll() // Allow CORS preflight requests
                        .pathMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/auth/register", "/auth/login", "/auth/public").permitAll()
                        .pathMatchers("/config/**").authenticated() // Example: Protect config service
                        .pathMatchers("/auth/admin/assign-role").hasRole("SUPER_ADMINISTRATOR")
                        .pathMatchers("/auth/admin/**").hasRole("ADMINISTRATOR")
                        .pathMatchers("/auth/teacher/**").hasAnyRole("TEACHER", "ADMINISTRATOR") // Example: Protect teacher endpoints
                        .pathMatchers("/auth/student/**").hasRole("STUDENT") // Example: Protect student endpoints
                        .anyExchange().authenticated() // All other endpoints require authentication
                )
                .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION) // Add JWT filter
                .build();
    }
}