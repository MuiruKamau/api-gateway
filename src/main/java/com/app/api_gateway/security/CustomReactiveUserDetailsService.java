package com.app.api_gateway.security;

import com.app.api_gateway.authentication.User;
import com.app.api_gateway.authentication.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.stream.Collectors;

@Service
public class CustomReactiveUserDetailsService implements ReactiveUserDetailsService { // Renamed the class

    private final UserRepository userRepository;

    public CustomReactiveUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        // Convert blocking repository call to reactive using Schedulers.boundedElastic()
        return Mono.fromCallable(() -> userRepository.findByUsername(username)
                        .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username)))
                .subscribeOn(Schedulers.boundedElastic()) // Use a scheduler for blocking calls
                .map(user -> new org.springframework.security.core.userdetails.User(
                        user.getUsername(), user.getPassword(),
                        user.getRoles().stream()
                                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                                .collect(Collectors.toList())));
    }
}