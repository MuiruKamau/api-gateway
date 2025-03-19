package com.app.api_gateway.authentication;

import com.app.api_gateway.security.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.HashSet;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ReactiveAuthenticationManager authenticationManager;

    public AuthController(JwtUtil jwtUtil, UserRepository userRepository, PasswordEncoder passwordEncoder, ReactiveAuthenticationManager authenticationManager) {
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/register")
    public Mono<ResponseEntity<ApiResponse>> registerUser(@RequestBody UserRegistrationDto registrationDto) {
        return Mono.fromCallable(() -> {
                    User user = new User();
                    user.setUsername(registrationDto.getUsername());
                    user.setFirstname(registrationDto.getFirstname());
                    user.setLastname(registrationDto.getLastname());
                    user.setEmail(registrationDto.getEmail());
                    user.setPassword(passwordEncoder.encode(registrationDto.getPassword()));
                    user.setRoles(new HashSet<>()); // Users initially have no roles

                    userRepository.save(user);
                    return ResponseEntity.ok().body(new ApiResponse(null, "Registration successful", HttpStatus.OK.value()));
                })
                .subscribeOn(Schedulers.boundedElastic()); // Important for blocking operations
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<ApiResponse>> authenticateUser(@RequestBody AuthenticationRequestDto authRequest) {
        return this.authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()))
                .map(auth -> ResponseEntity.ok(new ApiResponse(jwtUtil.generateToken(auth.getName()), "Login successful", HttpStatus.OK.value())))
                .onErrorResume(e -> Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ApiResponse("Invalid credentials", HttpStatus.UNAUTHORIZED.value())))); // Use convenience constructor
    }

    @PostMapping("/admin/assign-role")
    public Mono<ResponseEntity<ApiResponse>> assignRole(@RequestBody RoleAssignmentDto roleAssignmentDto) {
        return Mono.fromCallable(() -> {
            var userOptional = userRepository.findByUsername(roleAssignmentDto.getUsername());
            if (userOptional.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ApiResponse("User not found", HttpStatus.NOT_FOUND.value())); // Use convenience constructor
            }

            User user = userOptional.get();
            user.setRoles(roleAssignmentDto.getRoles());
            userRepository.save(user);

            return ResponseEntity.ok(new ApiResponse(null,
                    "Roles assigned successfully to user: " + user.getUsername(), HttpStatus.OK.value()));
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // Example endpoint - access controlled by Spring Security
    @GetMapping("/admin/dashboard")
    public Mono<ResponseEntity<ApiResponse>> adminDashboard() {
        return Mono.just(ResponseEntity.ok(new ApiResponse(null, "Admin Dashboard - Admin Role Required", HttpStatus.OK.value())));
    }

    @GetMapping("/teacher/courses")
    public Mono<ResponseEntity<ApiResponse>> teacherCourses() {
        return Mono.just(ResponseEntity.ok(new ApiResponse(null, "Teacher Courses - Teacher or Admin Role Required", HttpStatus.OK.value())));
    }

    @GetMapping("/student/profile")
    public Mono<ResponseEntity<ApiResponse>> studentProfile() {
        return Mono.just(ResponseEntity.ok(new ApiResponse(null, "Student Profile - Student, Teacher, or Admin Role Required", HttpStatus.OK.value())));
    }

    @GetMapping("/public")
    public Mono<ResponseEntity<ApiResponse>> publicEndpoint() {
        return Mono.just(ResponseEntity.ok(new ApiResponse(null, "Public Endpoint - No Authentication Required", HttpStatus.OK.value())));
    }


}
//package com.app.api_gateway.authentication;
//
//import com.app.api_gateway.security.JwtUtil;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.authentication.ReactiveAuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.web.bind.annotation.*;
//import reactor.core.publisher.Mono;
//import reactor.core.scheduler.Schedulers;
//
//import java.util.HashSet;
//
//@RestController
//@RequestMapping("/auth")
//public class AuthController {
//
//    private final JwtUtil jwtUtil;
//    private final UserRepository userRepository;
//    private final PasswordEncoder passwordEncoder;
//    private final ReactiveAuthenticationManager authenticationManager;
//
//    public AuthController(JwtUtil jwtUtil, UserRepository userRepository, PasswordEncoder passwordEncoder, ReactiveAuthenticationManager authenticationManager) {
//        this.jwtUtil = jwtUtil;
//        this.userRepository = userRepository;
//        this.passwordEncoder = passwordEncoder;
//        this.authenticationManager = authenticationManager;
//    }
//
//    @PostMapping("/register")
//    public Mono<ResponseEntity<ApiResponse>> registerUser(@RequestBody UserRegistrationDto registrationDto) {
//        return Mono.fromCallable(() -> {
//                    User user = new User();
//                    user.setUsername(registrationDto.getUsername());
//                    user.setFirstname(registrationDto.getFirstname());
//                    user.setLastname(registrationDto.getLastname());
//                    user.setEmail(registrationDto.getEmail());
//                    user.setPassword(passwordEncoder.encode(registrationDto.getPassword()));
//                    user.setRoles(new HashSet<>()); // Users initially have no roles
//
//                    userRepository.save(user);
//                    return ResponseEntity.ok().body(new ApiResponse(null, "Registration successful", HttpStatus.OK.value()));
//                })
//                .subscribeOn(Schedulers.boundedElastic()); // Important for blocking operations
//    }
//
//    @PostMapping("/login")
//    public Mono<ResponseEntity<ApiResponse>> authenticateUser(@RequestBody AuthenticationRequestDto authRequest) {
//        return this.authenticationManager.authenticate(
//                        new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()))
//                .map(auth -> ResponseEntity.ok(new ApiResponse(jwtUtil.generateToken(auth.getName()), "Login successful", HttpStatus.OK.value())))
//                .onErrorResume(e -> Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ApiResponse(null, "Invalid credentials", HttpStatus.UNAUTHORIZED.value())))); // Better error handling
//    }
//
//    @PostMapping("/admin/assign-role")
//    public Mono<ResponseEntity<ApiResponse>> assignRole(@RequestBody RoleAssignmentDto roleAssignmentDto) {
//        return Mono.fromCallable(() -> {
//            var userOptional = userRepository.findByUsername(roleAssignmentDto.getUsername());
//            if (userOptional.isEmpty()) {
//                return ResponseEntity.status(HttpStatus.NOT_FOUND)
//                        .body(new ApiResponse("User not found", HttpStatus.NOT_FOUND.value()));
//            }
//
//            User user = userOptional.get();
//            user.setRoles(roleAssignmentDto.getRoles());
//            userRepository.save(user);
//
//            return ResponseEntity.ok(new ApiResponse(null,
//                    "Roles assigned successfully to user: " + user.getUsername(), HttpStatus.OK.value()));
//        }).subscribeOn(Schedulers.boundedElastic());
//    }
//
//    // Example endpoint - access controlled by Spring Security
//    @GetMapping("/admin/dashboard")
//    public Mono<ResponseEntity<ApiResponse>> adminDashboard() {
//        return Mono.just(ResponseEntity.ok(new ApiResponse(null, "Admin Dashboard - Admin Role Required", HttpStatus.OK.value())));
//    }
//
//    @GetMapping("/teacher/courses")
//    public Mono<ResponseEntity<ApiResponse>> teacherCourses() {
//        return Mono.just(ResponseEntity.ok(new ApiResponse(null, "Teacher Courses - Teacher or Admin Role Required", HttpStatus.OK.value())));
//    }
//
//    @GetMapping("/student/profile")
//    public Mono<ResponseEntity<ApiResponse>> studentProfile() {
//        return Mono.just(ResponseEntity.ok(new ApiResponse(null, "Student Profile - Student, Teacher, or Admin Role Required", HttpStatus.OK.value())));
//    }
//
//    @GetMapping("/public")
//    public Mono<ResponseEntity<ApiResponse>> publicEndpoint() {
//        return Mono.just(ResponseEntity.ok(new ApiResponse(null, "Public Endpoint - No Authentication Required", HttpStatus.OK.value())));
//    }
//}