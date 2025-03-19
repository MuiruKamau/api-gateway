package com.app.api_gateway.authentication;

import lombok.Data;

@Data
public class UserRegistrationDto {
    private String username;
    private String firstname;
    private String lastname;
    private String password;
    private String email;
    // Removed: private Set<Role> roles;
}