package com.app.api_gateway.authentication;

import lombok.Data;

@Data
public class AuthenticationRequestDto {
    private String username;
    private String password;
}

